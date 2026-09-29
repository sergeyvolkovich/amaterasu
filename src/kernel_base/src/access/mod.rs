use attachable_slab_allocator::SlabError;

use crate::{
    access::{
        capability::{CapabilityObject, CapabilityZygote},
        namespace::{Namespace, NamespaceError, NamespaceRights},
    },
    collection::{LLSlabIO, RBSlabIO},
    task::tcb::GTcb,
    traits::memory::MemoryInterfaceUserspace,
};
use core::ptr::NonNull;

pub mod capability;
pub mod capspace;
pub mod namespace;

/// zygote и namespaces обслуживаются РАЗНЫМИ пулами id (queue_id +
/// reusable_queue), а не одним общим, как в исходном наброске. Причина:
/// у них разная политика переиспользования слота.
///   - zygote: слот НИКОГДА не удаляется из дерева по-настоящему (см.
///     комментарий у CapabilityZygote) — переиспользование id всегда
///     означает recycle() уже существующей записи.
///   - namespaces: слот при уничтожении реально удаляется из дерева
///     (память возвращается в slab) — переиспользование id означает
///     обычный insert() в пустое место.
///     Общий пул смешал бы эти два случая: id, освобождённый как
///     namespace, мог бы всплыть в очереди zygote и обвалить `.expect()`
///     на несуществующей записи (или наоборот — тихо потерять инвариант).
pub struct AccessManager<UMAP: MemoryInterfaceUserspace> {
    zygote: RBSlabIO<u64, CapabilityZygote<UMAP>, false>,
    namespaces: RBSlabIO<u64, Namespace, false>,

    zygote_queue_id: u64,
    zygote_reusable_queue: LLSlabIO<u64, false>,

    namespace_queue_id: u64,
    namespace_reusable_queue: LLSlabIO<u64, false>,
}

#[derive(Debug)]
pub enum AccessError {
    /// Пробросили ошибку из аллокатора слотов кэша.
    Slab(SlabError),
    /// Счётчик id переполнился (реалистично не должно случаться, но
    /// лучше явная ошибка, чем паника/переполнение до 0).
    IdSpaceExhausted,
}

impl From<SlabError> for AccessError {
    fn from(e: SlabError) -> Self {
        AccessError::Slab(e)
    }
}

#[derive(Debug)]
pub enum DestroyObjectError {
    NotFound,
    /// Повторный destroy уже затумбстоуненного слота — ошибка
    /// вызывающего кода. id НЕ возвращается в очередь повторно (иначе
    /// один и тот же id мог бы уйти в оборот дважды и одновременно
    /// обслуживать два разных "новых" объекта).
    AlreadyEmpty,
}

#[derive(Debug)]
pub enum DestroyNamespaceError {
    NotFound,
    /// Повторный destroy уже затумбстоуненного namespace — как и у
    /// DestroyObjectError::AlreadyEmpty, id НЕ уходит в очередь
    /// повторно (иначе он мог бы обслужить два разных "новых"
    /// namespace одновременно).
    AlreadyDestroyed,
    /// В namespace ещё есть живые задачи и/или занятая память —
    /// удалять его сейчас значит оставить их ссылающимися в никуда.
    NotEmpty,
}

#[derive(Debug)]
pub enum CreateTaskError {
    NamespaceNotFound,
    Namespace(NamespaceError),
    Access(AccessError),
}

/// Итог групповой (namespace-уровня) проверки прав задачи.
///
/// Это НЕ проверка самой capability (она в LinkedRecord::resolve / CapFault),
/// а проверка потолка неймспейса, у которого приоритет над правами потока.
#[derive(Debug)]
pub enum RightsCheckError {
    /// Задачи с таким cap id нет (или её capability отозвана).
    NoTask,
    /// Неймспейс задачи не даёт запрошенное малогранулярное право —
    /// доступ запрещён независимо от прав самой capability.
    RightsDenied,
}

#[derive(Debug)]
pub enum DestroyTaskError {
    NotFound,
    NotTask,
    NamespaceRevoked,
    NamespaceAccountingUnderflow,
    Object(DestroyObjectError),
}

/// Результат выделения id: разница между "совсем новый" и
/// "переиспользованный" важна только для zygote (см. create_new_object);
/// для namespaces оба случая обрабатываются одинаково.
enum IdSlot {
    Fresh(u64),
    Reused(u64),
}

impl<UMAP: MemoryInterfaceUserspace> AccessManager<UMAP> {
    pub fn new() -> Result<Self, SlabError> {
        Ok(Self {
            zygote: RBSlabIO::new()?,
            namespaces: RBSlabIO::new()?,
            zygote_queue_id: 0,
            zygote_reusable_queue: LLSlabIO::new()?,
            namespace_queue_id: 0,
            namespace_reusable_queue: LLSlabIO::new()?,
        })
    }

    fn allocate_id(
        next_id: &mut u64,
        reusable: &mut LLSlabIO<u64, false>,
    ) -> Result<IdSlot, AccessError> {
        if let Some(id) = reusable.pop_front() {
            return Ok(IdSlot::Reused(id));
        }
        let id = *next_id;
        *next_id = next_id
            .checked_add(1)
            .ok_or(AccessError::IdSpaceExhausted)?;
        Ok(IdSlot::Fresh(id))
    }

    fn release_id(reusable: &mut LLSlabIO<u64, false>, id: u64) {
        // Не критичный путь: если очередь переполнена — просто
        // теряем id (деградация, не ошибка).
        let _ = reusable.push_back(id);
    }

    /// Создаёт новый capability-объект.
    ///
    /// - Если id переиспользован из очереди — слот уже существует в
    ///   дереве (затумбстоунен предыдущим destroy_object), и мы
    ///   переиспользуем его in-place через `recycle` — адрес зиготы не
    ///   меняется (важно для LinkTarget::Zygote), меняется только
    ///   generation.
    /// - Если id совсем новый — обычная вставка в дерево.
    pub fn create_new_object(
        &mut self,
        capabily_type: CapabilityObject<UMAP>,
    ) -> Result<u64, AccessError> {
        match Self::allocate_id(&mut self.zygote_queue_id, &mut self.zygote_reusable_queue)? {
            IdSlot::Reused(id) => {
                let zygote = self.zygote.get(&id).expect(
                    "id из zygote_reusable_queue обязан ссылаться на существующий (tombstoned) слот",
                );
                // SAFETY: единственный держатель `&mut AccessManager`
                // прямо сейчас — этот же вызов.
                unsafe { zygote.recycle(capabily_type) };
                Ok(id)
            }
            IdSlot::Fresh(id) => {
                self.zygote
                    .insert(id, CapabilityZygote::new(capabily_type))
                    .map_err(AccessError::from)?;
                Ok(id)
            }
        }
    }

    /// Уничтожает capability-объект: слот тумбстоунится (не удаляется
    /// из дерева) и id уходит в очередь переиспользования. Прежний
    /// объект возвращается вызывающему для финализации (например,
    /// корректного разбора TCB) — сам AccessManager этим не занимается.
    pub fn destroy_object(
        &mut self,
        id: u64,
    ) -> Result<CapabilityObject<UMAP>, DestroyObjectError> {
        let zygote = self.zygote.get(&id).ok_or(DestroyObjectError::NotFound)?;
        // SAFETY: единственный держатель `&mut AccessManager` прямо сейчас.
        let taken = unsafe { zygote.tombstone() };
        match taken {
            Some(object) => {
                Self::release_id(&mut self.zygote_reusable_queue, id);
                Ok(object)
            }
            None => Err(DestroyObjectError::AlreadyEmpty),
        }
    }

    pub fn get_object(&self, id: u64) -> Option<&CapabilityObject<UMAP>> {
        self.zygote.get(&id).and_then(|z| z.object())
    }

    pub fn get_task_tcb(&self, id: u64) -> Option<NonNull<GTcb<UMAP>>> {
        self.get_object(id)
            .and_then(CapabilityObject::resolve_task_tcb)
    }

    /// NonNull на зиготу capability-объекта. Нужен слою capspace/сисколлов
    /// для минта первой (корневой) LinkedRecord на только что созданный
    /// объект: LinkedRecord::new_root хранит указатель на зиготу + снимок
    /// generation. Вызывать под тем же `&mut AccessManager`, под которым
    /// объект создавался, чтобы слот не уехал между create и get.
    pub fn get_zygote(&self, id: u64) -> Option<NonNull<CapabilityZygote<UMAP>>> {
        self.zygote.get(&id).map(NonNull::from)
    }

    /// NonNull на живой namespace-узел. Нужен для минта
    /// CapabilityObject::TaskGroupNamespace (тот же контракт, что у
    /// get_zygote: узлы namespaces никогда не удаляются из дерева
    /// по-настоящему, только тумбстоунятся, поэтому адрес стабилен).
    pub fn get_namespace_ptr(&self, id: u64) -> Option<NonNull<Namespace>> {
        self.namespaces
            .get(&id)
            .filter(|ns| ns.is_alive())
            .map(NonNull::from)
    }

    /// Namespace, в котором состоит задача (если она вообще задача).
    ///
    /// Генерация TaskTCB-капабилити сверяется с генерацией namespace —
    /// переиспользованный слот неймспейса не выдаст чужой namespace за
    /// "тот же самый".
    pub fn task_namespace(&self, task_cap_id: u64) -> Option<&Namespace> {
        match self.get_object(task_cap_id)? {
            CapabilityObject::TaskTCB {
                namespace_object,
                namespace_generation,
                ..
            } => {
                let namespace = unsafe { namespace_object.as_ref() };
                (namespace.generation() == *namespace_generation).then_some(namespace)
            }
            _ => None,
        }
    }

    /// Снимок групповых прав задачи (None — задача/неймспейс не найдены).
    pub fn task_namespace_rights(&self, task_cap_id: u64) -> Option<NamespaceRights> {
        self.task_namespace(task_cap_id).map(Namespace::rights)
    }

    /// Проверка групповых прав задачи: запрошенное множество должно
    /// целиком покрываться правами её неймспейса. Приоритет неймспейса:
    /// whatever более гранулярные права есть у capability потока, права
    /// "сверх" потолка группы просто не действуют — здесь отказ.
    pub fn check_task_rights(
        &self,
        task_cap_id: u64,
        requested: NamespaceRights,
    ) -> Result<(), RightsCheckError> {
        let namespace = self
            .task_namespace(task_cap_id)
            .ok_or(RightsCheckError::NoTask)?;
        namespace
            .check_rights(requested)
            .map_err(|_| RightsCheckError::RightsDenied)
    }

    /// Комбинированная проверка "задача может оперировать этим объектом":
    /// класс ресурса переводится в малогранулярное право
    /// (CapabilityObject::required_namespace_rights) и сверяется с
    /// групповыми правами задачи. Вызывается РЯДОМ с resolve() самой
    /// capability — обе проверки должны пройти.
    pub fn check_task_object_access(
        &self,
        task_cap_id: u64,
        object: &CapabilityObject<UMAP>,
    ) -> Result<(), RightsCheckError> {
        self.check_task_rights(task_cap_id, object.required_namespace_rights())
    }

    /// Состоят ли две задачи в одном и том же (живом) namespace —
    /// сравнение по адресам узлов дерева + совпадению generation.
    /// Полезно сисколлам: например, mint "чужой" capability без
    /// сквозного права CAP_MANAGE разумно разрешать только внутри своей
    /// группы.
    pub fn tasks_share_namespace(&self, a_task_cap: u64, b_task_cap: u64) -> bool {
        match (
            self.get_object(a_task_cap),
            self.get_object(b_task_cap),
        ) {
            (
                Some(CapabilityObject::TaskTCB {
                    namespace_object: a_ns,
                    namespace_generation: a_gen,
                    ..
                }),
                Some(CapabilityObject::TaskTCB {
                    namespace_object: b_ns,
                    namespace_generation: b_gen,
                    ..
                }),
            ) => {
                let a = unsafe { a_ns.as_ref() };
                let b = unsafe { b_ns.as_ref() };
                core::ptr::eq(a, b)
                    && a.generation() == *a_gen
                    && b.generation() == *b_gen
            }
            _ => false,
        }
    }

    /// АВТОРИТЕТ НАД ЦЕЛЕВОЙ ЗАДАЧЕЙ: в cspace вызывающего есть ЖИВАЯ
    /// TaskTCB-запись, резолвящаяся в GTcb целевой задачи.
    ///
    /// Закрывает ambient authority: права неймспейса (CAP_MANAGE и т.п.)
    /// разрешают КЛАСС действия, но ЦЕЛЬ действия обязана адресоваться
    /// capability — иначе любой поток с нужным правом группы оперирует
    /// произвольными задачами по угадываемым последовательным id, что
    /// превращает capability-систему в «привилегированную группу».
    /// O(слотов вызывающего); сисколлы управления — некритичный путь.
    ///
    /// Вызывать под permission_backend-локом (и резолв цели, и обход
    /// capspace консистентны только под ним).
    pub fn controls_task(&self, caller_gtcb: &GTcb<UMAP>, target_task_cap: u64) -> bool {
        let Some(target) = self.get_task_tcb(target_task_cap) else {
            return false;
        };
        let caps = caller_gtcb.capspace().lock();
        let mut found = false;
        caps.for_each(|record| {
            if found {
                return;
            }
            if let Ok((object, _)) = record.resolve()
                && object.resolve_task_tcb() == Some(target)
            {
                found = true;
            }
        });
        found
    }

    /// Регистрирует namespace и возвращает id, под которым его можно
    /// будет найти.
    ///
    /// Принимает параметры квоты и групповые права (см. NamespaceRights),
    /// а не готовый `Namespace`: при переиспользовании id нужно писать в
    /// УЖЕ существующий узел дерева через `recycle` (см. комментарий у
    /// struct AccessManager и у Namespace::recycle) — переданный
    /// полностью собранный `Namespace` было бы некуда "переместить" в
    /// этом случае, есть только `&Namespace`.
    pub fn create_namespace(
        &mut self,
        max_task_count: usize,
        max_memory_alloc_per_namespace: usize,
        persistency_badge: usize,
        rights: NamespaceRights,
        max_cap_objects: usize,
    ) -> Result<u64, AccessError> {
        match Self::allocate_id(
            &mut self.namespace_queue_id,
            &mut self.namespace_reusable_queue,
        )? {
            IdSlot::Reused(id) => {
                let namespace = self.namespaces.get(&id).expect(
                    "id из namespace_reusable_queue обязан ссылаться на существующий (tombstoned) слот",
                );
                namespace.recycle(
                    max_task_count,
                    max_memory_alloc_per_namespace,
                    persistency_badge,
                    rights,
                    max_cap_objects,
                );
                Ok(id)
            }
            IdSlot::Fresh(id) => {
                self.namespaces
                    .insert(
                        id,
                        Namespace::new(
                            max_task_count,
                            max_memory_alloc_per_namespace,
                            persistency_badge,
                            rights,
                            max_cap_objects,
                        ),
                    )
                    .map_err(AccessError::from)?;
                Ok(id)
            }
        }
    }

    /// Удаляет namespace, только если он пуст (нет живых задач и
    /// занятой памяти). Слот тумбстоунится, а не удаляется из дерева —
    /// см. комментарий у struct Namespace про `NonNull<Namespace>`
    /// внутри CapabilityObject::TaskGroupNamespace: настоящий remove
    /// оставил бы такие capability с dangling-указателем.
    pub fn destroy_namespace(&mut self, id: u64) -> Result<(), DestroyNamespaceError> {
        let namespace = self
            .namespaces
            .get(&id)
            .ok_or(DestroyNamespaceError::NotFound)?;

        if !namespace.is_alive() {
            return Err(DestroyNamespaceError::AlreadyDestroyed);
        }
        if namespace.task_count() != 0 || namespace.memory_in_use() != 0 {
            return Err(DestroyNamespaceError::NotEmpty);
        }

        namespace.tombstone();
        Self::release_id(&mut self.namespace_reusable_queue, id);
        Ok(())
    }

    /// `None` и для отсутствующего id, и для затумбстоуненного —
    /// вызывающему в обоих случаях просто нет живого namespace.
    pub fn get_namespace(&self, id: u64) -> Option<&Namespace> {
        self.namespaces.get(&id).filter(|ns| ns.is_alive())
    }

    /// Резервирует слот задачи в namespace и создаёт под него TCB-
    /// объект одной операцией. Если создание объекта не удалось —
    /// откатывает резервирование, чтобы учёт namespace не разъезжался
    /// с реальным числом живых задач. Требует только `&self` на
    /// namespace (см. namespace.rs) — get_mut у RBSlabIO нет.
    pub fn create_task_in_namespace(
        &mut self,
        namespace_id: u64,
        task_data: NonNull<GTcb<UMAP>>,
    ) -> Result<u64, CreateTaskError> {
        let namespace = self
            .namespaces
            .get(&namespace_id)
            .ok_or(CreateTaskError::NamespaceNotFound)?;

        namespace
            .try_reserve_task()
            .map_err(CreateTaskError::Namespace)?;

        let namespace_object = NonNull::from(namespace);
        let task_object = CapabilityObject::new_task_tcb(task_data, namespace_object);

        match self.create_new_object(task_object) {
            Ok(id) => Ok(id),
            Err(e) => {
                // Откат: TCB не создан — возвращаем слот в namespace.
                if let Some(namespace) = self.namespaces.get(&namespace_id) {
                    let _ = namespace.release_task();
                }
                Err(CreateTaskError::Access(e))
            }
        }
    }
    /// Destroys a TaskTCB and releases exactly the namespace quota that
    /// was captured when that TaskTCB capability was created.
    pub fn destroy_task(
        &mut self,
        task_cap_id: u64,
    ) -> Result<NonNull<GTcb<UMAP>>, DestroyTaskError> {
        let (task_data, namespace_object, namespace_generation) =
            match self.get_object(task_cap_id) {
                Some(CapabilityObject::TaskTCB {
                    task_data,
                    namespace_object,
                    namespace_generation,
                }) => (*task_data, *namespace_object, *namespace_generation),
                Some(_) => return Err(DestroyTaskError::NotTask),
                None => return Err(DestroyTaskError::NotFound),
            };

        let namespace = unsafe { namespace_object.as_ref() };
        if namespace.generation() != namespace_generation {
            return Err(DestroyTaskError::NamespaceRevoked);
        }
        if namespace.task_count() == 0 {
            return Err(DestroyTaskError::NamespaceAccountingUnderflow);
        }

        match self.destroy_object(task_cap_id) {
            Ok(CapabilityObject::TaskTCB {
                task_data: destroyed_task_data,
                ..
            }) => {
                debug_assert_eq!(destroyed_task_data, task_data);
                namespace
                    .release_task()
                    .map_err(|_| DestroyTaskError::NamespaceAccountingUnderflow)?;
                Ok(destroyed_task_data)
            }
            Ok(_) => Err(DestroyTaskError::NotTask),
            Err(e) => Err(DestroyTaskError::Object(e)),
        }
    }

}
