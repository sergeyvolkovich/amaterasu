use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::access::namespace::{Namespace, NamespaceRights};
use crate::{task::tcb::GTcb, traits::memory::MemoryInterfaceUserspace};
use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DirectCapabilityRights: u8 {
        const Clone = 1;
        const Mint  = 1 << 1;
        const Send  = 1 << 2;
    }
}

pub enum CapabilityObject<UMAP: MemoryInterfaceUserspace> {
    MemoryIPCPool {
        region_owner: NonNull<GTcb<UMAP>>,
    },
    MemoryMMIORegion {
        region_origin: usize,
        region_page_count: usize,
    },
    IRQAcc {
        cpu_id: usize,
        vector: u16,
    },
    TaskTCB {
        task_data: NonNull<GTcb<UMAP>>,
        /// Namespace quota that owns this task; generation protects
        /// against namespace slot recycling.
        namespace_object: NonNull<Namespace>,
        namespace_generation: u64,
    },
    TaskGroupNamespace {
        namespace_object: NonNull<Namespace>,
        /// Глобальный id неймспейса (ключ дерева AccessManager::namespaces).
        /// Нужен сисколлам, создающим задачи по капе неймспейса
        /// (TASK_CREATE): create_task_in_namespace адресуется id, а не
        /// указателем. Дубликат — сознательный: id неизменяем, указатель
        /// не пересчитывает обратное отображение (дерево RBSlabIO не даёт
        /// ptr→id без линейного скана).
        namespace_id: u64,
        /// Снимок Namespace::generation на момент создания этого
        /// CapabilityObject — то же ABA-предохранение, что у
        /// LinkTarget::Zygote, только уровнем ниже: namespaces тоже
        /// никогда не удаляются из своего дерева по-настоящему (см.
        /// AccessManager::destroy_namespace), только тумбстоунятся.
        generation_at_mint: u64,
    },
    /// Образ boot-модуля (ELF в памяти загрузчика, физический адрес +
    /// размер — см. kernel_exec::modules). Authority для TASK_CREATE:
    /// спавн новой задачи возможен ТОЛЬКО по капе на образ — имя модуля
    /// из ring3 было бы ambient authority (угадываемый перебор имён).
    ///
    /// Капы на образы создаются ТОЛЬКО ядром на буте (устанавливаются
    /// init-серверу; динамически созданные задачи таких кап не получают —
    /// спавн ограничен деревом init'а). Чистые данные (без указателей) —
    /// resolve не требует generation-чеков: module_id неизменяем, а
    /// реестр образов не переиспользуется.
    TaskImage {
        /// Индекс в реестре boot-образов (kernel_exec::modules).
        module_id: u32,
    },
    /// Домен трансляции IOMMU (Intel VT-d / AMD-Vi). SeL4-стиль: все
    /// операции над доменом (attach устройства, DMA-маппинг) — инвокации
    /// ЭТОЙ capability: сисколл принимает (task_cap, slot), резолвит
    /// запись через capspace/AccessManager (права Clone/Mint/Send
    /// работают для пересылки домена между задачами) и только потом
    /// лезет в драйвер.
    ///
    /// `unit` — индекс IOMMU-юнита платформы (0 — первый, из boot-таблицы);
    /// `domain_token` — непрозрачный хэндл, который резолвит таблица
    /// доменов в драйвере (slot + generation против ABA).
    IommuDomain {
        unit: u64,
        domain_token: u64,
    },
    /// PASID-пространство (SVA/GCR3): привязка (device, PASID) ->
    /// first-stage адресное пространство. Токен резолвит реестр
    /// PASID-пространств в arch-слое — тот же паттерн, что у IommuDomain.
    /// Инвокации: MapVa/UnmapVa идут через PASID-капабилити (v2),
    /// создание/уничтожение пространства — CreatePasidSpace/DestroyPasidSpace.
    PasidSpace {
        unit: u64,
        space_token: u64,
    },
    /// PASID-капабилити (v2): аппаратный PASID юнита, привязанный к
    /// PASID-пространству, с учётом пользователей (max_users задан при
    /// создании; bind сверх потолка — QuotaExceeded). Носитель капабилити
    /// может передавать её другим задачам (Send) — пользователи одного
    /// PASID считаются и ограничиваются независимо от задач-носителей.
    /// Инвокации: BindPasidDevice/UnbindPasidDevice/MapVa/UnmapVa/FreePasid.
    Pasid {
        unit: u64,
        pasid_token: u64,
    },
    /// Фолт-эндпоинт (стиль seL4 fault endpoint / KeyKOS keeper-ключ):
    /// фиксирует задачу-обработчика фолтов. Создаётся САМИМ обработчиком
    /// (CAP_CREATE_FAULT_ENDPOINT — handler = текущая задача), после
    /// чего любая задача с TaskTCB-капабилити цели может привязать
    /// эндпоинт к цели (FAULT_SET_ENDPOINT) — фолты цели пойдут
    /// обработчику (ipc::fault).
    ///
    /// ABA-защита — как у TaskTCB: снимок поколения зиготы обработчика.
    /// Уничтожение обработчика тумбстоунит его зиготу — поколение
    /// расходится, resolve_fault_endpoint() возвращает None, слот
    /// (и все производные записи) «протухает».
    FaultEndpoint {
        /// Зигота TaskTCB-объекта обработчика.
        handler_zygote: NonNull<CapabilityZygote<UMAP>>,
        /// Поколение зиготы на момент создания (снимок).
        handler_generation: u64,
        /// task_cap_id обработчика (для быстрого доступа; истина —
        /// только пока зигота жива, см. resolve_fault_endpoint).
        handler_task_cap: u64,
    },
}

impl<UMAP: MemoryInterfaceUserspace> CapabilityObject<UMAP> {
    /// Малогранулярное право namespace, требуемое для ОПЕРИРОВАНИЯ данным
    /// классом ресурса. Это вторая (групповая) ось контроля доступа рядом с
    /// высокогранулярными правами самой capability (Clone/Mint/Send):
    ///
    ///   доступ разрешён <=> resolve() капабилити успешен
    ///                      И namespace задачи покрывает required_namespace_rights()
    ///
    /// Благодаря этому даже полностью "всеправная" capability в руках
    /// потока из ограниченной группы бесполезна — неймспейс всегда сильнее
    /// (см. Namespace::check_rights).
    pub fn required_namespace_rights(&self) -> NamespaceRights {
        match self {
            // Пул памяти под IPC-буферы — оперирование обычной памятью.
            CapabilityObject::MemoryIPCPool { .. } => NamespaceRights::MEMORY_ALLOC,
            CapabilityObject::MemoryMMIORegion { .. } => NamespaceRights::MMIO_MAP,
            CapabilityObject::IRQAcc { .. } => NamespaceRights::IRQ_BIND,
            // TaskTCB — право управлять задачами группы (создавать и т.п.).
            CapabilityObject::TaskTCB { .. } => NamespaceRights::TASK_CREATE,
            CapabilityObject::TaskGroupNamespace { .. } => NamespaceRights::CAP_MANAGE,
            // Спавн по образу — та же компетенция, что и управление
            // задачами группы (потолок проверяется отдельно и у ЦЕЛЕВОГО
            // неймспейса, и у вызывающего — см. TASK_CREATE).
            CapabilityObject::TaskImage { .. } => NamespaceRights::TASK_CREATE,
            // DMA-домен — подключение устройств и маппинг DMA-буферов.
            CapabilityObject::IommuDomain { .. } => NamespaceRights::DMA_ATTACH,
            // PASID-пространство — та же DMA-осевшая компетенция группы.
            CapabilityObject::PasidSpace { .. } => NamespaceRights::DMA_ATTACH,
            // PASID-капабилити — оперирование привязками устройств и
            // first-stage маппингами: та же DMA-компетенция.
            CapabilityObject::Pasid { .. } => NamespaceRights::DMA_ATTACH,
            // Фолт-эндпоинт — компетенция обработки чужих фолтов.
            CapabilityObject::FaultEndpoint { .. } => NamespaceRights::FAULT_HANDLE,
        }
    }

    pub fn new_task_tcb(
        task_data: NonNull<GTcb<UMAP>>,
        namespace_object: NonNull<Namespace>,
    ) -> Self {
        let namespace_generation = unsafe { namespace_object.as_ref() }.generation();
        Self::TaskTCB {
            task_data,
            namespace_object,
            namespace_generation,
        }
    }

    pub fn resolve_task_tcb(&self) -> Option<NonNull<GTcb<UMAP>>> {
        match self {
            CapabilityObject::TaskTCB {
                task_data,
                namespace_object,
                namespace_generation,
            } => {
                let namespace = unsafe { namespace_object.as_ref() };
                if namespace.generation() == *namespace_generation {
                    Some(*task_data)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Единственный корректный способ завести TaskGroupNamespace —
    /// снимает generation в момент создания сам, а не полагается на
    /// вызывающего передать её руками (руками легко забыть/ошибиться).
    /// `namespace_id` — глобальный id неймспейса (см. поле варианта).
    pub fn new_task_group_namespace(namespace_object: NonNull<Namespace>, namespace_id: u64) -> Self {
        let generation_at_mint = unsafe { namespace_object.as_ref() }.generation();
        CapabilityObject::TaskGroupNamespace {
            namespace_object,
            namespace_id,
            generation_at_mint,
        }
    }

    /// Единственный корректный способ завести FaultEndpoint: снимает
    /// поколение зиготы обработчика на момент создания сам. Вызывается
    /// под permission_backend-локом (сразу после резолва зиготы
    /// обработчика — AccessManager::get_zygote).
    pub fn new_fault_endpoint(
        handler_zygote: NonNull<CapabilityZygote<UMAP>>,
        handler_task_cap: u64,
    ) -> Self {
        let handler_generation = unsafe { handler_zygote.as_ref() }.generation();
        CapabilityObject::FaultEndpoint {
            handler_zygote,
            handler_generation,
            handler_task_cap,
        }
    }

    /// Живой обработчик фолт-эндпоинта: Some(task_cap_id), пока зигота
    /// обработчика не тумбстоунена/не переиспользована (ABA-защита —
    /// тот же паттерн, что у resolve_task_tcb/resolve_namespace).
    /// Уничтожение задачи-обработчика инвалидирует эндпоинт.
    pub fn resolve_fault_endpoint(&self) -> Option<u64> {
        match self {
            CapabilityObject::FaultEndpoint {
                handler_zygote,
                handler_generation,
                handler_task_cap,
            } => {
                let zygote = unsafe { handler_zygote.as_ref() };
                if zygote.generation() == *handler_generation {
                    Some(*handler_task_cap)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Единственный легальный способ разыменовать `namespace_object` —
    /// сверяет generation (слот не был затумбстоунен/переиспользован с
    /// момента создания этого CapabilityObject) и только тогда отдаёт
    /// `&Namespace`. Аналог LinkedRecord::resolve(), но для дерева
    /// namespaces. Возвращает None и для "не тот вариант enum", и для
    /// "generation не совпала" — вызывающему в обоих случаях просто
    /// нет доступа к namespace.
    pub fn resolve_namespace(&self) -> Option<&Namespace> {
        match self {
            CapabilityObject::TaskGroupNamespace {
                namespace_object,
                generation_at_mint,
                ..
            } => {
                let namespace = unsafe { namespace_object.as_ref() };
                if namespace.generation() == *generation_at_mint {
                    Some(namespace)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// То же, что resolve_namespace, плюс глобальный id неймспейса:
    /// TASK_CREATE адресует create_task_in_namespace именно id.
    pub fn resolve_namespace_with_id(&self) -> Option<(u64, &Namespace)> {
        match self {
            CapabilityObject::TaskGroupNamespace {
                namespace_id,
                namespace_object,
                generation_at_mint,
            } => {
                let namespace = unsafe { namespace_object.as_ref() };
                if namespace.generation() == *generation_at_mint {
                    Some((*namespace_id, namespace))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Реальный ресурс. Жизненный цикл управляется отдельно от мембран.
///
/// ВАЖНО: `LinkTarget::Zygote` (ниже) хранит сырой `NonNull` прямо на
/// эту структуру внутри slab-памяти `RBSlabIO`. Адрес узла в
/// intrusive-дереве стабилен, ПОКА узел не удалён из дерева (ротации
/// RBTree переставляют только intrusive-линки, не сам узел). Поэтому
/// AccessManager НИКОГДА не делает настоящий `remove` для зигот —
/// вместо этого слот "тумбстоунится" (object -> None) и переиспользуется
/// на месте через `recycle`. `object`/`generation` поэтому лежат за
/// UnsafeCell/AtomicU64: RBSlabIO::get(&self) — единственный способ
/// достать существующую запись из дерева, и он даёт только `&V`
/// (get_mut для интрузивных деревьев в принципе не может быть безопасным
/// в этой библиотеке — мутация значения через дерево могла бы сломать
/// порядок, если бы задевала ключ). Мутация допустима лишь потому, что
/// единственный, кто когда-либо зовёт recycle/tombstone — код,
/// держащий `&mut AccessManager` (NoLock-контракт, тот же, что и у
/// самого slab-аллокатора); это внешний инвариант, который тип сам по
/// себе не проверяет.
pub struct CapabilityZygote<UMAP: MemoryInterfaceUserspace> {
    object: UnsafeCell<Option<CapabilityObject<UMAP>>>,
    /// Защита от ABA при переиспользовании слота — ось, не имеющая
    /// отношения к epoch мембраны.
    generation: AtomicU64,
}

impl<UMAP: MemoryInterfaceUserspace> CapabilityZygote<UMAP> {
    /// Создаёт новую зиготу с нулевым поколением — используется при
    /// первой (не переиспользованной) вставке слота в AccessManager.
    pub fn new(object: CapabilityObject<UMAP>) -> Self {
        Self {
            object: UnsafeCell::new(Some(object)),
            generation: AtomicU64::new(0),
        }
    }

    /// `None`, если слот сейчас затумбстоунен (объект уничтожен, но
    /// AccessManager ещё не переиспользовал слот под новый). resolve()
    /// обязан трактовать `None` как CapFault::Revoked.
    pub fn object(&self) -> Option<&CapabilityObject<UMAP>> {
        unsafe { (*self.object.get()).as_ref() }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Помечает слот как логически свободный и возвращает прежний
    /// объект вызывающему (для финализации — например, корректного
    /// разбора TCB). Слот остаётся в дереве, память не освобождается.
    ///
    /// # Safety
    /// Вызывающий обязан держать `&mut AccessManager` (или эквивалент)
    /// на момент вызова — гарантия того, что ни `object()`, ни другой
    /// `tombstone`/`recycle` не выполняются параллельно с этим же слотом.
    pub unsafe fn tombstone(&self) -> Option<CapabilityObject<UMAP>> {
        unsafe {
            self.generation.fetch_add(1, Ordering::AcqRel);
            (*self.object.get()).take()
        }
    }

    /// Переиспользует уже существующий (обычно затумбстоуненный) слот
    /// под новый объект, инкрементя generation — старые LinkedRecord,
    /// хранящие снимок предыдущего generation, перестают резолвиться.
    ///
    /// # Safety
    /// Тот же контракт, что и у `tombstone`.
    pub unsafe fn recycle(&self, object: CapabilityObject<UMAP>) {
        unsafe {
            self.generation.fetch_add(1, Ordering::AcqRel);
            *self.object.get() = Some(object);
        }
    }
}

/// Граница авторитета. Единственная точка правды о том, жив ли
/// доступ, выданный через неё.
pub struct CapabilityMembrane {
    epoch: AtomicU64,
    /// Мягкое ослабление "на лету", без полного отзыва.
    rights_ceiling: DirectCapabilityRights,

    parent: Option<NonNull<CapabilityMembrane>>,
}

impl CapabilityMembrane {
    pub fn new_root(rights_ceiling: DirectCapabilityRights) -> Self {
        Self {
            epoch: AtomicU64::new(0),
            rights_ceiling,
            parent: None,
        }
    }

    /// Дочерняя мембрана: revoke() у любого предка в этой цепочке
    /// автоматически "протухает" всё, что выдано под этой мембраной —
    /// см. effective_epoch().
    pub fn new_child(
        parent: NonNull<CapabilityMembrane>,
        rights_ceiling: DirectCapabilityRights,
    ) -> Self {
        Self {
            epoch: AtomicU64::new(0),
            rights_ceiling,
            parent: Some(parent),
        }
    }

    pub fn revoke(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel); // O(1) на саму мембрану
    }
    pub fn narrow(&mut self, ceiling: DirectCapabilityRights) {
        self.rights_ceiling &= ceiling; // потолок может только сужаться
    }
    fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Эпоха, свёрнутая по всей цепочке предков: revoke() где угодно
    /// выше по дереву меняет это значение, так что resolve() у
    /// потомков сам обнаруживает отзыв предка без обхода детей сверху
    /// вниз. revoke() остаётся O(1) (один atomic add); дороже
    /// становится resolve() — O(глубина дерева мембран), обычно 2-4
    /// уровня на практике.
    pub fn effective_epoch(&self) -> u64 {
        let mut combined = self.current_epoch();
        if let Some(parent) = self.parent {
            combined = combined.wrapping_add(unsafe { parent.as_ref() }.effective_epoch());
        }
        combined
    }
}

/// Цель записи: прямая ссылка на зиготу (корень) или цепочка на
/// родительскую запись (производные той же задачи). Копии В ЧУЖУЮ задачу
/// обязаны идти через flatten (см. transfer_flattened / mint_flattened):
/// цепочка, уходящая в чужой GTcb, делает его дроп use-after-free — слоты
/// capspace живут в slab-памяти задачи и возвращаются системе вместе с
/// GTcb (SlabCache::drop → hook деаллокации).
#[derive(Clone, Copy)]
pub enum LinkTarget<UMAP: MemoryInterfaceUserspace> {
    /// Указатель на зиготу + поколение объекта на момент выдачи. Если
    /// к моменту resolve() поколение зиготы другое — слот был
    /// переиспользован (или затумбстоунен) под другой/никакой объект,
    /// и capability должна считаться протухшей.
    Zygote(NonNull<CapabilityZygote<UMAP>>, u64),
    Chained(NonNull<LinkedRecord<UMAP>>), // делегирование через n границ
}

/// Содержимое записи. Отдельный Copy-тип: tombstone/recycle переписывают
/// его через `&LinkedRecord` (RBSlabIO::get даёт только &) — контракт тот
/// же, что у CapabilityZygote: мутация только кодом, держащим
/// permission_backend-лок (NoLock-контракт, внешний по отношению к типу).
#[derive(Clone, Copy)]
struct RecordBody<UMAP: MemoryInterfaceUserspace> {
    target: LinkTarget<UMAP>,
    membrane: NonNull<CapabilityMembrane>,
    epoch_at_mint: u64, // снимок на момент выдачи
    acc: DirectCapabilityRights, // права, зафиксированные при минте
    /// Снимок generation родительской записи (для Chained-целей): потомок
    /// резолвится только пока родитель жив И его generation не изменился
    /// (tombstone/recycle бампят generation — старые потомки протухают,
    /// даже если память записи осталась той же — ABA закрыт).
    parent_generation: u64,
}

/// Запись capability в слоте задачи.
///
/// ЖИЗНЕННЫЙ ЦИКЛ (критично для безопасности памяти): слоты capspace
/// НИКОГДА не удаляются физически (remove из RBSlabIO запрещён — память
/// слота ушла бы в slab-freelist и была бы переиспользована под чужую
/// запись, а Chained-потомки держат сырой NonNull сюда). Вместо этого:
///   - `tombstone()` — логическое снятие: live=false + bump generation;
///     память остаётся на месте, потомки обнаруживают смерть по
///     live/generation при resolve();
///   - `recycle_with()` — переиспользование затумбстоуненного слота под
///     новую запись на том же адресе (bump generation протухает старых
///     потомков).
/// Память возвращается системе только вместе с GTcb задачи (дроп всей
/// capspace), что безопасно: кросс-задачных Chained-ссылок не существует
/// по построению (только flatten-копии, см. LinkTarget).
pub struct LinkedRecord<UMAP: MemoryInterfaceUserspace> {
    body: UnsafeCell<RecordBody<UMAP>>,
    /// Слот жив (не затумбстоунен). Проверяется ДО любого разыменования body.
    live: AtomicBool,
    /// ABA-предохранитель: снимок берут потомки при минте; tombstone/recycle
    /// бампят. Acquire на чтение, AcqRel на запись.
    generation: AtomicU64,
}

#[derive(Debug)]
pub enum CapFault {
    Revoked,
    RightsExceeded,
}

impl<UMAP: MemoryInterfaceUserspace> LinkedRecord<UMAP> {
    /// Максимальная глубина цепочки Chained-записей. Итеративный resolve
    /// останавливается на этом пределе: юзерспейс не может ни переполнить
    /// ядерный стек длинной цепочкой mint'ов, ни сделать resolve
    /// O(бесконечность). Превышение трактуется как Revoked (запись
    /// юридически «протухла» — резолвиться не должна).
    pub const MAX_CHAIN_DEPTH: usize = 32;

    /// Единственный способ завести самую первую capability на
    /// свежесозданную (или только что переиспользованную) зиготу.
    /// Всё остальное (mint/clone_cap/flatten-копии) только производит
    /// записи от уже существующих.
    pub fn new_root(
        zygote: NonNull<CapabilityZygote<UMAP>>,
        membrane: NonNull<CapabilityMembrane>,
        rights: DirectCapabilityRights,
    ) -> Self {
        let gen_at_mint = unsafe { zygote.as_ref() }.generation();
        Self::new_root_at(zygote, gen_at_mint, membrane, rights)
    }

    /// Внутренний конструктор корня с УЖЕ снятым поколением зиготы
    /// (flatten-копии снимают его в ходе walk()).
    fn new_root_at(
        zygote: NonNull<CapabilityZygote<UMAP>>,
        zygote_generation: u64,
        membrane: NonNull<CapabilityMembrane>,
        rights: DirectCapabilityRights,
    ) -> Self {
        Self {
            body: UnsafeCell::new(RecordBody {
                target: LinkTarget::Zygote(zygote, zygote_generation),
                membrane,
                epoch_at_mint: unsafe { membrane.as_ref() }.effective_epoch(),
                acc: rights,
                parent_generation: 0,
            }),
            live: AtomicBool::new(true),
            generation: AtomicU64::new(0),
        }
    }

    /// Копия тела записи. SAFETY-контракт: вызывать только под
    /// permission_backend-локом (как и все мутации через &self у зигот —
    /// RBSlabIO::get даёт только &, мутации/копии консистентны лишь под
    /// внешним локом).
    fn body(&self) -> RecordBody<UMAP> {
        unsafe { *self.body.get() }
    }

    /// Жив ли слот (не затумбстоунен). Живой записи tombstone не полагается
    /// снаружи — resolve() честно вернёт Revoked.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Снимок generation (потомки берут его при минте).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Логическое снятие записи со слота БЕЗ освобождения памяти:
    /// live=false + bump generation. Потомки с прежним снимком generation
    /// перестают резолвиться (см. walk). Вызывать под
    /// permission_backend-локом.
    pub fn tombstone(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.live.store(false, Ordering::Release);
    }

    /// Переиспользует затумбстоуненный слот под НОВУЮ запись на том же
    /// адресе (bump generation протухает всех старых потомков). Вызывать
    /// под permission_backend-локом, только после is_live() == false.
    ///
    /// # Safety
    /// Контракт тот же, что у CapabilityZygote::recycle: единственный
    /// держатель мутации — код под внешним локом; параллельных
    /// tombstone/recycle быть не может.
    pub unsafe fn recycle_with(&self, body: RecordBody<UMAP>) {
        unsafe {
            self.generation.fetch_add(1, Ordering::AcqRel);
            *self.body.get() = body;
            self.live.store(true, Ordering::Release);
        }
    }

    /// Переиспользует затумбстоуненный слот под НОВУЮ корневую запись на
    /// том же адресе (install_root поверх мёртвого слота). Bump generation
    /// протухает всех старых потомков. Вызывать под permission_backend-локом,
    /// только после is_live() == false.
    pub fn recycle_as_root(
        &self,
        zygote: NonNull<CapabilityZygote<UMAP>>,
        membrane: NonNull<CapabilityMembrane>,
        rights: DirectCapabilityRights,
    ) {
        let gen_at_mint = unsafe { zygote.as_ref() }.generation();
        let body = RecordBody {
            target: LinkTarget::Zygote(zygote, gen_at_mint),
            membrane,
            epoch_at_mint: unsafe { membrane.as_ref() }.effective_epoch(),
            acc: rights,
            parent_generation: 0,
        };
        unsafe { self.recycle_with(body) };
    }

    /// (capspace-слой) Переиспользование затумбстоуненного слота-приёмника
    /// под запись, собранную в другом месте (put_linked_record со слотом,
    /// ранее снятым через take_slot). Вызывать под permission_backend-локом,
    /// только после is_live() == false.
    pub(crate) fn recycle_as(&self, incoming: &Self) {
        let body = incoming.body();
        unsafe { self.recycle_with(body) };
    }

    /// Мембрана, под которой живёт запись (capspace-слой отличает
    /// корневой слот от слота-приёмника clone).
    pub fn membrane_ptr(&self) -> NonNull<CapabilityMembrane> {
        self.body().membrane
    }

    /// Итеративный обход цепочки до зиготы: (зигота, поколение зиготы,
    /// эффективные права). Глубина ограничена MAX_CHAIN_DEPTH.
    ///
    /// КЛЮЧЕВЫЕ ПРОВЕРКИ ЦЕПОЧКИ (анти-UAF/ABA):
    ///   1. каждый узел должен быть жив (live) — затумбстоуненный слот
    ///      остаётся в памяти, но резолвиться не имеет права;
    ///   2. для Chained-узла — снимок parent_generation потомка обязан
    ///      совпадать с текущим generation родителя: tombstone/recycle
    ///      родителя протухает всех старых потомков, даже если память
    ///      осталась той же;
    ///   3. мембрана КАЖДОГО узла: effective_epoch() == epoch_at_mint
    ///      (lazy revocation, O(1) revoke) и права пересекаются по всей
    ///      цепочке (монотонность).
    fn walk(&self) -> Result<(NonNull<CapabilityZygote<UMAP>>, u64, DirectCapabilityRights), CapFault> {
        let mut node: &LinkedRecord<UMAP> = self;
        // Пересечение прав от потомков к предкам: начинается как «всё»,
        // каждый пройденный узел сужает. Финальные права считаются на
        // зиготном узле: effective & accumulated.
        let mut accumulated = DirectCapabilityRights::all();
        for _ in 0..Self::MAX_CHAIN_DEPTH {
            if !node.is_live() {
                return Err(CapFault::Revoked);
            }
            let body = node.body();
            let membrane = unsafe { body.membrane.as_ref() };
            if membrane.effective_epoch() != body.epoch_at_mint {
                return Err(CapFault::Revoked);
            }
            let effective = body.acc & membrane.rights_ceiling;
            match body.target {
                LinkTarget::Zygote(z, gen_at_mint) => {
                    let zygote = unsafe { z.as_ref() };
                    if zygote.generation() != gen_at_mint {
                        return Err(CapFault::Revoked);
                    }
                    // Объект обязан существовать (None — затумбстоунен).
                    if zygote.object().is_none() {
                        return Err(CapFault::Revoked);
                    }
                    return Ok((z, gen_at_mint, effective & accumulated));
                }
                LinkTarget::Chained(p) => {
                    let parent = unsafe { p.as_ref() };
                    // ABA/UAF-защита цепочки: родитель затумбстоунен или
                    // его слот переиспользован (generation разошёлся) —
                    // capability протухла.
                    if !parent.is_live() || parent.generation() != body.parent_generation {
                        return Err(CapFault::Revoked);
                    }
                    accumulated &= effective;
                    node = parent;
                }
            }
        }
        // Превышение глубины: юридически протухшая запись.
        Err(CapFault::Revoked)
    }

    /// Единственный легальный путь добраться до объекта — никакой
    /// другой код не матчит target/membrane напрямую.
    pub fn resolve(&self) -> Result<(&CapabilityObject<UMAP>, DirectCapabilityRights), CapFault> {
        let (z, gen, rights) = self.walk()?;
        let zygote = unsafe { z.as_ref() };
        // walk() только что проверил generation и живость объекта; между
        // ними гонки нет (код под permission_backend-локом).
        debug_assert_eq!(zygote.generation(), gen);
        let object = zygote.object().ok_or(CapFault::Revoked)?;
        Ok((object, rights))
    }

    /// Монотонность: новые права не могут превышать те, что есть у минтера.
    /// Производная запись ЦЕПЛЯЕТСЯ за родителя (LinkTarget::Chained):
    /// revoke/tombstone родителя протухает потомка. Ровно поэтому mint
    /// разрешён только В ПРЕДЕЛАХ ОДНОЙ capspace — кросс-задачные копии
    /// обязаны идти через mint_flattened (см. ниже).
    pub fn mint(
        &self,
        requested: DirectCapabilityRights,
        membrane: NonNull<CapabilityMembrane>,
    ) -> Result<Self, CapFault> {
        let (_, my_rights) = self.resolve()?;
        if !my_rights.contains(DirectCapabilityRights::Mint) {
            return Err(CapFault::RightsExceeded);
        }
        let new_rights = requested & my_rights;
        if new_rights != requested {
            return Err(CapFault::RightsExceeded);
        }
        Ok(Self {
            body: UnsafeCell::new(RecordBody {
                target: LinkTarget::Chained(NonNull::from(self)),
                membrane,
                epoch_at_mint: unsafe { membrane.as_ref() }.effective_epoch(),
                acc: new_rights,
                // Снимок поколения родителя: его tombstone/recycle
                // протухает этого потомка.
                parent_generation: self.generation(),
            }),
            live: AtomicBool::new(true),
            generation: AtomicU64::new(0),
        })
    }

    /// Кросс-задачный mint: цепочка НЕ строится — resolve() проходит по
    /// ней ЗДЕСЬ, и копия ставится ПРЯМО на зиготу под мембраной
    /// получателя. Осознанная плата: revoke слота источника больше не
    /// убивает копию получателя (работает уничтожение объекта — tombstone
    /// зиготы). Альтернатива (цепочка в чужой capspace) — use-after-free
    /// при дропе GTcb источника: slab-память записи-родителя возвращается
    /// системе вместе с задачей.
    pub fn mint_flattened(
        &self,
        requested: DirectCapabilityRights,
        membrane: NonNull<CapabilityMembrane>,
    ) -> Result<Self, CapFault> {
        let (_, my_rights) = self.resolve()?;
        if !my_rights.contains(DirectCapabilityRights::Mint) {
            return Err(CapFault::RightsExceeded);
        }
        let new_rights = requested & my_rights;
        if new_rights != requested {
            return Err(CapFault::RightsExceeded);
        }
        let (zygote, gen, _) = self.walk()?;
        Ok(Self::new_root_at(zygote, gen, membrane, new_rights))
    }

    /// Прямое клонирование в пределах ТОЙ ЖЕ capspace: права и потолок
    /// не меняются, требуется Clone (а не Mint). Полезно, когда одну и
    /// ту же capability нужно положить в два слота одного домена, не
    /// создавая новую границу авторитета.
    pub fn clone_cap(&self) -> Result<Self, CapFault> {
        let (_, my_rights) = self.resolve()?;
        if !my_rights.contains(DirectCapabilityRights::Clone) {
            return Err(CapFault::RightsExceeded);
        }
        Ok(Self {
            body: UnsafeCell::new(RecordBody {
                target: LinkTarget::Chained(NonNull::from(self)),
                membrane: self.body().membrane,
                epoch_at_mint: self.body().epoch_at_mint,
                acc: self.body().acc,
                parent_generation: self.generation(),
            }),
            live: AtomicBool::new(true),
            generation: AtomicU64::new(0),
        })
    }

    /// Кросс-задачный клон: права сохраняются, но копия ставится ПРЯМО на
    /// зиготу под мембраной получателя (без цепочки в чужую capspace —
    /// см. mint_flattened).
    pub fn clone_flattened(
        &self,
        membrane: NonNull<CapabilityMembrane>,
    ) -> Result<Self, CapFault> {
        let (_, my_rights) = self.resolve()?;
        if !my_rights.contains(DirectCapabilityRights::Clone) {
            return Err(CapFault::RightsExceeded);
        }
        let new_rights = self.body().acc & my_rights;
        let (zygote, gen, _) = self.walk()?;
        Ok(Self::new_root_at(zygote, gen, membrane, new_rights))
    }

    /// Проверка права на передачу через IPC. Сама пересылка (запись в
    /// cspace/сообщение целевой задачи) — забота IPC-кода; эта функция
    /// только гарантирует, что у отправителя есть Send, и возвращает
    /// уже суженные потолком мембраны права для копии на стороне
    /// получателя.
    pub fn check_send(&self) -> Result<DirectCapabilityRights, CapFault> {
        let (_, my_rights) = self.resolve()?;
        if !my_rights.contains(DirectCapabilityRights::Send) {
            return Err(CapFault::RightsExceeded);
        }
        Ok(my_rights)
    }

    /// Копия capability для пересылки через IPC (межзадачная — ВСЕГДА
    /// flatten, см. mint_flattened). Используется
    /// ipc::cap_transfer::transfer_capability.
    ///
    /// Отличия от mint_flattened():
    ///   - требуется не право Mint, а уже проверенный Send (вызывается
    ///     строго после check_send() — здесь он не повторяется);
    ///   - копия ставится под мембрану СЛОТА ПОЛУЧАТЕЛЯ: revoke() на
    ///     стороне получателя убивает его копию, не трогая оригинал
    ///     отправителя, и наоборот.
    ///
    /// Права копии — пересечение прав источника и запрошенных; запрос
    /// больше доступного — RightsExceeded (расширение прав при пересылке
    /// невозможно в принципе).
    pub fn transfer_flattened(
        &self,
        requested: DirectCapabilityRights,
        membrane: NonNull<CapabilityMembrane>,
    ) -> Result<Self, CapFault> {
        let (_, my_rights) = self.resolve()?;
        let new_rights = self.body().acc & my_rights & requested;
        if new_rights != requested {
            return Err(CapFault::RightsExceeded);
        }
        let (zygote, gen, _) = self.walk()?;
        Ok(Self::new_root_at(zygote, gen, membrane, new_rights))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{
        ErrorCode, FrameAllocator, MemoryInterfaceUserspace, MemoryPTR,
    };

    /// Фиктивный умап: capability-логика пользовательскую память не трогает.
    struct FakeUmap;

    impl MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _c: usize,
        ) -> Result<MemoryPTR, ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _r: MemoryPTR,
            _c: usize,
        ) -> Result<(), ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _p: MemoryPTR,
            _v: usize,
        ) -> Result<MemoryPTR, ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _p: MemoryPTR,
            _v: usize,
        ) -> Result<(), ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, _virt: usize) -> Option<usize> {
            None
        }
    }

    fn mmio_object(origin: usize) -> CapabilityObject<FakeUmap> {
        CapabilityObject::MemoryMMIORegion {
            region_origin: origin,
            region_page_count: 1,
        }
    }

    fn leaked<T>(v: T) -> NonNull<T> {
        NonNull::from(Box::leak(Box::new(v)))
    }

    fn assert_mmio_origin(obj: &CapabilityObject<FakeUmap>, expected: usize) {
        match obj {
            CapabilityObject::MemoryMMIORegion {
                region_origin, ..
            } => assert_eq!(*region_origin, expected),
            _ => panic!("ожидался MMIO-объект"),
        }
    }

    /// UAF-гипотеза (take_slot): tombstone записи ДОЛЖЕН протухать
    /// Chained-потомков, при этом память записи не освобождается.
    #[test]
    fn tombstone_kills_chained_children() {
        let zygote = leaked(CapabilityZygote::new(mmio_object(0x1000)));
        let membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let root = leaked(LinkedRecord::<FakeUmap>::new_root(
            zygote,
            membrane,
            DirectCapabilityRights::all(),
        ));

        let child_membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let child = leaked(
            root.mint(DirectCapabilityRights::all(), child_membrane)
                .expect("mint"),
        );

        // Пока родитель жив — ребёнок резолвится в тот же объект.
        let (obj, _) = child.resolve().expect("живая цепочка");
        assert_mmio_origin(obj, 0x1000);

        // take_slot-семантика: tombstone на месте (remove запрещён).
        root.tombstone();
        assert!(matches!(child.resolve(), Err(CapFault::Revoked)));
        // Снятая запись сама тоже перестаёт резолвиться.
        assert!(matches!(root.resolve(), Err(CapFault::Revoked)));
    }

    /// ABA-эскалация: слот переустановлен в ТОТ ЖЕ адрес под ДРУГОЙ объект.
    /// Потомок со старым снимком generation обязан протухнуть, а не
    /// унаследовать чужой объект/права (до фикса resolve() возвращал
    /// новый объект — эскалация прав без какой-либо capability на него).
    #[test]
    fn recycle_slot_closes_aba() {
        let zygote_a = leaked(CapabilityZygote::new(mmio_object(0xA000)));
        let membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let parent = leaked(LinkedRecord::<FakeUmap>::new_root(
            zygote_a,
            membrane,
            DirectCapabilityRights::all(),
        ));

        let child_membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let child = leaked(
            parent
                .mint(DirectCapabilityRights::all(), child_membrane)
                .expect("mint"),
        );
        assert!(child.resolve().is_ok());

        // destroy слота + повторная установка в тот же номер (recycle):
        // адрес записи тот же, generation и объект — другие.
        parent.tombstone();
        let zygote_b = leaked(CapabilityZygote::new(mmio_object(0xB000)));
        parent.recycle_as_root(zygote_b, membrane, DirectCapabilityRights::all());

        // Прежний потомок НЕ резолвится в чужой 0xB000.
        assert!(matches!(child.resolve(), Err(CapFault::Revoked)));
    }

    /// Flatten-копия переживает tombstone ИСТОЧНИКА (ссылается прямо на
    /// зиготу — дроп GTcb отправителя безопасен), но умирает вместе с
    /// уничтожением самого ОБЪЕКТА.
    #[test]
    fn flattened_copy_survives_source_tombstone() {
        let zygote = leaked(CapabilityZygote::new(mmio_object(0xC000)));
        let membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let source = leaked(LinkedRecord::<FakeUmap>::new_root(
            zygote,
            membrane,
            DirectCapabilityRights::all(),
        ));

        let recv_membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let copy = leaked(
            source
                .mint_flattened(DirectCapabilityRights::all(), recv_membrane)
                .expect("flatten mint"),
        );

        source.tombstone();
        let (obj, _) = copy.resolve().expect("flatten-копия переживает источник");
        assert_mmio_origin(obj, 0xC000);

        // Уничтожение объекта (tombstone зиготы) убивает flatten-копию.
        unsafe { zygote.as_ref() }.tombstone();
        assert!(matches!(copy.resolve(), Err(CapFault::Revoked)));
    }

    /// Lazy revocation мембраны убивает и корень, и производные цепочки.
    #[test]
    fn membrane_revoke_kills_chain() {
        let zygote = leaked(CapabilityZygote::new(mmio_object(0xD000)));
        let root_membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let root = leaked(LinkedRecord::<FakeUmap>::new_root(
            zygote,
            root_membrane,
            DirectCapabilityRights::all(),
        ));

        let child_membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let child = leaked(
            root.mint(DirectCapabilityRights::all(), child_membrane)
                .expect("mint"),
        );
        assert!(child.resolve().is_ok());

        unsafe { root_membrane.as_ref() }.revoke();
        assert!(matches!(root.resolve(), Err(CapFault::Revoked)));
        assert!(matches!(child.resolve(), Err(CapFault::Revoked)));
    }

    /// Глубина цепочки ограничена: юзерспейс не может ни переполнить
    /// ядерный стек длинной цепочкой mint'ов, ни сделать resolve O(n)
    /// без предела (итеративный walk, MAX_CHAIN_DEPTH).
    ///
    /// Семантика бюджета walk: 32 итерации = резолвятся записи с ЦЕПЯМИ
    /// до 31 Chained-ребра (32 узла). Запись глубины MAX_CHAIN_DEPTH
    /// (33 узла) уже не резолвится; mint от неё невозможен (resolve
    /// источника отказывает) — строим ровно до предела и проверяем.
    #[test]
    fn chain_depth_is_bounded() {
        let zygote = leaked(CapabilityZygote::new(mmio_object(0xE000)));
        let membrane = leaked(CapabilityMembrane::new_root(DirectCapabilityRights::all()));
        let mut node = leaked(LinkedRecord::<FakeUmap>::new_root(
            zygote,
            membrane,
            DirectCapabilityRights::all(),
        ));
        // После цикла node — запись глубины MAX_CHAIN_DEPTH (за пределом).
        for _ in 0..LinkedRecord::<FakeUmap>::MAX_CHAIN_DEPTH {
            let next = node
                .mint(DirectCapabilityRights::all(), membrane)
                .expect("mint в пределах глубины");
            node = leaked(next);
        }
        assert!(
            matches!(node.resolve(), Err(CapFault::Revoked)),
            "глубина обязана ограничиваться"
        );
        // Запись жива (не затумбстоунена) — отказ именно по глубине.
        assert!(node.is_live());
        assert_eq!(node.generation(), 0);
    }
}
