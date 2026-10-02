//! Сисколлы управления capability (домен DomainCapability).
//!
//! Что здесь есть:
//!   - создание capability-объектов всех типов: неймспейс, пул памяти IPC,
//!     MMIO-регион, IRQ — AccessManager::create_new_object + корневая
//!     запись в cspace владельца (access::capspace::install_root_capability);
//!   - управление записями cspace: mint (производная копия с сужением
//!     прав), clone (копия в той же мембране), revoke (отзыв мембраны
//!     слота — протухают все производные), destroy (снятие записи);
//!   - пересылка capability через IPC (ipc::cap_transfer::transfer_capability),
//!     пока транспорт сообщений — заглушка.
//!
//! АВТОРИЗАЦИЯ. Каждый сисколл сначала проверяет групповые права неймспейса
//! ТЕКУЩЕЙ задачи (check_task_rights) — права неймспейса имеют приоритет над
//! правами самих капабилити: поток из группы без CAP_MANAGE не создаст
//! capability, даже если раздобудет какую-то capability-запись. Дальше
//! включается высокогранулярный уровень: resolve() конкретной записи
//! (права Clone/Mint/Send, эпохи, генерации).
//!
//! ВОЗВРАТ. handle() -> u64: успех — код/идентификатор (id созданной
//! capability; id 0 валиден — успех/ошибка различаются старшим битом,
//! см. traits::syscall::syscall_result), ошибка — код со старшим битом.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    access::{
        AccessManager,
        capability::{CapabilityObject, DirectCapabilityRights},
        capspace,
        namespace::NamespaceRights,
    },
    task::tcb::GTcb,
    traits::irq::IrqChip as _,
    traits::{ArchImplementation, syscall::SyscallDomain, syscall::syscall_result as res},
};

// ─── Аргументы сисколлов ─────────────────────────────────────────────────────
// Все поля — u64: derive(SyscallArguments) кладёт сырые регистры.

/// Создание неймспейса (группы задач) + корневой capability на него
/// в cspace текущей задачи.
#[derive(SyscallArguments)]
pub struct SyscallCapCreateNamespace {
    /// Слот cspace текущей задачи, куда положить capability на неймспейс.
    dst_slot: u64,
    max_task_count: u64,
    /// Бюджет памяти группы в байтах (учёт ведёт umap::VmapRegion).
    max_memory_bytes: u64,
    persistency_badge: u64,
    /// Биты NamespaceRights (неизвестные биты отбрасываются).
    rights_mask: u64,
    /// Квота kernel-объектов capability группы (записи cspace + мембраны):
    /// они бессмертны (tombstone/recycle) — без лимита задача раздувает
    /// kernel slab (см. Namespace::try_reserve_cap_object).
    max_cap_objects: u64,
}

/// Создание capability на пул памяти IPC (CapabilityObject::MemoryIPCPool).
#[derive(SyscallArguments)]
pub struct SyscallCapCreateIpcPool {
    /// Задача-владелец будущей capability (капабилити кладётся в её cspace).
    owner_task_cap: u64,
    dst_slot: u64,
}

/// Создание capability на MMIO-регион.
#[derive(SyscallArguments)]
pub struct SyscallCapCreateMmio {
    owner_task_cap: u64,
    dst_slot: u64,
    /// Физический адрес начала региона (обязан быть выровнен на страницу).
    phys_origin: u64,
    /// Размер региона в страницах.
    page_count: u64,
}

/// Создание capability на РАЗДЕЛЯЕМЫЙ регион СОБСТВЕННОЙ памяти задачи
/// (shm для длинных IPC-сообщений: датапуть — юзерспейс, ядро не участвует).
///
/// Модель (аналог L4 map/grant, разложенный на существующие механизмы):
///   1. Задача выделяет страницы ALLOC_PAGES и создаёт на них capability
///      ЭТИМ сисколлом (физику резолвит ЯДРО через трекер vmap — юзерспейс
///      физических адресов НЕ видит);
///   2. Пересылает capability через IPC map-item'ом — получателю;
///   3. Получатель монтирует существующим MOUNT_CAP_REGION — те же
///      физические фреймы появляются в его пространстве (внешний
///      маппинг: фреймы остаются во владении/квоте отправителя).
///
/// Дальше оба читают/пишут общие страницы напрямую; ядро видит только
/// короткие «дверные» IPC-сообщения (сигналы готовности).
#[derive(SyscallArguments)]
pub struct SyscallCapCreateShared {
    /// Базовый ВА СОБСТВЕННОЙ аллокации текущей задачи (ALLOC_PAGES).
    src_vaddr: u64,
    /// Размер в страницах (обязан совпадать с аллокацией ЦЕЛИКОМ —
    /// частичное разделение не даём: владение/квота считаются на
    /// аллокацию целиком).
    pages: u64,
    /// Слот cspace текущей задачи под новую capability.
    dst_slot: u64,
}

/// Создание capability на ЛОГИЧЕСКУЮ линию прерывания платформы (v2):
/// валидация по чипу (диапазон/занятость), занятие в реестре (см.
/// crate::irq), программирование режима срабатывания. Линия остаётся
/// ЗАМАСКИРОВАННОЙ до первого WAIT (semantics «disable_irq → handler
/// → enable» — уровневые линии не спамят между ожиданиями).
#[derive(SyscallArguments)]
pub struct SyscallCapCreateIrq {
    /// Задача-владелец будущей capability (капабилити кладётся в её cspace).
    owner_task_cap: u64,
    dst_slot: u64,
    /// Логический номер линии (GSI/INTID/MSI — см. traits::irq::IrqChip).
    line: u64,
    /// Режим срабатывания: 0 = Edge, 1 = Level (TriggerMode::from_abi).
    trigger: u64,
}

/// Создание фолт-эндпоинта (seL4 fault endpoint / KeyKOS keeper):
/// фиксирует ТЕКУЩУЮ задачу как обработчика фолтов. Эндпоинт можно
/// привязать к любой задаче, на которую есть TaskTCB-капабилити
/// (FAULT_SET_ENDPOINT) — фолты цели пойдут обработчику через
/// обычный IPC-транспорт (см. ipc::fault). Обработчик обязан быть
/// жив, пока жив эндпоинт: смерть тумбстоунит его зиготу — и все
/// производные записи «протухают» (снимок поколения в объекте).
#[derive(SyscallArguments)]
pub struct SyscallCapCreateFaultEndpoint {
    /// Слот cspace текущей задачи (она же — обработчик) под новую capability.
    dst_slot: u64,
}

/// IPC_CREATE_GATE(14):capability-объект «IPC-гейт» (seL4-эндпоинт) в
/// слоте cspace ВЫЗЫВАЮЩЕГО. Корневые права — все (Clone|Mint|Send|Recv):
/// сервер минтит клиентам Send-копии (Recv не выдаёт — клиенты не
/// перехватывают чужие запросы), себе оставляет Recv для ожидания И
/// уничтожения (IPC_DESTROY_GATE).
#[derive(syscall_macros::SyscallArguments)]
pub struct SyscallIpcCreateGate {
    /// Слот cspace текущей задачи под корневую капу гейта.
    dst_slot: u64,
}

/// IPC_DESTROY_GATE(31): явное уничтожение гейта (держатель Recv-капы —
/// сервер/владелец корня). Поколение слота инкрементируется: ВСЕ капы с
/// прежним gen перестают резолвиться → E_CAP_REVOKED (tombstone-записи
/// протухают сами); блокированные отправители/получатели отзываются —
/// патч кадра E_CAP_REVOKED + wake по СВОИМ объектам (механизм
/// резолвера таймаутов); id возвращается в пул — чурнинг сервисов
/// больше не истощает таблицу. Права: Recv на гейт-капе (административ-
/// ный авторитет над каналом) + CAP_MANAGE неймспейса.
#[derive(SyscallArguments)]
pub struct SyscallIpcDestroyGate {
    /// Слот cspace текущей задачи с IpcGate-капой (право Recv).
    slot: u64,
}

/// Mint: производная копия с правами ⊆ источника, под мембрану слота
/// получателя (новая граница авторитета).
#[derive(SyscallArguments)]
pub struct SyscallCapMint {
    src_task_cap: u64,
    src_slot: u64,
    dst_task_cap: u64,
    dst_slot: u64,
    /// Биты DirectCapabilityRights для копии.
    rights_mask: u64,
}

/// Clone: копия в пределах ТОЙ ЖЕ мембраны (требует право Clone у источника).
#[derive(SyscallArguments)]
pub struct SyscallCapClone {
    src_task_cap: u64,
    src_slot: u64,
    dst_task_cap: u64,
    dst_slot: u64,
}

/// Revoke: ревок мембраны слота — протухают сама запись и все производные.
/// Слот остаётся занятым (запись на месте, но не резолвится).
#[derive(SyscallArguments)]
pub struct SyscallCapRevoke {
    task_cap: u64,
    slot: u64,
}

/// Destroy: ревок (если мембрана своя) + tombstone записи НА МЕСТЕ
/// (remove запрещён — Chained-потомки держат NonNull на запись; номер
/// слота переиспользуется через recycle при следующей установке).
#[derive(SyscallArguments)]
pub struct SyscallCapDestroy {
    task_cap: u64,
    slot: u64,
}

// ─── Домен ───────────────────────────────────────────────────────────────────
// ПРИМЕЧАНИЕ: сисколл 24 (CAP_TRANSFER) УДАЛЁН (bootstrap-остаток):
// он адресовал отправителя/получателя голыми task_cap-id — ambient
// authority поверх capability-модели. Ровно то же (и правильно) делает
// IPC_SEND с map items: адресация через TaskTCB-капабилити (право
// Send), валидация двухфазная, копия — flatten под мембрану получателя
// (см. ipc::cap_transfer). Номер 24 ЗАРЕЗЕРВИРОВАН (не переиспользовать).

/// Ограничение на число дескрипторов, валидируемое до разбора массива.
pub const MAX_CAPS_LIMIT: usize = 8;

pub struct DomainCapability<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainCapability<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

/// Маппинг ошибок capspace -> коды возврата сисколлов.
fn capspace_result_code(result: Result<(), capspace::CapspaceError>) -> u64 {
    match result {
        Ok(()) => res::OK,
        Err(capspace::CapspaceError::SlotOccupied) => res::E_SLOT_OCCUPIED,
        Err(capspace::CapspaceError::SlotEmpty) => res::E_SLOT_EMPTY,
        Err(capspace::CapspaceError::Slab(_)) => res::E_SLAB,
        Err(capspace::CapspaceError::Quota) => res::E_QUOTA,
    }
}

impl<A: ArchImplementation> DomainCapability<A, SyscallCapCreateNamespace> {
    /// Полный цикл создания неймспейса одной транзакцией: слот namespace
    /// (AccessManager) -> объект-капабилити -> корневая запись в cspace
    /// текущей задачи. Любая неудача откатывает предыдущие шаги, чтобы не
    /// оставлять полумёртвые неймспейсы/объекты.
    fn create_namespace_transaction(
        access: &mut AccessManager<A::Umap>,
        creator: &GTcb<A::Umap>,
        creator_task_cap: u64,
        args: &SyscallCapCreateNamespace,
        rights: NamespaceRights,
    ) -> u64 {
        let namespace_id = match access.create_namespace(
            args.max_task_count as usize,
            args.max_memory_bytes as usize,
            args.persistency_badge as usize,
            rights,
            args.max_cap_objects as usize,
        ) {
            Ok(id) => id,
            Err(crate::access::AccessError::Slab(_)) => return res::E_SLAB,
            Err(crate::access::AccessError::IdSpaceExhausted) => return res::E_IDS_EXHAUSTED,
        };

        // Rollback до конца транзакции при любой ошибке ниже.
        let rollback = |access: &mut AccessManager<A::Umap>| {
            let _ = access.destroy_namespace(namespace_id);
        };

        let Some(namespace_ptr) = access.get_namespace_ptr(namespace_id) else {
            rollback(access);
            return res::E_INTERNAL;
        };

        let cap_id = match access.create_new_object(CapabilityObject::new_task_group_namespace(namespace_ptr, namespace_id)) {
            Ok(id) => id,
            Err(crate::access::AccessError::Slab(_)) => {
                rollback(access);
                return res::E_SLAB;
            }
            Err(crate::access::AccessError::IdSpaceExhausted) => {
                rollback(access);
                return res::E_IDS_EXHAUSTED;
            }
        };

        let Some(zygote) = access.get_zygote(cap_id) else {
            let _ = access.destroy_object(cap_id);
            rollback(access);
            return res::E_INTERNAL;
        };

        let install = capspace::install_root_capability(
            creator,
            args.dst_slot,
            zygote,
            DirectCapabilityRights::all(),
            access.task_namespace(creator_task_cap),
        );
        if let Err(e) = install {
            let _ = access.destroy_object(cap_id);
            rollback(access);
            return capspace_result_code(Err(e));
        }

        cap_id
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateNamespace> {
    const SYSCALL_ID: usize = 16;
    type Args = SyscallCapCreateNamespace;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        // Без текущей задачи сисколл не авторизуем (bootstrap создаёт
        // неймспейсы напрямую через AccessManager, минуя сисколлы).
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let mut access = self.0.permission_backend.lock();

        // Групповой потолок: создавать неймспейсы может только носитель
        // CAP_MANAGE — независимо от того, что написано в его капабилити.
        if access.check_task_rights(current, NamespaceRights::CAP_MANAGE).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        // МОНОТОННОСТЬ ПОТОЛКА: права нового неймспейса обязаны быть
        // ПОДМНОЖЕСТВОМ прав неймспейса создателя. Иначе задача с CAP_MANAGE
        // из группы с узким потолком создаёт группу с NamespaceRights::all()
        // и выводит свои потоки из-под ограничений родителя (эскалация
        // через границу неймспейсов).
        let rights = NamespaceRights::from_bits_truncate(args.rights_mask as u16);
        let creator_rights = match access.task_namespace_rights(current) {
            Some(r) => r,
            None => return res::E_NOT_FOUND,
        };
        if !creator_rights.contains(rights) {
            return res::E_RIGHTS_DENIED;
        }

        let Some(creator) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let creator = unsafe { creator.as_ref() };

        Self::create_namespace_transaction(&mut access, creator, current, &args, rights)
    }
}

/// Общая реализация для "создать дескрипторный объект (MMIO/IRQ/пул IPC)
/// и положить корневую капабилити в cspace владельца".
///
/// Все три типа объектов — чистые дескрипторы: фреймы не выделяются,
/// IRQ не настраивается, MMIO не мапится. Реальные операции — забота
/// домена memory/драйверов, которые обязаны сверять capability.
pub(crate) fn create_descriptor_capability<A: ArchImplementation>(
    access: &mut AccessManager<A::Umap>,
    owner: &GTcb<A::Umap>,
    owner_task_cap: u64,
    dst_slot: u64,
    object: CapabilityObject<A::Umap>,
) -> u64 {
    let cap_id = match access.create_new_object(object) {
        Ok(id) => id,
        Err(crate::access::AccessError::Slab(_)) => return res::E_SLAB,
        Err(crate::access::AccessError::IdSpaceExhausted) => return res::E_IDS_EXHAUSTED,
    };

    let Some(zygote) = access.get_zygote(cap_id) else {
        let _ = access.destroy_object(cap_id);
        return res::E_INTERNAL;
    };

    if let Err(e) = capspace::install_root_capability(
        owner,
        dst_slot,
        zygote,
        DirectCapabilityRights::all(),
        access.task_namespace(owner_task_cap),
    ) {
        let _ = access.destroy_object(cap_id);
        return capspace_result_code(Err(e));
    }

    cap_id
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateIpcPool> {
    const SYSCALL_ID: usize = 17;
    type Args = SyscallCapCreateIpcPool;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let mut access = self.0.permission_backend.lock();

        // Оперирование памятью группы (пул IPC — память) + управление капами.
        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::MEMORY_ALLOC)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(owner_ptr) = access.get_task_tcb(args.owner_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // АВТОРИТЕТ НА ВЛАДЕЛЬЦА: owner_task_cap — голый id; класть
        // capability в ЧУЖОЙ cspace вправе только тот, кто адресует
        // владельца TaskTCB-капабилити (иначе — ambient authority:
        // занятие чужих слотов/дарение кап по угадываемым id).
        if args.owner_task_cap != current
            && !caller_controls::<A>(&access, current, args.owner_task_cap)
        {
            return res::E_RIGHTS_DENIED;
        }
        // SAFETY: под permission_backend-локом GTcb не уничтожается.
        let owner = unsafe { owner_ptr.as_ref() };

        create_descriptor_capability::<A>(
            &mut access,
            owner,
            args.owner_task_cap,
            args.dst_slot,
            CapabilityObject::MemoryIPCPool {
                region_owner: owner_ptr,
            },
        )
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateMmio> {
    const SYSCALL_ID: usize = 18;
    type Args = SyscallCapCreateMmio;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        // Дескриптор обязан быть валидным ещё до проверки прав.
        if args.page_count == 0 || args.phys_origin % crate::traits::memory::PAGE_SIZE as u64 != 0 {
            return res::E_INVALID_ARG;
        }
        // PHYS-ВАЛИДАЦИЯ: диапазон обязан лежать ВНЕ RAM (реальные
        // MMIO-дыры карты: framebuffer, device BAR, ACPI NVS) и не
        // задевать запреты (образ ядра/модулей, метаданные аллокатора,
        // BAD_MEMORY). Иначе задача монтирует себе RW-маппинг памяти
        // ядра/куча других задач и читает/пишет её В ОБХОД всей
        // capability-модели (физ_guard::mmio_allowed — fail-closed).
        {
            let begin = args.phys_origin as usize;
            let end = match (args
                .page_count
                .checked_mul(crate::traits::memory::PAGE_SIZE as u64))
            .and_then(|bytes| begin.checked_add(bytes as usize))
            {
                Some(e) => e,
                None => return res::E_INVALID_ARG,
            };
            if !crate::phys_guard::mmio_allowed(begin, end) {
                return res::E_INVALID_ARG;
            }
        }

        let mut access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::MMIO_MAP)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(owner_ptr) = access.get_task_tcb(args.owner_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // АВТОРИТЕТ НА ВЛАДЕЛЬЦА — как у CAP_CREATE_IPC_POOL (голый id
        // адресует cspace только по TaskTCB-капабилити на владельца).
        if args.owner_task_cap != current
            && !caller_controls::<A>(&access, current, args.owner_task_cap)
        {
            return res::E_RIGHTS_DENIED;
        }
        let owner = unsafe { owner_ptr.as_ref() };

        create_descriptor_capability::<A>(
            &mut access,
            owner,
            args.owner_task_cap,
            args.dst_slot,
            CapabilityObject::MemoryMMIORegion {
                region_origin: args.phys_origin as usize,
                region_page_count: args.page_count as usize,
            },
        )
    }
}

/// CAP_CREATE_SHARED(25): capability на СОБСТВЕННЫЙ vmap-регион задачи
/// (см. SyscallCapCreateShared — shm для длинных IPC без участия ядра
/// в датапути). Физику резолвит ядро (VmapRegion::lookup): юзерспейс
/// не знает физических адресов. Права — те же, что у MMIO-создания:
/// получателю для монтажа понадобится MMIO_MAP у группы.
impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateShared> {
    const SYSCALL_ID: usize = 25;
    type Args = SyscallCapCreateShared;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.pages == 0
            || args.src_vaddr % crate::traits::memory::PAGE_SIZE as u64 != 0
        {
            return res::E_INVALID_ARG;
        }

        let mut access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::MMIO_MAP)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(owner_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом GTcb не уничтожается.
        let owner = unsafe { owner_ptr.as_ref() };

        // Регион обязан быть СОБСТВЕННОЙ аллокацией ЦЕЛИКОМ: точная база,
        // точный размер, не внешний (внешние = заимствованные MMIO/shm —
        // их делиться повторно нельзя: владелец фреймов не эта задача).
        let phys_base = match owner.vmap().lookup(args.src_vaddr as usize) {
            Some(e) if !e.external && e.pages == args.pages as usize => e.phys_base,
            _ => return res::E_NOT_FOUND,
        };

        create_descriptor_capability::<A>(
            &mut access,
            owner,
            current,
            args.dst_slot,
            CapabilityObject::MemoryMMIORegion {
                region_origin: phys_base,
                region_page_count: args.pages as usize,
            },
        )
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateIrq> {
    const SYSCALL_ID: usize = 19;
    type Args = SyscallCapCreateIrq;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        // Линия — u32-пространство (переносимое, см. traits::irq).
        if args.line > u32::MAX as u64 {
            return res::E_INVALID_ARG;
        }
        let Some(trigger) = crate::traits::irq::TriggerMode::from_abi(args.trigger) else {
            return res::E_INVALID_ARG;
        };

        let mut access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::IRQ_BIND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(owner_ptr) = access.get_task_tcb(args.owner_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // АВТОРИТЕТ НА ВЛАДЕЛЬЦА — как у CAP_CREATE_IPC_POOL.
        if args.owner_task_cap != current
            && !caller_controls::<A>(&access, current, args.owner_task_cap)
        {
            return res::E_RIGHTS_DENIED;
        }
        let owner = unsafe { owner_ptr.as_ref() };

        // Валидация по чипу: линия обязана лежать в проводном пространстве
        // ИЛИ в MSI-пространстве (семантику перечисления задаёт порт).
        let Some(chip) = A::irq_chip() else {
            return res::E_INTERNAL; // подсистема не инициализирована портом
        };
        let line = args.line as u32;
        let in_wired = line < chip.wired_line_count();
        let in_msi = chip.msi_capacity() > 0
            && line >= chip.msi_line_base()
            && line < chip.msi_line_base() + chip.msi_capacity();
        if !in_wired && !in_msi {
            return res::E_INVALID_ARG;
        }

        // 1. Реестр: занять линию (Busy → E_BUSY).
        match crate::irq::claim_line(
            line,
            crate::irq::LineEntry {
                owner_task: args.owner_task_cap,
                trigger,
                wired: in_wired,
            },
        ) {
            Ok(()) => {}
            Err(crate::irq::LineError::Busy) => return res::E_BUSY,
            Err(crate::irq::LineError::Slab) => return res::E_SLAB,
            Err(crate::irq::LineError::NotFound) => unreachable!("claim не даёт NotFound"),
        }

        // 2. Режим срабатывания (линия пока замаскирована — RTE уже
        //    программировался бут-инициализацией порта с битом маски).
        if let Err(e) = chip.set_trigger(line, trigger) {
            let _ = crate::irq::release_line(line);
            return hw_result_code(e);
        }

        // 3. Корневая капа в cspace владельца (сбой — откат реестра).
        let cap_id = create_descriptor_capability::<A>(
            &mut access,
            owner,
            args.owner_task_cap,
            args.dst_slot,
            CapabilityObject::IrqLine { line },
        );
        if res::is_error(cap_id) {
            let _ = crate::irq::release_line(line);
        }
        cap_id
    }
}

/// Маппинг аппаратной ошибки чипа в код сисколла (для NR 19/51).
fn hw_result_code(e: crate::traits::irq::IrqHwError) -> u64 {
    match e {
        crate::traits::irq::IrqHwError::OutOfRange => res::E_INVALID_ARG,
        crate::traits::irq::IrqHwError::Unsupported => res::E_NOT_IMPLEMENTED,
        crate::traits::irq::IrqHwError::Hardware => res::E_INTERNAL,
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapCreateFaultEndpoint> {
    const SYSCALL_ID: usize = 26;
    type Args = SyscallCapCreateFaultEndpoint;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let mut access = self.0.permission_backend.lock();

        // Фолт-домен (создание капабилити класса) + компетенция
        // обработки чужих фолтов.
        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::FAULT_HANDLE)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        // Обработчик — сама текущая задача: зигота её TaskTCB-объекта
        // (task_cap_id == id объекта) нужна для ABA-снимка поколения;
        // резолв gtcb проверяет, что объект жив и является задачей.
        let Some(handler_zygote) = access.get_zygote(current) else {
            return res::E_NOT_FOUND;
        };
        let Some(creator_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом GTcb не уничтожается.
        let creator = unsafe { creator_ptr.as_ref() };

        create_descriptor_capability::<A>(
            &mut access,
            creator,
            current,
            args.dst_slot,
            CapabilityObject::new_fault_endpoint(handler_zygote, current),
        )
    }
}

/// IPC_CREATE_GATE(14): создаёт гейт (слот таблицы ipc::gate) и корневую
/// капу в cspace вызывающего. Права: CAP_MANAGE (создание объектов) +
/// IPC_SEND (компетенция IPC-каналов).
impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallIpcCreateGate> {
    const SYSCALL_ID: usize = 14;
    type Args = SyscallIpcCreateGate;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let mut access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE | NamespaceRights::IPC_SEND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(creator_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом GTcb не уничтожается.
        let creator = unsafe { creator_ptr.as_ref() };

        // 1. Слот таблицы гейтов (до капы — при отказе ничего не создано).
        //    Пул id исчерпан — E_IDS_EXHAUSTED; slab недоступен — E_SLAB
        //    (честное различение вместо прежнего «всё в один код»).
        let (gate_id, gate_gen) = match crate::ipc::gate::gate_alloc() {
            Ok(pair) => pair,
            Err(crate::ipc::gate::GateAllocError::Exhausted) => return res::E_IDS_EXHAUSTED,
            Err(crate::ipc::gate::GateAllocError::Slab) => return res::E_SLAB,
        };

        // 2. Объект + корневая капа (все права: Clone|Mint|Send|Recv);
        //    поколение слота — в капе (ABA-защита resolve_ipc_gate).
        let cap_id = create_descriptor_capability::<A>(
            &mut access,
            creator,
            current,
            args.dst_slot,
            CapabilityObject::new_ipc_gate(gate_id, gate_gen),
        );
        if crate::traits::syscall::syscall_result::is_error(cap_id) {
            crate::ipc::gate::gate_free(gate_id);
            return cap_id;
        }
        cap_id
    }
}

/// IPC_DESTROY_GATE(31): явное уничтожение гейта (см. SyscallIpcDestroyGate).
/// Дренаж — под task_manager-локом (все мутации очередей — под ним);
/// будильщик-колбэк патчит кадры (слово результата — знание порта) и
/// будит ВНЕ локов шарда: дренаж идёт партиями, wake между ними
/// (порядок WAKE_LOCK → ipc → gate не обращается).
impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallIpcDestroyGate> {
    const SYSCALL_ID: usize = 31;
    type Args = SyscallIpcDestroyGate;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        if access
            .check_task_rights(current, NamespaceRights::CAP_MANAGE)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(holder_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом GTcb не уничтожается.
        let holder = unsafe { holder_ptr.as_ref() };

        // Маршрут гейта + право Recv: административный авторитет над
        // каналом у держателя Recv-капы (сервер; корень владеет всеми
        // правами, минченные клиентам копии — обычно Send-only).
        let route = {
            let caps = holder.capspace().lock();
            let Some(record) = caps.get(&args.slot) else {
                return res::E_SLOT_EMPTY;
            };
            let (object, rights) = match record.resolve() {
                Ok(pair) => pair,
                Err(_) => return res::E_CAP_REVOKED,
            };
            if !rights.contains(DirectCapabilityRights::Recv) {
                return res::E_RIGHTS_DENIED;
            }
            match object.resolve_ipc_gate() {
                Some(route) => route,
                // Слот уничтожен/переиспользован — капа протухла.
                None => return res::E_CAP_REVOKED,
            }
        };
        drop(access);

        // Дренаж под task_manager-локом: alive=false + gen++ под локом
        // шарда, затем партии detach+отзыв; каждая жертва — патч кадра
        // (E_CAP_REVOKED) + wake по СВОИМ объектам. Отправителю — ОБА
        // объекта (SEND-спящий — на sender-объекте; CALL-клиент в фазе
        // ожидания ответа — на эндпоинт-объекте); лишний wake безобиден.
        let stats = {
            let tasks = self.0.task_manager().lock();
            crate::ipc::gate::gate_destroy(&tasks, route, |victim| {
                if let Some(tcb) = tasks.get_tcb(victim.task) {
                    tcb.patch_resume_result(A::RESUME_RESULT_WORD, res::E_CAP_REVOKED);
                }
                if victim.is_sender {
                    lctl.scheduler_release_object(crate::ipc::endpoint::sender_wait_object(
                        victim.task,
                    ));
                    lctl.scheduler_release_object(crate::ipc::endpoint::endpoint_wait_object(
                        victim.task,
                    ));
                } else {
                    lctl.scheduler_release_object(crate::ipc::endpoint::endpoint_wait_object(
                        victim.task,
                    ));
                }
            })
        };
        match stats {
            Ok((senders, receivers)) => {
                if senders + receivers > 0 {
                    crate::kernel_log!(
                        "ipc: gate {} destroyed, {} senders + {} receivers revoked\n",
                        route.id,
                        senders,
                        receivers
                    );
                }
                res::OK
            }
            // Двойной destroy / гонка (маршрут уже невалиден).
            Err(()) => res::E_CAP_REVOKED,
        }
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapMint> {
    const SYSCALL_ID: usize = 20;
    type Args = SyscallCapMint;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let requested = DirectCapabilityRights::from_bits_truncate(args.rights_mask as u8);
        if requested.is_empty() {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend.lock();

        if access.check_task_rights(current, NamespaceRights::CAP_MINT).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        // АВТОРИТЕТ НА ЦЕЛИ: и источник, и получатель обязаны адресоваться
        // TaskTCB-капабилити в cspace вызывающего (ambient authority закрыт:
        // голые task_cap_id — последовательные числа, угадываются перебором).
        if !caller_controls_both::<A>(&access, current, args.src_task_cap, args.dst_task_cap) {
            return res::E_RIGHTS_DENIED;
        }

        let Some(src_ptr) = access.get_task_tcb(args.src_task_cap) else {
            return res::E_NOT_FOUND;
        };
        let Some(dst_ptr) = access.get_task_tcb(args.dst_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let src = unsafe { src_ptr.as_ref() };
        let dst = unsafe { dst_ptr.as_ref() };

        // Мембрана слота получателя — до минта (mint снимает с неё эпоху).
        let membrane = match capspace::ensure_slot_membrane(dst, args.dst_slot, requested, access.task_namespace(args.dst_task_cap)) {
            Ok(membrane) => membrane,
            Err(e) => return capspace_result_code(Err(e)),
        };

        let minted = {
            let src_caps = src.capspace().lock();
            let Some(record) = src_caps.get(&args.src_slot) else {
                return res::E_SLOT_EMPTY;
            };
            // Высокогранулярная проверка: право Mint у источника + потолок
            // его мембраны. Расширение прав невозможно по построению.
            //
            // РОУТИНГ ЦЕПОЧЕК: mint В ПРЕДЕЛАХ ОДНОЙ capspace строит
            // Chained-запись (revoke/tombstone источника протухает копию —
            // полноценная иерархия авторитета). КРОСС-задачный mint обязан
            // идти через flatten: цепочка в чужой capspace делала бы дроп
            // GTcb источника use-after-free (см. LinkedRecord).
            if args.src_task_cap == args.dst_task_cap {
                match record.mint(requested, membrane) {
                    Ok(minted) => minted,
                    Err(crate::access::capability::CapFault::Revoked) => return res::E_CAP_REVOKED,
                    Err(crate::access::capability::CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
                }
            } else {
                match record.mint_flattened(requested, membrane) {
                    Ok(minted) => minted,
                    Err(crate::access::capability::CapFault::Revoked) => return res::E_CAP_REVOKED,
                    Err(crate::access::capability::CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
                }
            }
        };

        capspace_result_code(capspace::put_linked_record(
            dst,
            args.dst_slot,
            minted,
            access.task_namespace(args.dst_task_cap),
        ))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapClone> {
    const SYSCALL_ID: usize = 21;
    type Args = SyscallCapClone;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        if access.check_task_rights(current, NamespaceRights::CAP_MINT).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        // АВТОРИТЕТ НА ЦЕЛИ — как у mint (см. там).
        if !caller_controls_both::<A>(&access, current, args.src_task_cap, args.dst_task_cap) {
            return res::E_RIGHTS_DENIED;
        }

        let Some(src_ptr) = access.get_task_tcb(args.src_task_cap) else {
            return res::E_NOT_FOUND;
        };
        let Some(dst_ptr) = access.get_task_tcb(args.dst_task_cap) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let src = unsafe { src_ptr.as_ref() };
        let dst = unsafe { dst_ptr.as_ref() };

        let cloned = {
            let src_caps = src.capspace().lock();
            let Some(record) = src_caps.get(&args.src_slot) else {
                return res::E_SLOT_EMPTY;
            };
            // clone_cap() требует право Clone. В пределах одной capspace
            // копируется В ТОЙ ЖЕ мембране: revoke источника убивает и клон
            // (осознанная семантика). Кросс-задачный клон — flatten под
            // мембрану слота получателя (цепочка в чужой capspace = UAF
            // при дропе GTcb источника).
            if args.src_task_cap == args.dst_task_cap {
                match record.clone_cap() {
                    Ok(cloned) => cloned,
                    Err(crate::access::capability::CapFault::Revoked) => return res::E_CAP_REVOKED,
                    Err(crate::access::capability::CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
                }
            } else {
                // Потолок мембраны приёмника — фактические права записи
                // (пересечение всей цепочки): clone сохраняет права.
                let ceiling = match record.resolve() {
                    Ok((_, r)) => r,
                    Err(crate::access::capability::CapFault::Revoked) => return res::E_CAP_REVOKED,
                    Err(crate::access::capability::CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
                };
                let membrane = match capspace::ensure_slot_membrane(dst, args.dst_slot, ceiling, access.task_namespace(args.dst_task_cap)) {
                    Ok(m) => m,
                    Err(e) => return capspace_result_code(Err(e)),
                };
                match record.clone_flattened(membrane) {
                    Ok(cloned) => cloned,
                    Err(crate::access::capability::CapFault::Revoked) => return res::E_CAP_REVOKED,
                    Err(crate::access::capability::CapFault::RightsExceeded) => return res::E_RIGHTS_EXCEEDED,
                }
            }
        };

        capspace_result_code(capspace::put_linked_record(
            dst,
            args.dst_slot,
            cloned,
            access.task_namespace(args.dst_task_cap),
        ))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapRevoke> {
    const SYSCALL_ID: usize = 22;
    type Args = SyscallCapRevoke;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        if access.check_task_rights(current, NamespaceRights::CAP_MANAGE).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        // АВТОРИТЕТ: ревокать чужой слот — только по TaskTCB-капабилити
        // на владельца (см. комментарий про ambient authority у хелперов
        // caller_controls внизу файла).
        if !caller_controls::<A>(&access, current, args.task_cap) {
            return res::E_RIGHTS_DENIED;
        }

        let Some(task_ptr) = access.get_task_tcb(args.task_cap) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let task = unsafe { task_ptr.as_ref() };

        capspace_result_code(capspace::revoke_slot(task, args.slot))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainCapability<A, SyscallCapDestroy> {
    const SYSCALL_ID: usize = 23;
    type Args = SyscallCapDestroy;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        if access.check_task_rights(current, NamespaceRights::CAP_MANAGE).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        // АВТОРИТЕТ: снимать чужой слот — только по TaskTCB-капабилити
        // на владельца (см. комментарий у caller_controls).
        if !caller_controls::<A>(&access, current, args.task_cap) {
            return res::E_RIGHTS_DENIED;
        }

        let Some(task_ptr) = access.get_task_tcb(args.task_cap) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let task = unsafe { task_ptr.as_ref() };

        // take_slot ревокает собственную мембрану слота (если она у него
        // есть) и ЗАТУМБСТОУНИВАЕТ запись НА МЕСТЕ: remove запрещён —
        // Chained-копии держат NonNull на запись (UAF/ABA при переисполь-
        // зовании slab-слота, см. access::capspace / LinkedRecord).
        // Слот остаётся занят мёртвой записью; номер переиспользуется
        // install_root/put через recycle (generation протухает потомков).
        let taken = capspace::take_slot(task, args.slot);
        match &taken {
            Err(capspace::CapspaceError::Quota) => res::E_QUOTA,
            Ok(_) => res::OK,
            Err(capspace::CapspaceError::SlotOccupied) => res::E_SLOT_OCCUPIED,
            Err(capspace::CapspaceError::SlotEmpty) => res::E_SLOT_EMPTY,
            Err(capspace::CapspaceError::Slab(_)) => res::E_SLAB,
        }
    }
}

/// АВТОРИТЕТ ВЫЗЫВАЮЩЕГО НА ЦЕЛЕВУЮ ЗАДАЧУ: в cspace вызывающего есть
/// живая TaskTCB-капабилити, резолвящаяся в GTcb целевой задачи.
/// Закрывает ambient authority: namespace-право (CAP_MANAGE/CAP_MINT)
/// разрешает КЛАСС действия, но ЦЕЛЬ обязана адресоваться capability —
/// иначе любой поток группы оперирует произвольными задачами по
/// угадываемым последовательным task_cap_id (индексы зигот — маленькие
/// числа, перебор тривиален).
/// Вызывать под permission_backend-локом.
pub(crate) fn caller_controls<A: ArchImplementation>(
    access: &AccessManager<A::Umap>,
    current: u64,
    target_task_cap: u64,
) -> bool {
    let Some(caller_ptr) = access.get_task_tcb(current) else {
        return false;
    };
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let caller = unsafe { caller_ptr.as_ref() };
    access.controls_task(caller, target_task_cap)
}

/// То же для ПАРЫ целей (mint/clone: источник + получатель).
fn caller_controls_both<A: ArchImplementation>(
    access: &AccessManager<A::Umap>,
    current: u64,
    a_task_cap: u64,
    b_task_cap: u64,
) -> bool {
    caller_controls::<A>(access, current, a_task_cap)
        && caller_controls::<A>(access, current, b_task_cap)
}
