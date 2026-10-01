//! Сисколл-домен kernel_exec: TASK_CREATE / TASK_CREATE_FROM_MEM —
//! динамический спавн задач (ELF) по capability-authority.
//!
//! До этого патча задачи создавал ТОЛЬКО бут (`spawn_boot_servers`):
//! `TaskManager::create_task` недостижим из ring3, поэтому «init
//! поднимает файловый сервер и драйвер» был невозможен в принципе.
//! Домен живёт в kernel_exec, потому что ELF-загрузка (`load_image`,
//! `build_initial_stack`) — собственность этого крейта; регистрация —
//! из порта (`kernel_exec::syscall::init_exec_syscalls`) рядом с
//! `kernel_base::init_syscalls` (kernel_limine уже зависит от обоих).
//!
//! ДВА ИСТОЧНИКА ОБРАЗА:
//!   - TASK_CREATE(44): капа `TaskImage` на boot-модуль (реестр
//!     kernel_exec::modules — образы лежат в памяти загрузчика);
//!   - TASK_CREATE_FROM_MEM(45): произвольный ELF в ЧИТАЕМОЙ памяти
//!     ВЫЗЫВАЮЩЕГО (например, бинарь, загруженный файловым сервером и
//!     отданный map item'ом; или собственный ALLOC_PAGES-буфер). Ядро
//!     снимает СНАПШОТ в свои кадры ДО разбора (copyin по страницам
//!     через translate_user) — парсер и загрузчик никогда не читают
//!     пользовательскую память, которую отправитель может менять
//!     параллельно (TOCTOU исключён по построению).
//!
//! AUTHORITY (ambient authority из списка аудита закрыт по построению):
//!   1. TASK_CREATE: капа `TaskImage` — есть только у boot-серверов
//!      (стало быть, у init); динамические потомки её не получают.
//!      TASK_CREATE_FROM_MEM: exec того, что МОЖЕШЬ ПРОЧИТАТЬ — код не
//!      несёт полномочий, ребёнок получает ровно 3 bootstrap-капы;
//!   2. капа `TaskGroupNamespace` на ЦЕЛЕВОЙ неймспейс — задача
//!      создаётся в чужой группе только по капе на неё;
//!   3. потолки: TASK_CREATE у неймспейса ВЫЗЫВАЮЩЕГО (групповой
//!      потолок) и у ЦЕЛЕВОГО неймспейса (`Namespace::check_rights`) —
//!      неймспейс без TASK_CREATE (например, неймспейс драйвера)
//!      не принимает новые задачи, даже если поток раздобудет капы.
//!
//! BOOTSTRAP созданной задачи (симметрично boot-серверам + родитель):
//!   слот 0 = self-TaskTCB, слот 1 = капа её неймспейса, слот 2 =
//!   TaskTCB СОЗДАТЕЛЯ (BOOT_SLOT_PARENT — адресация IPC-ответа);
//!   создателю в его cspace ложится TaskTCB ребёнка (dst_slot) —
//!   всё одной транзакцией: любой сбой ПОСЛЕ создания задачи
//!   уничтожает её целиком (полу-живых задач не остаётся).
//!
//! АРГУМЕНТЫ: TASK_CREATE — argv = [имя модуля]; FROM_MEM — argv = []
//! (имя/путь ребёнок узнаёт по IPC от создателя, BOOT_SLOT_PARENT);
//! envp = []. FB/ACPI-параметры потомкам не передаются — инициализация
//! железа через капы от init (map items).

use core::marker::PhantomData;

use kernel_base::access::capability::{CapabilityObject, DirectCapabilityRights};
use kernel_base::access::namespace::{NamespaceError, NamespaceRights};
use kernel_base::access::{capspace, CreateTaskError};
use kernel_base::kernel_log;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::task::tcb::GTcb;
use kernel_base::task::CreateTaskManagerError;
use kernel_base::traits::memory::{
    is_user_range, phys_to_virt, FrameAllocator, MemoryInterfaceUserspace, PAGE_SIZE,
};
use kernel_base::traits::syscall::{SyscallDomain, syscall_result as res};
use kernel_base::traits::ArchImplementation;
use kernel_base::KernelCTL;
use syscall_macros::SyscallArguments;

use crate::modules;
use crate::spawn::{
    BOOT_SLOT_NAMESPACE, BOOT_SLOT_PARENT, BOOT_SLOT_SELF, TaskArgs, build_initial_stack,
    exec_registry, load_image,
};

/// TASK_CREATE(ns_cap_slot, image_cap_slot, dst_slot) -> task_cap_id.
#[derive(SyscallArguments)]
pub struct SyscallTaskCreate {
    /// Слот cspace ВЫЗЫВАЮЩЕГО с TaskGroupNamespace-капабилити ЦЕЛЕВОГО
    /// неймспейса (там будет жить новая задача).
    ns_cap_slot: u64,
    /// Слот cspace ВЫЗЫВАЮЩЕГО с TaskImage-капабилити boot-образа.
    image_cap_slot: u64,
    /// Слот cspace ВЫЗЫВАЮЩЕГО, куда положить TaskTCB-капабилити ребёнка
    /// (адресация IPC). Занятый слот — E_SLOT_OCCUPIED (атомарность:
    /// ребёнок при этом уничтожается).
    dst_slot: u64,
}

/// Верхняя граница размера образа для TASK_CREATE_FROM_MEM: снапшот
/// держится в ядерных кадрах только на время загрузки (транзиентно,
/// кадры возвращаются пулу сразу после load_image), но без лимита
/// один вызов выметал бы кадровой пул.
pub const MAX_EXEC_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// TASK_CREATE_FROM_MEM(ns_cap_slot, image_va, image_size, dst_slot)
/// -> task_cap_id. Образ — [image_va, image_va+image_size) в ЧИТАЕМОЙ
/// памяти ВЫЗЫВАЮЩЕГО (любое выравнивание: снапшот выравнивает).
#[derive(SyscallArguments)]
pub struct SyscallTaskCreateFromMem {
    /// Слот cspace ВЫЗЫВАЮЩЕГО с TaskGroupNamespace-капабилити ЦЕЛЕВОГО
    /// неймспейса (там будет жить новая задача).
    ns_cap_slot: u64,
    /// Базовый VA образа в адресном пространстве ВЫЗЫВАЮЩЕГО.
    image_va: u64,
    /// Размер образа в байтах (1..=MAX_EXEC_IMAGE_BYTES).
    image_size: u64,
    /// Слот cspace ВЫЗЫВАЮЩЕГО под TaskTCB ребёнка (адресация IPC;
    /// занятый слот — E_SLOT_OCCUPIED, ребёнок уничтожается).
    dst_slot: u64,
}

pub struct DomainTaskSpawn<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation + 'static, Handler> DomainTaskSpawn<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

/// Регистрация домена: вызывает порт ПОСЛЕ kernel_base::init_syscalls
/// (реестр сисколлов един, порядок не важен — важна уникальность номеров).
pub fn init_exec_syscalls<A: ArchImplementation + 'static>(kctl: &'static KernelCTL<A>) {
    A::register_syscalls(DomainTaskSpawn::<_, SyscallTaskCreate>::new(kctl));
    A::register_syscalls(DomainTaskSpawn::<_, SyscallTaskCreateFromMem>::new(kctl));
}

/// Маппинг ошибки транзакции TaskManager в код сисколла.
fn create_task_error_code(e: CreateTaskManagerError) -> u64 {
    match e {
        CreateTaskManagerError::IdSpaceExhausted => res::E_IDS_EXHAUSTED,
        CreateTaskManagerError::Slab(_) => res::E_SLAB,
        CreateTaskManagerError::Access(CreateTaskError::NamespaceNotFound) => res::E_NOT_FOUND,
        CreateTaskManagerError::Access(CreateTaskError::Namespace(
            NamespaceError::TaskLimitExceeded,
        ))
        | CreateTaskManagerError::Access(CreateTaskError::Namespace(
            NamespaceError::MemoryLimitExceeded,
        ))
        | CreateTaskManagerError::Access(CreateTaskError::Namespace(
            NamespaceError::CapObjectLimitExceeded,
        )) => res::E_QUOTA,
        CreateTaskManagerError::Access(CreateTaskError::Namespace(
            NamespaceError::RightsDenied,
        )) => res::E_RIGHTS_DENIED,
        CreateTaskManagerError::Access(CreateTaskError::Namespace(NamespaceError::Underflow)) => {
            res::E_INTERNAL
        }
        CreateTaskManagerError::Access(CreateTaskError::Access(_)) => res::E_SLAB,
    }
}

/// Маппинг CapspaceError -> код сисколла (зеркало kernel_base::syscall).
fn capspace_error_code(e: capspace::CapspaceError) -> u64 {
    match e {
        capspace::CapspaceError::SlotOccupied => res::E_SLOT_OCCUPIED,
        capspace::CapspaceError::SlotEmpty => res::E_SLOT_EMPTY,
        capspace::CapspaceError::Slab(_) => res::E_SLAB,
        capspace::CapspaceError::Quota => res::E_QUOTA,
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainTaskSpawn<A, SyscallTaskCreate> {
    // Раскладка NR: iommu 32..45, log 46/47, exec 48/49.
    const SYSCALL_ID: usize = 48;
    type Args = SyscallTaskCreate;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        // Кадровый аллокатор — глобальный бут-хук (init_allocator ставит
        // его до первого сисколла; см. traits::memory::init_hooks).
        let Some(frames) = kernel_base::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        // Lock order ядра: AccessManager -> TaskManager (как в бут-спавне).
        let mut access = self.0.permission_backend().lock();

        // Потолок группы ВЫЗЫВАЮЩЕГО: спавн — компетенция TASK_CREATE
        // (драйверный неймспейс без TASK_CREATE не спавнит, даже со
        // всеми капами на руках).
        if access
            .check_task_rights(current, NamespaceRights::TASK_CREATE)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(caller_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let caller = unsafe { caller_ptr.as_ref() };

        // ── Authority #1: капа на образ ─────────────────────────────
        let module_id = {
            let caps = caller.capspace().lock();
            let Some(record) = caps.get(&args.image_cap_slot) else {
                return res::E_SLOT_EMPTY;
            };
            let (object, _) = match record.resolve() {
                Ok(resolved) => resolved,
                Err(_) => return res::E_CAP_REVOKED,
            };
            match object {
                CapabilityObject::TaskImage { module_id } => *module_id as usize,
                _ => return res::E_INVALID_ARG,
            }
        };

        // ── Authority #2: капа на целевой неймспейс (ABA-чек внутри) ─
        let namespace_id = {
            let caps = caller.capspace().lock();
            let Some(record) = caps.get(&args.ns_cap_slot) else {
                return res::E_SLOT_EMPTY;
            };
            let (object, _) = match record.resolve() {
                Ok(resolved) => resolved,
                Err(_) => return res::E_CAP_REVOKED,
            };
            match object.resolve_namespace_with_id() {
                Some((id, namespace)) => {
                    // Потолок ЦЕЛЕВОЙ группы: без TASK_CREATE приём новых
                    // задач запрещён независимо от прав создателя.
                    if namespace
                        .check_rights(NamespaceRights::TASK_CREATE)
                        .is_err()
                    {
                        return res::E_RIGHTS_DENIED;
                    }
                    id
                }
                None => return res::E_CAP_REVOKED,
            }
        };

        // ── Образ ────────────────────────────────────────────────────
        let Some(module) = modules::boot_module(module_id as u32) else {
            return res::E_NOT_FOUND;
        };
        if module.size == 0 {
            return res::E_INVALID_ARG;
        }
        // SAFETY: boot-образы лежат в замапленной HHDM памяти (тот же
        // контракт, что у boot-спавна; кадры не возвращаются пулу).
        let image = unsafe {
            core::slice::from_raw_parts(phys_to_virt(module.phys) as *const u8, module.size)
        };

        // ── Умап + загрузка (drop gtcb при ошибке отдаёт память) ─────
        let umap = match A::create_task_umap(&self.0.kernel_map().lock(), frames) {
            Ok(u) => u,
            Err(_) => return res::E_SLAB,
        };
        let gtcb = GTcb::new(umap, None);
        let info = match load_image(gtcb.userspace_map(), frames, image, exec_registry()) {
            Ok(info) => info,
            // Битый/чужой образ — ошибка данных задачи, не ядра.
            Err(_) => return res::E_INVALID_ARG,
        };
        let code_size = info.segments.iter().map(|s| s.mem_size).max().unwrap_or(0);

        // ── Транзакция спавна (общий хвост TASK_CREATE/FROM_MEM) ─────
        let mut tasks = self.0.task_manager().lock();
        let tx = match transaction_tail::<A>(
            &mut tasks,
            &mut access,
            caller,
            current,
            namespace_id,
            gtcb,
            info.entry,
            code_size,
            &[module.name.as_str()],
            args.dst_slot,
            frames,
        ) {
            Ok(tx) => tx,
            Err(code) => return code,
        };

        drop(tasks);
        drop(access);
        // Планировщик: ребёнок готов к диспетчеризации (boot-серверы
        // регистрируются так же — exec_up в порту).
        let _ = lctl.scheduler_register_task(tx.task_cap_id, tx.entry as u64, tx.code_size as u64, 0);

        kernel_log!(
            "exec: TASK_CREATE '{}': cap={} entry={:#x} rsp={:#x} ns={}\n",
            module.name.as_str(),
            tx.task_cap_id,
            tx.entry,
            tx.stack_top,
            namespace_id
        );
        tx.task_cap_id
    }
}

/// Результат транзакции спавна (до регистрации в планировщике: планировщик
/// регистрируется ПОРТОМ после сброса локов — тот же порядок, что в 44).
struct TxInfo {
    task_cap_id: u64,
    entry: usize,
    code_size: usize,
    stack_top: usize,
}

/// Bootstrap-капабилити созданной задачи (вызывается под локами
/// AccessManager -> TaskManager). Возврат — id созданного объекта
/// капабилити на неймспейс (нужен auxv AT_NOMAD_NS_CAP ребёнка).
///
/// Порядок: сначала капы В cspace ребёнка (слоты 0/1/2); ошибка —
/// немедленный Err без частичных следов в cspace создателя.
fn bootstrap_child<A: ArchImplementation + 'static>(
    access: &mut kernel_base::access::AccessManager<A::Umap>,
    caller_task_cap: u64,
    task_cap_id: u64,
    namespace_id: u64,
) -> Result<u64, u64> {
    let Some(child_ptr) = access.get_task_tcb(task_cap_id) else {
        return Err(res::E_INTERNAL);
    };
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let child = unsafe { child_ptr.as_ref() };
    // BUILD-COPY HACK: &'static-подобный доступ через NonNull, чтобы
    // заимствование не пересекалось с create_new_object(&mut access).
    // Слэб-записи Namespace бессмертны (tombstone-на-месте) — контракт
    // тот же, что у NonNull-кэшей капабилити.
    let child_ns_ptr = access
        .task_namespace(task_cap_id)
        .map(core::ptr::NonNull::from);
    let child_ns = || child_ns_ptr.map(|p| unsafe { p.as_ref() });

    // Слот 0: self-TaskTCB.
    let Some(self_zygote) = access.get_zygote(task_cap_id) else {
        return Err(res::E_INTERNAL);
    };
    capspace::install_root_capability(
        child,
        BOOT_SLOT_SELF,
        self_zygote,
        DirectCapabilityRights::all(),
        child_ns(),
    )
    .map_err(capspace_error_code)?;

    // Слот 1: капа на СВОЙ неймспейс (новый capability-объект).
    let Some(ns_ptr) = access.get_namespace_ptr(namespace_id) else {
        return Err(res::E_INTERNAL);
    };
    let ns_cap_id = access
        .create_new_object(CapabilityObject::new_task_group_namespace(ns_ptr, namespace_id))
        .map_err(|_| res::E_SLAB)?;
    let Some(ns_zygote) = access.get_zygote(ns_cap_id) else {
        let _ = access.destroy_object(ns_cap_id);
        return Err(res::E_INTERNAL);
    };
    if let Err(e) = capspace::install_root_capability(
        child,
        BOOT_SLOT_NAMESPACE,
        ns_zygote,
        DirectCapabilityRights::all(),
        child_ns(),
    ) {
        let _ = access.destroy_object(ns_cap_id);
        return Err(capspace_error_code(e));
    }

    // Слот 2: TaskTCB создателя (адресация IPC-ответа). Зигота
    // создателя тумбстоунится при его смерти — капа протухает сама.
    let Some(parent_zygote) = access.get_zygote(caller_task_cap) else {
        return Err(res::E_INTERNAL);
    };
    capspace::install_root_capability(
        child,
        BOOT_SLOT_PARENT,
        parent_zygote,
        DirectCapabilityRights::all(),
        child_ns(),
    )
    .map_err(capspace_error_code)?;

    Ok(ns_cap_id)
}

/// Общий хвост спавна TASK_CREATE/TASK_CREATE_FROM_MEM: транзакция
/// «создать задачу (квота неймспейса внутри) → bootstrap-капы →
/// стартовый стек → регистрация runtime → TaskTCB ребёнка в dst_slot».
/// Вызывается ПОД локами AccessManager → TaskManager, с уже загруженным
/// образом (`gtcb` с заполненным умапом). Любой сбой после create_task
/// уничтожает задачу целиком (rollback = destroy_task) — полу-живых
/// задач не остаётся.
#[allow(clippy::too_many_arguments)]
fn transaction_tail<A: ArchImplementation + 'static>(
    tasks: &mut kernel_base::task::TaskManager<A::Umap>,
    access: &mut kernel_base::access::AccessManager<A::Umap>,
    caller: &GTcb<A::Umap>,
    caller_cap_id: u64,
    namespace_id: u64,
    gtcb: GTcb<A::Umap>,
    entry: usize,
    code_size: usize,
    argv: &[&str],
    dst_slot: u64,
    frames: &(dyn FrameAllocator + Sync),
) -> Result<TxInfo, u64> {
    // ── Транзакция создания задачи (квота неймспейса внутри) ─────
    let task_cap_id = match tasks.create_task(access, namespace_id, gtcb) {
        Ok(id) => id,
        Err(e) => return Err(create_task_error_code(e)),
    };

    // Rollback: всё, что не удалось после create_task, уничтожает
    // задачу целиком (возврат квоты/TCB/умапа — см. destroy_task).
    let mut rollback = |tasks: &mut kernel_base::task::TaskManager<A::Umap>,
                        access: &mut kernel_base::access::AccessManager<A::Umap>| {
        let _ = tasks.destroy_task(access, task_cap_id);
        kernel_log!("exec: TASK_CREATE откат задачи {}\n", task_cap_id);
    };

    // ── Bootstrap-капабилити ребёнка: 0=self, 1=неймспейс, 2=родитель
    let ns_cap_id = match bootstrap_child::<A>(access, caller_cap_id, task_cap_id, namespace_id) {
        Ok(id) => id,
        Err(code) => {
            rollback(tasks, access);
            return Err(code);
        }
    };

    // ── Стартовый стек: argv от источника образа, auxv пустой ────
    let task_args = TaskArgs { argv, envp: &[] };
    let Some(child_ptr) = access.get_task_tcb(task_cap_id) else {
        rollback(tasks, access);
        return Err(res::E_INTERNAL);
    };
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let child = unsafe { child_ptr.as_ref() };
    let stack = match build_initial_stack(
        child.vmap(),
        child.userspace_map(),
        frames,
        &task_args,
        &[],
        entry,
        task_cap_id,
        ns_cap_id,
    ) {
        Ok(s) => s,
        Err(_) => {
            rollback(tasks, access);
            return Err(res::E_SLAB);
        }
    };

    // ── Регистрация: runtime (TaskManager); планировщик — после сброса
    // локов в вызывающем handle (register_task валидирует капу против
    // GTcb и ставит entry — configure_runtime).
    if tasks
        .register_task(&*access, task_cap_id, entry as u64, code_size as u64, 0)
        .is_err()
    {
        rollback(tasks, access);
        return Err(res::E_INTERNAL);
    }
    if let Some(tcb) = tasks.get_tcb(task_cap_id) {
        tcb.set_initial_stack_top(stack.stack_top as u64);
    }

    // ── TaskTCB ребёнка → cspace СОЗДАТЕЛЯ (dst_slot) ────────────
    // Последний шаг: сбой здесь тоже откатывает ребёнка целиком,
    // чтобы создатель не увидел E_... при живом детёныше без капы
    // на него (недосягаемая сирота).
    let Some(child_zygote) = access.get_zygote(task_cap_id) else {
        rollback(tasks, access);
        return Err(res::E_INTERNAL);
    };
    if let Err(e) = capspace::install_root_capability(
        caller,
        dst_slot,
        child_zygote,
        DirectCapabilityRights::all(),
        access.task_namespace(caller_cap_id),
    ) {
        rollback(tasks, access);
        return Err(capspace_error_code(e));
    }

    Ok(TxInfo {
        task_cap_id,
        entry,
        code_size,
        stack_top: stack.stack_top,
    })
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainTaskSpawn<A, SyscallTaskCreateFromMem> {
    const SYSCALL_ID: usize = 49;
    type Args = SyscallTaskCreateFromMem;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        // Кадровый аллокатор — глобальный бут-хук (как в TASK_CREATE).
        let Some(frames) = kernel_base::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        // Lock order ядра: AccessManager -> TaskManager (как в бут-спавне).
        let mut access = self.0.permission_backend().lock();

        // Потолок группы ВЫЗЫВАЮЩЕГО: спавн — компетенция TASK_CREATE.
        if access
            .check_task_rights(current, NamespaceRights::TASK_CREATE)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(caller_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let caller = unsafe { caller_ptr.as_ref() };

        // ── Authority: капа на целевой неймспейс (ABA-чек внутри) ───
        let namespace_id = {
            let caps = caller.capspace().lock();
            let Some(record) = caps.get(&args.ns_cap_slot) else {
                return res::E_SLOT_EMPTY;
            };
            let (object, _) = match record.resolve() {
                Ok(resolved) => resolved,
                Err(_) => return res::E_CAP_REVOKED,
            };
            match object.resolve_namespace_with_id() {
                Some((id, namespace)) => {
                    // Потолок ЦЕЛЕВОЙ группы: без TASK_CREATE приём новых
                    // задач запрещён независимо от прав создателя.
                    if namespace
                        .check_rights(NamespaceRights::TASK_CREATE)
                        .is_err()
                    {
                        return res::E_RIGHTS_DENIED;
                    }
                    id
                }
                None => return res::E_CAP_REVOKED,
            }
        };

        // ── Образ: [image_va, image_va+size) — ЧИТАЕМАЯ память ──────
        // ВЫЗЫВАЮЩЕГО («exec того, что можешь прочитать»: код не несёт
        // полномочий — ребёнок получает ровно bootstrap-капы, права
        // задаёт целевой неймспейс).
        if args.image_size == 0
            || args.image_size as usize > MAX_EXEC_IMAGE_BYTES
            || !is_user_range(args.image_va as usize, args.image_size as usize)
        {
            return res::E_INVALID_ARG;
        }
        let image_va = args.image_va as usize;
        let image_size = args.image_size as usize;

        // Снапшот в ядерные кадры ДО разбора: парсер и загрузчик читают
        // копию — отправитель не может менять байты под их ногами
        // (TOCTOU). Кадры возвращаются пулу сразу после load_image.
        let snap_pages = image_size.div_ceil(PAGE_SIZE);
        let Some(snap) = frames.allocate_pages(snap_pages) else {
            return res::E_SLAB;
        };
        {
            // SAFETY: кадры только что выделены, [virt_base, +pages)
            // принадлежат ядру до deallocate_pages; пишем [0, image_size).
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    snap.virt_base() as *mut u8,
                    snap_pages * PAGE_SIZE,
                )
            };
            let umap = caller.userspace_map();
            let mut copied = 0usize;
            while copied < image_size {
                let cur = image_va + copied;
                let page_va = cur & !(PAGE_SIZE - 1);
                let chunk = core::cmp::min(PAGE_SIZE - (cur - page_va), image_size - copied);
                // defense-in-depth: постраничный translate_user (нижняя
                // половина + PRESENT|USER), is_user_range не доверяем.
                let Some(phys) = umap.translate_user(page_va, false) else {
                    frames.deallocate_pages(snap);
                    return res::E_INVALID_ARG;
                };
                // SAFETY: phys — рам-кадр пользовательской страницы;
                // HHDM-зеркало валидно (тот же путь, что copyin ядра).
                let src = phys_to_virt(phys) + (cur - page_va);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src as *const u8,
                        buf.as_mut_ptr().add(copied),
                        chunk,
                    );
                }
                copied += chunk;
            }
        }

        // ── Умап + загрузка снапшота (тот же загрузчик, что у бута) ─
        let umap = match A::create_task_umap(&self.0.kernel_map().lock(), frames) {
            Ok(u) => u,
            Err(_) => {
                frames.deallocate_pages(snap);
                return res::E_SLAB;
            }
        };
        let gtcb = GTcb::new(umap, None);
        // SAFETY: снапшот — ядерные кадры, живы до deallocate ниже.
        let image: &[u8] =
            unsafe { core::slice::from_raw_parts(snap.virt_base() as *const u8, image_size) };
        let info = match load_image(gtcb.userspace_map(), frames, image, exec_registry()) {
            Ok(info) => info,
            // Битый образ — ошибка данных вызывающего, не ядра.
            Err(_) => {
                frames.deallocate_pages(snap);
                return res::E_INVALID_ARG;
            }
        };
        // Снапшот больше не нужен: сегменты скопированы в умап ребёнка.
        frames.deallocate_pages(snap);

        let code_size = info.segments.iter().map(|s| s.mem_size).max().unwrap_or(0);

        // ── Транзакция спавна (общий хвост TASK_CREATE/FROM_MEM) ─────
        let mut tasks = self.0.task_manager().lock();
        let tx = match transaction_tail::<A>(
            &mut tasks,
            &mut access,
            caller,
            current,
            namespace_id,
            gtcb,
            info.entry,
            code_size,
            &[],
            args.dst_slot,
            frames,
        ) {
            Ok(tx) => tx,
            Err(code) => return code,
        };

        drop(tasks);
        drop(access);
        let _ = lctl.scheduler_register_task(tx.task_cap_id, tx.entry as u64, tx.code_size as u64, 0);

        kernel_log!(
            "exec: TASK_CREATE_FROM_MEM: cap={} entry={:#x} rsp={:#x} ns={} bytes={}\n",
            tx.task_cap_id,
            tx.entry,
            tx.stack_top,
            namespace_id,
            image_size
        );
        tx.task_cap_id
    }
}
