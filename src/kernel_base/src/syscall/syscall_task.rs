use core::marker::PhantomData;

use crate::{
    KernelCTL,
    task::stats::{STATS_WORDS, TaskStatsSnapshot},
    traits::{
        ArchImplementation,
        scheduller::WaitModel,
        syscall::{SyscallDomain, syscall_result as res},
    },
};
use syscall_macros::SyscallArguments;

// ─── Хук уничтожения задачи (порты регистрируют политику очистки) ───────────

/// Хук смерти задачи: вызывается из destroy_task_full ПОСЛЕ успешного
/// уничтожения (транзакция capability/TCB + очистка реестров). Порты
/// (kernel_limine) регистрируют обёртку над arch-политикой — например,
/// kernel_x86::iommu::on_task_destroy (отзыв IOMMU-объектов погибшей
/// задачи). Сигнатура — только task_cap_id: хук не имеет доступа к
/// LocalKernelCTL (уже частично освобождён), вся политика — по статикам
/// arch-слоя.
pub type TaskDestroyHook = fn(task_cap_id: u64);

static mut TASK_DESTROY_HOOK: Option<TaskDestroyHook> = None;

/// Регистрирует хук уничтожения задачи (порт — до первого spawn).
pub fn set_task_destroy_hook(hook: TaskDestroyHook) {
    // Rust-2024: static mut — только через сырые указатели.
    let slot: *mut Option<TaskDestroyHook> = core::ptr::addr_of_mut!(TASK_DESTROY_HOOK);
    unsafe { slot.write(Some(hook)) };
}

fn task_destroy_hook() -> Option<TaskDestroyHook> {
    let slot: *const Option<TaskDestroyHook> = core::ptr::addr_of!(TASK_DESTROY_HOOK);
    unsafe { slot.read() }
}

#[derive(SyscallArguments)]
pub struct SyscallHandleYield;

#[derive(SyscallArguments)]
pub struct SyscallTaskStats {
    /// Глобальный id TaskTCB-капабилити задачи, чью статистику читаем
    /// (собственный id — самоинспекция без прав; чужой — право
    /// STATS_READ у группы).
    task_cap_id: u64,
    /// ВА буфера задачи под блок из STATS_WORDS u64-слов.
    buf_ptr: u64,
    /// Ёмкость буфера в БАЙТАХ (обязана вместить блок целиком).
    buf_len: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallRegisterTask {
    task_begin_addr: u64,
    task_code_size: u64,
    task_stack_size: u64,
    task_cap_id: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallDestroyTask {
    task_cap_id: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallBlockOnObject {
    object_id: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallReleaseObject {
    object_id: u64,
}

pub struct DomainScheduler<A: ArchImplementation, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainScheduler<A, Handler> {
    pub const fn new(handler: &'static KernelCTL<A>) -> Self {
        Self(handler, PhantomData)
    }
}

impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallHandleYield> {
    const SYSCALL_ID: usize = 0;

    type Args = SyscallHandleYield;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        _args: Self::Args,
    ) -> u64 {
        crate::task::stats::count_yield(lctl);
        let _ = lctl.scheduler_yield();
        res::OK
    }
}

impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallRegisterTask> {
    const SYSCALL_ID: usize = 1;

    type Args = SyscallRegisterTask;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let registered = {
            // Lock order is always AccessManager -> TaskManager.  The same
            // order is used by destroy_task, so the two managers cannot
            // deadlock each other when they are updated as one transaction.
            let access = self.0.permission_backend.lock();
            let tasks = self.0.task_manager.lock();

            tasks.register_task(
                &access,
                args.task_cap_id,
                args.task_begin_addr,
                args.task_code_size,
                args.task_stack_size,
            )
        };

        match registered {
            Ok(_) => {
                let _ = lctl.scheduler_register_task(
                    args.task_cap_id,
                    args.task_begin_addr,
                    args.task_code_size,
                    args.task_stack_size,
                );
                res::OK
            }
            Err(crate::task::RegisterTaskError::NotFound) => res::E_NOT_FOUND,
            Err(crate::task::RegisterTaskError::CapabilityRevoked) => res::E_CAP_REVOKED,
            Err(crate::task::RegisterTaskError::CapabilityDoesNotMatchTcb) => res::E_INTERNAL,
        }
    }
}

/// ЯДРО УНИЧТОЖЕНИЯ ЗАДАЧИ — транзакция TaskManager + очистка всех
/// реестров (планировщик, IPC-эндпоинты/ящики, IRQ-wait, фолт-биндинги).
///
/// Общий код двух сценариев:
///   1. SCHED_DESTROY_TASK(2) — self-exit или destroy по authority;
///   2. kill-пути ПОРТА (kernel_x86::fault::TaskKillHook): ring3-фолт
///      без доставимого обработчика и возврат в ring3 с неканоничным
///      кадром — задача убивается, система продолжает планирование
///      (вместо фатального halt всего CPU).
///
/// Возврат — код сисколла (res::OK / E_NOT_FOUND / E_INTERNAL).
pub fn destroy_task_full<A: ArchImplementation>(
    kctl: &'static crate::KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    task_cap_id: u64,
) -> u64 {
    // ВОЗВРАТ УЧЁТА cap-объектов неймспейсу: записи capspace + мембраны
    // cap_list возвращаются slab вместе с GTcb (SlabCache::drop → hook
    // деаллокации) — квота группы обязана их отпустить. Считаем и
    // списываем ДО транзакции (после destroy задача недоступна); при
    // неудаче транзакции — best-effort компенсация (см. ветки Err).
    let released_cap_objects = {
        let access = kctl.permission_backend.lock();
        let mut count = 0usize;
        if let Some(ns) = access.task_namespace(task_cap_id)
            && let Some(gtcb_ptr) = access.get_task_tcb(task_cap_id)
        {
            // SAFETY: под permission_backend-локом уничтожение невозможно.
            let gtcb = unsafe { gtcb_ptr.as_ref() };
            gtcb.capspace().lock().for_each(|_| count += 1);
            gtcb.cap_list().lock().for_each(|_| count += 1);
            for _ in 0..count {
                ns.release_cap_object();
            }
        }
        drop(access);
        count
    };

    // Транзакция capability + TCB идёт первой и атомарна по отношению к
    // планировщику: при неудаче задача остаётся полностью живой и в
    // менеджерах, и в планировщике — рассинхрона нет. Планировщик хранит
    // только task_cap_id (без указателей на TCB), так что освобождение
    // слотов во время транзакции ничего не делает висячим.
    let destroyed = {
        // Lock order is always AccessManager -> TaskManager.  The same
        // order is used by register_task, so the two managers cannot
        // deadlock each other when they are updated as one transaction.
        let mut access = kctl.permission_backend.lock();
        let mut tasks = kctl.task_manager.lock();

        tasks.destroy_task(&mut access, task_cap_id)
    };

    match destroyed {
        Ok(_) => {
            // Локальное отсоединение — только после фактического уничтожения.
            // clear_current_task_if сверяет закэшированный cap id и не
            // разыменовывает (уже освобождённый) TCB.
            let _ = lctl.scheduler_unregister_task(task_cap_id);
            lctl.clear_current_task_if(task_cap_id);

            // IPC: умерший получатель будит спящих отправителей их
            // сообщений (RAX их кадров перезаписывается ДО
            // пробуждения — E_NOT_FOUND).
            for (sender, wait_object) in
                crate::ipc::endpoint::on_task_destroyed(task_cap_id).iter()
            {
                {
                    let tasks = kctl.task_manager().lock();
                    if let Some(tcb) = tasks.get_tcb(*sender) {
                        tcb.patch_resume_result(A::RESUME_RESULT_WORD, res::E_NOT_FOUND);
                    }
                }
                lctl.scheduler_release_object(*wait_object);
            }

            // IRQ: реестр ожиданий не должен течь (мёртвая задача
            // никогда не перевызовет WaitIrq), линии владельца
            // возвращаются платформе (маскирование — через колбэк
            // порта, см. crate::irq::set_mask_callback).
            crate::task::irq_wait::unregister_task_wait(task_cap_id);
            crate::irq::teardown_task(task_cap_id);

            // Фолты (ipc::fault): биндинги снимаются, упавшие под
            // умершим обработчиком БУДЯТСЯ — задача повторит упавшую
            // инструкцию и сфолтит уже без обработчика (громкая
            // диагностика вместо тихого зависания). Смерть самой
            // упавшей (спит в фолте — для self-exit недостижимо)
            // освобождает слоты молча.
            for wait_object in crate::ipc::fault::on_task_destroyed(task_cap_id) {
                lctl.scheduler_release_object(wait_object);
            }

            // Дедлайны (IPC_WAIT deadline): слот погибшей задачи больше
            // не пригодится — хендлер не проснётся, тик не должен будить
            // мёртвую (слот снимаем до-IOMMU-хука, безусловно).
            crate::task::deadline::remove_task(task_cap_id);

            // IOMMU (v2): единственная точка, где центральная политика
            // знает о смерти задачи. Порт (kernel_limine) регистрирует
            // хук, отвязывающий аппаратные PASID-контексты и
            // тумбстоунящий реестры (домены/пространства/PASID),
            // созданные погибшей задачей. БЕЗ этого SVA-пространство
            // переживало бы владельца: PASIDTE.FLRTP продолжал бы
            // указывать на освобождённые таблицы страниц процесса
            // (IOMMU ходил бы по переиспользованной памяти).
            if let Some(hook) = task_destroy_hook() {
                hook(task_cap_id);
            }

            res::OK
        }
        Err(crate::task::DestroyTaskManagerError::NotFound) => {
            restore_cap_object_quota::<A>(kctl, task_cap_id, released_cap_objects);
            res::E_NOT_FOUND
        }
        Err(crate::task::DestroyTaskManagerError::NotTask) => {
            restore_cap_object_quota::<A>(kctl, task_cap_id, released_cap_objects);
            res::E_NOT_FOUND
        }
        Err(crate::task::DestroyTaskManagerError::InvariantBroken) => {
            restore_cap_object_quota::<A>(kctl, task_cap_id, released_cap_objects);
            res::E_INTERNAL
        }
        Err(crate::task::DestroyTaskManagerError::Access(_)) => {
            restore_cap_object_quota::<A>(kctl, task_cap_id, released_cap_objects);
            res::E_INTERNAL
        }
    }
}

/// Best-effort компенсация учёта cap-объектов: транзакция destroy не
/// состоялась — задача жива, и её записи/мембраны снова занимают квоту.
/// Повторное резервирование может не удаться только при гонке за лимит —
/// в этом случае оставляем недосчёт (безопасное направление: квота
/// срабатывает раньше, чем slab переполнится).
fn restore_cap_object_quota<A: ArchImplementation>(
    kctl: &'static crate::KernelCTL<A>,
    task_cap_id: u64,
    count: usize,
) {
    if count == 0 {
        return;
    }
    let access = kctl.permission_backend.lock();
    if let Some(ns) = access.task_namespace(task_cap_id) {
        for _ in 0..count {
            let _ = ns.try_reserve_cap_object();
        }
    }
}

impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallDestroyTask> {
    const SYSCALL_ID: usize = 2;

    type Args = SyscallDestroyTask;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        // АВТОРИТЕТ НА ЧУЖУЮ ЗАДАЧУ: self-exit разрешён всегда; уничтожение
        // ЧУЖОЙ задачи — только по живой TaskTCB-капабилити на цель в cspace
        // вызывающего. Без этой проверки любой ring3-поток уничтожает любую
        // задачу перебором последовательных task_cap_id (ambient authority —
        // полный DoS системы).
        if let Some(current) = lctl.current_task_cap_id()
            && args.task_cap_id != current
        {
            let access = self.0.permission_backend.lock();
            let authorized = match access.get_task_tcb(current) {
                // SAFETY: под permission_backend-локом (см. контракты AccessManager).
                Some(caller) => access.controls_task(unsafe { caller.as_ref() }, args.task_cap_id),
                None => false,
            };
            drop(access);
            if !authorized {
                return res::E_RIGHTS_DENIED;
            }
        }

        // Транзакция уничтожения + очистка реестров (IPC/IRQ/фолты) —
        // общий код с kill-путями порта (ring3-фолт без обработчика,
        // SYSRET-гард): см. destroy_task_full.
        destroy_task_full::<A>(self.0, lctl, args.task_cap_id)
    }
}

impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallBlockOnObject> {
    const SYSCALL_ID: usize = 3;

    type Args = SyscallBlockOnObject;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        // ЗАЩИТА ОЧЕРЕДЕЙ ОЖИДАНИЯ ЯДРА: внутренние wait-объекты (ящики
        // IPC-отправителей, эндпоинты, фолт-слоты, IRQ-линии) не адресуются
        // из ring3. Rogue-задача, заснувшая на чужом объекте, перехватывает
        // OneShot-пробуждение: настоящий адресат (отправитель/упавшая)
        // остаётся спать навсегда. Публичные id (вне резерва) остаются
        // доступны — координация тестовых задач (mt_test/mt_waker, 0xAA);
        // согласованное использование чужого публичного id — ответственность
        // самих задач (в полной модели это будут capability-нотификации).
        if is_kernel_wait_object(args.object_id as usize) {
            return res::E_INVALID_ARG;
        }
        // A single syscall maps to one wait model for now.  The actual
        // queueing policy remains in the scheduler implementation.
        crate::task::stats::count_block(lctl);
        let _ = lctl.scheduler_block_on_object(args.object_id as usize, WaitModel::OneShot);
        res::OK
    }
}

/// Резервированные ядром диапазоны wait-объектов (см. ipc::endpoint /
/// ipc::fault / task::irq_wait): юзерспейс-блокировка/пробуждение на них
/// запрещена — это механизмы доставки, а не публичные примитивы.
fn is_kernel_wait_object(id: usize) -> bool {
    const IPC_BASE: usize = crate::ipc::endpoint::IPC_OBJECT_BASE;
    // Ящики отправителей: [BASE, BASE+MAILBOX_SLOTS); эндпоинты:
    // [BASE+64, BASE+64+MAX_ENDPOINTS) — см. endpoint::sender/endpoint_wait_object.
    const IPC_SPAN: usize = 64 + crate::ipc::endpoint::MAX_ENDPOINTS;
    const FAULT_BASE: usize = crate::ipc::fault::FAULT_OBJECT_BASE;
    id < 64
        || (IPC_BASE..IPC_BASE + IPC_SPAN).contains(&id)
        || (FAULT_BASE..FAULT_BASE + crate::ipc::fault::MAX_FAULT_SLOTS).contains(&id)
}

impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallReleaseObject> {
    const SYSCALL_ID: usize = 4;

    type Args = SyscallReleaseObject;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        // Симметрично BLOCK: пробуждение внутренних очередей — только
        // ядро (доставка IPC/фолтов, IRQ). Иначе любой ring3-поток
        // рассыпает спурийные пробуждения по чужим механизмам.
        if is_kernel_wait_object(args.object_id as usize) {
            return res::E_INVALID_ARG;
        }
        lctl.scheduler_release_object(args.object_id as usize);
        res::OK
    }
}

/// TASK_STATS(29): снапшот статистики задачи + глобальные счётчики —
/// ПЕРЕНОС СТАТИСТИКИ В ЮЗЕРСПЕЙС. Ядро только считает события (см.
/// task::stats); чтение — либо собственной статистики (без прав), либо
/// чужой при праве STATS_READ у группы (потолок неймспейса).
impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallTaskStats> {
    const SYSCALL_ID: usize = 29;

    type Args = SyscallTaskStats;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if (args.buf_ptr % 8) != 0 || args.buf_len < (STATS_WORDS * 8) as u64 {
            return res::E_INVALID_ARG;
        }

        // Самоинспекция — всегда; чужая статистика — право группы.
        if args.task_cap_id != current {
            let access = self.0.permission_backend.lock();
            if access
                .check_task_rights(
                    current,
                    crate::access::namespace::NamespaceRights::STATS_READ,
                )
                .is_err()
            {
                return res::E_RIGHTS_DENIED;
            }
        }

        let snapshot = {
            let tasks = self.0.task_manager().lock();
            let Some(tcb) = tasks.get_tcb(args.task_cap_id) else {
                return res::E_NOT_FOUND;
            };
            TaskStatsSnapshot::take(args.task_cap_id, tcb.stats())
        };
        let words = snapshot.to_words();

        // Доступ к TCB — под локом task_manager; буфер пишем через умап
        // самой задачи (права уже проверены; umap жив, пока жива задача).
        let access = self.0.permission_backend.lock();
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                words.as_ptr().cast::<u8>(),
                STATS_WORDS * 8,
            )
        };
        if !crate::ipc::endpoint::write_to_user(
            gtcb.userspace_map(),
            args.buf_ptr as usize,
            bytes,
        ) {
            return res::E_INVALID_ARG;
        }
        res::OK
    }
}
