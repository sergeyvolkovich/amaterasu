#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitModel {
    OneShot,
    Multiple,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskExecStatus {
    ChangeTask(usize),
    NopTask,
    NoAction,
}

/// High-level scheduler commands exposed to the kernel task syscalls.
///
/// The scheduler implementation itself stays outside kernel_base.  The
/// default implementations intentionally keep the interface backwards
/// compatible for ports that only implement the tick/wait primitives.
pub trait GKernelSchedullerInterface {}

/// КОНТРАКТ РАЗДЕЛЯЕМОСТИ: `&self` во всех методах (состояние — за
/// внутренней IRQ-безопасной блокировкой реализации) + Sync-супертрейт.
/// Обоснование — межъядерное пробуждение (см. task::wake): ожидать задачи
/// могут на ЛЮБОМ ядре, а событие (IRQ, IPC, смерть задачи) случается на
/// произвольном. Реализация обязана корректно работать при конкурентных
/// вызовах с разных ядер — IrqSafeSpinMutex внутри это даёт.
pub trait LocalSchedullerInterface: Sync {
    fn process_tick(&self, time: usize) -> TaskExecStatus;

    /// Кто должен исполняться сейчас по мнению планировщика.
    ///
    /// ПОЧТИ всегда совпадает с задачей, владеющей текущим сисколлом;
    /// расхождение после диспетчеризации (yield поставил другую задачу,
    /// текущая ушла в wait-очередь) — команда порту переключить контекст.
    /// Без этого метода порт не может отличить «задача уступила» от
    /// «обычный сисколл» — метод ОБЯЗАТЕЛЕН (в отличие от остальных,
    /// имеющих дефолты ради совместимости портов).
    fn current_task(&self) -> Option<u64>;

    /// Voluntary reschedule requested by the current task.
    fn yield_current_task(&self) -> TaskExecStatus {
        TaskExecStatus::NoAction
    }

    /// Register a task that already owns a live TaskTCB capability.
    fn register_task(
        &self,
        task_cap_id: u64,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) -> TaskExecStatus {
        let _ = (task_cap_id, task_begin_addr, task_code_size, task_stack_size);
        TaskExecStatus::NoAction
    }

    /// Remove a task from scheduler-owned run/wait queues.
    fn unregister_task(&self, task_cap_id: u64) -> TaskExecStatus {
        let _ = task_cap_id;
        TaskExecStatus::NoAction
    }

    /// Put the current task on the wait queue associated with `object_id`.
    ///
    /// The returned queue id is the token later consumed by
    /// `awake_task_from_wait`.
    fn assign_current_task_to_wait(&self, object_id: usize, model: WaitModel) -> usize;

    /// Пробуждение всех ждущих `queue_id` по модели очереди.
    ///
    /// Возвращает число задач, СТАВШИХ runnable ЭТИМ вызовом (перевод
    /// wait → ready). Задачи, уже стоявшие в ready (разбудил кто-то
    /// другой), не считаются: новый runnable на целевом ядре не появился,
    /// Resched-IPI для него избыточен. 0 — никто не проснулся.
    fn awake_task_from_wait(&self, queue_id: usize) -> usize;
}
