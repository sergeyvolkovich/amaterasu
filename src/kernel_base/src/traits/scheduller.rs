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

pub trait LocalSchedullerInterface {
    fn process_tick(&mut self, time: usize) -> TaskExecStatus;

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
    fn yield_current_task(&mut self) -> TaskExecStatus {
        TaskExecStatus::NoAction
    }

    /// Register a task that already owns a live TaskTCB capability.
    fn register_task(
        &mut self,
        task_cap_id: u64,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) -> TaskExecStatus {
        let _ = (task_cap_id, task_begin_addr, task_code_size, task_stack_size);
        TaskExecStatus::NoAction
    }

    /// Remove a task from scheduler-owned run/wait queues.
    fn unregister_task(&mut self, task_cap_id: u64) -> TaskExecStatus {
        let _ = task_cap_id;
        TaskExecStatus::NoAction
    }

    /// Put the current task on the wait queue associated with `object_id`.
    ///
    /// The returned queue id is the token later consumed by
    /// `awake_task_from_wait`.
    fn assign_current_task_to_wait(
        &mut self,
        object_id: usize,
        model: WaitModel,
    ) -> usize;

    fn awake_task_from_wait(&mut self, queue_id: usize);
}
