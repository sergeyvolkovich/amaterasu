use crate::{
    task::tcb::TCB,
    traits::{
        memory::MemoryInterfaceUserspace,
        scheduller::{LocalSchedullerInterface, TaskExecStatus, WaitModel},
    },
};
use core::marker::PhantomData;
use core::ptr::NonNull;

pub struct LocalKernelCTL<UMAP: MemoryInterfaceUserspace> {
    scheduler: Option<NonNull<dyn LocalSchedullerInterface>>,
    current_task: Option<NonNull<TCB<UMAP>>>,
    /// Capability id текущей задачи, снятый в момент set_current_task().
    /// Хранится отдельно от указателя: после уничтожения задачи слот TCB
    /// возвращается в slab, и разыменование `current_task` для сверки id
    /// стало бы use-after-free — а сверка/сброс как раз нужны ПОСЛЕ
    /// уничтожения (см. SyscallDestroyTask).
    current_task_cap_id: Option<u64>,
    _p: PhantomData<UMAP>,
}

impl<UMAP: MemoryInterfaceUserspace> Default for LocalKernelCTL<UMAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<UMAP: MemoryInterfaceUserspace> LocalKernelCTL<UMAP> {
    pub const fn new() -> Self {
        Self {
            scheduler: None,
            current_task: None,
            current_task_cap_id: None,
            _p: PhantomData,
        }
    }

    /// Installs the already-created per-core scheduler.
    ///
    /// The scheduler is intentionally not implemented in kernel_base; the
    /// port that owns it attaches it here after LocalKernelCTL creation.
    ///
    /// Принимает `&'static dyn` (а не `&'static mut`): планировщики —
    /// статические объекты порта (например, const-инициализированный
    /// массив), а все мутации и так идут через `NonNull::as_mut`
    /// (внутренняя мутабельность под спин-локом планировщика).
    pub fn install_scheduler(
        &mut self,
        scheduler: &'static dyn LocalSchedullerInterface,
    ) {
        self.scheduler = Some(NonNull::from(scheduler));
    }

    /// TCB обязан быть живым на момент вызова — cap id снимается здесь
    /// единственный раз, дальше хранится копией.
    pub fn set_current_task(&mut self, task: NonNull<TCB<UMAP>>) {
        // SAFETY: контракт выше — TCB жив и не уничтожается параллельно.
        self.current_task_cap_id = Some(unsafe { task.as_ref() }.task_cap_id());
        self.current_task = Some(task);
    }

    pub fn clear_current_task(&mut self) {
        self.current_task = None;
        self.current_task_cap_id = None;
    }

    pub fn clear_current_task_if(&mut self, task_cap_id: u64) {
        if self.current_task_cap_id == Some(task_cap_id) {
            self.clear_current_task();
        }
    }

    pub fn get_current_task(&self) -> Option<&TCB<UMAP>> {
        self.current_task
            .map(|task| unsafe { task.as_ref() })
    }

    pub fn current_task_cap_id(&self) -> Option<u64> {
        self.current_task_cap_id
    }

    fn scheduler_mut(&mut self) -> Option<&mut dyn LocalSchedullerInterface> {
        self.scheduler
            .map(|mut scheduler| unsafe { scheduler.as_mut() })
    }

    pub fn scheduler_yield(&mut self) -> TaskExecStatus {
        self.scheduler_mut()
            .map(LocalSchedullerInterface::yield_current_task)
            .unwrap_or(TaskExecStatus::NoAction)
    }

    /// Кто должен исполняться сейчас по мнению планировщика.
    /// Порт сверяет это с задачей, владеющей текущим сисколлом:
    /// расхождение = переключить контекст (yield/усыпание текущей).
    pub fn scheduler_current_task(&mut self) -> Option<u64> {
        self.scheduler_mut()
            .and_then(|scheduler| scheduler.current_task())
    }

    pub fn scheduler_register_task(
        &mut self,
        task_cap_id: u64,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) -> TaskExecStatus {
        self.scheduler_mut()
            .map(|scheduler| {
                scheduler.register_task(
                    task_cap_id,
                    task_begin_addr,
                    task_code_size,
                    task_stack_size,
                )
            })
            .unwrap_or(TaskExecStatus::NoAction)
    }

    pub fn scheduler_unregister_task(&mut self, task_cap_id: u64) -> TaskExecStatus {
        self.scheduler_mut()
            .map(|scheduler| scheduler.unregister_task(task_cap_id))
            .unwrap_or(TaskExecStatus::NoAction)
    }

    pub fn scheduler_block_on_object(
        &mut self,
        object_id: usize,
        model: WaitModel,
    ) -> Option<usize> {
        self.scheduler_mut()
            .map(|scheduler| scheduler.assign_current_task_to_wait(object_id, model))
    }

    pub fn scheduler_release_object(&mut self, object_id: usize) {
        if let Some(scheduler) = self.scheduler_mut() {
            scheduler.awake_task_from_wait(object_id);
        }
    }
}
