use crate::{
    task::{
        tcb::TCB,
        wake::{self, WAKE_LOCK},
    },
    traits::{
        memory::MemoryInterfaceUserspace,
        scheduller::{LocalSchedullerInterface, TaskExecStatus, WaitModel},
    },
};
use core::marker::PhantomData;
use core::ptr::NonNull;

pub struct LocalKernelCTL<UMAP: MemoryInterfaceUserspace> {
    /// Планировщик этого ядра. `&'static` (не NonNull): трейт теперь
    /// `&self`-методы за IrqSafeSpinMutex — сырые as_mut не нужны вовсе
    /// (межъядерный wake зовёт awake_task_from_wait через task::wake).
    scheduler: Option<&'static dyn LocalSchedullerInterface>,
    /// Слот этого ядра в реестре пробуждения (task::wake). None — ранний
    /// бут/тесты: wake работает только локально.
    cpu_slot: Option<usize>,
    current_task: Option<NonNull<TCB<UMAP>>>,
    /// Capability id текущей задачи, снятый в момент set_current_task().
    /// Хранится отдельно от указателя: после уничтожения задачи слот TCB
    /// возвращается в slab, и разыменование `current_task` для сверки id
    /// стало бы use-after-free — а сверка/сброс как раз нужны ПОСЛЕ
    /// уничтожения (см. SyscallDestroyTask).
    current_task_cap_id: Option<u64>,
    /// Отложенная преемпция: планировщик (тик таймера, заставший задачу
    /// в ring3) выбрал другую задачу. Хвост IRQ-диспетчера порта —
    /// единственный, кто видит прерванный кадр, — забирает решение
    /// (`take_preempt_next`) и выполняет переключение. Задача в ring3 не
    /// держит ядерных локов/состояния, поэтому решение безопасно отложить
    /// до конца обработки прерывания. per-CPU поле (lctl живёт в
    /// per-CPU области), гонок нет: тик и хвост — один и тот же IRQ.
    preempt_next: Option<u64>,
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
            cpu_slot: None,
            current_task: None,
            current_task_cap_id: None,
            preempt_next: None,
            _p: PhantomData,
        }
    }

    /// Installs the already-created per-core scheduler.
    ///
    /// The scheduler is intentionally not implemented in kernel_base; the
    /// port that owns it attaches it here after LocalKernelCTL creation.
    ///
    /// Вариант БЕЗ слота (ранний бут/тесты): wake — только локальный.
    /// Для полноценного ядра использовать [`install_cpu_scheduler`].
    pub fn install_scheduler(&mut self, scheduler: &'static dyn LocalSchedullerInterface) {
        self.scheduler = Some(scheduler);
    }

    /// Ставит планировщик на текущее ядро И в глобальный реестр
    /// пробуждения (task::wake): с этого момента чужие ядра могут будить
    /// задачи, спящие на этом планировщике (и наоборот).
    ///
    /// Вызывается фронтом из per-CPU инициализации (BSP и каждый AP).
    pub fn install_cpu_scheduler(
        &mut self,
        slot: usize,
        scheduler: &'static dyn LocalSchedullerInterface,
    ) {
        self.scheduler = Some(scheduler);
        self.cpu_slot = Some(slot);
        wake::install_cpu_scheduler(slot, scheduler);
    }

    /// Слот этого ядра в реестре пробуждения (None — не установлен).
    pub fn cpu_slot(&self) -> Option<usize> {
        self.cpu_slot
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

    fn scheduler_ref(&self) -> Option<&'static dyn LocalSchedullerInterface> {
        self.scheduler
    }

    pub fn scheduler_yield(&mut self) -> TaskExecStatus {
        self.scheduler_ref()
            .map(LocalSchedullerInterface::yield_current_task)
            .unwrap_or(TaskExecStatus::NoAction)
    }

    /// Кто должен исполняться сейчас по мнению планировщика.
    /// Порт сверяет это с задачей, владеющей текущим сисколлом:
    /// расхождение = переключить контекст (yield/усыпание текущей).
    pub fn scheduler_current_task(&mut self) -> Option<u64> {
        self.scheduler_ref()
            .and_then(|scheduler| scheduler.current_task())
    }

    pub fn scheduler_register_task(
        &mut self,
        task_cap_id: u64,
        task_begin_addr: u64,
        task_code_size: u64,
        task_stack_size: u64,
    ) -> TaskExecStatus {
        self.scheduler_ref()
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
        self.scheduler_ref()
            .map(|scheduler| scheduler.unregister_task(task_cap_id))
            .unwrap_or(TaskExecStatus::NoAction)
    }

    /// Отложить переключение до хвоста IRQ-диспетчера (ставит тик таймера).
    /// Перезапись — «последний тик выиграл» (переключение всё равно
    /// произойдёт не раньше текущего IRQ).
    pub fn set_preempt_next(&mut self, task_cap_id: u64) {
        self.preempt_next = Some(task_cap_id);
    }

    /// Забрать отложенное решение о преемпции (хвост IRQ-диспетчера).
    /// Извлечение очищает флаг: решение потребляется ровно один раз.
    pub fn take_preempt_next(&mut self) -> Option<u64> {
        self.preempt_next.take()
    }

    /// Сон текущей задачи на объекте. Под ГЛОБАЛЬНЫМ локом протокола
    /// block/wake (task::wake::WAKE_LOCK): постановка в wait-очередь
    /// сериализована со сканом пробуждения — потерянный wake невозможен
    /// (waker не может просканировать это ядро МЕЖДУ проверкой и
    /// постановкой в очередь).
    pub fn scheduler_block_on_object(
        &mut self,
        object_id: usize,
        model: WaitModel,
    ) -> Option<usize> {
        let _protocol = WAKE_LOCK.lock();
        self.scheduler_ref()
            .map(|scheduler| scheduler.assign_current_task_to_wait(object_id, model))
    }

    /// Вариант [`Self::scheduler_block_on_object`] с ПРЕДИКАТОМ-проверкой
    /// под тем же WAKE_LOCK (lost-wakeup guard для rendezvous-транспорта).
    ///
    /// Гонка, которую закрывает: доставляющий успевает ОБРАБОТАТЬ событие
    /// (изъять сообщение, снять готовность) в окне между проверкой
    /// вызывающего и фактической постановкой в очередь — пробуждение
    /// уходит в пустоту, спящий остаётся навсегда. Здесь проверка
    /// `pred` выполняется ПОД WAKE_LOCK, то есть АТОМИРОВАННО с очередями
    /// пробуждения: если событие уже случилось — задача НЕ засыпает
    /// (возврат false), если случится после — waker дренит очередь под
    /// тем же локом и будит её.
    ///
    /// `pred` обязан быть коротким (листовые локи ipc/гейтов — см.
    /// task::ipc_state: порядок WAKE_LOCK → ipc → gate) и НЕ должен
    /// звать планировщик/копировать userspace.
    ///
    /// Возврат: true — задача ушла в сон (проснется release'ем объекта);
    /// false — предикат сработал до сна, вызов немедленно возвращается.
    pub fn scheduler_block_on_object_if(
        &mut self,
        object_id: usize,
        model: WaitModel,
        pred: impl FnOnce() -> bool,
    ) -> bool {
        let _protocol = WAKE_LOCK.lock();
        if pred() {
            // Событие уже произошло (доставка/изъятие/отмена) — спать
            // нельзя: проснуться было бы нечем.
            return false;
        }
        match self.scheduler_ref() {
            Some(scheduler) => {
                scheduler.assign_current_task_to_wait(object_id, model);
                true
            }
            // Планировщика нет (ранний бут/тесты): спать некуда —
            // считаем "не уснул" (вызывающий перепроверит состояние).
            None => false,
        }
    }

    /// Пробуждение ждущих объекта: локальный планировщик + ВСЕ чужие ядра
    /// (task::wake::release_object_global) + Resched-IPI разбуженным.
    /// Единая точка для ВСЕХ wake-сайтов ядра (IPC/фолты/IRQ/дедлайны/
    /// destroy): кросс-CPU wake больше не теряется.
    pub fn scheduler_release_object(&mut self, object_id: usize) {
        // Локальный планировщик — всегда (слот мог не быть установлен:
        // ранний бут, тесты).
        if let Some(scheduler) = self.scheduler_ref() {
            let _ = scheduler.awake_task_from_wait(object_id);
        }
        // Чужие ядра: глобальный скан + кик. exclude = свой слот — локальный
        // путь уже прошёл (double-wake безопасен, но зачем).
        wake::release_object_global(object_id, self.cpu_slot);
    }

    /// Тик планировщика (вызывает хук линии таймера порта). Возврат
    /// `ChangeTask(next)` — команда порту переключить контекст; порт
    /// выполняет её в хвосте IRQ-диспетчера (кадр уже виден) через
    /// `set_preempt_next`, либо сразу — на границе сисколла.
    pub fn scheduler_process_tick(&mut self, time: usize) -> TaskExecStatus {
        self.scheduler_ref()
            .map(|scheduler| scheduler.process_tick(time))
            .unwrap_or(TaskExecStatus::NoAction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::scheduller::WaitModel;

    /// Фейковый Umap: lctl типизируется пространством пользователя, но
    /// для преемпций/тик-обёрток память не нужна.
    struct FakeUmap;
    impl crate::traits::memory::MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _c: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _r: crate::traits::memory::MemoryPTR,
            _c: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, _virt: usize) -> Option<usize> {
            None
        }
    }

    /// Планировщик-двойник: фиксированный ответ тика.
    struct FixedSched(u64);
    impl LocalSchedullerInterface for FixedSched {
        fn process_tick(&self, _time: usize) -> crate::traits::scheduller::TaskExecStatus {
            crate::traits::scheduller::TaskExecStatus::ChangeTask(self.0 as usize)
        }

        fn current_task(&self) -> Option<u64> {
            None
        }

        fn assign_current_task_to_wait(&self, _object_id: usize, _model: WaitModel) -> usize {
            0
        }

        fn awake_task_from_wait(&self, _queue_id: usize) -> usize {
            0
        }
    }

    #[test]
    fn process_tick_wrapper_forwards_to_scheduler() {
        let mut lctl: LocalKernelCTL<FakeUmap> = LocalKernelCTL::new();
        // Без планировщика — NoAction.
        assert_eq!(
            lctl.scheduler_process_tick(7),
            crate::traits::scheduller::TaskExecStatus::NoAction
        );
        static SCHED: FixedSched = FixedSched(42);
        lctl.install_scheduler(&SCHED);
        assert_eq!(
            lctl.scheduler_process_tick(7),
            crate::traits::scheduller::TaskExecStatus::ChangeTask(42)
        );
    }

    #[test]
    fn preempt_flag_is_taken_once() {
        let mut lctl: LocalKernelCTL<FakeUmap> = LocalKernelCTL::new();
        assert_eq!(lctl.take_preempt_next(), None);
        lctl.set_preempt_next(9);
        lctl.set_preempt_next(11); // перезапись — последний выиграл
        assert_eq!(lctl.take_preempt_next(), Some(11));
        // Извлечение очищает: повторный take — пусто.
        assert_eq!(lctl.take_preempt_next(), None);
    }
}
