#![no_std]

//! kernel_sched — архитектурно-НЕЗАВИСИМЫЕ планировщики NOMAD.
//!
//! [`RoundRobinScheduler`] — простейший карусельный планировщик поверх
//! трейта `LocalSchedullerInterface` (kernel_base): очередь готовых задач
//! + очереди ожидания по object_id. Логика чистая — тестируется на хосте.
//!   Порт ставит инстанс на каждое ядро (install_scheduler) и качает
//!   `process_tick` из таймера (или зовёт yield из сисколла).
//!
//! Замечание: `heapless::Vec::remove(0)` — O(n), но MAX_READY=64 и тики
//! редки; сложность осознанно принята ради простоты.

use kernel_base::irqsafe::IrqSafeSpinMutex;
use kernel_base::traits::scheduller::{LocalSchedullerInterface, TaskExecStatus, WaitModel};

/// Максимум задач в очереди готовых.
pub const MAX_READY: usize = 64;
/// Максимум объектов ожидания (очередей блокировки). IPC-транспорт
/// заводит до 16 (отправители) + 32 (эндпоинты) объектов, IRQ-wait —
/// 16, плюс объекты тестовых задач — берём с запасом.
pub const MAX_WAIT_OBJECTS: usize = 128;
/// Максимум задач на один объект ожидания.
pub const MAX_WAITERS: usize = 16;

/// Простейший round-robin.
///
/// Состояние под IRQ-безопасным спин-локом: пробуждать задачи могут
/// не только сисколлы, но и обработчики прерываний (тик таймера будит
/// irq_wait-ожидающих через awake_task_from_wait) — гашение IRQ на
/// секции исключает дедлок «обработчик крутится на локе прерванного
/// владельца». Одно на планировщик: тики редки, а атомарные структуры
/// здесь дали бы только гонки между register/tick/wake.
pub struct RoundRobinScheduler {
    inner: IrqSafeSpinMutex<Inner>,
}

struct Inner {
    /// Очередь готовых (task_cap_id); front = следующий к запуску.
    ready: heapless::Vec<u64, MAX_READY>,
    /// Текущая задача (капабилити) — уже снята с очереди.
    current: Option<u64>,
    /// Очереди ожидания: object_id -> (модель пробуждения, ожидающие).
    /// Модель хранится вместе с очередью: awake_task_from_wait обязан
    /// различать OneShot (событие потребляет ОДИН ждущий) и Multiple
    /// (будим всех) — иначе OneShot-событие доставляется нескольким
    /// задачам и «теряется» только одной из них.
    waits: heapless::Vec<
        (usize, WaitModel, heapless::Vec<u64, MAX_WAITERS>),
        MAX_WAIT_OBJECTS,
    >,
    /// Счётчик тиков (диагностика).
    ticks: usize,
}

impl RoundRobinScheduler {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinMutex::new(Inner {
                ready: heapless::Vec::new(),
                current: None,
                waits: heapless::Vec::new(),
                ticks: 0,
            }),
        }
    }

    /// Число готовых задач (диагностика).
    pub fn ready_count(&self) -> usize {
        self.inner.lock().ready.len()
    }

    /// Текущая задача (диагностика).
    pub fn current(&self) -> Option<u64> {
        self.inner.lock().current
    }

    /// Число тиков (диагностика).
    pub fn ticks(&self) -> usize {
        self.inner.lock().ticks
    }

    /// Общий шаг карусели: вернуть текущую в хвост, взять следующую.
    fn rotate(inner: &mut Inner) -> TaskExecStatus {
        if let Some(next) = inner.ready.pop_front_from_start() {
            if let Some(prev) = inner.current.replace(next) {
                let _ = inner.ready.push_back(prev);
            }
            TaskExecStatus::ChangeTask(next as usize)
        } else if let Some(cur) = inner.current {
            // Один живой: ничего не меняем.
            TaskExecStatus::ChangeTask(cur as usize)
        } else {
            TaskExecStatus::NoAction
        }
    }
}

impl Default for RoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

trait DequeExt {
    fn pop_front_from_start(&mut self) -> Option<u64>;
    fn push_back(&mut self, v: u64) -> Result<(), u64>;
}

impl DequeExt for heapless::Vec<u64, MAX_READY> {
    fn pop_front_from_start(&mut self) -> Option<u64> {
        if self.is_empty() {
            None
        } else {
            Some(self.remove(0))
        }
    }

    fn push_back(&mut self, v: u64) -> Result<(), u64> {
        self.push(v)
    }
}

impl LocalSchedullerInterface for RoundRobinScheduler {
    /// Текущая задача по мнению планировщика (для сверки портом после
    /// сисколла: расхождение с фактической текущей = переключить контекст).
    fn current_task(&self) -> Option<u64> {
        self.inner.lock().current
    }

    /// Тик: карусель. Возвращает смену задачи (порт грузит контекст).
    fn process_tick(&mut self, _time: usize) -> TaskExecStatus {
        let mut inner = self.inner.lock();
        inner.ticks += 1;
        Self::rotate(&mut inner)
    }

    fn yield_current_task(&mut self) -> TaskExecStatus {
        let mut inner = self.inner.lock();
        Self::rotate(&mut inner)
    }

    fn register_task(
        &mut self,
        task_cap_id: u64,
        _task_begin_addr: u64,
        _task_code_size: u64,
        _task_stack_size: u64,
    ) -> TaskExecStatus {
        let mut inner = self.inner.lock();
        if inner.current.is_none() {
            inner.current = Some(task_cap_id);
            return TaskExecStatus::NopTask;
        }
        // Уже известна планировщику (текущая ИЛИ в готовых) — не дублируем:
        // дубль текущей в ready приводил бы к двойному запуску задачи
        // (current и ready одновременно).
        if inner.current == Some(task_cap_id) || inner.ready.contains(&task_cap_id) {
            return TaskExecStatus::NopTask;
        }
        match inner.ready.push(task_cap_id) {
            Ok(()) => TaskExecStatus::NopTask,
            Err(_) => TaskExecStatus::NoAction, // очередь полна — задача не принята
        }
    }

    fn unregister_task(&mut self, task_cap_id: u64) -> TaskExecStatus {
        let mut inner = self.inner.lock();
        inner.ready.retain(|t| *t != task_cap_id);
        // Из очередей ожидания тоже (задача умирает во сне).
        for (_, _, q) in inner.waits.iter_mut() {
            q.retain(|t| *t != task_cap_id);
        }
        inner.waits.retain(|(_, _, q)| !q.is_empty());
        if inner.current == Some(task_cap_id) {
            // Умирает текущая: переключиться на следующую.
            inner.current = None;
            Self::rotate(&mut inner)
        } else {
            TaskExecStatus::NopTask
        }
    }

    /// Сон: текущая задача уходит в очередь объекта, карусель переключает.
    /// Возвращаемый queue_id = object_id (awake принимает его же).
    ///
    /// Если wait-очередь переполнена (объектов > MAX_WAIT_OBJECTS или
    /// ждущих > MAX_WAITERS), задача ОСТАЁТСЯ текущей (sleep не состоялся):
    /// раньше она снималась с current, не попадая ни в wait, ни в ready —
    /// и терялась навсегда (никогда больше не запланируется).
    fn assign_current_task_to_wait(&mut self, object_id: usize, model: WaitModel) -> usize {
        let mut inner = self.inner.lock();
        let current = inner.current;
        let queue_id = object_id;
        if let Some(cur) = current {
            let slot = match inner
                .waits
                .iter_mut()
                .find(|(id, _, _)| *id == object_id)
            {
                Some((_, _, q)) => Some(q),
                None => inner
                    .waits
                    .push((object_id, model, heapless::Vec::new()))
                    .ok()
                    .and_then(|_| {
                        inner
                            .waits
                            .iter_mut()
                            .find(|(id, _, _)| *id == object_id)
                            .map(|(_, _, q)| q)
                    }),
            };
            let enqueued = match slot {
                Some(q) => q.push(cur).is_ok(),
                None => false,
            };
            if enqueued {
                // Снимаем текущую и переключаемся.
                inner.current = None;
                Self::rotate(&mut inner);
            }
            // !enqueued: sleep не состоялся — задача остаётся текущей,
            // вызовавший слой может повторить попытку.
        }
        queue_id
    }

    /// Пробуждение: OneShot — событие потребляет ровно ОДНОГО ждущего
    /// (FIFO); Multiple — будим всех. Текущая не трогается.
    ///
    /// Если ready переполнена, не поместившиеся остаются в wait-очереди
    /// (дождутся следующего пробуждения) — раньше они молча терялись.
    fn awake_task_from_wait(&mut self, queue_id: usize) {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let Some(pos) = inner.waits.iter().position(|(id, _, _)| *id == queue_id) else {
            return;
        };
        match inner.waits[pos].1 {
            WaitModel::OneShot => {
                if let Some(&t) = inner.waits[pos].2.first() {
                    if inner.ready.contains(&t) {
                        // Уже в готовых (не должно случаться) — просто снять.
                        inner.waits[pos].2.remove(0);
                    } else if inner.ready.push(t).is_ok() {
                        inner.waits[pos].2.remove(0);
                    }
                    // ready полна — ждущий остаётся в очереди.
                }
                if inner.waits[pos].2.is_empty() {
                    inner.waits.remove(pos);
                }
            }
            WaitModel::Multiple => {
                let q = &mut inner.waits[pos].2;
                let mut i = 0;
                while i < q.len() {
                    let t = q[i];
                    if inner.ready.contains(&t) {
                        q.remove(i);
                        continue;
                    }
                    if inner.ready.push(t).is_ok() {
                        q.remove(i);
                    } else {
                        // ready полна — остальные ждут следующего пробуждения.
                        i += 1;
                    }
                }
                if q.is_empty() {
                    inner.waits.remove(pos);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_rotates_round_robin() {
        let mut sched = RoundRobinScheduler::new();
        // Первая регистрация становится текущей.
        sched.register_task(1, 0, 0, 0);
        sched.register_task(2, 0, 0, 0);
        sched.register_task(3, 0, 0, 0);
        assert_eq!(sched.current(), Some(1));
        assert_eq!(sched.ready_count(), 2);

        // Тик: 1 -> хвост, текущая 2. Затем 3, затем 1.
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(2));
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(3));
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(1));
        assert_eq!(sched.ticks(), 3);
    }

    #[test]
    fn yield_switches_task() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(10, 0, 0, 0);
        sched.register_task(20, 0, 0, 0);
        assert_eq!(sched.yield_current_task(), TaskExecStatus::ChangeTask(20));
        assert_eq!(sched.yield_current_task(), TaskExecStatus::ChangeTask(10));
    }

    #[test]
    fn single_task_stays_current() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(7, 0, 0, 0);
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(7));
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(7));
    }

    #[test]
    fn block_wakes_and_resumes() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(1, 0, 0, 0);
        sched.register_task(2, 0, 0, 0);
        assert_eq!(sched.current(), Some(1));

        // Задача 1 засыпает на объекте 5: current -> 2, 1 в wait-очереди.
        let q = sched.assign_current_task_to_wait(5, WaitModel::OneShot);
        assert_eq!(q, 5);
        assert_eq!(sched.current(), Some(2));
        assert_eq!(sched.ready_count(), 0);

        // Пробуждение: 1 в готовые; тик — снова карусель 2 <-> 1.
        sched.awake_task_from_wait(5);
        assert_eq!(sched.ready_count(), 1);
        assert_eq!(sched.process_tick(0), TaskExecStatus::ChangeTask(1));
    }

    #[test]
    fn unregister_dying_current_switches() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(1, 0, 0, 0);
        sched.register_task(2, 0, 0, 0);
        sched.register_task(3, 0, 0, 0);
        assert_eq!(sched.current(), Some(1));
        // 1 умирает: карусель делает текущей следующую (2), 3 остаётся в готовых.
        let st = sched.unregister_task(1);
        assert!(matches!(st, TaskExecStatus::ChangeTask(2)));
        assert_eq!(sched.current(), Some(2));
        assert_eq!(sched.ready_count(), 1);
        // Повторная регистрация не дублирует.
        sched.register_task(2, 0, 0, 0);
        assert_eq!(sched.ready_count(), 1);
    }

    #[test]
    fn oneshot_wakes_exactly_one_waiter() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(1, 0, 0, 0); // станет текущей
        sched.register_task(2, 0, 0, 0);
        sched.register_task(3, 0, 0, 0);
        // 1 спит на объекте 9; 2 становится текущей; 3 в ready.
        let _ = sched.assign_current_task_to_wait(9, WaitModel::OneShot);
        assert_eq!(sched.current(), Some(2));
        // Текущая 2 тоже засыпает на 9: current -> 3.
        let _ = sched.assign_current_task_to_wait(9, WaitModel::OneShot);
        assert_eq!(sched.current(), Some(3));
        // OneShot-событие: просыпается ровно один (первый заснувший — 1).
        sched.awake_task_from_wait(9);
        assert_eq!(sched.ready_count(), 1);
        // Второй (2) всё ещё спит.
        sched.awake_task_from_wait(9);
        assert_eq!(sched.ready_count(), 2);
        // Третьего ждущего нет — пробуждение no-op.
        sched.awake_task_from_wait(9);
        assert_eq!(sched.ready_count(), 2);
    }

    #[test]
    fn multiple_wakes_all_waiters() {
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(1, 0, 0, 0);
        sched.register_task(2, 0, 0, 0);
        sched.register_task(3, 0, 0, 0);
        let _ = sched.assign_current_task_to_wait(4, WaitModel::Multiple); // спит 1
        let _ = sched.assign_current_task_to_wait(4, WaitModel::Multiple); // спит 2
        assert_eq!(sched.current(), Some(3));
        sched.awake_task_from_wait(4);
        // Проснулись ОБА (1 и 2) — semantics Multiple (IRQ-wait).
        assert_eq!(sched.ready_count(), 2);
    }

    #[test]
    fn current_task_tracks_scheduling() {
        // Трейт-метод current_task() — источник истины для порта:
        // после yield он обязан показать ДРУГУЮ задачу (порт переключит
        // контекст), после усыпания — следующую живую (или None).
        let mut sched = RoundRobinScheduler::new();
        sched.register_task(1, 0, 0, 0);
        sched.register_task(2, 0, 0, 0);
        sched.register_task(3, 0, 0, 0);
        assert_eq!(sched.current_task(), Some(1));
        // Yield: карусель переводит current на 2 — порт обязан увидеть 2.
        let _ = sched.yield_current_task();
        assert_eq!(sched.current_task(), Some(2));
        // Усыпание текущей (2): current переходит на 3 (1 осталась в ready
        // после своего yield).
        let _ = sched.assign_current_task_to_wait(8, WaitModel::OneShot);
        assert_eq!(sched.current_task(), Some(3));
        // Усыпание 3: current переходит на 1 (та была в готовых).
        let _ = sched.assign_current_task_to_wait(8, WaitModel::OneShot);
        assert_eq!(sched.current_task(), Some(1));
        // Усыпание последней (1): готовых нет — current пуст (все спят;
        // порт обязан выйти в idle-цикл планировщика).
        let _ = sched.assign_current_task_to_wait(8, WaitModel::OneShot);
        assert_eq!(sched.current_task(), None);
        // Пробуждение 2: current остаётся пустым (выбирает цикл),
        // но 2 — в готовых.
        sched.awake_task_from_wait(8);
        assert_eq!(sched.current_task(), None);
        assert_eq!(sched.ready_count(), 1);
    }
}
