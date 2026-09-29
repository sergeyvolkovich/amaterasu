//! Дедлайны блокирующих ожиданий: "спать до сообщения ИЛИ срока".
//!
//! Зачем: IPC_WAIT без срока зависает навсегда, если сервер умер/залип —
//! клиент никогда не узнает. Классическое микро-ядро решает это
//! таймаутами на ожидании; тайм-сервис из юзерспейса разбудить
//! заблокированный IPC_WAIT не может (эндпоинтные wait-объекты —
//! kernel-reserved, RELEASE с ring3 отклонён: см. is_kernel_wait_object).
//! Поэтому минимальный механизм в ядре: абсолютный дедлайн в ТИКАХ
//! (stats::global_ticks, разрешение = частота тика порта), пробуждение
//! из тика таймера.
//!
//! Контракт с сисколлом IPC_WAIT (аргумент deadline):
//!   deadline == 0  — ждать вечно (прежняя семантика);
//!   deadline  > 0  — абсолютный тик; по достижении задача будится,
//!                    IPC_WAIT возвращает E_TIMEOUT. Если в тот же тик
//!                    пришло сообщение — побеждает сообщение (хендлер
//!                    перепроверяет pending после пробуждения).
//!
//! Потокобезопасность: слоты под IrqSafeSpinMutex — реестр берут
//! сисколл WAIT (контекст задачи) и тик таймера (IRQ-контекст, любое
//! ядро). Пробуждение (scheduler_release_object) — ВНЕ лока, как в
//! irq_wait::on_irq_fired.
//!
//! Одноразовость: слот снимает сам хендлер WAIT после пробуждения
//! (cancel) — и при доставке сообщения, и при таймауте; смерть задачи
//! чистит слот через remove_task (destroy_task_full). register
//! замещает прежний слот той же задачи (повторный WAIT без пробуждения
//! не выжигает реестр).

use crate::irqsafe::IrqSafeSpinMutex;
use crate::lctl::LocalKernelCTL;
use crate::traits::memory::MemoryInterfaceUserspace;

/// Максимальное число одновременных ожидающих с дедлайном.
pub const MAX_DEADLINE_WAITERS: usize = 32;

#[derive(Debug, Clone, Copy)]
struct DeadlineWaiter {
    /// Capability id задачи-ожидателя.
    task_cap_id: u64,
    /// Wait-объект, на котором задача спит (эндпоинт); по нему будим.
    object_id: usize,
    /// Абсолютный тик истечения (stats::global_ticks).
    deadline: u64,
    /// Сработало (тик дошёл до deadline; хендлер прочитает через cancel).
    fired: bool,
}

/// Слот реестра (None — свободен).
type Slot = Option<DeadlineWaiter>;

static SLOTS: IrqSafeSpinMutex<[Slot; MAX_DEADLINE_WAITERS]> =
    IrqSafeSpinMutex::new([None; MAX_DEADLINE_WAITERS]);

/// Регистрирует дедлайн для задачи (замещает прежний слот задачи).
/// Вызывается из IPC_WAIT непосредственно перед блокировкой.
pub fn register(task_cap_id: u64, object_id: usize, deadline: u64) -> Result<(), ()> {
    let mut slots = SLOTS.lock();
    // Замена собственной регистрации той же задачи.
    for slot in slots.iter_mut() {
        if let Some(w) = slot {
            if w.task_cap_id == task_cap_id {
                *slot = Some(DeadlineWaiter {
                    task_cap_id,
                    object_id,
                    deadline,
                    fired: false,
                });
                return Ok(());
            }
        }
    }
    // Свободный слот.
    for slot in slots.iter_mut() {
        if slot.is_none() {
            *slot = Some(DeadlineWaiter {
                task_cap_id,
                object_id,
                deadline,
                fired: false,
            });
            return Ok(());
        }
    }
    Err(())
}

/// Тик таймера (IRQ-контекст): будим всех, чей срок вышел. Слот
/// ОСТАЁТСЯ (пометка fired) — его снимет хендлер WAIT через cancel,
/// когда задача проснётся; иначе гонка "тик будит, хендлер не успел"
/// потеряла бы факт таймаута. Задачи, умершие до cancel, чистит
/// remove_task.
pub fn on_tick<Umap: MemoryInterfaceUserspace>(lctl: &mut LocalKernelCTL<Umap>, now: u64) {
    // 1. Под локом: пометить сработавшие (будить БУДЕМ вне лока).
    let mut to_wake: [Option<usize>; MAX_DEADLINE_WAITERS] = [None; MAX_DEADLINE_WAITERS];
    let mut wake_count = 0usize;
    {
        let mut slots = SLOTS.lock();
        for slot in slots.iter_mut() {
            let Some(w) = slot else { continue };
            if !w.fired && now >= w.deadline {
                w.fired = true;
                to_wake[wake_count % MAX_DEADLINE_WAITERS] = Some(w.object_id);
                wake_count += 1;
            }
        }
    }
    // 2. Вне лока: пробуждение (может брать чужие локи — шедулер).
    for object_id in to_wake.iter().take(wake_count) {
        if let Some(obj) = object_id {
            lctl.scheduler_release_object(*obj);
        }
    }
}

/// Снимает регистрацию задачи, возвращает факт срабатывания дедлайна.
/// Хендлер WAIT зовёт СРАЗУ после пробуждения: true — проснулся по
/// сроку (сообщение может быть доставлено в тот же тик — хендлер
/// обязан перепроверить pending, сообщение старше таймаута).
pub fn cancel(task_cap_id: u64) -> bool {
    let mut slots = SLOTS.lock();
    for slot in slots.iter_mut() {
        if let Some(w) = slot {
            if w.task_cap_id == task_cap_id {
                let fired = w.fired;
                *slot = None;
                return fired;
            }
        }
    }
    false
}

/// Смерть задачи: слот больше не пригодится (хендлер не проснётся).
pub fn remove_task(task_cap_id: u64) {
    let mut slots = SLOTS.lock();
    for slot in slots.iter_mut() {
        if let Some(w) = slot {
            if w.task_cap_id == task_cap_id {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Один последовательный тест: реестр — глобальный статик, параллельные
    /// тесты выжигали бы слоты друг друга (учеба irq_wait: там своя
    /// синхронизация; здесь проще одна цепочка).
    #[test]
    fn deadline_registry_lifecycle() {
        // Замещение: повторный register той же задачи — один слот; cancel
        // возвращает флаг СРАБАТЫВАНИЯ (не стреляло — false), слот снят.
        assert!(register(7001, 100, 500).is_ok());
        assert!(register(7001, 200, 900).is_ok());
        assert!(!cancel(7001));
        assert!(!cancel(7001)); // слот уже пуст

        // Флаг fired: не стреляло — false.
        assert!(register(7002, 300, 100).is_ok());
        assert!(!cancel(7002));

        // Переполнение: MAX слотов, следующий — отказ; cancel освобождает.
        for i in 0..MAX_DEADLINE_WAITERS {
            assert!(register(8000 + i as u64, 400 + i, 1000).is_ok());
        }
        assert!(register(9999, 500, 1000).is_err());
        assert!(!cancel(8000));
        assert!(register(9999, 500, 1000).is_ok());
        assert!(!cancel(9999)); // снялся, не стреляв
    }
}
