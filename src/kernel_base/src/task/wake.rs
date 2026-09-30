//! Межъядерное пробуждение (remote wakeup).
//!
//! ПРОБЛЕМА: планировщики per-CPU (`RoundRobinScheduler` на каждое ядро,
//! см. фронт), а события пробуждения происходят на ПРОИЗВОЛЬНОМ ядре:
//!   - смерть задачи будит отправителей её IPC-сообщений (могут спать на
//!     других ядрах);
//!   - IRQ, пойманный ядром A, будит задачу, ожидающую линию и спящую
//!     на ядре B (irq_wait::on_irq_fired);
//!   - RELEASE/фолты/дедлайны — тот же класс.
//! Локальный `lctl.scheduler_release_object` видит ТОЛЬКО планировщик
//! своего ядра — кросс-CPU wake терялся (задача спала навсегда).
//!
//! РЕШЕНИЕ: глобальный реестр планировщиков по слотам ядер + единая
//! точка пробуждения, дренящая объект на ВСЕХ установленных
//! планировщиках. Планировщик — Sync с `&self`-методами (внутренний
//! IrqSafeSpinMutex), поэтому вызов `awake_task_from_wait` с чужого ядра
//! корректен. Разбудившим ядерам (появились новые runnable) отправляется
//! Resched-IPI через хук порта — ядро быстро подхватит новую задачу
//! (виртуальный тик: см. kernel_x86::ipi::on_resched_ipi); без IPI
//! задача всё равно запустится на ближайшем тике таймера — IPI только
//! снижает латентность.
//!
//! ПРОТОКОЛ БЕЗ ПОТЕРЬ (lost wakeup): гонка «waker просканировал ядро B,
//! задача встала в очередь B ПОСЛЕ скана» закрыта ГЛОБАЛЬНОЙ блокировкой
//! WAKE_LOCK: и постановка в ожидание (lctl::scheduler_block_on_object),
//! и скан (release_object_global) идут под одним локом — операции
//! сериализованы. Лок — irq-safe: пробуждения приходят из IRQ-контекста.
//!
//! ЦЕНА: одно приобретение глобального лока на block/wake. Частоты
//! syscall/IRQ — приемлемо; contention между ядрами на wake — осознанный
//! компромисс против per-object таблиц (без аллокаций и без эвикций).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::irqsafe::IrqSafeSpinMutex;
use crate::traits::scheduller::LocalSchedullerInterface;

/// Максимум слотов ядер в реестре пробуждения. ЧИСЛЕННО совпадает с
/// контрактом `IpiController::online_mask` (u64-битмаска) и MAX_CPUS
/// портов; порты с бо́льшим числом ядер обязаны сначала расширить
/// u64-маску IPI-контракта.
pub const MAX_WAKE_CPUS: usize = 64;

/// Реестр планировщиков по слотам: слот i — планировщик ядра i.
/// Лениво (Once): планировщики ставятся фронтом по ходу бута.
static CPU_SCHEDULERS: [spin::Once<&'static dyn LocalSchedullerInterface>; MAX_WAKE_CPUS] =
    [const { spin::Once::new() }; MAX_WAKE_CPUS];

/// Глобальный лок протокола block/wake (см. шапку — lost wakeup).
pub(crate) static WAKE_LOCK: IrqSafeSpinMutex<()> = IrqSafeSpinMutex::new(());

/// Хук Resched-IPI (порт): fn(slot) — кик планировщика ядра `slot`.
/// Регистрируется фронтом (kernel_limine) после инициализации IPI;
/// в теле — `ArchImplementation::ipi()` → `send_to_cpu(slot, Reschedule)`.
/// Fn-указатель (как irq::set_mask_callback): kernel_base не знает типов
/// порта, а аллокаций иdyn здесь быть не должно.
pub type KickHook = fn(slot: usize);

static KICK_HOOK: AtomicU64 = AtomicU64::new(0);

/// Регистрирует хук кика (повторная установка — заменяет; идемпотентно).
pub fn set_kick_hook(hook: KickHook) {
    KICK_HOOK.store(hook as usize as u64, Ordering::Release);
}

fn kick(slot: usize) {
    let raw = KICK_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: raw — fn-указатель, записанный set_kick_hook.
        let f: KickHook = unsafe { core::mem::transmute(raw) };
        f(slot);
    }
}

/// Ставит планировщик в глобальный реестр (фронт, при per-CPU
/// инициализации). Повторный вызов для того же слота — замена не
/// поддерживается Once (инвариант: слот живёт одному ядру навсегда).
pub fn install_cpu_scheduler(slot: usize, scheduler: &'static dyn LocalSchedullerInterface) {
    if slot < MAX_WAKE_CPUS {
        CPU_SCHEDULERS[slot].call_once(|| scheduler);
    }
}

/// Глобальное пробуждение: дренит `object_id` на ВСЕХ установленных
/// планировщиках (кроме `exclude` — своего, который вызывающий уже
/// обошёл локально) и кикает Resched-IPI ядра, где кто-то проснулся.
///
/// Возвращает битмаску ядер с НОВЫМИ runnable (диагностика/тесты).
/// Вызываемо из любого контекста (IRQ в том числе: WAKE_LOCK irq-safe).
pub fn release_object_global(object_id: usize, exclude: Option<usize>) -> u64 {
    let _g = WAKE_LOCK.lock();
    let mut kicked = 0u64;
    for slot in 0..MAX_WAKE_CPUS {
        let Some(sched) = CPU_SCHEDULERS[slot].get() else {
            continue;
        };
        if Some(slot) == exclude {
            continue;
        }
        if sched.awake_task_from_wait(object_id) > 0 {
            kicked |= 1u64 << slot;
        }
    }
    drop(_g);
    // Кик ВНЕ лока: IPI-отправка может быть медленной (MMIO ICR), не
    // держим глобальный протокол на её протяжении. Разбудившие ядра
    // уже получили задачи в ready — кик лишь ускоряет их старт.
    for slot in 0..MAX_WAKE_CPUS {
        if kicked & (1u64 << slot) != 0 {
            kick(slot);
        }
    }
    kicked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::scheduller::{LocalSchedullerInterface, TaskExecStatus, WaitModel};
    use core::sync::atomic::AtomicUsize;

    /// Планировщик-двойник с счётчиком пробуждений (Sync через атомики).
    struct CountingSched {
        waits: IrqSafeSpinMutex<heapless::Vec<usize, 8>>,
        wakes: AtomicUsize,
    }

    // SAFETY: только атомики + IrqSafeSpinMutex.
    unsafe impl Send for CountingSched {}
    unsafe impl Sync for CountingSched {}

    impl CountingSched {
        const fn new() -> Self {
            Self {
                waits: IrqSafeSpinMutex::new(heapless::Vec::new()),
                wakes: AtomicUsize::new(0),
            }
        }
    }

    impl LocalSchedullerInterface for CountingSched {
        fn process_tick(&self, _time: usize) -> TaskExecStatus {
            TaskExecStatus::NoAction
        }
        fn current_task(&self) -> Option<u64> {
            None
        }
        fn assign_current_task_to_wait(&self, object_id: usize, _model: WaitModel) -> usize {
            let _ = self.waits.lock().push(object_id);
            object_id
        }
        fn awake_task_from_wait(&self, queue_id: usize) -> usize {
            let mut w = self.waits.lock();
            if let Some(pos) = w.iter().position(|&id| id == queue_id) {
                w.remove(pos);
                self.wakes.fetch_add(1, Ordering::AcqRel);
                1
            } else {
                0
            }
        }
    }

    /// Уникальные слоты на тест (реестр — статика между тестами).
    const SLOT_A: usize = 61;
    const SLOT_B: usize = 62;
    const SLOT_C: usize = 63;

    static SCHED_A: CountingSched = CountingSched::new();
    static SCHED_B: CountingSched = CountingSched::new();
    static SCHED_C: CountingSched = CountingSched::new();

    #[test]
    fn global_wake_reaches_remote_schedulers() {
        let _guard = crate::test_guard::GLOBAL.lock();

        install_cpu_scheduler(SLOT_A, &SCHED_A);
        install_cpu_scheduler(SLOT_B, &SCHED_B);
        install_cpu_scheduler(SLOT_C, &SCHED_C);

        // Задачи засыпают на объекте 0xBEEF на ядрах B и C.
        SCHED_B.assign_current_task_to_wait(0xBEEF, WaitModel::OneShot);
        SCHED_C.assign_current_task_to_wait(0xBEEF, WaitModel::OneShot);

        // Пробуждение с ядра A (exclude = A): маска {B, C}, оба проснулись.
        let mask = release_object_global(0xBEEF, Some(SLOT_A));
        assert_eq!(mask, (1 << SLOT_B) | (1 << SLOT_C));
        assert_eq!(SCHED_B.wakes.load(Ordering::Acquire), 1);
        assert_eq!(SCHED_C.wakes.load(Ordering::Acquire), 1);

        // Повтор — пусто (OneShot: очереди опустели).
        let mask = release_object_global(0xBEEF, None);
        assert_eq!(mask, 0);
    }

    #[test]
    fn global_wake_excludes_self_slot() {
        let _guard = crate::test_guard::GLOBAL.lock();

        // Слоты независимы от порядка тестов (Once идемпотентен).
        install_cpu_scheduler(SLOT_A, &SCHED_A);

        SCHED_A.assign_current_task_to_wait(0xF00D, WaitModel::OneShot);
        // exclude = A: собственный планировщик НЕ дренится (вызывающий
        // уже сделал это локально через lctl).
        let mask = release_object_global(0xF00D, Some(SLOT_A));
        assert_eq!(mask, 0);
        assert_eq!(SCHED_A.wakes.load(Ordering::Acquire), 0);
        // Без exclude — дренится.
        let mask = release_object_global(0xF00D, None);
        assert_eq!(mask, 1 << SLOT_A);
        assert_eq!(SCHED_A.wakes.load(Ordering::Acquire), 1);
    }

    #[test]
    fn wake_outside_registry_is_noop() {
        let _guard = crate::test_guard::GLOBAL.lock();
        // Объект, на котором никто не ждёт: пустая маска, без паник.
        assert_eq!(release_object_global(0x1234, None), 0);
    }
}
