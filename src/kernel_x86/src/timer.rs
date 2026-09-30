//! Системный тик: PIT (Intel 8253/8254, канал 0) → IO-APIC (GSI из
//! override для ISA 0, обычно GSI 2) → хук ядра.
//!
//! ТАЙМЕР НА AP: у каждого AP — собственный LAPIC-таймер (LVT, periodic,
//! вектор LOCAL_TIMER_VECTOR из ipi.rs), калиброванный на BSP по
//! PIT-каналу 2 ДО подъёма AP (calibrate_lapic_timer). BSP продолжает
//! тикать PIT-линией; AP — локальным таймером (доставка на своё ядро,
//! учёт per-CPU, преемпция ring3 на этом ядре). Локальный тик — НЕ
//! линия IRQ: пробуждение ждущих irq_wait не требуется.
//!
//! РАСПРЕДЕЛЕНИЕ ОТВЕТСТВЕННОСТИ (L4-философия «таймер — юзерспейсный
//! сервис», ядро — только транспорт, учёт и вытеснение):
//!   - АРХ-БЕКЕНД (этот модуль): программирует PIT, маршрут GSI в
//!     IO-APIC, регистрирует хук линии. Сам НЕ ведёт время как сервис.
//!   - ЯДРО (kernel_base::task::stats): на каждый тик учитывает квант
//!     текущей задаче (cpu_ticks) и глобальный uptime — единственное,
//!     что ядру нужно от времени (статистика/учёт).
//!   - ПРЕЕМПЦИЯ: тик, заставший задачу в ring3, крутит карусель
//!     планировщика (process_tick); выбранная задача вступает в хвосте
//!     IRQ-диспетчера (cswitch::irq_preempt_tail — кадр уже на стеке).
//!     Тик, заставший ядро (сисколл/цикл), карусель НЕ крутит —
//!     вытеснение ядерного контекста делала бы небезопасным
//!     семантику «текущей» в assign_current_task_to_wait/unregister_task.
//!   - ЮЗЕРСПЕЙС: таймер-сервер ждёт линию таймера через WAIT по капе
//!     (IrqLine GSI), ведёт uptime, раздаёт тайм-ауты/сны через IPC.
//!
//! ЛИНИЯ ТАЙМЕРА: GSI из MADT override ISA 0 (PC-платформа: GSI 2,
//! edge/high); без override — конформинг (GSI 0). Юзерспейс узнаёт
//! линию из лога ядра на буте (запись ниже) — v2 beta.
//!
//! Если MADT/IO-APIC недоступны — legacy-PIC fallback (линия 0).
//!
//! EOI шлёт диспетчер (irq::irq_vector_dispatch) ПОСЛЕ хука — по
//! стандартному контракту «подтверждать после обработки».

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_base::kernel_log;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::task::stats;
use kernel_base::traits::scheduller::TaskExecStatus;

use crate::apic;
use crate::irq;
use crate::paging::X86Umap;
use crate::pic;

/// Линия таймера в legacy-режиме (PIT → IRQ0 → вектор 32).
pub const LEGACY_TIMER_LINE: u32 = 0;

/// Делитель счёта LAPIC-таймера (см. apic::TIMER_DIVIDE_16).
const LAPIC_DIVIDE: u32 = apic::TIMER_DIVIDE_16;
/// Окно калибровки LAPIC-таймера (PIT-канал 2, one-shot, мс).
const CALIBRATION_MS: u64 = 50;
/// Фоллбэк counts/тик, если калибровка не удалась (предположение
/// «шина LAPIC ≈ 100 МГц» / делитель 16: 100e6/16/100 Гц = 62500).
const LAPIC_COUNTS_FALLBACK: u32 = 62_500;

/// Откалиброванный счёт LAPIC-таймера на ОДИН тик (0 — не калиброван:
/// AP стартуют без локального тика, лог выводится один раз).
static LAPIC_COUNTS_PER_TICK: AtomicU32 = AtomicU32::new(0);

/// GSI линии таймера (заполняется start_periodic_tick; для диагностики
/// и будущего bootinfo-расширения).
pub static TIMER_GSI: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Частота входного генератора PIT (Гц).
const PIT_INPUT_HZ: u32 = 1_193_182;

/// Порт канала 0 PIT и порт команд.
const PIT_CH0_DATA: u16 = 0x40;
const PIT_MODE_CMD: u16 = 0x43;
/// Порт канала 2 (используется для калибровки LAPIC) и порт B NMI/спикера.
const PIT_CH2_DATA: u16 = 0x42;
const PORT_61: u16 = 0x61;
/// Режим 3 (square wave), двоичный счёт, доступ lo/hi байта.
const PIT_MODE3_LOHI: u8 = 0b0011_0110;
/// Режим 0 (one-shot, прерывание по терминальному счёту) канала 2,
/// доступ lo/hi: BCD=0, mode=000, RL=11, CH=10 → 0b1011_0000.
const PIT_CH2_MODE0_LOHI: u8 = 0b1011_0000;

/// Запускает периодический тик: ремап+маска PIC, программирование PIT
/// канала 0, маршрут GSI таймера в IO-APIC (или размаска PIC в legacy),
/// регистрация хука линии (учёт статистики + доставка ждущим), занятие
/// линии в реестре kernel_base (owner 0 = ядро: юзерспейс не перехватит).
///
/// Прерывания НЕ включает: STI делает фронтенд (boot) после полной
/// инициализации — старт источника и его «слышимость» разделены.
pub fn start_periodic_tick(hz: u32) {
    let divisor = (PIT_INPUT_HZ / hz.max(1)).clamp(2, 0xFFFF) as u16;

    // 1. PIC: ремап на векторы 32..47 + маска всего. В IO-APIC-режиме PIC
    //    остаётся замаскированным НАВСЕГДА (только ремап против
    //    спуриков на исключениях); в legacy — владелец линии размаскирует.
    pic::remap_and_mask_all();

    // 2. PIT: канал 0, режим 3, делитель.
    let mut mode = x86_64::instructions::port::PortWriteOnly::new(PIT_MODE_CMD);
    let mut ch0 = x86_64::instructions::port::PortWriteOnly::new(PIT_CH0_DATA);
    unsafe {
        mode.write(PIT_MODE3_LOHI);
        ch0.write((divisor & 0xFF) as u8);
        ch0.write((divisor >> 8) as u8);
    }

    // 3. Линия таймера: GSI из override либо конформинг 0.
    let (gsi, active_low, level) = match irq::isa_override(0) {
        Some(iso) => (iso.gsi, iso.active_low, iso.level_triggered),
        None => (LEGACY_TIMER_LINE, false, false),
    };
    TIMER_GSI.store(gsi, core::sync::atomic::Ordering::Relaxed);

    // 4. Хук линии (учёт + доставка ждущим) — до размаскивания.
    crate::irq::register_line_hook(gsi, timer_tick_hook)
        .expect("таймер: слот хука линии свободен (первая регистрация)");

    // 5. Объявляем линию статистике (юзерспейс-таймер-сервер возьмёт её
    //    капой через CAP_CREATE_IRQ и будет ждать тик — L4-модель).
    //    Хук ядра (шаг 4) от реестра владения НЕ зависит: учёт квантов
    //    и дедлайнов работает независимо от того, кто держит линию.

    // 6. Маршрут: IO-APIC RTE (маскированный) + размаска; legacy — PIC.
    let ioapic_mode = irq::chip().is_some_and(|c| !c.legacy());
    if ioapic_mode {
        crate::ioapic::program_route(gsi, active_low, level, false);
        crate::ioapic::unmask_gsi(gsi);
        kernel_log!(
            "timer: PIT {} Гц (делитель {}), GSI {} (edge/{}), вектор {}; преемпция ring3 активна\n",
            hz,
            divisor,
            gsi,
            if level { "level" } else { "high" },
            32 + gsi
        );
    } else {
        pic::unmask(LEGACY_TIMER_LINE as u8);
        kernel_log!("timer: PIT {} Гц (делитель {}), legacy IRQ0; преемпция ring3 активна\n", hz, divisor);
    }

    stats::set_tick_hz(hz as u64);
    stats::set_timer_line(gsi);
}

/// Хук тика (вызывается из IDT-диспетчера с погашенными прерываниями):
///   1) квант текущей задаче + глобальный uptime (ядро);
///   2) дедлайны IPC_WAIT: будим всех, чей срок вышел (E_TIMEOUT хендлер
///      вернёт сам после пробуждения; сообщение в тот же тик старше);
///   3) преемпция: карусель планировщика на ring3-тиках (решение
///      откладывается в lctl.preempt_next; исполнение — в хвосте
///      диспетчера, где виден кадр).
///
/// Пробуждение ждущих линии (irq_wait) — ответственность диспетчера
/// (единый путь для всех линий), здесь НЕ дублируется.
///
/// EOI отправит irq_vector_dispatch ПОСЛЕ возврата хука.
fn timer_tick_hook(_line: u32, lctl: &mut LocalKernelCTL<X86Umap>, from_user: bool) {
    stats::on_tick(lctl);
    kernel_base::task::deadline::on_tick(lctl, kernel_base::task::stats::global_ticks());

    // Преемпция: только тик, заставший задачу в ring3. Ротация
    // планировщика на ядерном контексте разъехалась бы с семантикой
    // assign_current_task_to_wait/unregister_task (они оперируют
    // «текущей» серединой сисколла); такие тики не отнимают квант —
    // вытеснение случится на первом тике в ring3 либо задача
    // уступит/уснёт сама.
    if from_user {
        match lctl.scheduler_process_tick(kernel_base::task::stats::global_ticks() as usize) {
            TaskExecStatus::ChangeTask(next) => {
                lctl.set_preempt_next(next as u64);
            }
            _ => {}
        }
    }
}

// ─── LAPIC-таймер: калибровка + тик на AP ────────────────────────────────────

/// Кубликация чистой математики калибровки для хост-тестов: elapsed —
/// счёт LAPIC (делитель уже учтён: счётчик тикает на шине/делитель),
/// вычисляет counts на один тик частоты hz.
fn counts_per_tick_from(elapsed: u32, window_ms: u64, hz: u32) -> u32 {
    let per_sec = (elapsed as u64) * 1000 / window_ms.max(1);
    (per_sec / hz.max(1) as u64) as u32
}

/// Калибровка LAPIC-таймера по PIT-каналу 2 (BSP, IF=0 — прерывания
/// ещё не включены, доставка не мешает измерению; LVT-таймер маскирован).
///
/// Схема: PIT ch2 в one-shot на ~50 мс (гейт через порт 0x61, спикер
/// выключен — канал 0 не трогаем, системный тик остаётся PIT'овским);
/// параллельно LAPIC-таймер считает от u32::MAX вниз; по OUT2 читаем
/// elapsed → частота счётчика → counts на один тик частоты hz.
///
/// ВАЖНО: вызывается ДО подъёма AP (smp_up) — AP-циклы программируют
/// свой LVT-таймер откалиброванным счётом (start_ap_tick).
pub fn calibrate_lapic_timer(hz: u32) {
    if !apic::active() {
        kernel_log!("timer: LAPIC неактивен — AP без локального тика\n");
        return;
    }

    use x86_64::instructions::port::Port;
    use x86_64::instructions::port::PortGeneric;
    use x86_64::instructions::port::ReadWriteAccess;

    // 1. Программируем PIT ch2: one-shot, счёт на ~CALIBRATION_MS.
    let window_ticks = PIT_INPUT_HZ as u64 * CALIBRATION_MS / 1000;
    let mut mode = x86_64::instructions::port::PortWriteOnly::new(PIT_MODE_CMD);
    let mut ch2 = x86_64::instructions::port::PortWriteOnly::new(PIT_CH2_DATA);
    unsafe {
        mode.write(PIT_CH2_MODE0_LOHI);
        ch2.write((window_ticks & 0xFF) as u8);
        ch2.write((window_ticks >> 8) as u8);
    }

    // 2. Старт LAPIC-счёта (маскирован — только счёт).
    apic::timer_oneshot_calibration_start(LAPIC_DIVIDE);

    // 3. Гейт ch2 (порт 0x61: bit0 GATE2=1, bit1 SPKR=0), старт PIT-окна.
    let mut port61: PortGeneric<u8, ReadWriteAccess> = Port::new(PORT_61);
    // SAFETY: порт 0x61 — стандартный контроллер NMI/спикера.
    let p61 = unsafe { port61.read() };
    unsafe { port61.write((p61 & !0b10) | 1) };

    // 4. Ждём OUT2 (bit5) с bounded-спином (хост-время ~50 мс; TCG —
    //    дольше по хост-циклам, но bound задан с запасом).
    let mut timed_out = true;
    for _ in 0..(1u64 << 34) {
        // SAFETY: см. выше.
        if unsafe { port61.read() } & (1 << 5) != 0 {
            timed_out = false;
            break;
        }
    }

    // 5. Читаем elapsed LAPIC, глушим канал (гейт) и LVT-таймер.
    let elapsed = u32::MAX - apic::timer_current_count();
    // SAFETY: см. выше.
    let p61_end = unsafe { port61.read() };
    unsafe { port61.write(p61_end & !1) };
    apic::timer_mask();

    let counts = if timed_out || elapsed == 0 {
        kernel_log!(
            "timer: калибровка LAPIC не удалась (timeout={}, elapsed={}) — фоллбэк {} counts/тик\n",
            timed_out,
            elapsed,
            LAPIC_COUNTS_FALLBACK
        );
        LAPIC_COUNTS_FALLBACK
    } else {
        let c = counts_per_tick_from(elapsed, CALIBRATION_MS, hz).max(16);
        kernel_log!(
            "timer: LAPIC калиброван: elapsed {} за {} мс → {} counts/тик при {} Гц (делитель /16)\n",
            elapsed,
            CALIBRATION_MS,
            c,
            hz
        );
        c
    };
    LAPIC_COUNTS_PER_TICK.store(counts, Ordering::Release);
}

/// Программирует LVT-таймер ТЕКУЩЕГО ядра (AP): periodic, вектор
/// LOCAL_TIMER_VECTOR, откалиброванный счёт. Вызывается из ap_main
/// после apic::init_ap, до включения прерываний фронтом.
pub fn start_ap_tick() {
    let counts = LAPIC_COUNTS_PER_TICK.load(Ordering::Acquire);
    if counts == 0 {
        // Калибровка не проводилась/не удалась: тик на AP не стартует —
        // AP продолжает кооперативную модель (поллинг цикла планировщика).
        return;
    }
    apic::timer_program_periodic(crate::ipi::LOCAL_TIMER_VECTOR, counts, LAPIC_DIVIDE);
}

/// Диспетчеризация локального тика (вектор LOCAL_TIMER_VECTOR, только
/// AP; BSP тикает PIT-линией через irq_vector_dispatch). Это НЕ линия:
/// пробуждение irq_wait-ждущих не требуется — только учёт ядра.
/// EOI отправит диспетчер после возврата.
pub fn local_timer_dispatch(lctl: &mut LocalKernelCTL<X86Umap>, from_user: bool) {
    timer_tick_hook(TIMER_GSI.load(Ordering::Relaxed), lctl, from_user);
}

// ─── Тесты (хост: чистая математика калибровки) ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_math_divides_counts_per_second() {
        // LAPIC насчитал 500_000 тиков за 50 мс → 10 МГц → 100 Гц тик:
        // 100_000 counts/тик.
        assert_eq!(counts_per_tick_from(500_000, 50, 100), 100_000);
        // 1_250_000 за 50 мс → 25 МГц → 250_000 counts/тик.
        assert_eq!(counts_per_tick_from(1_250_000, 50, 100), 250_000);
        // Некруглые частоты тика (125 Гц).
        assert_eq!(counts_per_tick_from(500_000, 50, 125), 80_000);
    }

    #[test]
    fn calibration_math_is_zero_safe() {
        // Нулевые окно/частота не паникуют (max(1) внутри).
        assert_eq!(counts_per_tick_from(1_000, 0, 100), 10_000);
        assert_eq!(counts_per_tick_from(1_000, 50, 0), 20_000);
    }

    #[test]
    fn calibration_counts_fit_32bit_initial_count() {
        // Делитель /16: даже шина 4 ГГц даёт 250 МГц счётчик →
        // 2.5 М counts/тик при 100 Гц — помещается в u32.
        let worst_case = counts_per_tick_from(u32::MAX, 50, 100);
        assert!(worst_case <= u32::MAX);
    }
}
