//! Системный тик: PIT (Intel 8253/8254, канал 0) → IO-APIC (GSI из
//! override для ISA 0, обычно GSI 2) → хук ядра.
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

use kernel_base::kernel_log;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::task::stats;
use kernel_base::traits::scheduller::TaskExecStatus;

use crate::irq;
use crate::paging::X86Umap;
use crate::pic;

/// Линия таймера в legacy-режиме (PIT → IRQ0 → вектор 32).
pub const LEGACY_TIMER_LINE: u32 = 0;

/// GSI линии таймера (заполняется start_periodic_tick; для диагностики
/// и будущего bootinfo-расширения).
pub static TIMER_GSI: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Частота входного генератора PIT (Гц).
const PIT_INPUT_HZ: u32 = 1_193_182;

/// Порт канала 0 PIT и порт команд.
const PIT_CH0_DATA: u16 = 0x40;
const PIT_MODE_CMD: u16 = 0x43;
/// Режим 3 (square wave), двоичный счёт, доступ lo/hi байта.
const PIT_MODE3_LOHI: u8 = 0b0011_0110;

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
