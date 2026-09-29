//! Системный тик: PIT (Intel 8253/8254, канал 0) на линии IRQ0.
//!
//! РАСПРЕДЕЛЕНИЕ ОТВЕТСТВЕННОСТИ (L4-философия «таймер — юзерспейсный
//! сервис», ядро — только транспорт и учёт):
//!   - АРХ-БЕКЕНД (этот модуль): программирует PIT/PIC, держит хук
//!     линии 0. Сам НЕ ведёт время как сервис.
//!   - ЯДРО (kernel_base::task::stats): на каждый тик учитывает квант
//!     текущей задаче (cpu_ticks) и глобальный uptime — это единственное,
//!     что ядру нужно от времени (статистика/учёт).
//!   - ЮЗЕРСПЕЙС: таймер-сервер спит на WaitIrq(линия 0), ведёт uptime,
//!     раздаёт тайм-ауты/сны через IPC — сервисная политика вне ядра.
//!     (Пропущенные сервером тики не теряются для отчётности: глобальный
//!     счётчик тиков читается сисколлом TASK_STATS.)
//!
//! EOI шлёт диспетчер (irq::irq_vector_dispatch) ПОСЛЕ хука — по
//! стандартному контракту «подтверждать после обработки».

use kernel_base::kernel_log;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::task::stats;

use crate::paging::X86Umap;
use crate::pic;

/// Линия таймера (PIT → IRQ0 → вектор 32).
pub const TIMER_LINE: u32 = 0;

/// Частота входного генератора PIT (Гц).
const PIT_INPUT_HZ: u32 = 1_193_182;

/// Порт канала 0 PIT и порт команд.
const PIT_CH0_DATA: u16 = 0x40;
const PIT_MODE_CMD: u16 = 0x43;
/// Режим 3 (square wave), двоичный счёт, доступ lo/hi байта.
const PIT_MODE3_LOHI: u8 = 0b0011_0110;

/// Запускает периодический тик: ремап+маска PIC, программирование PIT
/// канала 0, регистрация хука линии 0 (учёт статистики + пробуждение
/// ждущих юзерспейс-задач), размаскировка IRQ0.
///
/// Прерывания НЕ включает: STI делает фронтенд (boot) после полной
/// инициализации — старт источника и его «слышимость» разделены.
///
/// Частота объявляется статистике (юзерспейс переводит тики в секунды
/// по снапшоту TASK_STATS — архитектурная деталь не утекает в API).
pub fn start_periodic_tick(hz: u32) {
    let divisor = (PIT_INPUT_HZ / hz.max(1)).clamp(2, 0xFFFF) as u16;

    // 1. PIC: ремап на векторы 32..47 + маска всего (размаскируем только
    //    линию таймера — чужие устройства молчат до своего владельца).
    pic::remap_and_mask_all();

    // 2. PIT: канал 0, режим 3, делитель.
    let mut mode = x86_64::instructions::port::PortWriteOnly::new(PIT_MODE_CMD);
    let mut ch0 = x86_64::instructions::port::PortWriteOnly::new(PIT_CH0_DATA);
    unsafe {
        mode.write(PIT_MODE3_LOHI);
        ch0.write((divisor & 0xFF) as u8);
        ch0.write((divisor >> 8) as u8);
    }

    // 3. Хук линии таймера: учёт (kernel_base, нейтрально) + доставка
    //    ждущим юзерспейс-задачам (on_irq_fired будит WaitIrq-спящих).
    crate::irq::register_irq_line_handler(TIMER_LINE, timer_tick_hook)
        .expect("таймер: линия 0 свободна (первая регистрация)");

    // 4. Размаскировка линии и объявление частоты статистике.
    pic::unmask(TIMER_LINE as u8);
    stats::set_tick_hz(hz as u64);

    kernel_log!("timer: PIT запущен, {} Гц (делитель {})\n", hz, divisor);
}

/// Хук тика (вызывается из IDT-диспетчера с погашенными прерываниями):
///   1) квант текущей задаче + глобальный uptime (ядро);
///   2) пробуждение юзерспейс-ожидающих линии (транспорт).
///
/// EOI отправит irq_vector_dispatch ПОСЛЕ возврата хука.
fn timer_tick_hook(line: u32, lctl: &mut LocalKernelCTL<X86Umap>) {
    stats::on_tick(lctl);
    kernel_base::task::irq_wait::on_irq_fired(lctl, line);
}
