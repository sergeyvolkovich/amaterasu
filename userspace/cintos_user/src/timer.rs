//! timer — юзерспейсный таймер-сервис NOMAD (L4-модель).
//!
//! Ядро доставляет тик аппаратного таймера (PIT, линия IRQ0 = линия 0
//! WaitIrq) БЕЗ интерпретации: кто и как ведёт время — решает
//! юзерспейс. Эта библиотека — минимальный клиентский слой таймер-сервера:
//! сон до тика и перевод тиков в миллисекунды.
//!
//! Пропущенные тики: WaitIrq одноразовый (OneShot); пока сервер
//! обрабатывал предыдущий тик, новый мог прийти «в пустоту». Для
//! точного uptime сверяйтесь с глобальным счётчиком ядра —
//! [`crate::stats`] (TASK_STATS отдаёт global_ticks + tick_hz).

use crate::abi;
use crate::syscall::{self, SyscallResult};

/// Линия WaitIrq, на которой ядро x86_64 доставляет тик PIT (IRQ0).
pub const TIMER_IRQ_LINE: u32 = 0;

/// Частота тика, на которой бут запускает PIT (см. kernel_limine).
pub const TICK_HZ: u64 = 100;

/// Массив приёма WaitIrq: `[count: u64][line0: u64]` (ёмкость 1).
pub type TickWaitBuf = [u64; 2];

/// Свежий буфер ожидания тика.
pub const fn tick_wait_buf() -> TickWaitBuf {
    [0; 2]
}

/// Уснуть до ближайшего тика таймера. Возврат — номер сработавшей
/// линии (для маски из одной линии — всегда TIMER_IRQ_LINE).
pub fn wait_tick(buf: &mut TickWaitBuf) -> SyscallResult<u64> {
    let code = unsafe {
        syscall::syscall3(
            abi::nr::IRQ_WAIT,
            1u64 << TIMER_IRQ_LINE,
            buf.as_mut_ptr() as u64,
            1,
        )
    };
    syscall::check(code)?;
    Ok(buf[1])
}

/// Тики в миллисекундах (округление вниз; частота — TICK_HZ бута).
pub const fn ticks_to_ms(ticks: u64) -> u64 {
    ticks * 1000 / TICK_HZ
}
