//! timer — юзерспейсный таймер-сервис NOMAD (L4-модель, v2).
//!
//! Ядро доставляет тик аппаратного таймера (PIT → IO-APIC GSI из
//! MADT override, обычно GSI 2) БЕЗ интерпретации: кто и как ведёт
//! время — решает юзерспейс. Эта библиотека — клиентский слой
//! таймер-сервера v2:
//!   1. `claim_tick_line` — занять линию тика капой IrqLine
//!      (CAP_CREATE_IRQ; линия и частота приходят из TASK_STATS —
//!      ядро объявляет их при старте таймера).
//!   2. `wait_tick` — уснуть до тика (IRQ_WAIT v2 по списку кап-слотов).
//!
//! Пропущенные тики: WAIT одноразовый (OneShot); пока сервер
//! обрабатывал предыдущий тик, новый мог прийти «в пустоту». Для
//! точного uptime сверяйтесь с глобальным счётчиком ядра —
//! [`crate::stats`] (TASK_STATS отдаёт global_ticks + tick_hz).

use crate::abi;
use crate::syscall::{self, SyscallResult};

/// Частота тика, на которой бут запускает PIT (см. kernel_limine).
pub const TICK_HZ: u64 = 100;

/// Линия тика по умолчанию на случай, если ядро не объявило (старое
/// ядро/статистика без слова [10]): legacy IRQ0. На IO-APIC-платформе
/// реальная линия — из TASK_STATS (обычно GSI 2).
pub const FALLBACK_TIMER_LINE: u64 = 0;

/// Слот cspace под капу линии тика (у сервера свой cspace; слот 40
/// свободен — ростер кап монтируется с низких номеров).
pub const TICK_CAP_SLOT: u64 = 40;

/// Массив приёма WaitIrq: `[count: u64][line0: u64]` (ёмкость 1).
pub type TickWaitBuf = [u64; 2];

/// Массив кап-слотов для WAIT по одной линии: `[слот]`.
pub type TickCapsBuf = [u64; 1];

/// Свежий буфер ожидания тика.
pub const fn tick_wait_buf() -> TickWaitBuf {
    [0; 2]
}

/// Свежий массив кап-слотов (одна линия — один слот).
pub const fn tick_caps_buf() -> TickCapsBuf {
    [TICK_CAP_SLOT]
}

/// Занять линию тика капой IrqLine (CAP_CREATE_IRQ). `timer_line` —
/// логическая линия из TASK_STATS (`stats.timer_line`). Повторный вызов:
/// если капа уже в слоте — успех без syscall (линия уже наша).
pub fn claim_tick_line(self_cap: u64, timer_line: u64) -> SyscallResult<()> {
    // u32::MAX (пилот не объявлен) — legacy-линия 0.
    let line = if timer_line == u64::from(u32::MAX) {
        FALLBACK_TIMER_LINE
    } else {
        timer_line
    };
    let code = unsafe {
        syscall::syscall4(
            abi::nr::CAP_CREATE_IRQ,
            self_cap,      // owner_task_cap — сам сервер
            TICK_CAP_SLOT, // dst_slot
            line,          // line (GSI)
            0,             // trigger: edge (PIT)
        )
    };
    syscall::check(code)?;
    Ok(())
}

/// Уснуть до ближайшего тика таймера (IRQ_WAIT v2 по капе в
/// TICK_CAP_SLOT). Возврат — номер сработавшей линии.
pub fn wait_tick(buf: &mut TickWaitBuf, caps: &TickCapsBuf) -> SyscallResult<u64> {
    let code = unsafe {
        syscall::syscall4(
            abi::nr::IRQ_WAIT,
            caps.as_ptr() as u64,
            caps.len() as u64,
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
