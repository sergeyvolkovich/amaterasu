//! timer_server — юзерспейсный таймер-сервис NOMAD (L4-модель).
//!
//! Ядро доставляет тик PIT линией IRQ0 (WaitIrq) БЕЗ интерпретации:
//! кто ведёт время и что с ним делать — решает ЭТОТ сервер. Сценарий
//! демо (serial через DBG_LOG_WRITE):
//!   1. Спит на линии 0 (WaitIrq, OneShot) — «тикает».
//!   2. Каждые 50 тиков (0.5 с) читает СВОЮ статистику сисколлом
//!      TASK_STATS (перенос статистики в юзерспейс) и логирует
//!      сводку: локальные тики vs глобальный uptime ядра (разница —
//!      тики, пропущенные одноразовым WaitIrq), cpu_ticks, yields,
//!      ipc, blocks.
//!   3. Не завершается: живёт вечно, спит между тиками (не мешает
//!      кооперативной карусели).
//!
//! Здесь же видна философия: uptime/квоты — СЕРВЕР агрегирует и
//! форматирует; ядро лишь отдаёт сырые атомарные счётчики.

#![no_std]
#![no_main]

use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::stats;
use cintos_user::timer;

#[used]
static _FORCE_ENTRY: unsafe extern "C" fn() -> ! = crt0::_start;

/// Логировать статистику раз в столько тиков (0.5 c при 100 Гц).
const REPORT_EVERY: u64 = 50;

#[unsafe(no_mangle)]
pub extern "C" fn main(
    _argc: usize,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    let self_cap = crt0::auxv_get(cintos_user::abi::auxv::AT_CINTOS_SELF_CAP).unwrap_or(u64::MAX);

    // Линия тика — от ядра (TASK_STATS: слово [10]); на IO-APIC-платформе
    // это GSI из MADT override (обычно 2), не «IRQ0».
    let mut sbuf = stats::stats_buf();
    let timer_line = stats::task_stats(self_cap, &mut sbuf)
        .map(|s| s.timer_line)
        .unwrap_or(timer::FALLBACK_TIMER_LINE);
    match timer::claim_tick_line(self_cap, timer_line) {
        Ok(()) => {
            let mut l = Line::new();
            l.str("timer_server: линия тика занята капой (GSI ".as_bytes());
            l.u64(timer_line);
            l.str("), 100 Гц\n".as_bytes());
            dlog::log(l.as_bytes());
        }
        Err(e) => {
            let mut l = Line::new();
            l.str("timer_server: claim линии тика err ".as_bytes());
            l.u64(code_of(e));
            l.nl();
            dlog::log(l.as_bytes());
            // Без капы WAIT вернёт отказ — но сервер продолжит цикл
            // (yield), чтобы не зависнуть наглухо в диагностике.
        }
    }

    let mut wait = timer::tick_wait_buf();
    let caps = timer::tick_caps_buf();
    let mut ticks: u64 = 0;

    loop {
        match timer::wait_tick(&mut wait, &caps) {
            Ok(_line) => {
                ticks += 1;
                if ticks.is_multiple_of(REPORT_EVERY) {
                    match stats::task_stats(self_cap, &mut sbuf) {
                        Ok(s) => log_report(ticks, &s),
                        Err(_) => dlog::log(b"timer_server: TASK_STATS err\n"),
                    }
                }
            }
            Err(e) => {
                let mut l = Line::new();
                l.str(b"timer_server: WaitIrq err ");
                l.u64(code_of(e));
                l.nl();
                dlog::log(l.as_bytes());
                // Ошибка сняла ожидание — отдаём квант и ждём снова
                // (иначе рискуем busy-loop на повторяющемся отказе).
                unsafe {
                    cintos_user::syscall::syscall0(cintos_user::abi::nr::SCHED_YIELD)
                };
            }
        }
    }
}

/// Сводка: локальные тики, uptime (с ядра), пропущенные тики, счётчики.
fn log_report(local: u64, s: &stats::TaskStats) {
    let mut l = Line::new();
    l.str("timer_server: тик ".as_bytes());
    l.u64(local);
    l.str(b", uptime ");
    l.u64(timer::ticks_to_ms(s.global_ticks) / 1000);
    l.ch(b'.');
    l.u64((timer::ticks_to_ms(s.global_ticks) % 1000) / 100);
    l.str(" с (глоб. ".as_bytes());
    l.u64(s.global_ticks);
    l.str(" тиков, пропущено ".as_bytes());
    l.u64(s.global_ticks.saturating_sub(local));
    l.str(b"); cpu=");
    l.u64(s.cpu_ticks);
    l.str(b" yields=");
    l.u64(s.yields);
    l.str(b" ipc=");
    l.u64(s.ipc_sent + s.ipc_recv);
    l.str(b" blocks=");
    l.u64(s.blocks);
    l.nl();
    dlog::log(l.as_bytes());
}

fn code_of(e: cintos_user::syscall::SyscallError) -> u64 {
    match e {
        cintos_user::syscall::SyscallError::Kernel(code) => code,
    }
}
