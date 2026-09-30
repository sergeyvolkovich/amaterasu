//! init — первый userspace-процесс NOMAD.
//!
//! Бинарная обвязка cintos-user: точка входа — `crt0::_start` (e_entry
//! образа), main вызывается им после разбора стартового стека. Логика:
//! читать дельту лога ядра (DBG_LOG_READ) и рисовать её во фреймбуфер.
//! Без FB (headless) — просто живём и отдаём кванты (SCHED_YIELD):
//! ядро дублирует лог на serial, система наблюдаема и так.
//!
//! Сборка: x86_64-unknown-none, статический ET_EXEC по базе 0x400000
//! (init.ld), после линковки постпроцессор ставит EI_OSABI = 0xC1
//! (маркер NOMAD; ядро отклоняет чужие ELF — см. kernel_exec::elf).

#![no_std]

use cintos_user::abi::nr;
use cintos_user::fb::FbInfo;
use cintos_user::init::{feed_console, fb_info_from_aux, make_console, read_log_delta};
use cintos_user::syscall;

/// main системного сервера (зовётся crt0 через start lang item;
/// argc/argv при необходимости — crt0::args()/argv_at()).
fn main() {
    match fb_info_from_aux() {
        Some(info) => console_loop(&info),
        None => headless_loop(),
    }
}

/// Основной цикл: дельта лога -> консоль на FB -> yield.
/// Перерисовка только при появлении новых байтов (FB-запись дорогая).
fn console_loop(info: &FbInfo) -> ! {
    let mut con = make_console(info);
    // FB как плоский буфер пикселей (32bpp ожидается; pitch в байтах).
    let pixels = (info.pitch / 4) * info.height as usize;
    // SAFETY: ядро замапило образ MMIO по фиксированному VA и передало
    // параметры через auxv; диапазон [addr, addr + pitch*height) — вся
    // видеопамять.
    let buf = unsafe {
        core::slice::from_raw_parts_mut(info.addr as *mut u32, pixels)
    };
    // Первая отрисовка: заголовок + весь лог, который ядро успело
    // написать до старта init. ВАЖНО: дельту первой выдачи нельзя
    // выбрасывать (раньше буфер читался и отбрасывался — заголовок и
    // бут-лог не рисовались НИ РАЗУ, и при молчащем после бута ядре
    // экран оставался чёрным вечно; redraw звался только на новые
    // строки, которых нет).
    con.push_line("NOMAD init: консоль лога ядра");
    let mut pending = [0u8; 2048];
    let (base, n0) = read_log_delta(0, &mut pending);
    if n0 > 0 {
        feed_console(&mut con, &pending[..n0]);
    }
    let mut since = base;
    con.redraw(buf, info);
    loop {
        let (new_since, n) = read_log_delta(since, &mut pending);
        if n > 0 {
            since = new_since;
            feed_console(&mut con, &pending[..n]);
            con.redraw(buf, info);
        } else {
            // Нечего рисовать — отдаём квант (кооперативная модель
            // ядра; с таймер-IRQ цикл не изменится — только пробуждение).
            unsafe { syscall::syscall0(nr::SCHED_YIELD) };
        }
    }
}

/// Headless-режим: FB нет (QEMU -nographic без видеоряда или ошибка
/// маппинга) — лог ядра всё равно виден на serial.
fn headless_loop() -> ! {
    let mut buf = [0u8; 1024];
    let mut since = 0u64;
    loop {
        let (new_since, _n) = read_log_delta(since, &mut buf);
        since = new_since;
        unsafe { syscall::syscall0(nr::SCHED_YIELD) };
    }
}

// Паник-хендлер — единственный в графе: crt0 (аварийный self-exit).
