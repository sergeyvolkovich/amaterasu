//! mt_waker — вторая задача испытателя многозадачности: будит mt_test.
//!
//! Сценарий:
//!   1. Несколько квантов SCHED_YIELD с пометкой спина — в логе видно
//!      чередование с тиками mt_test (пока тот не уснул).
//!   2. После восьмого спина — SCHED_RELEASE_OBJECT(0xAA): пробуждение
//!      спящей mt_test (она продолжит с тика 4 — возобновление кадра).
//!   3. Пара квантов после пробуждения (mt_test успевает доработать
//!      и self-exit-нуть) и собственный self-exit.
//!
//! Если бы блокировка не работала (v1: SYSRET в «уснувшую» задачу),
//! mt_test выдал бы все тики подряд без паузы на mt_waker.

#![no_std]

use cintos_user::abi;
use cintos_user::syscall;

/// Объект ожидания (договорённость с mt_test).
const WAKE_OBJECT: u64 = 0xAA;

fn main() {
    for i in 1..=8u64 {
        log_line(b"mt_waker: spin ", i);
        let _ = unsafe { syscall::syscall0(abi::nr::SCHED_YIELD) };
    }

    // mt_test к этому моменту гарантированно спит (уснул после тика 3,
    // карусель: каждый тик mt_test чередуется со спином mt_waker).
    log_line(b"mt_waker: release 0xAA", 0);
    let _ = unsafe { syscall::syscall1(abi::nr::SCHED_RELEASE_OBJECT, WAKE_OBJECT) };
    log_line(b"mt_waker: released", 0);

    // Пара квантов: mt_test просыпается, дорабатывает и умирает.
    for _ in 0..2 {
        let _ = unsafe { syscall::syscall0(abi::nr::SCHED_YIELD) };
    }

    log_line(b"mt_waker: done, self-exit", 0);
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

/// Строка-префикс + десятичное число + перевод строки -> DBG_LOG_WRITE.
fn log_line(prefix: &[u8], n: u64) {
    let mut buf = [0u8; 64];
    // Длина префикса с запасом под число (максимум 20 цифр u64) и '\n'.
    let plen = prefix.len().min(buf.len() - 24);
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut len = plen;
    if n > 0 {
        let start = len;
        let mut v = n;
        while v > 0 {
            buf[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
        buf[start..len].reverse();
    }
    buf[len] = b'\n';
    len += 1;
    let _ = unsafe { syscall::syscall2(abi::nr::DBG_LOG_WRITE, buf.as_ptr() as u64, len as u64) };
}
