//! mt_test — задача-испытатель кооперативной многозадачности NOMAD.
//!
//! Сценарий (виден в serial-логе через DBG_LOG_WRITE):
//!   1. Три тика с SCHED_YIELD — доказательство карусели: между тиками
//!      исполняются другие задачи (init, mt_waker).
//!   2. SCHED_BLOCK_ON_OBJECT(0xAA) — усыпление. Пока задача спит,
//!      остальные продолжают исполняться (логи mt_waker идут).
//!   3. Пробуждение от mt_waker (SCHED_RELEASE_OBJECT): задача обязана
//!      продолжить С МЕСТА блокировки — счётчик тиков идёт 4, 5, 6.
//!      Перезапуск с точки входа выдал бы тик 1 снова — это и есть
//!      главный проверяемый инвариант (слот возобновления в TCB).
//!   4. Возврат из main — self-exit (SCHED_DESTROY_TASK): остальные
//!      задачи обязаны продолжать жить.
//!
//! Строки собираются вручную (без core::fmt) — только целочисленные
//! операции, никакого SSE-состояния между сисколлами.

#![no_std]
#![no_main]

use cintos_user::abi;
use cintos_user::crt0;
use cintos_user::syscall;

/// Явная ссылка на точку входа: линкер тянет crt0::_start из rlib.
#[used]
static _FORCE_ENTRY: unsafe extern "C" fn() -> ! = crt0::_start;

/// Объект ожидания (договорённость с mt_waker).
const WAKE_OBJECT: u64 = 0xAA;

#[unsafe(no_mangle)]
pub extern "C" fn main(
    _argc: usize,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    // Фаза 1: карусель — тик и уступка кванта.
    for i in 1..=3u64 {
        log_line(b"mt_test: tick ", i);
        let _ = unsafe { syscall::syscall0(abi::nr::SCHED_YIELD) };
    }

    // Фаза 2: усыпление на объекте — управление уходит другим задачам.
    log_line(b"mt_test: sleep on 0xAA", 0);
    let _ = unsafe { syscall::syscall1(abi::nr::SCHED_BLOCK_ON_OBJECT, WAKE_OBJECT) };

    // Фаза 3: здесь мы оказываемся только после пробуждения от mt_waker.
    // Счётчик 4..=6 доказывает возобновление контекста (не рестарт):
    // локальные переменные и позиция исполнения сохранены.
    for i in 4..=6u64 {
        log_line(b"mt_test: woke up, tick ", i);
        let _ = unsafe { syscall::syscall0(abi::nr::SCHED_YIELD) };
    }

    // Фаза 4: self-exit — задача умирает, система живёт.
    log_line(b"mt_test: done, self-exit", 0);
    0 // crt0: SCHED_DESTROY_TASK(self_cap)
}

/// Строка-префикс + десятичное число + перевод строки -> DBG_LOG_WRITE.
fn log_line(prefix: &[u8], n: u64) {
    let mut buf = [0u8; 64];
    // Длина префикса с запасом под число (максимум 20 цифр u64) и '\n'.
    let plen = prefix.len().min(buf.len() - 24);
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut len = plen;
    // Десятичная запись задом наперёд, затем разворот.
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
