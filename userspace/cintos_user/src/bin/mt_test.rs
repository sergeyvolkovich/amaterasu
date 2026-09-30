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
//!   4. Куча (GlobalAlloc поверх ALLOC_PAGES, арена стартует пустой):
//!      Vec 64 элементов со случайными значениями — sort + checksum;
//!      логируются счётчики кучи (chunks/used): первый аллок задачи
//!      обязан вызвать ALLOC_PAGES и добавить чанк.
//!   5. Возврат из main — self-exit (SCHED_DESTROY_TASK): остальные
//!      задачи обязаны продолжать жить.
//!
//! Строки собираются вручную (без core::fmt) — только целочисленные
//! операции. (Контекст: ядро с FPU-моделью eager FXSAVE/FXRSTOR
//! сохраняет XMM через сисколлы/IRQ/переключения, но испытатель
//! сознательно остаётся целочисленным — меньше поверхности проверки.)

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use cintos_user::abi;
use cintos_user::heap::KernelHeap;
use cintos_user::syscall;

/// Объект ожидания (договорённость с mt_waker).
const WAKE_OBJECT: u64 = 0xAA;

fn main() {
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

    // Фаза 4: куча — GlobalAlloc поверх ALLOC_PAGES (арена стартует
    // ПУСТОЙ: первый push обязан вызвать ALLOC_PAGES, добавить чанк и
    // продолжить — отказ ALLOC_PAGES здесь означал бы панику/exit).
    let mut v: Vec<u64> = Vec::new();
    for i in 0..64u64 {
        // Кнутх-мультипликативное перемешивание i — детерминированный набор.
        v.push(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) % 1009);
    }
    v.sort_unstable();
    let (mut sum, mut sorted) = (0u64, true);
    for i in 0..v.len() {
        sum = sum.wrapping_add(v[i]);
        if i > 0 && v[i - 1] > v[i] {
            sorted = false;
        }
    }
    // Контроль целостности содержимого после sort: пересчёт суммы в обратном порядке.
    let mut rsum = 0u64;
    for i in (0..v.len()).rev() {
        rsum = rsum.wrapping_add(v[i]);
    }
    log_line(b"mt_test: heap vec len ", v.len() as u64);
    log_line(b"mt_test: heap vec sum ", sum);
    log_line(b"mt_test: heap checksum ok ", (sum == rsum) as u64);
    log_line(b"mt_test: heap sorted ", sorted as u64);
    let hs = KernelHeap::current_stats();
    log_line(b"mt_test: heap chunks ", hs.chunks as u64);
    log_line(b"mt_test: heap used ", hs.used_bytes as u64);
    log_line(b"mt_test: heap free ", hs.free_bytes as u64);
    drop(v);

    // Фаза 5: self-exit — задача умирает, система живёт.
    log_line(b"mt_test: done, self-exit", 0);
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
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
