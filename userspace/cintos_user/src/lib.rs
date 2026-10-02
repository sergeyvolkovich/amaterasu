//! cintos-user — userspace-библиотека NOMAD.
//!
//! Слои:
//!   - [`abi`]  — единое ABI-пространство: номера сисколлов, конвенция
//!     регистров, коды ошибок, AUXV-теги;
//!   - [`syscall`] — сырые обёртки SYSCALL-инструкции + Result-конверсия;
//!   - [`crt0`] — точка входа задачи: разбор стартового стека
//!     (argc/argv/envp/auxv), bootstrap-capability системного сервера
//!     (слот 0 = self-TCB, слот 1 = неймспейс, 2+i = peer-TCB), `main`,
//!     self-exit, паник-хендлер;
//!   - [`ipc`] — Rust-обвязка L4-транспорта (send/wait + map items);
//!     тело сообщения — фиксированный заголовок {label, payload_len}
//!     + payload (сериализация — задача протокола поверх, seL4-стиль);
//!   - [`cap`]/[`mem`] — capability-операции (create_*/mint/clone/
//!     revoke/destroy, монтаж регионов) и сырая память задачи;
//!   - [`handle`] — типизированные хендлы поверх u64 (Slot/CapId/
//!     TaskCap/Va/Phys/Pages): перепутать слот с капой — ошибка
//!     компиляции;
//!   - [`task`] — динамический спавн задач (TASK_CREATE по TaskImage-
//!     капе / TASK_CREATE_FROM_MEM — exec ELF из читаемой памяти);
//!   - [`capi`] — C-совместимый ABI (extern "C" + #[repr(C)]; заголовок
//!     include/nomad.h) — юзерспейс-код NOMAD пригоден для C.
//!
//! Бинарник NOMAD — `#![no_std]`-крейт с обычным `fn main()`:
//! `#![no_main]` НЕ нужен — crt0 определяет `start` lang item
//! (rustc сам генерирует C-шиму main → lang_start → fn main()),
//! `_start`, паник-хендлер и self-exit. Удобные импорты — glob из
//! [`prelude`]. C-серверы (staticlib) определяют 2-арговый
//! `main(long argc, char** argv)` — см. include/nomad.h.
//!
//! Хостовые юнит-тесты (SPSC-кольцо shm и др.) запускаются со std:
//! `#![cfg_attr(not(test), no_std)]` — тот же паттерн, что у kernel_base.
#![cfg_attr(not(test), no_std)]
// `start` lang item в crt0 — nightly-only механизм (как у std);
// он internal to compiler — глушим соответствующий варнинг.
#![allow(internal_features)]
#![feature(lang_items)]

// Коллекции alloc-крейта (Vec/String/Box/...) поверх кучи crate::heap
// (GlobalAlloc с ростом через ALLOC_PAGES); re-export'ы — в prelude.
extern crate alloc;

pub mod abi;
pub mod arena;
pub mod cap;
pub mod capi;
pub mod crt0;
pub mod dlog;
pub mod dekker;
pub mod fault;
pub mod fb;
pub mod handle;
// heap: GlobalAlloc с сисколлами — ТОЛЬКО для целевого target (в
// хост-тестах он подменял бы аллокатор std-харнесса).
#[cfg(all(not(test), target_os = "none"))]
pub mod heap;
pub mod init;
pub mod ipc;
pub mod mem;
pub mod prelude;
pub mod shm;
pub mod stats;
pub mod syscall;
pub mod task;
pub mod timer;
