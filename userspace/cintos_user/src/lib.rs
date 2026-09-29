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
//!   - [`flatbuf`] — мини-FlatBuffers-рантайм (сериализация IPC-сообщений:
//!     ЯДРО не разбирает payload — сериализация целиком в юзерспейсе);
//!   - [`ipc`] — Rust-обвязка L4-транспорта (send/wait + map items);
//!   - [`task`] — динамический спавн задач (TASK_CREATE по TaskImage-
//!     капе / TASK_CREATE_FROM_MEM — exec ELF из читаемой памяти);
//!   - [`capi`] — C-совместимый ABI (extern "C" + #[repr(C)]; заголовок
//!     include/cintos.h) — юзерспейс-код NOMAD пригоден для C.
//!
//! Бинарная обвязка сервера обязана определить
//! `#[no_mangle] extern "C" fn main(argc, argv, envp) -> i32` и
//! компоноваться с `crt0::_start` (e_entry образа).
//!
//! Хостовые юнит-тесты (SPSC-кольцо shm и др.) запускаются со std:
//! `#![cfg_attr(not(test), no_std)]` — тот же паттерн, что у kernel_base.
#![cfg_attr(not(test), no_std)]

pub mod abi;
pub mod capi;
pub mod crt0;
pub mod dlog;
pub mod fault;
pub mod fb;
pub mod flatbuf;
pub mod init;
pub mod ipc;
pub mod shm;
pub mod stats;
pub mod syscall;
pub mod task;
pub mod timer;
