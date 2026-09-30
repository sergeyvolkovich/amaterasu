//! prelude — рекомендуемый glob-импорт для серверов NOMAD:
//!
//! ```
//! use cintos_user::prelude::*;
//! ```
//!
//! Тянет модули ABI/транспорта ([`abi`], [`syscall`], [`ipc`], [`shm`],
//! [`timer`], ...), crt0-аксессоры ([`args`], [`argv_at`], [`envp`],
//! [`auxv_get`], [`bootstrap`], [`exit`]) и макросы лога (`log!`,
//! `logln!` — отдельное пространство имён, с функцией dlog::log не
//! конфликтуют).

pub use crate::abi::nr;
pub use crate::crt0::{args, argv_at, auxv_get, bootstrap, envp, exit, stack_base};
pub use crate::{abi, crt0, dlog, fault, fb, flatbuf, init, ipc, shm, stats, syscall, task, timer};

// Макросы лога (macro_export кладёт их в корень крейта).
#[allow(unused_imports)]
pub use crate::{log, logln};
