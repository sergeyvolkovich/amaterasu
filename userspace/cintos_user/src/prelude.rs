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
pub use crate::handle::{CapId, Pages, Phys, Slot, TaskCap, Va};
pub use crate::{
    abi, arena, cap, crt0, dlog, fault, fb, flatbuf, handle, init, ipc, mem, shm, stats, syscall,
    task, timer,
};
// heap — только на целевом target (GlobalAlloc с сисколлами).
#[cfg(all(not(test), target_os = "none"))]
pub use crate::heap;

// Коллекции alloc-крейта поверх кучи (crate::heap: рост через
// ALLOC_PAGES): бинам достаточно `use cintos_user::prelude::*`.
pub use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

// Макросы лога (macro_export кладёт их в корень крейта).
#[allow(unused_imports)]
pub use crate::{log, logln};
