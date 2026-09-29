//! ipc_sender — отправитель IPC-демо NOMAD (L4-транспорт + FlatBuffers).
//!
//! Сценарий (serial-лог через DBG_LOG_WRITE):
//!   1. Находит ipc_receiver в ростере (argv → слот peer).
//!   2. Посылает PING (label + payload «ping-N», N — счётчик попыток)
//!      С capability-дескриптором: пересылает свой слот 1
//!      (capability неймспейса) в слот 4 получателя (L4 map item).
//!      Send блокируется, пока получатель не войдёт в wait — rendezvous.
//!   3. Ждёт PONG (closed wait на получателя), логирует payload.
//!   4. Self-exit.

#![no_std]
#![no_main]

use cintos_user::crt0;
use cintos_user::ipc::{self, CapDesc};

#[used]
static _FORCE_ENTRY: unsafe extern "C" fn() -> ! = crt0::_start;

#[unsafe(no_mangle)]
pub extern "C" fn main(
    _argc: usize,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    log(b"ipc_sender: start\n");

    let Some(receiver_slot) = peer_slot_of(b"ipc_receiver") else {
        log(b"ipc_sender: ipc_receiver not found in roster\n");
        return 1;
    };

    // 1. PING + пересылка capability: свой слот 1 (неймспейс) → свободный
    //    слот получателя (TRANSFER_SLOT — выше peer-диапазона), право SEND
    //    (сужение: у источника все права).
    //    Payload: "имя:текст" — приёмник отвечает по имени.
    let caps = [CapDesc::new(1, ipc::TRANSFER_SLOT, ipc::rights::SEND)];
    match ipc::send(receiver_slot, LABEL_PING, b"ipc_sender:ping-1", &caps) {
        Ok(()) => log(b"ipc_sender: ping delivered (rendezvous)\n"),
        Err(e) => {
            log_code(b"ipc_sender: send err ", code_of(e));
            return 1;
        }
    }

    // 2. Ждём PONG строго от получателя (closed wait на его слот).
    let mut buf = ipc::recv_buffer();
    match ipc::wait(receiver_slot, ipc::RECV_NONE, &mut buf) {
        Ok(r) => {
            log_code(b"ipc_sender: label=", r.label);
            log_bytes(b"ipc_sender: payload=", r.payload);
        }
        Err(e) => log_code(b"ipc_sender: wait err ", code_of(e)),
    }

    log(b"ipc_sender: done, self-exit\n");
    0 // crt0: SCHED_DESTROY_TASK(self_cap)
}

pub const LABEL_PING: u64 = 0xC1A0_0001;
pub const LABEL_PONG: u64 = 0xC1A0_0002;

/// Слот peer-TaskTCB по имени (ростер в argv: [0]=своё имя, [1+i]=i-й).
/// Имена модулей — ПУТИ (/boot/modules/X): сравниваем базовое имя.
pub fn peer_slot_of(name: &[u8]) -> Option<u64> {
    let argc = crt0::args()?;
    for i in 1..argc {
        let p = crt0::argv_at(i)?;
        let mut len = 0usize;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
        }
        let bytes = unsafe { core::slice::from_raw_parts(p, len) };
        let base = match bytes.iter().rposition(|&b| b == b'/') {
            Some(pos) => &bytes[pos + 1..],
            None => bytes,
        };
        if base == name {
            return Some(ipc::PEER_SLOT_BASE + (i - 1) as u64);
        }
    }
    None
}

// ─── Логирование ────────────────────────────────────────────────────────────

fn code_of(e: cintos_user::syscall::SyscallError) -> u64 {
    match e {
        cintos_user::syscall::SyscallError::Kernel(code) => code,
    }
}

fn log(msg: &[u8]) {
    unsafe {
        cintos_user::syscall::syscall2(
            cintos_user::abi::nr::DBG_LOG_WRITE,
            msg.as_ptr() as u64,
            msg.len() as u64,
        )
    };
}

fn log_code(prefix: &[u8], v: u64) {
    let mut buf = [0u8; 72];
    let plen = prefix.len().min(buf.len() - 20);
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut len = plen;
    let start = len;
    let mut v = v;
    if v == 0 {
        buf[len] = b'0';
        len += 1;
    } else {
        while v > 0 {
            buf[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
        buf[start..len].reverse();
    }
    buf[len] = b'\n';
    len += 1;
    log(&buf[..len]);
}

fn log_bytes(prefix: &[u8], bytes: &[u8]) {
    let mut buf = [0u8; 96];
    let plen = prefix.len().min(buf.len() - 34);
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut len = plen;
    for &b in bytes.iter().take(24) {
        if b.is_ascii_graphic() || b == b' ' {
            buf[len] = b;
            len += 1;
        }
    }
    buf[len] = b'\n';
    len += 1;
    log(&buf[..len]);
}
