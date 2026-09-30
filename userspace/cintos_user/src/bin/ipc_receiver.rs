//! ipc_receiver — приёмник IPC-демо NOMAD (L4-транспорт + FlatBuffers).
//!
//! Сценарий (serial-лог через DBG_LOG_WRITE): принимает ДВА сообщения
//! (от ipc_sender на Rust и от ipc_cdemo на C — доказательство
//! C-совместимости юзерспейса), на каждое отвечает PONG по слоту
//! отправителя. Отправитель представляется в payload: "ИМЯ:текст" —
//! имя ищется в ростере argv (слот peer = 2 + позиция). Сообщения
//! могут нести capability (map items) — ядро кладёт копии в указанные
//! слоты, логируем их. После двух обменов — self-exit.
//!
//! Ростер серверов: argv[0] — своё имя, argv[1+i] — имя i-го сервера
//! (слот peer = 2 + i; см. kernel_exec::spawn).

#![no_std]

use cintos_user::crt0;
use cintos_user::flatbuf::MessageRef;
use cintos_user::ipc::{self, Received, WAIT_ANY};

/// Лейблы сообщений демо (FlatBuffers label).
pub const LABEL_PING: u64 = 0xC1A0_0001;
pub const LABEL_PONG: u64 = 0xC1A0_0002;

/// Число обслуживаемых сообщений (ipc_sender + ipc_cdemo).
const ROUNDS: usize = 2;

fn main() {
    log(b"ipc_receiver: waiting for msg (open wait)\n");

    for round in 1..=ROUNDS {
        let mut buf = ipc::recv_buffer();
        let received: Received = match ipc::wait(WAIT_ANY, ipc::recv_window(ipc::TRANSFER_SLOT, 4), &mut buf) {
            Ok(r) => r,
            Err(e) => {
                log_code(b"ipc_receiver: wait err ", code_of(e));
                crt0::exit(1);
            }
        };

        log_code(b"ipc_receiver: [round ", round as u64);
        log_hex(b"ipc_receiver: sender cap=", received.sender);
        log_code(b"ipc_receiver: label=", received.label);
        log_bytes(b"ipc_receiver: payload=", received.payload);
        for &slot in received.cap_slots.iter().take(received.caps_len) {
            log_code(b"ipc_receiver: capability landed in slot ", slot);
        }

        // Ответ по слоту отправителя: payload либо сырой («имя:текст»),
        // либо FlatBuffers-обёрнутый (C-демо кодирует тело через
        // cint_fb_*): пробуем верифицирующий FB-разбор и берём внутренний
        // payload, затем — имя до ':'.
        let inner = MessageRef::parse(received.payload)
            .map(|m| m.payload())
            .unwrap_or(received.payload);
        let name = sender_name_of(inner);
        if let Some(slot) = name.and_then(peer_slot_of) {
            match ipc::send(slot, LABEL_PONG, b"pong", &[]) {
                Ok(()) => log(b"ipc_receiver: pong sent\n"),
                Err(e) => log_code(b"ipc_receiver: send err ", code_of(e)),
            }
        } else {
            log(b"ipc_receiver: sender name unknown, no reply\n");
        }
    }

    log(b"ipc_receiver: done, self-exit\n");
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

/// Имя отправителя из payload "имя:текст" (до ':').
fn sender_name_of(payload: &[u8]) -> Option<&[u8]> {
    let pos = payload.iter().position(|&b| b == b':')?;
    Some(&payload[..pos])
}

/// Слот peer-TaskTCB по имени (ростер в argv: [0]=своё имя, [1+i]=i-й).
/// Имена модулей — ПУТИ (/boot/modules/X): сравниваем базовое имя.
pub fn peer_slot_of(name: &[u8]) -> Option<u64> {
    let argc = crt0::args()?;
    for i in 1..argc {
        let p = crt0::argv_at(i)?;
        // NUL-строка → срез
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

// ─── Логирование (без fmt/аллокаций) ────────────────────────────────────────

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
    let started_len = len;
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
        buf[started_len..len].reverse();
    }
    buf[len] = b'\n';
    len += 1;
    log(&buf[..len]);
}

/// HEX-код (для label/адресов).
fn log_hex(prefix: &[u8], v: u64) {
    let mut buf = [0u8; 72];
    let plen = prefix.len().min(buf.len() - 20);
    buf[..plen].copy_from_slice(&prefix[..plen]);
    let mut len = plen;
    buf[len] = b'0';
    buf[len + 1] = b'x';
    len += 2;
    for shift in (0..16).rev() {
        let nib = ((v >> (shift * 4)) & 0xF) as usize;
        buf[len] = b"0123456789ABCDEF"[nib];
        len += 1;
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
