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
use cintos_user::dlog::{self, Line};
use cintos_user::flatbuf::MessageRef;
use cintos_user::ipc::{self, Received};
use cintos_user::task;

/// Лейблы сообщений демо (FlatBuffers label).
pub const LABEL_PING: u64 = 0xC1A0_0001;
pub const LABEL_PONG: u64 = 0xC1A0_0002;

/// Число обслуживаемых сообщений (ipc_sender + ipc_cdemo).
const ROUNDS: usize = 2;

fn main() {
    dlog::log("ipc_receiver: waiting for msg (open wait)\n");

    for round in 1..=ROUNDS {
        let mut buf = ipc::recv_buffer();
        let received: Received =
            match ipc::wait(ipc::WaitFrom::Any, ipc::recv_window(ipc::TRANSFER_SLOT, 4), &mut buf)
            {
            Ok(r) => r,
            Err(e) => {
                log_code("ipc_receiver: wait err ", code_of(e));
                crt0::exit(1);
            }
        };

        log_code("ipc_receiver: [round ", round as u64);
        log_hex("ipc_receiver: sender cap=", received.sender.raw());
        log_code("ipc_receiver: label=", received.label);
        log_bytes("ipc_receiver: payload=", received.payload);
        for &slot in received.cap_slots.iter().take(received.caps_len) {
            log_code("ipc_receiver: capability landed in slot ", slot.raw());
        }

        // Ответ по слоту отправителя: payload либо сырой («имя:текст»),
        // либо FlatBuffers-обёрнутый (C-демо кодирует тело через
        // nomad_fb_*): пробуем верифицирующий FB-разбор и берём внутренний
        // payload, затем — имя до ':'.
        let inner = MessageRef::parse(received.payload)
            .map(|m| m.payload())
            .unwrap_or(received.payload);
        let name = sender_name_of(inner).and_then(|b| core::str::from_utf8(b).ok());
        if let Some(slot) = name.and_then(task::peer_slot_of) {
            match ipc::send(slot, LABEL_PONG, b"pong", &[]) {
                Ok(()) => dlog::log("ipc_receiver: pong sent\n"),
                Err(e) => log_code("ipc_receiver: send err ", code_of(e)),
            }
        } else {
            dlog::log("ipc_receiver: sender name unknown, no reply\n");
        }
    }

    dlog::log("ipc_receiver: done, self-exit\n");
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

/// Имя отправителя из payload "имя:текст" (до ':').
fn sender_name_of(payload: &[u8]) -> Option<&[u8]> {
    let pos = payload.iter().position(|&b| b == b':')?;
    Some(&payload[..pos])
}

// ─── Логирование (поверх dlog::Line — без fmt/аллокаций) ────────────────────

fn code_of(e: cintos_user::syscall::SyscallError) -> u64 {
    match e {
        cintos_user::syscall::SyscallError::Kernel(code) => code,
    }
}

/// «prefix + десятичное + \n».
fn log_code(prefix: &str, v: u64) {
    let mut l = Line::new();
    l.str(prefix);
    l.u64(v);
    l.nl();
    dlog::log(l.as_str());
}

/// «prefix + 0x… + \n» (label/адреса).
fn log_hex(prefix: &str, v: u64) {
    let mut l = Line::new();
    l.str(prefix);
    l.hex(v);
    l.nl();
    dlog::log(l.as_str());
}

/// «prefix + печатные байты payload'а (до 24) + \n». Байты могут быть
/// не-UTF8 — выпуск через dlog::log_bytes (as_str тут не корректен).
fn log_bytes(prefix: &str, bytes: &[u8]) {
    let mut l = Line::new();
    l.str(prefix);
    for &b in bytes.iter().take(24) {
        if b.is_ascii_graphic() || b == b' ' {
            l.ch(b);
        }
    }
    l.nl();
    dlog::log_bytes(l.as_bytes());
}
