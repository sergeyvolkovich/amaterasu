//! ipc_receiver — приёмник IPC-демо NOMAD (L4-транспорт).
//!
//! Сценарий (serial-лог через DBG_LOG_WRITE):
//!   1. Принимает ДВА сообщения (от ipc_sender на Rust и от ipc_cdemo
//!      на C — доказательство C-совместимости юзерспейса); на каждое
//!      отвечает PONG через IPC_REPLY (неявный reply-адресат ядра —
//!      TaskTCB-капа отправителя НЕ нужна).
//!   2. Перед PONG'ом ipc_sender'у создаёт IPC-гейт (seL4-эндпоинт) и
//!      передаёт его Send-копию map item'ом в ответе.
//!   3. После двух обменов ждёт НА ГЕЙТЕ (право Recv): клиент шлёт
//!      GATE_REQ атомарным IPC_CALL (запрос ставится в очередь гейта,
//!      если сервер ещё не ждёт), сервер отвечает GATE_RESP через
//!      IPC_REPLY. Отправитель представляется в payload: "ИМЯ:текст".
//!
//! Ростер серверов: argv[0] — своё имя, argv[1+i] — имя i-го сервера
//! (слот peer = 2 + i; см. kernel_exec::spawn).

#![no_std]

use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::ipc::{self, Received};

/// Лейблы сообщений демо (теги тела).
pub const LABEL_PING: u64 = 0xC1A0_0001;
pub const LABEL_PONG: u64 = 0xC1A0_0002;
/// Гейт-фаза: запрос клиента (через IPC_CALL) и ответ сервера.
pub const LABEL_GATE_REQ: u64 = 0xC1A0_0003;
pub const LABEL_GATE_RESP: u64 = 0xC1A0_0004;

/// Число обслуживаемых сообщений (ipc_sender + ipc_cdemo).
const ROUNDS: usize = 2;
/// Слот гейта в cspace этого сервера (выше peer-диапазона и окна 16..20).
const GATE_SLOT: u64 = 20;

fn main() {
    dlog::log("ipc_receiver: waiting for msg (open wait)\n");

    // Гейт создаётся заранее: Send-копия уйдёт ipc_sender'у map item'ом
    // в первом PONG (в окно приёма его wait'а).
    let gate_id = match ipc::create_gate(cintos_user::handle::Slot::new(GATE_SLOT)) {
        Ok(id) => id,
        Err(e) => {
            log_code("ipc_receiver: create_gate err ", code_of(e));
            crt0::exit(1);
        }
    };
    log_hex("ipc_receiver: gate cap id=", gate_id);

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

        // Ответ через IPC_REPLY: неявный адресат (последний отправитель)
        // хранится в TCB сервера — TaskTCB-капа отправителя не нужна.
        // ipc_sender'у дополнительно уходит Send-копия гейта (map item):
        // C-демо ждёт с окном 0 — ему гейт не передаём.
        let name = sender_name_of(received.payload).and_then(|b| core::str::from_utf8(b).ok());
        let caps_for_sender: [ipc::CapDesc; 1] = [ipc::CapDesc::new(
            cintos_user::handle::Slot::new(GATE_SLOT),
            cintos_user::handle::Slot::new(0), // dst игнорируется ядром
            cintos_user::cap::Rights::SEND,
        )];
        let caps: &[ipc::CapDesc] = if name == Some("ipc_sender") {
            &caps_for_sender
        } else {
            &[]
        };
        match ipc::reply(LABEL_PONG, b"pong", caps) {
            Ok(()) => dlog::log("ipc_receiver: pong sent (ipc_reply)\n"),
            Err(e) => log_code("ipc_receiver: reply err ", code_of(e)),
        }
    }

    // ── Гейт-фаза: ожидание НА ГЕЙТЕ (право Recv) ──
    dlog::log("ipc_receiver: waiting on gate\n");
    let mut buf = ipc::recv_buffer();
    match ipc::wait(
        ipc::WaitFrom::Slot(cintos_user::handle::Slot::new(GATE_SLOT)),
        ipc::RECV_NONE,
        &mut buf,
    ) {
        Ok(r) => {
            log_hex("ipc_receiver: [gate] sender=", r.sender.raw());
            log_code("ipc_receiver: [gate] label=", r.label);
            log_bytes("ipc_receiver: [gate] payload=", r.payload);
        }
        Err(e) => {
            log_code("ipc_receiver: gate wait err ", code_of(e));
            crt0::exit(1);
        }
    }
    // Ответ клиенту через IPC_REPLY (reply_to = автор GATE_REQ).
    match ipc::reply(LABEL_GATE_RESP, b"gate-pong", &[]) {
        Ok(()) => dlog::log("ipc_receiver: gate-pong sent\n"),
        Err(e) => log_code("ipc_receiver: gate reply err ", code_of(e)),
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
