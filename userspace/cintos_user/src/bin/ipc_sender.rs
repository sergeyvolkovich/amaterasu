//! ipc_sender — отправитель IPC-демо NOMAD (L4-транспорт).
//!
//! Сценарий (serial-лог через DBG_LOG_WRITE):
//!   1. Находит ipc_receiver в ростере (argv → слот peer).
//!   2. Посылает PING С capability-дескриптором: пересылает свой слот 1
//!      (capability неймспейса) получателю (L4 map item). Send
//!      блокируется, пока получатель не войдёт в wait — rendezvous.
//!   3. Ждёт PONG (closed wait на получателя) С ОКНОМ ПРИЁМА: в PONG
//!      приходит Send-копия IPC-гейта сервера (map item от reply).
//!   4. Гейт-фаза: атомарный IPC_CALL через гейт (GATE_REQ) — клиент
//!      не использует TaskTCB-капу сервера вообще; ответ (GATE_RESP)
//!      приходит в тот же буфер (двунаправленный call).
//!   5. Self-exit.

#![no_std]

use cintos_user::cap::Rights;
use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::handle::Slot;
use cintos_user::ipc::{self, CapDesc};
use cintos_user::task;

fn main() {
    dlog::log("ipc_sender: start\n");

    let Some(receiver_slot) = task::peer_slot_of("ipc_receiver") else {
        dlog::log("ipc_sender: ipc_receiver not found in roster\n");
        crt0::exit(1);
    };

    // 1. PING + пересылка capability: свой слот 1 (неймспейс) → свободный
    //    слот получателя (TRANSFER_SLOT — выше peer-диапазона), право SEND
    //    (сужение: у источника все права).
    //    Payload: "имя:текст" — приёмник отвечает по имени.
    let caps = [CapDesc::new(Slot::new(1), ipc::TRANSFER_SLOT, Rights::SEND)];
    match ipc::send(receiver_slot, LABEL_PING, b"ipc_sender:ping-1", &caps) {
        Ok(()) => dlog::log("ipc_sender: ping delivered (rendezvous)\n"),
        Err(e) => {
            log_code("ipc_sender: send err ", code_of(e));
            crt0::exit(1);
        }
    }

    // 2. Ждём PONG строго от получателя (closed wait) С ОКНОМ ПРИЁМА:
    //    в PONG приходит Send-копия IPC-гейта сервера.
    let mut buf = ipc::recv_buffer();
    let gate_slot = match ipc::wait(
        ipc::WaitFrom::Slot(receiver_slot),
        ipc::recv_window(ipc::TRANSFER_SLOT, 4),
        &mut buf,
    ) {
        Ok(r) => {
            log_code("ipc_sender: label=", r.label);
            log_bytes("ipc_sender: payload=", r.payload);
            if r.caps_len == 0 {
                dlog::log("ipc_sender: no gate cap in pong\n");
                return;
            }
            r.cap_slots[0]
        }
        Err(e) => {
            log_code("ipc_sender: wait err ", code_of(e));
            return;
        }
    };
    log_code("ipc_sender: gate cap in slot ", gate_slot.raw());

    // 3. Гейт-фаза: атомарный IPC_CALL через гейт — TaskTCB-капа сервера
    //    не нужна вообще. Ответ приходит В ТОТ ЖЕ буфер (seL4-стиль).
    match ipc::call(
        gate_slot,
        LABEL_GATE_REQ,
        b"gate-ping",
        &[],
        ipc::RECV_NONE,
        0,
        &mut buf,
    ) {
        Ok(r) => {
            log_code("ipc_sender: [gate] label=", r.label);
            log_bytes("ipc_sender: [gate] payload=", r.payload);
        }
        Err(e) => log_code("ipc_sender: gate call err ", code_of(e)),
    }

    dlog::log("ipc_sender: done, self-exit\n");
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

pub const LABEL_PING: u64 = 0xC1A0_0001;
pub const LABEL_PONG: u64 = 0xC1A0_0002;
/// Гейт-фаза: запрос через IPC_CALL и ответ сервера.
pub const LABEL_GATE_REQ: u64 = 0xC1A0_0003;
pub const LABEL_GATE_RESP: u64 = 0xC1A0_0004;

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
