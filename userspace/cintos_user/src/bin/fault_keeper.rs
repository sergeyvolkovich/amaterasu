//! fault_keeper — демон фолт-эндпоинтов NOMAD (seL4/KeyKOS-keeper).
//!
//! Сценарий (serial-лог через DBG_LOG_WRITE): создаёт фолт-эндпоинт
//! (слот 17 — выше peer-диапазона и TRANSFER_SLOT), привязывает его к
//! peer-задаче fault_child и засыпает в IPC_WAIT. Сначала приходит
//! handshake-запрос fault_child («готова ли привязка?») — отвечает
//! PONG. Дальше — ДВА фолта fault_child (#UD на ud2): на каждый keeper
//! отвечает FAULT_REPLY с new_rip = ip + 2 (ud2 — 2 байта: пропустить
//! упавшую инструкцию — эмуляция «skip»). Если fault_child выживает
//! после обоих фолтов и корректно завершается — механизм доставки и
//! resume с изменённым контекстом работает (свидетельство в serial).
//!
//! Ростер серверов: argv[0] — своё имя, argv[1+i] — имя i-го сервера
//! (слот peer = 2 + i; см. kernel_exec::spawn).

#![no_std]

use cintos_user::crt0;
use cintos_user::fault::{self, FaultInfo};
use cintos_user::ipc::{self, Received, WAIT_ANY};

/// Слот cspace под фолт-эндпоинт (выше peer-диапазона 2..14 и
/// TRANSFER_SLOT=16 — см. ipc::TRANSFER_SLOT).
const FAULT_EP_SLOT: u64 = 17;

/// Лейблы handshake (FlatBuffers label; не NOMAD_FAULT_LABEL).
const LABEL_ASK_BOUND: u64 = 0xFA17_0001;
const LABEL_BOUND_ACK: u64 = 0xFA17_0002;

/// Число фолтов fault_child, которые обслуживаем.
const FAULT_ROUNDS: usize = 2;

fn main() {
    log(b"fault_keeper: creating fault endpoint (slot 17)\n");
    if let Err(e) = fault::create_endpoint(FAULT_EP_SLOT) {
        log_code(b"fault_keeper: create err ", code_of(e));
        crt0::exit(1);
    }

    // Привязка к fault_child (peer-слот по ростеру argv).
    let Some(child_slot) = peer_slot_of(b"fault_child") else {
        log(b"fault_keeper: fault_child not in roster\n");
        crt0::exit(1);
    };
    match fault::set_endpoint(FAULT_EP_SLOT, child_slot) {
        Ok(()) => log(b"fault_keeper: endpoint bound to fault_child\n"),
        Err(e) => {
            log_code(b"fault_keeper: bind err ", code_of(e));
            crt0::exit(1);
        }
    }

    // Цикл: handshake + фолты. Сообщения различаются label'ом.
    for round in 0..FAULT_ROUNDS + 1 {
        let mut buf = ipc::recv_buffer();
        let received: Received = match ipc::wait(WAIT_ANY, ipc::RECV_NONE, &mut buf) {
            Ok(r) => r,
            Err(e) => {
                log_code(b"fault_keeper: wait err ", code_of(e));
                crt0::exit(1);
            }
        };

        if let Some(f) = fault::parse_fault(&received) {
            handle_fault(round, received.sender, &f);
        } else if received.label == LABEL_ASK_BOUND {
            // Handshake: fault_child спрашивает «привязка готова?».
            log(b"fault_keeper: handshake, ack\n");
            if let Err(e) = ipc::send(child_slot, LABEL_BOUND_ACK, b"bound", &[]) {
                log_code(b"fault_keeper: ack err ", code_of(e));
            }
        } else {
            log_code(b"fault_keeper: unexpected label ", received.label);
        }
    }

    log(b"fault_keeper: done, self-exit\n");
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

/// Обработка фолта: лог + FAULT_REPLY. #UD на ud2 (2 байта) —
/// пропускаем инструкцию: new_rip = ip + 2, стек прежний (new_rsp=0).
fn handle_fault(round: usize, faulting: u64, f: &FaultInfo) {
    log_code(b"fault_keeper: [fault ", round as u64);
    log_code(b"fault_keeper: kind=", f.kind);
    log_hex(b"fault_keeper: faulting cap=", faulting);
    log_hex(b"fault_keeper: ip=", f.ip);
    log_hex(b"fault_keeper: sp=", f.sp);

    // ud2 — 2-байтовая инструкция: возобновить СЛЕДУЮЩЕЙ инструкцией.
    // (new_rsp = 0 — прежний стек; пейджер-семантика для #PF была бы
    // reply(faulting, 0, 0): повторить упавшую инструкцию после
    // починки причины — здесь маппить нечего, пропускаем.)
    match fault::reply(faulting, f.ip + 2, 0) {
        Ok(()) => log(b"fault_keeper: replied (skip ud2)\n"),
        Err(e) => log_code(b"fault_keeper: reply err ", code_of(e)),
    }
}

/// Слот peer-TaskTCB по имени (ростер argv: [0]=своё имя, [1+i]=i-й).
/// Имена модулей — ПУТИ (/boot/modules/X): сравниваем базовое имя.
fn peer_slot_of(name: &[u8]) -> Option<u64> {
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

// ─── Логирование (без fmt/аллокаций; как у ipc_receiver) ────────────────────

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
