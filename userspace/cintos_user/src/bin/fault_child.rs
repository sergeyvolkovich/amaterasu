//! fault_child — жертва демо фолт-эндпоинтов (спутник fault_keeper).
//!
//! Сценарий: handshake (убедиться, что fault_keeper привязал эндпоинт —
//! иначе #UD без обработчика остановит МАШИНУ), затем ДВА фолта #UD на
//! явном `ud2`: после каждого keeper возобновляет задачу СЛЕДУЮЩЕЙ
//! инструкцией (new_rip = ip + 2). Выживание после обоих (лог между
//! ud2) доказывает сохранение контекста через фолт-доставку и resume.
//! После второго — self-exit.
//!
//! ud2 выбран как детерминированный 2-байтовый триггер #UD: длина
//! инструкции известна ЗАРАНЕЕ, поэтому keeper может её пропустить.
//! #PF для демо не годится: lazy-маппинга из обработчика пока нет
//! (cross-task map — дорожная карта), повтор инструкции зациклил бы
//! фолт.

#![no_std]

use core::arch::asm;

use cintos_user::crt0;
use cintos_user::ipc::{self, WAIT_ANY};

/// Лейблы handshake (зеркало fault_keeper).
const LABEL_ASK_BOUND: u64 = 0xFA17_0001;
const LABEL_BOUND_ACK: u64 = 0xFA17_0002;

fn main() {
    // Handshake: спросить fault_keeper, готова ли привязка. Без него
    // гонка старта (child фолтнет раньше bind'а) остановила бы машину.
    let Some(keeper_slot) = peer_slot_of(b"fault_keeper") else {
        log(b"fault_child: fault_keeper not in roster\n");
        crt0::exit(1);
    };
    log(b"fault_child: handshake\n");
    if let Err(e) = ipc::send(keeper_slot, LABEL_ASK_BOUND, b"ask", &[]) {
        log_code(b"fault_child: ask err ", code_of(e));
        crt0::exit(1);
    }
    let mut buf = ipc::recv_buffer();
    match ipc::wait(WAIT_ANY, ipc::RECV_NONE, &mut buf) {
        Ok(r) if r.label == LABEL_BOUND_ACK => log(b"fault_child: bound confirmed\n"),
        Ok(r) => {
            log_code(b"fault_child: unexpected label ", r.label);
            crt0::exit(1);
        }
        Err(e) => {
            log_code(b"fault_child: wait err ", code_of(e));
            crt0::exit(1);
        }
    }

    // Фолт #1: ud2 (2 байта). Контекст обязан сохраниться полностью —
    // лог между фолтами проверяет корректность продолжения.
    log(b"fault_child: provoking #UD (1/2)\n");
    unsafe {
        asm!("ud2", options(nomem, nostack, preserves_flags));
    }
    log(b"fault_child: survived #1\n");

    // Фолт #2: ещё раз — resume-механизм обязан работать многократно.
    log(b"fault_child: provoking #UD (2/2)\n");
    unsafe {
        asm!("ud2", options(nomem, nostack, preserves_flags));
    }
    log(b"fault_child: survived #2\n");

    log(b"fault_child: done, self-exit\n");
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

/// Слот peer-TaskTCB по имени (ростер argv: [0]=своё имя, [1+i]=i-й).
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
