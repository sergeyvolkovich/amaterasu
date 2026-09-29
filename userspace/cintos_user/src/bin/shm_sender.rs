//! shm_sender — демо длинных IPC через разделяемую память (владелец).
//!
//! Протокол (ядро — только транспорт коротких «дверей»; данные идут
//! по общим страницам МИМО ядра):
//!   1. ALLOC_PAGES(4) → собственный регион; инициализация SPSC-кольца.
//!   2. CAP_CREATE_SHARED — capability на регион (физику резолвит ядро);
//!      SHM_OFFER получателю: capability map-item'ом + глобальный id в
//!      payload; монтирование получателем — MOUNT_CAP_REGION ПО СЛОТУ
//!      приёмного окна).
//!   3. Ждёт SHM_READY (получатель смонтировал и прочитал кольцо).
//!   4. 16 сообщений по 1 КиБ (суммарно 16 КиБ — кратно больше лимита
//!      транспорта 512 Б): push в кольцо + дверь SHM_DATA; ждёт ACK
//!      (ring никогда не переполняется — ping-pong).
//!   5. Ждёт SHM_DONE с контрольной суммой потребителя, сверяет со
//!      своей, логирует сводку «данные vs. байты через ядро»; self-exit.

#![no_std]
#![no_main]

use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::ipc::{self, CapDesc};
use cintos_user::shm::{self, Producer};

#[used]
static _FORCE_ENTRY: unsafe extern "C" fn() -> ! = crt0::_start;

/// Страниц под разделяемый регион.
const SHM_PAGES: u64 = 4;
/// Сообщений в демо.
const MSG_COUNT: usize = 16;
/// Размер одного сообщения (байт) — больше MAX_MSG транспорта вдвое.
const MSG_LEN: usize = 1024;
/// Слот cspace под capability разделяемого региона (свой и получателя;
/// над peer-диапазоном 2..2+N).
const SLOT_SHM_CAP: u64 = 16;

#[unsafe(no_mangle)]
pub extern "C" fn main(
    _argc: usize,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    dlog::log("shm_sender: старт\n".as_bytes());

    let Some(receiver_slot) = peer_slot_of(b"shm_receiver") else {
        dlog::log("shm_sender: shm_receiver не найден в ростере\n".as_bytes());
        return 1;
    };

    // 1. Собственный регион + кольцо.
    let va = match alloc_pages(SHM_PAGES) {
        Ok(va) => va,
        Err(code) => return fail("shm_sender: ALLOC_PAGES err ", code),
    };
    let mut ring = match unsafe { Producer::init(va as usize, SHM_PAGES as usize) } {
        Some(p) => p,
        None => return fail("shm_sender: кольцо не инициализировано ", 0),
    };

    // 2. Capability на регион + предложение получателю.
    let cap_id = match cap_create_shared(va, SHM_PAGES, SLOT_SHM_CAP) {
        Ok(id) => id,
        Err(code) => return fail("shm_sender: CAP_CREATE_SHARED err ", code),
    };
    let offer = cap_id.to_le_bytes();
    let caps = [CapDesc::new(SLOT_SHM_CAP, SLOT_SHM_CAP, ipc::rights::SEND)];
    let mut kernel_bytes = match ipc::send_cost(
        receiver_slot,
        shm::labels::SHM_OFFER,
        &offer,
        &caps,
    ) {
        Ok(n) => n,
        Err(e) => return fail("shm_sender: SHM_OFFER err ", code_of(e)),
    };

    // 3. Готовность получателя.
    let mut buf = ipc::recv_buffer();
    match ipc::wait(receiver_slot, ipc::RECV_NONE, &mut buf) {
        Ok(r) if r.label == shm::labels::SHM_READY => {
            dlog::log("shm_sender: получатель смонтировал регион\n".as_bytes());
        }
        Ok(r) => {
            let mut l = Line::new();
            l.str("shm_sender: неожиданная метка ".as_bytes());
            l.u64(r.label);
            l.nl();
            dlog::log(l.as_bytes());
            return 1;
        }
        Err(e) => return fail("shm_sender: wait READY err ", code_of(e)),
    }

    // 4. Поток сообщений: push в кольцо + дверь; контрольная сумма по
    //    записанным байтам.
    let mut msg = [0u8; MSG_LEN];
    let mut checksum: u64 = 0;
    for seq in 0..MSG_COUNT {
        for (j, b) in msg.iter_mut().enumerate() {
            *b = (seq as u8).wrapping_mul(31).wrapping_add(j as u8);
        }
        checksum = checksum.wrapping_add(sum(&msg));
        if !ring.push(&msg) {
            return fail("shm_sender: кольцо переполнено (ACK потерян?) ", seq as u64);
        }
        kernel_bytes += match ipc::send_cost(
            receiver_slot,
            shm::labels::SHM_DATA,
            &(seq as u64).to_le_bytes(),
            &[],
        ) {
            Ok(n) => n,
            Err(e) => return fail("shm_sender: SHM_DATA err ", code_of(e)),
        };
        // ACK-дверь: получатель освободил кадр (ping-pong — кольцо
        // не переполняется даже при ёмкости в одно сообщение).
        match ipc::wait(receiver_slot, ipc::RECV_NONE, &mut buf) {
            Ok(r) if r.label == shm::labels::SHM_ACK => {}
            Ok(r) => {
                let mut l = Line::new();
                l.str("shm_sender: ждал ACK, пришла метка ".as_bytes());
                l.u64(r.label);
                l.nl();
                dlog::log(l.as_bytes());
                return 1;
            }
            Err(e) => return fail("shm_sender: wait ACK err ", code_of(e)),
        }
    }

    // 5. Финал: контрольная сумма потребителя.
    let remote_sum = match ipc::wait(receiver_slot, ipc::RECV_NONE, &mut buf) {
        Ok(r) if r.label == shm::labels::SHM_DONE && r.payload.len() == 8 => {
            u64::from_le_bytes(r.payload[..8].try_into().unwrap())
        }
        Ok(r) => {
            let mut l = Line::new();
            l.str("shm_sender: ждал DONE, пришла метка ".as_bytes());
            l.u64(r.label);
            l.nl();
            dlog::log(l.as_bytes());
            return 1;
        }
        Err(e) => return fail("shm_sender: wait DONE err ", code_of(e)),
    };

    let data_bytes = (MSG_COUNT * MSG_LEN) as u64;
    let mut l = Line::new();
    if remote_sum == checksum {
        l.str("shm_sender: ОК — через общие страницы ".as_bytes());
        l.u64(data_bytes);
        l.str(" Б, ядро перенесло только ".as_bytes());
        l.u64(kernel_bytes);
        l.str(" Б дверных IPC (".as_bytes());
        l.u64(data_bytes * 100 / kernel_bytes.max(1));
        l.str("x меньше); контрольные суммы совпали: ".as_bytes());
        l.u64(checksum);
        l.nl();
        dlog::log(l.as_bytes());
        dlog::log("shm_sender: готово, self-exit\n".as_bytes());
        0
    } else {
        l.str("shm_sender: КОНТРОЛЬНЫЕ СУММЫ РАЗОШЛИСЬ: лок ".as_bytes());
        l.u64(checksum);
        l.str(" vs удал ".as_bytes());
        l.u64(remote_sum);
        l.nl();
        dlog::log(l.as_bytes());
        1
    }
}

// ─── Сисколл-обёртки демо ─────────────────────────────────────────────────────

fn alloc_pages(pages: u64) -> Result<u64, u64> {
    let code =
        unsafe { cintos_user::syscall::syscall1(cintos_user::abi::nr::ALLOC_PAGES, pages) };
    cintos_user::syscall::check(code).map_err(code_of)
}

fn cap_create_shared(vaddr: u64, pages: u64, dst_slot: u64) -> Result<u64, u64> {
    let code = unsafe {
        cintos_user::syscall::syscall3(
            cintos_user::abi::nr::CAP_CREATE_SHARED,
            vaddr,
            pages,
            dst_slot,
        )
    };
    cintos_user::syscall::check(code).map_err(code_of)
}

fn sum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, b| acc.wrapping_add(*b as u64))
}

/// Слот peer-TaskTCB по имени (ростер в argv: [0]=своё имя, [1+i]=i-й).
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

fn code_of(e: cintos_user::syscall::SyscallError) -> u64 {
    match e {
        cintos_user::syscall::SyscallError::Kernel(code) => code,
    }
}

fn fail(prefix: &str, code: u64) -> i32 {
    let mut l = Line::new();
    l.str(prefix.as_bytes());
    l.u64(code);
    l.nl();
    dlog::log(l.as_bytes());
    1
}
