//! shm_receiver — демо длинных IPC через разделяемую память (потребитель).
//!
//! Протокол (см. shm_sender):
//!   1. Ждёт SHM_OFFER: capability региона в слоте + глобальный id в
//!      payload.
//!   2. MOUNT_CAP_REGION(id) — физические фреймы отправителя появляются
//!      в НАШЕМ пространстве (внешний маппинг, владение остаётся у
//!      отправителя); открывает SPSC-кольцо.
//!   3. SHM_READY — готов принимать.
//!   4. 16 кадров: дверь SHM_DATA → pop из кольца (мимо ядра) →
//!      контрольная сумма → ACK-дверь.
//!   5. SHM_DONE: отправляет контрольную сумму; self-exit.

#![no_std]
#![no_main]

use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::ipc;
use cintos_user::shm::{self, Consumer};

#[used]
static _FORCE_ENTRY: unsafe extern "C" fn() -> ! = crt0::_start;

/// Ожидаемая геометрия демо (согласована с shm_sender).
const MSG_COUNT: usize = 16;
const MSG_LEN: usize = 1024;
const SHM_PAGES: usize = 4;

/// Приёмный слот capability (база приёмного окна IPC_WAIT).
const RECV_SLOT: u64 = 16;

#[unsafe(no_mangle)]
pub extern "C" fn main(
    _argc: usize,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    dlog::log("shm_receiver: старт\n".as_bytes());

    let Some(sender_slot) = peer_slot_of(b"shm_sender") else {
        dlog::log("shm_receiver: shm_sender не найден в ростере\n".as_bytes());
        return 1;
    };

    // 1. Предложение: capability (лёгла в наш приёмный слот) + глобальный id
    //    (в payload — только для журналирования; монтируем ПО СЛОТУ).
    let mut buf = ipc::recv_buffer();
    let _cap_id = match ipc::wait(ipc::WAIT_ANY, ipc::recv_window(RECV_SLOT, 2), &mut buf) {
        Ok(r) if r.label == shm::labels::SHM_OFFER && r.payload.len() == 8 => {
            u64::from_le_bytes(r.payload[..8].try_into().unwrap())
        }
        Ok(r) => {
            let mut l = Line::new();
            l.str("shm_receiver: ждал OFFER, пришла метка ".as_bytes());
            l.u64(r.label);
            l.nl();
            dlog::log(l.as_bytes());
            return 1;
        }
        Err(e) => return fail("shm_receiver: wait OFFER err ", code_of(e)),
    };

    // 2. Монтирование общих фреймов (внешний маппинг) ПО ПРИЁМНОМУ СЛОТУ:
    //    ядро резолвит capability через мембраны/поколения — ревок
    //    источника реально запрещает монтирование.
    let va = match mount_cap_region(RECV_SLOT) {
        Ok(va) => va,
        Err(code) => return fail("shm_receiver: MOUNT_CAP_REGION err ", code),
    };
    let mut ring = match unsafe { Consumer::open(va as usize, SHM_PAGES) } {
        Some(c) => c,
        None => return fail("shm_receiver: кольцо не открылось (magic?) ", 0),
    };

    // 3. Готовность.
    if let Err(e) = ipc::send(sender_slot, shm::labels::SHM_READY, &[], &[]) {
        return fail("shm_receiver: SHM_READY err ", code_of(e));
    }

    // 4. Приём: дверь → кадр из кольца → сумма → ACK.
    let mut msg = [0u8; MSG_LEN];
    let mut checksum: u64 = 0;
    for expected in 0..MSG_COUNT {
        match ipc::wait(sender_slot, ipc::RECV_NONE, &mut buf) {
            Ok(r) if r.label == shm::labels::SHM_DATA => {
                let seq = if r.payload.len() == 8 {
                    u64::from_le_bytes(r.payload[..8].try_into().unwrap())
                } else {
                    u64::MAX
                };
                if seq != expected as u64 {
                    let mut l = Line::new();
                    l.str("shm_receiver: сбой порядка кадров: ждал ".as_bytes());
                    l.u64(expected as u64);
                    l.str(", пришёл ".as_bytes());
                    l.u64(seq);
                    l.nl();
                    dlog::log(l.as_bytes());
                    return 1;
                }
            }
            Ok(r) => {
                let mut l = Line::new();
                l.str("shm_receiver: ждал DATA, пришла метка ".as_bytes());
                l.u64(r.label);
                l.nl();
                dlog::log(l.as_bytes());
                return 1;
            }
            Err(e) => return fail("shm_receiver: wait DATA err ", code_of(e)),
        }
        // Данные — из общих страниц, МИМО ядра.
        let n = match ring.pop(&mut msg) {
            Some(n) => n,
            None => return fail("shm_receiver: кольцо пусто на двери DATA ", expected as u64),
        };
        if n != MSG_LEN {
            return fail("shm_receiver: кадр неожиданной длины ", n as u64);
        }
        checksum = checksum.wrapping_add(msg.iter().fold(0u64, |a, b| a.wrapping_add(*b as u64)));
        if let Err(e) = ipc::send(
            sender_slot,
            shm::labels::SHM_ACK,
            &(n as u64).to_le_bytes(),
            &[],
        ) {
            return fail("shm_receiver: ACK err ", code_of(e));
        }
    }

    // 5. Контрольная сумма — отправителю.
    if let Err(e) = ipc::send(
        sender_slot,
        shm::labels::SHM_DONE,
        &checksum.to_le_bytes(),
        &[],
    ) {
        return fail("shm_receiver: DONE err ", code_of(e));
    }

    let mut l = Line::new();
    l.str("shm_receiver: принял ".as_bytes());
    l.u64((MSG_COUNT * MSG_LEN) as u64);
    l.str(" Б из общих страниц, сумма ".as_bytes());
    l.u64(checksum);
    l.str(b", self-exit\n");
    dlog::log(l.as_bytes());
    0
}

fn mount_cap_region(cap_slot: u64) -> Result<u64, u64> {
    // MOUNT_CAP_REGION адресуется СЛОТОМ cspace (capability в нашем
    // приёмном окне), а не голым глобальным id из payload: слот ядро
    // резолвит через мембраны/поколения — ревок источника реально
    // запрещает монтирование.
    let code = unsafe {
        cintos_user::syscall::syscall1(cintos_user::abi::nr::MOUNT_CAP_REGION, cap_slot)
    };
    cintos_user::syscall::check(code).map_err(code_of)
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
