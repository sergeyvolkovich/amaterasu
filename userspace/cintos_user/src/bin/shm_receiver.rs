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

use cintos_user::crt0;
use cintos_user::dlog::{self, Line};
use cintos_user::ipc;
use cintos_user::shm::{self, Consumer};
use cintos_user::task;
use cintos_user::cap;

/// Ожидаемая геометрия демо (согласована с shm_sender).
const MSG_COUNT: usize = 16;
const MSG_LEN: usize = 1024;
const SHM_PAGES: usize = 4;

/// Приёмный слот capability (база приёмного окна IPC_WAIT).
const RECV_SLOT: u64 = 16;

fn main() {
    dlog::log("shm_receiver: старт\n");

    let Some(sender_slot) = task::peer_slot_of("shm_sender") else {
        dlog::log("shm_receiver: shm_sender не найден в ростере\n");
        crt0::exit(1);
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
            l.str("shm_receiver: ждал OFFER, пришла метка ");
            l.u64(r.label);
            l.nl();
            dlog::log(l.as_str());
            crt0::exit(1);
        }
        Err(e) => fail("shm_receiver: wait OFFER err ", code_of(e)),
    };

    // 2. Монтирование общих фреймов (внешний маппинг) ПО ПРИЁМНОМУ СЛОТУ:
    //    ядро резолвит capability через мембраны/поколения — ревок
    //    источника реально запрещает монтирование.
    let va = match cap::mount_region(RECV_SLOT) {
        Ok(va) => va,
        Err(e) => fail("shm_receiver: MOUNT_CAP_REGION err ", code_of(e)),
    };
    let mut ring = match unsafe { Consumer::open(va as usize, SHM_PAGES) } {
        Some(c) => c,
        None => fail("shm_receiver: кольцо не открылось (magic?) ", 0),
    };

    // 3. Готовность.
    if let Err(e) = ipc::send(sender_slot, shm::labels::SHM_READY, &[], &[]) {
        fail("shm_receiver: SHM_READY err ", code_of(e));
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
                    l.str("shm_receiver: сбой порядка кадров: ждал ");
                    l.u64(expected as u64);
                    l.str(", пришёл ");
                    l.u64(seq);
                    l.nl();
                    dlog::log(l.as_str());
                    crt0::exit(1);
                }
            }
            Ok(r) => {
                let mut l = Line::new();
                l.str("shm_receiver: ждал DATA, пришла метка ");
                l.u64(r.label);
                l.nl();
                dlog::log(l.as_str());
                crt0::exit(1);
            }
            Err(e) => fail("shm_receiver: wait DATA err ", code_of(e)),
        }
        // Данные — из общих страниц, МИМО ядра.
        let n = match ring.pop(&mut msg) {
            Some(n) => n,
            None => fail("shm_receiver: кольцо пусто на двери DATA ", expected as u64),
        };
        if n != MSG_LEN {
            fail("shm_receiver: кадр неожиданной длины ", n as u64);
        }
        checksum = checksum.wrapping_add(msg.iter().fold(0u64, |a, b| a.wrapping_add(*b as u64)));
        if let Err(e) = ipc::send(
            sender_slot,
            shm::labels::SHM_ACK,
            &(n as u64).to_le_bytes(),
            &[],
        ) {
            fail("shm_receiver: ACK err ", code_of(e));
        }
    }

    // 5. Контрольная сумма — отправителю.
    if let Err(e) = ipc::send(
        sender_slot,
        shm::labels::SHM_DONE,
        &checksum.to_le_bytes(),
        &[],
    ) {
        fail("shm_receiver: DONE err ", code_of(e));
    }

    let mut l = Line::new();
    l.str("shm_receiver: принял ");
    l.u64((MSG_COUNT * MSG_LEN) as u64);
    l.str(" Б из общих страниц, сумма ");
    l.u64(checksum);
    l.str(", self-exit\n");
    dlog::log(l.as_str());
    // Возврат из main → lang_start → crt0::exit (SCHED_DESTROY_TASK).
}

fn code_of(e: cintos_user::syscall::SyscallError) -> u64 {
    match e {
        cintos_user::syscall::SyscallError::Kernel(code) => code,
    }
}

/// Диагностика + аварийный self-exit (код ядром игнорируется).
fn fail(prefix: &str, code: u64) -> ! {
    let mut l = Line::new();
    l.str(prefix);
    l.u64(code);
    l.nl();
    dlog::log(l.as_str());
    crt0::exit(1)
}
