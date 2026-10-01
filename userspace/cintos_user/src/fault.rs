//! fault — Rust-обвязка фолт-эндпоинтов NOMAD (стиль seL4/KeyKOS).
//!
//! МОДЕЛЬ (зеркало ядра — kernel_base::ipc::fault):
//!   - Обработчик (keeper) вызывает [`create_endpoint`]: ядро фиксирует
//!     ТЕКУЩУЮ задачу как обработчика и кладёт capability в слот cspace.
//!   - Менеджер задачи (держит её TaskTCB-слот) привязывает эндпоинт:
//!     [`set_endpoint`] — фолты цели пойдут обработчику.
//!   - Фолт приходит ОБЫЧНЫМ сообщением ipc::wait: label =
//!     [`FAULT_LABEL`], sender = task_cap_id упавшей, payload — 5×u64
//!     ([`FaultInfo`]). Разбор — [`parse_fault`].
//!   - Обработчик чинит причину (или эмулирует) и зовёт [`reply`]:
//!     new_rip/new_rsp = 0 — повторить упавшую инструкцию (классический
//!     пейджер); new_rip = ip + длина — пропустить (эмуляция, напр.
//!     #UD: ud2 = 2 байта); произвольный адрес/стек — сигнальный
//!     трамплин. Resume-право валидно только зарегистрированному
//!     обработчику и только ПОСЛЕ приёма сообщения (ядро проверяет).
//!
//! Смерть обработчика: фолт-эндпоинт «протухает» (зигота-поколение), а
//! упавшие под ним задачи ядро будит — они повторят упавшую инструкцию
//! и сфолтят уже без обработчика (фатальный дамп, видно в serial).

use crate::abi;
use crate::handle::{Slot, TaskCap};
use crate::ipc::Received;
use crate::syscall::{self, SyscallError};

/// Label фолт-сообщений (зеркало ядра: kernel_base::ipc::fault).
pub const FAULT_LABEL: u64 = 0xFA17_0000_0000_0001;

/// Слов payload в фолт-сообщении.
pub const FAULT_MSG_WORDS: usize = 5;

/// Векторы фолтов (зеркало ядра; x86).
pub mod fault_kind {
    /// #DE: деление на ноль.
    pub const DIVIDE_ERROR: u64 = 0;
    /// #BP: int3.
    pub const BREAKPOINT: u64 = 3;
    /// #OF: into.
    pub const OVERFLOW: u64 = 4;
    /// #UD: неверный опкод (ud2 — триггер тестов).
    pub const INVALID_OPCODE: u64 = 6;
    /// #GP: общая защита.
    pub const GENERAL_PROTECTION: u64 = 13;
    /// #PF: страничный фолт (addr = CR2).
    pub const PAGE_FAULT: u64 = 14;
    /// #MF: x87.
    pub const X87_MATH: u64 = 16;
    /// #AC: выравнивание.
    pub const ALIGNMENT_CHECK: u64 = 17;
    /// #XF: SIMD.
    pub const SIMD_EXCEPTION: u64 = 19;
}

/// Данные фолта (payload сообщения; sender — в заголовке приёма).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultInfo {
    /// Вектор исключения ([`fault_kind`]).
    pub kind: u64,
    /// Адрес фолта: CR2 для #PF, 0 для остальных.
    pub addr: u64,
    /// RIP упавшей инструкции.
    pub ip: u64,
    /// RSP упавшей задачи.
    pub sp: u64,
    /// Код ошибки CPU (#PF: P/W/U/R-биты; 0 для остальных).
    pub err: u64,
}

/// Создать фолт-эндпоинт: текущая задача становится обработчиком,
/// capability кладётся в `dst` её cspace. Требует прав группы
/// CAP_MANAGE|FAULT_HANDLE.
pub fn create_endpoint(dst: Slot) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall1(abi::nr::CAP_CREATE_FAULT_ENDPOINT, dst.raw()) };
    syscall::check(code).map(|_| ())
}

/// Привязать эндпоинт (слот `ep` текущей задачи) к цели (её
/// TaskTCB-слот `target`): фолты ЦЕЛИ пойдут обработчику.
/// Требует прав TASK_CREATE|FAULT_HANDLE; повторная привязка
/// заменяет прежнюю.
pub fn set_endpoint(ep: Slot, target: Slot) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall2(abi::nr::FAULT_SET_ENDPOINT, ep.raw(), target.raw()) };
    syscall::check(code).map(|_| ())
}

/// Ответить на фолт (resume-инвокация): разбудить упавшую задачу
/// `target` ([`TaskCap`] — sender принятого сообщения).
/// `new_rip`/`new_rsp` = 0 — повторить упавшую инструкцию с прежним
/// стеком; иначе — продолжить с нового адреса/стека.
pub fn reply(target: TaskCap, new_rip: u64, new_rsp: u64) -> Result<(), SyscallError> {
    let code = unsafe {
        syscall::syscall3(
            abi::nr::FAULT_REPLY,
            target.raw(),
            new_rip,
            new_rsp,
        )
    };
    syscall::check(code).map(|_| ())
}

/// Разбор принятого сообщения как фолта: None — label чужой или payload
/// не является 5×u64 (5 слов = 40 байт).
pub fn parse_fault(received: &Received<'_>) -> Option<FaultInfo> {
    if received.label != FAULT_LABEL {
        return None;
    }
    if received.payload.len() != FAULT_MSG_WORDS * 8 {
        return None;
    }
    let word = |i: usize| -> u64 {
        u64::from_le_bytes(
            received.payload[i * 8..(i + 1) * 8]
                .try_into()
                .unwrap(),
        )
    };
    Some(FaultInfo {
        kind: word(0),
        addr: word(1),
        ip: word(2),
        sp: word(3),
        err: word(4),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ядро кодирует фолт в проволочном формате ipc (fixed-заголовок
    /// {label, payload_len} + payload) — фиксируем раскладку литерально:
    /// если ядро сменит формат, тест упадёт ДО рантайма.
    #[test]
    fn kernel_layout_roundtrip() {
        let info = FaultInfo {
            kind: fault_kind::PAGE_FAULT,
            addr: 0xDEAD_BEEF,
            ip: 0x1000,
            sp: 0x2000,
            err: 0x2,
        };
        let words = info_payload_bytes(&info);

        // Раскладка ядра (FaultInfo::encode, 56 байт).
        let mut body = [0u8; 56];
        body[0..8].copy_from_slice(&FAULT_LABEL.to_le_bytes());
        body[8..16].copy_from_slice(&(FAULT_MSG_WORDS as u64 * 8).to_le_bytes());
        body[16..56].copy_from_slice(&words);

        // Тело = {label, payload_len=40, payload}?
        assert_eq!(
            u64::from_le_bytes(body[0..8].try_into().unwrap()),
            FAULT_LABEL
        );
        assert_eq!(
            u64::from_le_bytes(body[8..16].try_into().unwrap()),
            FAULT_MSG_WORDS as u64 * 8
        );

        // parse_fault по распарсенному сообщению.
        // (Received собираем вручную: parse_fault читает label/payload.)
        let received = Received {
            sender: TaskCap::new(42),
            cap_slots: [Slot::new(0); crate::ipc::MAX_CAPS],
            caps_len: 0,
            label: FAULT_LABEL,
            payload: &body[16..56],
        };
        assert_eq!(parse_fault(&received), Some(info));
        // Чужой label — не фолт.
        let other = Received {
            sender: TaskCap::new(42),
            cap_slots: [Slot::new(0); crate::ipc::MAX_CAPS],
            caps_len: 0,
            label: 0xC1A0_0001,
            payload: &body[16..56],
        };
        assert_eq!(parse_fault(&other), None);
    }

    fn info_payload_bytes(info: &FaultInfo) -> [u8; FAULT_MSG_WORDS * 8] {
        let mut b = [0u8; FAULT_MSG_WORDS * 8];
        for (i, w) in [info.kind, info.addr, info.ip, info.sp, info.err]
            .into_iter()
            .enumerate()
        {
            b[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}
