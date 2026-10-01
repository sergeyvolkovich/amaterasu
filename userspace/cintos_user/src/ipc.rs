//! ipc — Rust-обвязка синхронного IPC-транспорта NOMAD (стиль Лидтке/L4).
//!
//! Разделение ответственности (архитектура по решению пользователя):
//!   - ЯДРО — только транспорт: rendezvous send/wait, пересылка
//!     capability дескрипторами (аналог L4 map items). Payload ядро
//!     НЕ разбирает.
//!   - ЮЗЕРСПЕЙС — сериализация: тело сообщения кодируется мини-
//!     FlatBuffers-рантаймом [`crate::flatbuf`] (IpcMessage{label,
//!     payload}).
//!
//! Проволочный формат доставки (буфер приёма wait, little-endian):
//!   [0] task_cap_id отправителя        (u64)
//!   [1] размер тела (FlatBuffers)      (u64, байт)
//!   [2] число доставленных capability  (u64, N)
//!   [3..3+N] слоты ПОЛУЧАТЕЛЯ capability(u64 × N)
//!   [3+N .. 3+N+size] тело сообщения   (FlatBuffers: label + payload)
//!
//! Слоты cspace (bootstrap-раскладка spawn):
//!   0 — self TaskTCB, 1 — неймспейс, 2+i — TaskTCB i-го boot-сервера
//!   (порядок модулей; см. kernel_exec::spawn). Отправка адресуется
//!   СЛОТОМ получателя (право Send), ожидание — слотом отправителя или
//!   [`WaitFrom::Any`] (open wait, L4 from-any).

use crate::abi;
use crate::cap::Rights;
use crate::flatbuf::{Builder, MessageRef};
use crate::handle::{Slot, TaskCap};
use crate::syscall::{self, SyscallError};

/// Слов заголовка доставки до списка слотов capability.
pub const HEADER_WORDS: usize = 3;

/// Максимум capability в одном сообщении (зеркало ядра).
pub const MAX_CAPS: usize = 8;

/// От кого ждать ([`wait`]): конкретный peer (closed wait) или кто
/// угодно (open wait, L4 from-any). Замена сырого `WAIT_ANY = u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitFrom {
    /// Открытое ожидание: любое сообщение endpoint'а задачи.
    Any,
    /// Закрытое ожидание: только от TaskTCB-капы в этом слоте cspace.
    Slot(Slot),
}

impl WaitFrom {
    /// Wire-значение IPC_WAIT (u64::MAX — from-any).
    pub const fn raw(self) -> u64 {
        match self {
            Self::Any => u64::MAX,
            Self::Slot(s) => s.raw(),
        }
    }
}

/// ПРИЁМНОЕ ОКНО capability (seL4-стиль): получатель в IPC_WAIT задаёт
/// диапазон СВОИХ слотов, и ядро кладёт i-ю capability сообщения в
/// ПЕРВЫЙ СВОБОДНЫЙ слот окна. Отправитель cspace получателя
/// адресовать не может (поле dst_slot дескриптора игнорируется ядром).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvWindow {
    pub base: Slot,
    pub count: u64,
}

/// «Capability не принимать»: сообщения с map items отклоняются
/// отправителю, обычные сообщения доставляются.
pub const RECV_NONE: RecvWindow = RecvWindow {
    base: Slot::new(0),
    count: 0,
};

/// Окно приёма [base, base+count).
pub const fn recv_window(base: Slot, count: u64) -> RecvWindow {
    RecvWindow { base, count }
}

/// Первый слот peer-капабилитей (TaskTCB boot-серверов): i-й сервер
/// ростера — `Slot::new(PEER_SLOT_BASE.raw() + i)`.
pub const PEER_SLOT_BASE: Slot = Slot::new(2);

/// Свободный слот для ПРИНИМАЕМЫХ capability (map item'ы IPC).
/// Обязан быть ВЫШЕ peer-диапазона (2..2+MAX_BOOT_MODULES=2..14): ростер
/// спавна занимает peer-слоты, и пересылка в занятый слот даёт
/// E_SLOT_OCCUPIED (поймано в QEMU: демо писало в слоты 4/5).
pub const TRANSFER_SLOT: Slot = Slot::new(16);

/// Дескриптор пересылки capability (аналог L4 map item).
/// src_slot — слот ОТПРАВИТЕЛЯ, rights — права копии (не могут
/// превысить права источника). ПОЛЕ dst_slot УСТАРЕЛО: ядро назначает
/// слоты получателя из ЕГО приёмного окна (см. [`wait`],
/// [`RecvWindow`]) — значение dst_slot игнорируется.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapDesc {
    pub src_slot: Slot,
    pub dst_slot: Slot,
    pub rights: Rights,
}

impl CapDesc {
    pub const fn new(src_slot: Slot, dst_slot: Slot, rights: Rights) -> Self {
        Self {
            src_slot,
            dst_slot,
            rights,
        }
    }
}

/// Негабарит локальной сборки (payload + заголовок не влезают в
/// транспортный лимит ядра).
pub const E_MSG_TOO_BIG: u64 = abi::SYSCALL_ERROR_FLAG | 100;

/// Отправка сообщения (блокируется до приёма получателем — rendezvous).
///
/// `slot` — слот cspace с TaskTCB-капабилити получателя;
/// тело — FlatBuffers {label, payload}; caps — дескрипторы пересылки.
/// `Err(SyscallError::Kernel(code))` — отказ транспорта (права,
/// негабарит буфера получателя, смерть получателя).
pub fn send(
    slot: Slot,
    label: u64,
    payload: &[u8],
    caps: &[CapDesc],
) -> Result<(), SyscallError> {
    send_cost(slot, label, payload, caps).map(|_| ())
}

/// Как [`send`], но успех возвращает ЧИСЛО БАЙТ, перенесённых ядром при
/// доставке (заголовок + слоты capability + тело): метрика «стоимости»
/// сообщения транспортом. Датапуть shm-канала ([`crate::shm`]) живёт в
/// общих страницах — ядро переносит только такие короткие «двери»;
/// демо сравнивает объёмы.
pub fn send_cost(
    slot: Slot,
    label: u64,
    payload: &[u8],
    caps: &[CapDesc],
) -> Result<u64, SyscallError> {
    let mut builder = Builder::new();
    builder.label(label).payload(payload);
    // Билдер жив до возврата из syscall — ядро копирует тело в момент
    // вызова (быстрый путь) или в свой почтовый ящик (медленный).
    let Some(wire) = builder.finish() else {
        return Err(SyscallError::Kernel(E_MSG_TOO_BIG));
    };

    let mut caps_wire = [0u64; MAX_CAPS * 3];
    let n = caps.len().min(MAX_CAPS);
    for (i, c) in caps.iter().take(n).enumerate() {
        caps_wire[i * 3] = c.src_slot.raw();
        caps_wire[i * 3 + 1] = c.dst_slot.raw();
        caps_wire[i * 3 + 2] = c.rights.bits();
    }

    let code = unsafe {
        syscall::syscall5(
            abi::nr::IPC_SEND,
            slot.raw(),
            wire.as_ptr() as u64,
            wire.len() as u64,
            if n > 0 { caps_wire.as_ptr() as u64 } else { 0 },
            n as u64,
        )
    };
    syscall::check(code)?;
    // Зеркало ядра (endpoint::delivery_bytes): 3 слова заголовка +
    // слот на capability + тело.
    Ok(((HEADER_WORDS + n) * 8 + wire.len()) as u64)
}

/// Принятое сообщение: заголовок транспорта + разобранное FlatBuffers-тело.
#[derive(Debug)]
pub struct Received<'a> {
    /// TaskTCB-капа отправителя (адресация ответа/фолт-reply).
    pub sender: TaskCap,
    /// Слоты ПОЛУЧАТЕЛЯ, куда легли capability (первые caps_len).
    pub cap_slots: [Slot; MAX_CAPS],
    pub caps_len: usize,
    /// Тег типа сообщения (FlatBuffers label).
    pub label: u64,
    /// Непрозрачное тело (FlatBuffers payload).
    pub payload: &'a [u8],
}

/// Ожидание сообщения (блокируется до доставки — rendezvous).
///
/// `from` — слот cspace с TaskTCB отправителя (closed wait) или
/// [`WAIT_ANY`]. `buf` — буфер приёма (рекомендуется
/// [`recv_buffer`]); после возврата содержит заголовок + тело.
///
/// `recv` — приёмное окно capability ([`recv_window`]): ядро кладёт
/// i-ю capability сообщения в ПЕРВЫЙ СВОБОДНЫЙ слот окна и сообщает
/// фактические слоты в заголовке доставки ([`Received::cap_slots`]).
/// [`RECV_NONE`] — capability не принимать (сообщение с map items
/// отклонит отправителю).
pub fn wait<'a>(
    from: WaitFrom,
    recv: RecvWindow,
    buf: &'a mut [u8],
) -> Result<Received<'a>, SyscallError> {
    wait_deadline(from, recv, buf, 0)
}

/// IPC_WAIT с дедлайном: deadline — абсолютный тик ядра
/// (TASK_STATS даёт global ticks + tick_hz); 0 — ждать вечно.
/// По истечении — E_TIMEOUT; сообщение, доставленное в тот же тик,
/// старше таймаута (доставка побеждает).
pub fn wait_deadline<'a>(
    from: WaitFrom,
    recv: RecvWindow,
    buf: &'a mut [u8],
    deadline: u64,
) -> Result<Received<'a>, SyscallError> {
    if buf.len() < HEADER_WORDS * 8 {
        return Err(SyscallError::Kernel(abi::result::E_INVALID_ARG));
    }
    let code = unsafe {
        syscall::syscall6(
            abi::nr::IPC_WAIT,
            from.raw(),
            buf.as_ptr() as u64,
            buf.len() as u64,
            recv.base.raw(),
            recv.count,
            deadline,
        )
    };
    syscall::check(code)?;
    parse_received(buf).ok_or(SyscallError::Kernel(abi::result::E_INTERNAL))
}

/// Разбор буфера после успешного wait (выделен для C-ABI-переиспользования).
pub fn parse_received(buf: &[u8]) -> Option<Received<'_>> {
    let rd = |at: usize| -> Option<u64> {
        let e = at.checked_add(8)?;
        if e > buf.len() {
            return None;
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(&buf[at..e]);
        Some(u64::from_le_bytes(w))
    };
    let sender = rd(0)?;
    let body_len = rd(8)? as usize;
    let caps_len = rd(16)? as usize;
    if caps_len > MAX_CAPS {
        return None;
    }
    let mut cap_slots = [Slot::new(0); MAX_CAPS];
    for (i, slot) in cap_slots.iter_mut().enumerate().take(caps_len) {
        *slot = Slot::new(rd(HEADER_WORDS * 8 + i * 8)?);
    }
    let body_at = (HEADER_WORDS + caps_len) * 8;
    let body_end = body_at.checked_add(body_len)?;
    if body_end > buf.len() {
        return None;
    }
    let body = &buf[body_at..body_end];
    let msg = MessageRef::parse(body)?;
    Some(Received {
        sender: TaskCap::new(sender),
        cap_slots,
        caps_len,
        label: msg.label(),
        payload: msg.payload(),
    })
}

/// Буфер приёма на транспортный лимит (выравнивание u64 не требуется —
/// заголовок читается unaligned-словами).
pub fn recv_buffer() -> [u8; 1024] {
    [0; 1024]
}
