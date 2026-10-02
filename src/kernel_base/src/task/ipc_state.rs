//! IPC-состояние задачи (TCB-центричный rendezvous в стиле L4).
//!
//! Классический L4 не буферизует сообщения в ядре: заблокированный
//! отправитель держит сообщение в СВОЁМ буфере, получатель копирует
//! напрямую через его умап. Здесь так же: параметры заблокированной
//! стороны живут в её TCB ([`SendSpec`]/[`RecvSpec`]), почтовых ящиков
//! нет — ни двойной копии, ни глобального пула, ни лимита 16 ящиков на
//! всю систему.
//!
//! СОСТОЯНИЕ ([`IpcChan`], под SpinMutex в TCB):
//!   - `send: Option<SendSpec>` — задача блокирована в SEND (медленный
//!     путь): сообщение остаётся в её userspace-буфере. Инвариант
//!     стабильности: задача спит внутри сисколла, сама свой умап менять
//!     не может; ядро копирует из её буфера в момент доставки.
//!   - `recv: IpcRecv` — Idle / Receiving(спецификация ожидания) /
//!     Claimed(захвачен доставляющим отправителем).
//!   - `queue` — ОЧЕРЕДЬ ОТПРАВИТЕЛЕЙ, нацеленных на ЭТУ задачу
//!     (медленный путь SEND: их task_cap_id + флаг фолта). Данные — в
//!     TCB отправителей, очередь — только идентификаторы (FIFO).
//!   - `reply_to` — неявный адресат ответа (RPC): task_cap_id последнего
//!     НЕ-фолтового отправителя, чьё сообщение принято; изымается
//!     IPC_REPLY / IPC_REPLY_WAIT (см. syscall::ipc).
//!   - `seq` — монотонный счётчик событий доставки (lost-wakeup guard:
//!     предикат засыпания сверяет снимок, см. lctl::
//!     scheduler_block_on_object_if).
//!
//! ПРАВИЛА БЛОКИРОВОК: IpcChan — ЛИСТОВОЙ лок (внутри его секции чужие
//! локи не берутся; копирования userspace — только после снятия).
//! Внешний порядок: permission_backend → task_manager → ipc-локи →
//! гейт-локи. WAKE_LOCK (task::wake) берётся ТОЛЬКО с отпущенными
//! ipc/gate-локами — единственное исключение: предикат
//! scheduler_block_on_object_if, выполняемый ПОД WAKE_LOCK, берёт
//! ipc/гейт-локи коротко (порядок WAKE_LOCK → ipc → gate нигде не
//! обращён).

use heapless::Vec as HVec;
use spin::mutex::SpinMutex;

use crate::ipc::endpoint::{CapItem, MAX_CAPS};

/// Максимум отправителей в очереди одной задачи (медленный путь SEND).
/// Переполнение — E_SLAB отправителю (ресурс задачи исчерпан).
pub const MAX_IPC_QUEUE: usize = 16;

/// Параметры заблокированного отправителя (медленный путь).
///
/// Сообщение НЕ копируется в ядро: `msg_va/msg_len` адресуют буфер
/// отправителя, стабильный пока он спит (см. модульный комментарий).
/// Дескрипторы capability (`caps`) снимаются из userspace В МОМЕНТ
/// SEND — это маленький массив фиксированной ёмкости, и его ранняя
/// валидация (права на слоты) дешевле на пути доставки.
#[derive(Debug, Clone, Copy)]
pub struct SendSpec {
    /// Адресат: task_cap_id получателя (0 — отправка через гейт).
    pub to: u64,
    /// Гейт-маршрут (Some — отправка в очередь гейта, `to` не используется).
    pub gate: Option<u64>,
    /// VA тела сообщения (проволочный формат: {label, payload_len,
    /// payload}) в пространстве ОТПРАВИТЕЛЯ.
    pub msg_va: usize,
    pub msg_len: usize,
    /// Дескрипторы пересылки capability (сняты из userspace при SEND).
    pub caps: [CapItem; MAX_CAPS],
    pub caps_count: usize,
    /// Фолт-доставка (ipc::fault): отправитель спит на фолт-объекте, его
    /// нельзя будить при изъятии — только FAULT_REPLY.
    pub is_fault: bool,
}

/// Параметры заблокированного получателя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvSpec {
    /// Closed-wait фильтр: Some(cap) — принимать только от него.
    pub from: Option<u64>,
    /// Ожидание на гейте (Some) либо на собственном эндпоинте (None).
    pub gate: Option<u64>,
    /// VA буфера приёма (заголовок + слоты caps + тело).
    pub tgt_va: usize,
    pub tgt_capacity: usize,
    /// ПРИЁМНОЕ ОКНО capability (seL4-стиль): i-я capability сообщения
    /// кладётся в recv_base + i (первый свободный слот окна).
    pub recv_base: u64,
    pub recv_count: usize,
}

/// Состояние приёма. Claimed — захвачен доставляющим отправителем:
/// повторные отправители его не видят (двойная доставка исключена),
/// при неудаче доставки spec возвращается в Receiving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpcRecv {
    #[default]
    Idle,
    Receiving(RecvSpec),
    Claimed(RecvSpec),
}

/// IPC-состояние задачи (см. модульный комментарий).
#[derive(Default)]
pub struct IpcChan {
    pub send: Option<SendSpec>,
    pub recv: IpcRecv,
    /// Очередь отправителей этой задачи: (task_cap_id, is_fault), FIFO.
    pub queue: HVec<(u64, bool), MAX_IPC_QUEUE>,
    /// Неявный адресат ответа (RPC, IPC_REPLY); снимается изъятием.
    pub reply_to: Option<u64>,
    /// Исход доставки заблокированного отправителя для гонки «не успел
    /// уснуть» (lctl::scheduler_block_on_object_if вернул false):
    /// Some(code) — ошибка доставки (транспорт успел изъять сообщение и
    /// записать отказ ДО фактического сна), None — успех/не релевантно.
    /// Читается хендлером SEND через take_send_result.
    pub send_rax: Option<u64>,
    /// Счётчик событий доставки/очереди (lost-wakeup guard).
    pub seq: u64,
}

impl IpcChan {
    pub const fn new() -> Self {
        Self {
            send: None,
            recv: IpcRecv::Idle,
            queue: HVec::new(),
            reply_to: None,
            send_rax: None,
            seq: 0,
        }
    }

    /// Снимок счётчика событий (для предиката засыпания).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Есть ли немедленно доставляемая работа для получателя `me`:
    /// очередь не пуста (open wait) ИЛИ захвачен доставляющим.
    /// Closed-wait фильтр учитывает вызывающий (поп кандидата — с ним).
    pub fn has_work(&self) -> bool {
        !self.queue.is_empty() || matches!(self.recv, IpcRecv::Claimed(_))
    }
}

/// Обёртка над IpcChan в TCB (см. task::tcb).
pub struct IpcCell(SpinMutex<IpcChan>);

impl Default for IpcCell {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcCell {
    pub const fn new() -> Self {
        Self(SpinMutex::new(IpcChan::new()))
    }

    pub fn lock(&self) -> spin::mutex::SpinMutexGuard<'_, IpcChan> {
        self.0.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Пустое состояние: работы нет, ответа нет.
    #[test]
    fn fresh_chan_is_idle() {
        let c = IpcChan::new();
        assert_eq!(c.seq(), 0);
        assert!(c.send.is_none());
        assert_eq!(c.recv, IpcRecv::Idle);
        assert!(c.queue.is_empty());
        assert!(c.reply_to.is_none());
        assert!(!c.has_work());
    }

    /// Очередь отправителей: FIFO-наполнение до предела.
    #[test]
    fn queue_fifo_until_full() {
        let mut c = IpcChan::new();
        for i in 0..MAX_IPC_QUEUE {
            assert!(c.queue.push((100 + i as u64, false)).is_ok());
        }
        assert!(c.queue.push((999, false)).is_err());
        assert_eq!(c.queue.len(), MAX_IPC_QUEUE);
        assert!(c.has_work());
        // FIFO-порядок.
        assert_eq!(c.queue.remove(0), (100, false));
        assert_eq!(c.queue.remove(0), (101, false));
    }
}
