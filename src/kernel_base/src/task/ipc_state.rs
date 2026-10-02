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
//! ГЕЙТ-ЧЛЕНСТВО (интрузивные очереди ipc::gate): задача ждёт максимум
//! в ОДНОЙ гейт-очереди, поэтому ссылки лежат ЗДЕСЬ (паттерн seL4
//! tcbEPNext/Prev): `gate_prev`/`gate_next` — соседи по FIFO (task_cap_id
//! узлов), `gate_queued` — Some((гейт, сторона)) для O(1) purge и
//! самопроверок. Никаких аллокаций под постановку в очередь — никакой
//! E_SLAB на «33-м блокированном клиенте». Мутации ссылок — под
//! task_manager-локом (лок ipc-состояния узла/соседей — страховка:
//! предикаты сна читают ipc-состояние под WAKE_LOCK).
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

/// Максимум отправителей в очереди одной задачи (медленный путь SEND
/// на ПРЯМОЙ эндпоинт; гейт-очереди НЕ ограничены — интрузивные, см.
/// модульный комментарий). Переполнение — E_SLAB отправителю.
pub const MAX_IPC_QUEUE: usize = 16;

/// ABA-защищённая ссылка на IPC-гейт: id слота + поколение, снятое с
/// капы в момент резолва ([`crate::ipc::gate::gate_live`]). После
/// IPC_DESTROY_GATE id возвращается в пул и может быть выдан ЗАНОВО —
/// расхождение gen делает все старые ссылки невалидными (push/pop/
/// предикаты отказывают → E_CAP_REVOKED), клиент не может незаметно
/// «переехать» на чужой гейт с тем же номером.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateRoute {
    pub id: u64,
    pub generation: u32,
}

/// Сторона интрузивной очереди гейта (в какой из двух FIFO стоит узел).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateQueueSide {
    Senders,
    Receivers,
}

/// Снимок гейт-членства задачи (для O(1) purge при её уничтожении):
/// id гейта + сторона + соседи по FIFO. Поколение не нужно: purge
/// структурный (защитные проверки соседей; после destroy очереди
/// пусты — естественный no-op), а умирающая задача не может встать
/// в очередь заново (push сверяет gen под локом шарда).
pub type GateMembership = (u64, GateQueueSide, Option<u64>, Option<u64>);

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
    /// ABA-защищён (generation из капы): уничтожение/переиспользование слота
    /// делает маршрут невалидным — все операции с ним отказывают.
    pub gate: Option<GateRoute>,
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
    /// ABA-защищён (generation из капы, см. SendSpec::gate).
    pub gate: Option<GateRoute>,
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
    /// Интрузивные ссылки в гейт-очереди (см. шапку модуля): prev/next —
    /// task_cap_id соседей, queued — членство (гейт + сторона). Не-None
    /// ТОЛЬКО пока узел реально прошит в FIFO слота (инвариант держится
    /// под локом шарда; постановка/снятие — под task_manager-локом).
    pub gate_prev: Option<u64>,
    pub gate_next: Option<u64>,
    pub gate_queued: Option<(u64, GateQueueSide)>,
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
            gate_prev: None,
            gate_next: None,
            gate_queued: None,
            reply_to: None,
            send_rax: None,
            seq: 0,
        }
    }

    /// Снимок гейт-членства (O(1) purge умирающей задачи: соседей и
    /// сторону знает САМА задача — после снятия TCB читать будет
    /// нечего). Вызывать под собственным ipc-локом (здесь — под
    /// task_manager-локом дестроера).
    pub fn gate_membership(&self) -> Option<GateMembership> {
        let (gate_id, side) = self.gate_queued?;
        Some((gate_id, side, self.gate_prev, self.gate_next))
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

    /// Пустое состояние: работы нет, ответа нет, гейт-членства нет.
    #[test]
    fn fresh_chan_is_idle() {
        let c = IpcChan::new();
        assert_eq!(c.seq(), 0);
        assert!(c.send.is_none());
        assert_eq!(c.recv, IpcRecv::Idle);
        assert!(c.queue.is_empty());
        assert!(c.reply_to.is_none());
        assert!(c.gate_queued.is_none());
        assert!(c.gate_prev.is_none());
        assert!(c.gate_next.is_none());
        assert!(c.gate_membership().is_none());
        assert!(!c.has_work());
    }

    /// Гейт-членство: снимок отдаёт id/сторону/соседей как есть.
    #[test]
    fn gate_membership_snapshot() {
        let mut c = IpcChan::new();
        c.gate_prev = Some(7);
        c.gate_next = Some(9);
        c.gate_queued = Some((42, GateQueueSide::Senders));
        let (gate_id, side, prev, next) = c.gate_membership().expect("queued");
        assert_eq!(gate_id, 42);
        assert_eq!(side, GateQueueSide::Senders);
        assert_eq!(prev, Some(7));
        assert_eq!(next, Some(9));
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
