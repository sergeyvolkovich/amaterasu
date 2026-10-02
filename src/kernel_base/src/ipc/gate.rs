//! IPC-гейты — точки мультиплексирования IPC в стиле seL4-эндпоинтов.
//!
//! ЗАЧЕМ: прямая адресация «задача → задача» (TaskTCB-капа с правом
//! Send) требует от клиента authority на САМУ задачу сервера. Гейт
//! отделяет канал от исполнителя: сервер публикует гейт, клиенты шлют
//! В ГЕЙТ (капа гейта с правом Send — и ничего больше), сервер ждёт на
//! гейте. Один гейт — много клиентов; много гейтов — один сервер;
//! клиенты не видят task_cap_id сервера.
//!
//! СОСТОЯНИЕ: две FIFO-очереди идентификаторов задач (данные — в TCB
//! участников, здесь только routing):
//!   - `senders`: отправители, вставшие в гейт (медленный путь), пока
//!     ни один получатель не зарегистрирован на гейте;
//!   - `receivers`: зарегистрированные ожидатели гейта (их RecvSpec —
//!     в их TCB, gate = Some(id)).
//!
//! МАРШРУТ:
//!   - send(гейт): клейм первого зарегистрированного получателя
//!     (transport::claim_receiver с gate=Some(id)); никого — в очередь
//!     senders и сон на СВОЁМ объекте.
//!   - wait(гейт): изъять первого отправителя из senders; пусто —
//!     регистрация в receivers + сон на СВОЁМ объекте.
//!   - пробуждения — только по СВОИМ объектам задач (никаких общих
//!     wait-объектов гейта: lost-wakeup закрыт предикатами, см.
//!     transport::receiver_pred — он проверяет senders очереди гейта).
//!
//! ЖИЗНЕННЫЙ ЦИКЛ: слот гейта выделяется при создании capability
//! (IPC_CREATE_GATE) и живёт до конца работы ядра — как прочие
//! descriptor-объекты (MMIO-регионы, shm), у которых смерть записи
//! capability не уничтожает объект (см. access::capspace — tombstone
//! записи). Переполнение таблицы — E_IDS_EXHAUSTED.

use heapless::Vec as HVec;

use crate::irqsafe::IrqSafeSpinMutex;

/// Максимум гейтов в системе.
pub const MAX_GATES: usize = 64;

/// Ёмкость каждой очереди гейта.
pub const GATE_QUEUE_CAP: usize = 32;

/// Состояние одного гейта.
pub struct Gate {
    /// Отправители, вставшие в гейт (FIFO их task_cap_id).
    pub senders: HVec<u64, GATE_QUEUE_CAP>,
    /// Зарегистрированные ожидатели гейта (FIFO их task_cap_id).
    pub receivers: HVec<u64, GATE_QUEUE_CAP>,
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            senders: HVec::new(),
            receivers: HVec::new(),
        }
    }
}

static GATES: [IrqSafeSpinMutex<Option<Gate>>; MAX_GATES] =
    [const { IrqSafeSpinMutex::new(None) }; MAX_GATES];

/// Выделяет слот гейта, возвращает id (None — таблица переполнена).
pub fn gate_alloc() -> Option<u64> {
    for (id, slot) in GATES.iter().enumerate() {
        let mut gate = slot.lock();
        if gate.is_none() {
            *gate = Some(Gate::new());
            return Some(id as u64);
        }
    }
    None
}

/// Освобождает слот гейта (откат IPC_CREATE_GATE при неудаче установки
/// капы; «нормального» освобождения нет — гейты живёт до конца работы
/// ядра, как прочие descriptor-объекты).
pub fn gate_free(gate_id: u64) {
    if let Some(mut gate) = gate_of(gate_id) {
        *gate = None;
    }
}

/// Живой гейт (для инвариантов; None — id вне таблицы/мертв).
pub fn gate_of(
    id: u64,
) -> Option<crate::irqsafe::IrqSafeGuard<'static, Option<Gate>>> {
    GATES.get(id as usize).map(|slot| slot.lock())
}

/// Поставить отправителя в очередь гейта (медленный путь).
pub fn gate_push_sender(id: u64, sender: u64) -> Result<(), ()> {
    let mut gate = gate_of(id).ok_or(())?;
    let Some(gate) = gate.as_mut() else {
        return Err(());
    };
    gate.senders.push(sender).map_err(|_| ())
}

/// Поставить ожидателя в очередь гейта (регистрация wait).
pub fn gate_push_receiver(id: u64, receiver: u64) -> Result<(), ()> {
    let mut gate = gate_of(id).ok_or(())?;
    let Some(gate) = gate.as_mut() else {
        return Err(());
    };
    // Повторная регистрация той же задачи — замена позиции не нужна
    // (задача не может ждать дважды), просто не дублируем.
    if gate.receivers.contains(&receiver) {
        return Ok(());
    }
    gate.receivers.push(receiver).map_err(|_| ())
}

/// Первый поставленный в очередь отправитель гейта (FIFO-изъятие).
pub fn gate_pop_sender(id: u64) -> Option<u64> {
    let mut gate = gate_of(id)?;
    let gate = gate.as_mut()?;
    if gate.senders.is_empty() {
        return None;
    }
    Some(gate.senders.remove(0))
}

/// Первый зарегистрированный ожидатель гейта (FIFO-изъятие).
pub fn gate_pop_receiver(id: u64) -> Option<u64> {
    let mut gate = gate_of(id)?;
    let gate = gate.as_mut()?;
    if gate.receivers.is_empty() {
        return None;
    }
    Some(gate.receivers.remove(0))
}

/// Вернуть ожидателя в НАЧАЛО очереди (клейм не состоялся).
pub fn gate_unpop_receiver(id: u64, receiver: u64) {
    if let Some(mut gate) = gate_of(id)
        && let Some(gate) = gate.as_mut()
    {
        if !gate.receivers.contains(&receiver) {
            let _ = gate.receivers.insert(0, receiver);
        }
    }
}

/// Есть ли ждущие отправители (предикат сна получателя).
pub fn gate_has_senders(id: u64) -> bool {
    gate_of(id)
        .and_then(|gate| gate.as_ref().map(|g| !g.senders.is_empty()))
        .unwrap_or(false)
}

/// Убрать отправителя из очереди гейта (таймаут/уничтожение).
pub fn gate_remove_sender(id: u64, sender: u64) {
    if let Some(mut gate) = gate_of(id)
        && let Some(gate) = gate.as_mut()
    {
        gate.senders.retain(|s| *s != sender);
    }
}

/// Убрать ожидателя из очереди гейта (таймаут/уничтожение).
pub fn gate_remove_receiver(id: u64, receiver: u64) {
    if let Some(mut gate) = gate_of(id)
        && let Some(gate) = gate.as_mut()
    {
        gate.receivers.retain(|r| *r != receiver);
    }
}

/// Очистить все очереди гейта от следов задачи (уничтожение задачи).
pub fn gate_purge_task(task_cap_id: u64) {
    for slot in GATES.iter() {
        let mut gate = slot.lock();
        if let Some(gate) = gate.as_mut() {
            gate.senders.retain(|s| *s != task_cap_id);
            gate.receivers.retain(|r| *r != task_cap_id);
        }
    }
}

/// Wait-объект гейта (зарезервированный диапазон — см. endpoint::
/// IPC_OBJECT_BASE). Используется только в диагностических целях:
/// участники спят на СОБСТВЕННЫХ объектах, гейт-объект никем не
/// занимается — зарезервирован, чтобы is_kernel_wait_object не отдавал
/// диапазон юзерспейсу.
pub fn gate_wait_object(gate_id: u64) -> usize {
    crate::ipc::endpoint::IPC_OBJECT_BASE + 0x2000 + (gate_id as usize & 0xFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Один последовательный тест (глобальная таблица — статик):
    /// аллокация, очереди FIFO, purge.
    #[test]
    fn gate_table_lifecycle() {
        let _guard = crate::test_guard::GLOBAL.lock();
        let id = gate_alloc().expect("слот гейта");
        let id2 = gate_alloc().expect("второй слот");
        assert_ne!(id, id2);

        // Очередь отправителей: FIFO до ёмкости.
        for i in 0..GATE_QUEUE_CAP {
            assert!(gate_push_sender(id, 100 + i as u64).is_ok());
        }
        assert_eq!(gate_push_sender(id, 999), Err(()));
        assert!(gate_has_senders(id));
        assert_eq!(gate_pop_sender(id), Some(100));
        assert_eq!(gate_pop_sender(id), Some(101));

        // Очередь ожидателей: FIFO + unpop в голову + дубликат.
        assert!(gate_push_receiver(id, 500).is_ok());
        assert!(gate_push_receiver(id, 501).is_ok());
        assert!(gate_push_receiver(id, 500).is_ok(), "дубликат игнорируется");
        assert_eq!(gate_pop_receiver(id), Some(500));
        gate_unpop_receiver(id, 500);
        assert_eq!(gate_pop_receiver(id), Some(500));
        assert_eq!(gate_pop_receiver(id), Some(501));
        assert_eq!(gate_pop_receiver(id), None);

        // Purge задачи из всех очередей (перед этим добьём остатки
        // отправителей из фазы заполнения, чтобы проверка была чистой).
        while gate_pop_sender(id).is_some() {}
        gate_push_sender(id, 777).ok();
        gate_push_receiver(id, 777).ok();
        gate_purge_task(777);
        assert!(!gate_has_senders(id));
        assert_eq!(gate_pop_receiver(id), None);

        // Мёртвый id — мягкие отказы.
        let dead = MAX_GATES as u64 + 100;
        assert!(gate_push_sender(dead, 1).is_err());
        assert_eq!(gate_pop_sender(dead), None);
        assert!(!gate_has_senders(dead));

        // Исчерпание таблицы: MAX_GATES-2 уже занято, добиваем.
        let mut allocated = 2usize;
        while gate_alloc().is_some() {
            allocated += 1;
        }
        assert_eq!(allocated, MAX_GATES);
        assert_eq!(gate_alloc(), None);
    }
}
