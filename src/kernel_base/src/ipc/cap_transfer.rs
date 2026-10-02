//! Пересылка capability через IPC.
//!
//! Механизм, которым IPC-транспорт (SyscallIPCSend/SyscallIPCWait)
//! доставляет capability вместе с сообщением. Транспорт кладёт в сообщение
//! дескрипторы `CapTransferSpec` (какой слот отправителя в какой слот
//! получателя, с какими правами), а доставку выполняет
//! [`transfer_capability`].
//!
//! Модель безопасности пересылки (обе стороны проверяются НЕЗАВИСИМО):
//!   1. Отправитель: у его записи в src_slot есть право Send
//!      (LinkedRecord::check_send), запрошенные права не превышают
//!      доступных; его namespace даёт IPC_SEND + CAP_TRANSFER.
//!   2. Получатель: его namespace должен покрывать малогранулярное право
//!      класса ресурса (CapabilityObject::required_namespace_rights) —
//!      приоритет неймспейса работает и на приёме: поток из группы без
//!      IRQ_BIND не получит IRQ-капабилити, даже если отправитель успел
//!      её послать.
//!   3. Копия ставится под мембрану слота получателя (transfer_flattened):
//!      стороны ревокаются независимо, расширение прав при пересылке
//!      невозможно. Копия — ВСЕГДА flatten (прямая ссылка на зиготу,
//!      без цепочки в capspace отправителя): иначе дроп GTcb отправителя
//!      (уничтожение задачи) оставил бы в копии получателя сырой
//!      NonNull в возвращённую системе slab-память — use-after-free
//!      с эскалацией прав (см. LinkedRecord — жизненный цикл).
//!
//! КОНТРАКТ БЕЗОПАСНОСТИ: функция рассчитана на вызов под захваченным
//! permission_backend (AccessManager)-локом — тем же, что держат сисколлы
//! и будущий IPC-транспорт. Он исключает гонки capspace и уничтожение
//! задач между фазами (отправитель -> получатель).

use attachable_slab_allocator::SlabError;

use crate::{
    access::{
        AccessManager,
        capability::{CapFault, DirectCapabilityRights},
        capspace,
        namespace::NamespaceRights,
    },
    traits::memory::MemoryInterfaceUserspace,
};

/// Дескриптор пересылки одной capability внутри IPC-сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapTransferSpec {
    /// Слот cspace отправителя, из которого берётся capability.
    pub src_slot: u64,
    /// Слот cspace получателя, куда кладётся копия.
    pub dst_slot: u64,
    /// Права, запрошенные для копии (не могут превысить права источника).
    pub rights: DirectCapabilityRights,
}

#[derive(Debug)]
pub enum CapTransferError {
    /// Задача-отправитель не найдена / её TaskTCB отозван.
    SenderTaskNotFound,
    /// Задача-получатель не найдена / её TaskTCB отозван.
    ReceiverTaskNotFound,
    /// Namespace отправителя не даёт IPC_SEND + CAP_TRANSFER.
    SenderRightsDenied,
    /// Namespace получателя не покрывает право класса пересылаемого
    /// ресурса (приоритет неймспейса над правами потока).
    ReceiverRightsDenied(NamespaceRights),
    /// В src_slot отправителя нет capability.
    SenderSlotEmpty,
    /// Capability отправителя отозвана (зигота затумбстоунена/переиспользована,
    /// мембрана ревокнута).
    CapRevoked,
    /// Запрошенные права превышают доступные.
    RightsExceeded,
    /// В dst_slot получателя уже есть capability.
    ReceiverSlotOccupied,
    /// Исчерпана квота cap-объектов неймспейса получателя
    /// (записи/мембраны бессмертны — см. Namespace::max_cap_objects).
    Quota,
    /// Ошибка slab-аллокатора при создании мембраны/записи получателя.
    Slab(SlabError),
}

impl From<CapFault> for CapTransferError {
    fn from(fault: CapFault) -> Self {
        match fault {
            CapFault::Revoked => CapTransferError::CapRevoked,
            CapFault::RightsExceeded => CapTransferError::RightsExceeded,
        }
    }
}

impl From<capspace::CapspaceError> for CapTransferError {
    fn from(e: capspace::CapspaceError) -> Self {
        match e {
            capspace::CapspaceError::SlotOccupied => CapTransferError::ReceiverSlotOccupied,
            capspace::CapspaceError::SlotEmpty => CapTransferError::SenderSlotEmpty,
            capspace::CapspaceError::Slab(e) => CapTransferError::Slab(e),
            capspace::CapspaceError::Quota => CapTransferError::Quota,
        }
    }
}

/// Пересылает capability от задачи-отправителя задаче-получателю.
///
/// Вызывать под permission_backend-локом (см. модульный комментарий).
/// Возврат Ok означает, что копия уже лежит в cspace получателя —
/// транспорт после этого лишь доставляет само тело сообщения.
pub fn transfer_capability<UMAP: MemoryInterfaceUserspace>(
    access: &AccessManager<UMAP>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    spec: CapTransferSpec,
) -> Result<(), CapTransferError> {
    validate_transfer(access, sender_task_cap, receiver_task_cap, &spec)?;
    execute_transfer(access, sender_task_cap, receiver_task_cap, &spec)
}

/// Фазы 1-3 пересылки без побочных эффектов: группы/права/слоты обеих
/// сторон проверяются, НИЧЕГО не создаётся. Выделяется отдельно, чтобы
/// IPC-транспорт мог провалидировать ВСЕ дескрипторы сообщения до
/// первого мутабельного шага — сообщение с N capability либо доходит
/// целиком, либо не трогает cspace получателя вовсе (кроме редких
/// slab-отказов на фазе исполнения).
pub fn validate_transfer<UMAP: MemoryInterfaceUserspace>(
    access: &AccessManager<UMAP>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    spec: &CapTransferSpec,
) -> Result<(), CapTransferError> {
    // ── Фаза 1: группы отправителя и получателя ──
    let sender_namespace = access
        .task_namespace(sender_task_cap)
        .ok_or(CapTransferError::SenderTaskNotFound)?;
    sender_namespace
        .check_rights(NamespaceRights::IPC_SEND | NamespaceRights::CAP_TRANSFER)
        .map_err(|_| CapTransferError::SenderRightsDenied)?;

    let receiver_namespace = access
        .task_namespace(receiver_task_cap)
        .ok_or(CapTransferError::ReceiverTaskNotFound)?;

    let sender_gtcb = access
        .get_task_tcb(sender_task_cap)
        .ok_or(CapTransferError::SenderTaskNotFound)?;
    access
        .get_task_tcb(receiver_task_cap)
        .ok_or(CapTransferError::ReceiverTaskNotFound)?;

    // SAFETY: под permission_backend-локом уничтожение задач (которое
    // освобождает GTcb из slab) невозможно — контракт модуля.
    let sender_gtcb = unsafe { sender_gtcb.as_ref() };

    // ── Фаза 2: слот отправителя — права и класс ресурса ──
    let required_namespace_rights = {
        let sender_caps = sender_gtcb.capspace().lock();
        let record = sender_caps
            .get(&spec.src_slot)
            .ok_or(CapTransferError::SenderSlotEmpty)?;

        // Право Send + потолок прав на копию (без расширения прав).
        let sendable = record.check_send()?;
        if !sendable.contains(spec.rights) {
            return Err(CapTransferError::RightsExceeded);
        }

        let (object, _) = record.resolve()?;
        object.required_namespace_rights()
    };

    // ── Фаза 3: группа получателя (приоритет неймспейса на приёме) ──
    receiver_namespace
        .check_rights(required_namespace_rights)
        .map_err(|_| CapTransferError::ReceiverRightsDenied(required_namespace_rights))?;

    // ── Фаза 3b: занятость слота получателя (ДО мутаций) ──
    // Без этой проверки occupancy обнаруживается только на исполнении,
    // когда первые capability сообщения УЖЕ легли в cspace получателя:
    // сообщение отбрасывается, а записи остаются — получатель не узнаёт
    // ни про записи, ни про отброшенное сообщение. Живой слот — ошибка
    // заранее; затумбстоуненный — разрешён (put_linked_record рекайклит
    // его на месте, bump generation протухает старых потомков).
    let receiver_ptr = access
        .get_task_tcb(receiver_task_cap)
        .ok_or(CapTransferError::ReceiverTaskNotFound)?;
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let receiver_gtcb = unsafe { receiver_ptr.as_ref() };
    {
        let receiver_caps = receiver_gtcb.capspace().lock();
        if let Some(existing) = receiver_caps.get(&spec.dst_slot)
            && existing.is_live()
        {
            return Err(CapTransferError::ReceiverSlotOccupied);
        }
    }

    Ok(())
}

/// Фаза 4: мембрана слота получателя + копия + запись. Вызывать ТОЛЬКО
/// после успешной validate_transfer (и под тем же локом — между
/// валидацией и исполнением права не должны меняться).
fn execute_transfer<UMAP: MemoryInterfaceUserspace>(
    access: &AccessManager<UMAP>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    spec: &CapTransferSpec,
) -> Result<(), CapTransferError> {
    let sender_gtcb = access
        .get_task_tcb(sender_task_cap)
        .ok_or(CapTransferError::SenderTaskNotFound)?;
    let receiver_gtcb = access
        .get_task_tcb(receiver_task_cap)
        .ok_or(CapTransferError::ReceiverTaskNotFound)?;

    // SAFETY: под permission_backend-локом (контракт модуля).
    let sender_gtcb = unsafe { sender_gtcb.as_ref() };
    let receiver_gtcb = unsafe { receiver_gtcb.as_ref() };

    // ── Фаза 4: мембрана слота получателя + flatten-копия + запись ──
    // Порядок локов: capspace отправителя (уже отпущен) ->
    // cap_list получателя; обратного порядка в коде нет.
    // Flatten обязателен: копия ссылается прямо на зиготу (глобальный
    // AccessManager, адрес стабилен), НЕ на запись отправителя — дроп
    // GTcb отправителя безопасен. Квота cap-объектов — по неймспейсу
    // ПОЛУЧАТЕЛЯ (объекты создаются в его capspace/cap_list).
    let receiver_ns = access.task_namespace(receiver_task_cap);
    let copy = {
        let sender_caps = sender_gtcb.capspace().lock();
        let record = sender_caps
            .get(&spec.src_slot)
            .ok_or(CapTransferError::SenderSlotEmpty)?;
        let membrane = capspace::ensure_slot_membrane(
            receiver_gtcb,
            spec.dst_slot,
            spec.rights,
            receiver_ns,
        )?;
        record.transfer_flattened(spec.rights, membrane)?
    };
    capspace::put_linked_record(receiver_gtcb, spec.dst_slot, copy, receiver_ns)?;

    Ok(())
}

/// Мульти-пересылка: все дескрипторы IPC-сообщения одной транзакцией.
///
/// Сначала [`validate_transfer`] КАЖДОГО спека (без мутаций), затем
/// [`execute_transfer`] каждого: сообщение не оставляет половину
/// capability у получателя из-за невалидного N-го дескриптора. Ошибка
/// валидации возвращает индекс виновного спека; ошибка исполнения
/// (slab-отказ — исчерпание памяти) тоже возвращает индекс, но часть
/// предыдущих копий могла уже встать (логируется вызывающим).
pub fn transfer_capabilities<UMAP: MemoryInterfaceUserspace>(
    access: &AccessManager<UMAP>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    specs: &[CapTransferSpec],
) -> Result<(), (usize, CapTransferError)> {
    for (i, spec) in specs.iter().enumerate() {
        validate_transfer(access, sender_task_cap, receiver_task_cap, spec)
            .map_err(|e| (i, e))?;
    }
    for (i, spec) in specs.iter().enumerate() {
        execute_transfer(access, sender_task_cap, receiver_task_cap, spec)
            .map_err(|e| (i, e))?;
    }
    Ok(())
}
