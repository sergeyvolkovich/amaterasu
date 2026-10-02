//! Capspace — пространство capability конкретной задачи.
//!
//! Слот задачи состоит из двух половин (обе живут в GTcb):
//!   - `GTcb::cap_list()`  — мембрана слота (RBSlabIO<u64, CapabilityMembrane>):
//!     граница авторитета, через которую REVOK-ается всё, что выдано в слот;
//!   - `GTcb::capspace()`  — сама capability (RBSlabIO<u64, LinkedRecord>):
//!     запись с правами и целью (зигота объекта или цепочка до неё).
//!
//! ЖИЗНЕННЫЙ ЦИКЛ СЛОТОВ (критично — см. LinkedRecord): записи capspace
//! НИКОГДА не удаляются физически (remove → slab-freelist → переиспользование
//! памяти под чужую запись → UAF/ABA для Chained-потомков). Снятие —
//! tombstone на месте; переустановка — recycle того же слота (bump
//! generation протухает старых потомков). Память capspace возвращается
//! системе только вместе с GTcb — что безопасно, поскольку кросс-задачных
//! Chained-ссылок не существует (flatten-копии ссылаются прямо на зиготу,
//! которая живёт в глобальном AccessManager и никогда не переезжает).
//!
//! Корневая capability слота (install_root_capability) кладётся под
//! собственную мембрану слота — revoke() мембраны убивает и корень, и все
//! производные копии. Производные записи (mint/clone/пересылка по IPC)
//! цепляются либо под ЧУЖУЮ мембрану (clone — мембрану источника, приёмник
//! IPC — мембрану своего слота), поэтому:
//!   1. remove (фактическое освобождение слота) для мембран запрещён:
//!      производные записи хранят NonNull на мембрану; слот снимается
//!      только через revoke-семантику (см. take_slot);
//!   2. записи LinkedRecord, снятые со слота, остаются в памяти
//!      (tombstone) — на них могут ссылаться Chained-потомки, проверяющие
//!      live/generation при resolve().
//!
//! ЗАЩИТА ОТ ГОНок (races): все функции рассчитаны на вызов под захваченным
//! `permission_backend` (AccessManager) — там, где сидят сисколлы и IPC-путь.
//! Вложенность локов строго в одну сторону (capspace -> cap_list: take_slot,
//! revoke_slot, фаза отправителя в ipc::cap_transfer); cap_list без
//! удерживаемого capspace берут только install_root/ensure_slot_membrane.
//! Обратного порядка нигде нет, поэтому циклов в порядке локов не возникает.
//!
//! РЕФКАУНТ КАП ГЕЙТА (ipc::gate): установка записи с прямой ссылкой на
//! зиготу IpcGate (install_root_capability / put_linked_record) берёт
//! ссылку (gate_cap_retain), снятие (take_slot) возвращает её
//! (gate_cap_release — последняя автоматически уничтожает гейт). Лок
//! шарда гейта — под локами capspace (permission_backend → gate —
//! порядок шапки ipc::gate); цепочки (Chained, mint в пределах одного
//! cspace) ссылок не берут — их жизнь ограничена tombstone родителя.

use core::ptr::NonNull;

use attachable_slab_allocator::SlabError;

use crate::{
    access::capability::{CapabilityMembrane, CapabilityZygote, LinkedRecord},
    access::namespace::Namespace,
    task::tcb::GTcb,
    traits::memory::MemoryInterfaceUserspace,
};

#[derive(Debug)]
pub enum CapspaceError {
    /// В слоте уже есть capability (или мембрана) — повторная установка.
    SlotOccupied,
    /// Слот пуст — снимать/ревокать нечего.
    SlotEmpty,
    /// Ошибка slab-аллокатора при вставке мембраны/записи.
    Slab(SlabError),
    /// Исчерпана квота kernel-объектов capability неймспейса
    /// (Namespace::max_cap_objects): запись/мембрана НЕ созданы.
    Quota,
}

/// Резервирует учёт cap-объекта против квоты неймспейса (если он известен).
fn reserve_cap_object(ns: Option<&Namespace>) -> Result<(), CapspaceError> {
    match ns {
        Some(ns) => ns.try_reserve_cap_object().map_err(|_| CapspaceError::Quota),
        None => Ok(()),
    }
}

/// Устанавливает корневую capability на свежесозданный (или
/// переиспользованный через recycle) объект в слот задачи.
///
/// Мембрана слота создаётся при первой установке и живёт вечно вместе со
/// слотом (см. модульный комментарий): при повторной установке в слот,
/// уже имевший мембрану, используется она — итоговые права записи при
/// resolve() пересекутся с её (возможно более узким) потолком.
///
/// Права `rights` становятся и правами записи (acc), и стартовым потолком
/// мембраны. Вызывается сисколлами создания capability (DomainCapability)
/// после AccessManager::create_new_object + get_zygote, под
/// permission_backend-локом.
///
/// `ns` — неймспейс ВЛАДЕЛЬЦА слота (для квоты cap-объектов): None —
/// учёт недоступен (ранний бут — квота не применяется).
pub fn install_root_capability<UMAP: MemoryInterfaceUserspace>(
    gtcb: &GTcb<UMAP>,
    slot: u64,
    zygote: NonNull<CapabilityZygote<UMAP>>,
    rights: crate::access::capability::DirectCapabilityRights,
    ns: Option<&Namespace>,
) -> Result<(), CapspaceError> {
    let membrane_ptr = {
        let mut membranes = gtcb.cap_list().lock();
        match membranes.get(&slot) {
            Some(existing) => NonNull::from(existing),
            None => {
                // НОВОЯ мембрана: зарядить квоту (при отказе аллокации —
                // вернуть учёт).
                reserve_cap_object(ns)?;
                if let Err(e) = membranes.insert(slot, CapabilityMembrane::new_root(rights)) {
                    if let Some(ns) = ns {
                        ns.release_cap_object();
                    }
                    return Err(CapspaceError::Slab(e));
                }
                NonNull::from(membranes.get(&slot).expect("мембрана только что вставлена"))
            }
        }
    };

    let mut caps = gtcb.capspace().lock();
    if let Some(existing) = caps.get(&slot) {
        // Слот уже существует: ЖИВОЙ — занят; ЗАТУМБСТОЕНЕННЫЙ —
        // переиспользуется НА МЕСТЕ (recycle): память слота не отдавалась
        // в slab (см. take_slot), Chained-потомки прежней записи протухают
        // по bump generation внутри recycle.
        if existing.is_live() {
            return Err(CapspaceError::SlotOccupied);
        }
        existing.recycle_as_root(zygote, membrane_ptr, rights);
        // РЕФКАУНТ ГЕЙТОВ: новая живая запись — новая ссылка на гейт
        // (последняя снятая ссылка уничтожает гейт — см. ipc::gate).
        retain_gate_of(zygote);
        return Ok(());
    }
    // НОВОЯ запись: зарядить квоту (при отказе аллокации — вернуть учёт).
    reserve_cap_object(ns)?;
    let record = LinkedRecord::new_root(zygote, membrane_ptr, rights);
    // Маршрут гейта снимается ДО вставки: после неё тело записи
    // принадлежит slab-дереву, а владение ссылкой начинается только с
    // успешной установки (при Slab-откате ссылка не берётся вовсе).
    let gate_route = unsafe { zygote.as_ref() }.gate_route();
    if let Err(e) = caps.insert(slot, record) {
        if let Some(ns) = ns {
            ns.release_cap_object();
        }
        return Err(CapspaceError::Slab(e));
    }
    if let Some((gate_id, generation)) = gate_route {
        crate::ipc::gate::gate_cap_retain(gate_id, generation);
    }
    Ok(())
}

/// Рефкаунт гейтов для переиспользованной (recycle) записи: маршрут
/// снимается с зиготы, на которую заново смотрит запись. Отказ retain
/// (гейт уже мёртв) — не ошибка установки: капа протухшая, все операции
/// по ней ответят E_CAP_REVOKED (resolve_ipc_gate не резолвит мёртвый
/// слот). Зиготы не переезжают и не освобождаются — разыменование
/// безопасно под permission_backend-локом (контракт модуля).
fn retain_gate_of<UMAP: MemoryInterfaceUserspace>(
    zygote: NonNull<crate::access::capability::CapabilityZygote<UMAP>>,
) {
    if let Some((gate_id, generation)) = unsafe { zygote.as_ref() }.gate_route() {
        crate::ipc::gate::gate_cap_retain(gate_id, generation);
    }
}

/// Кладёт ГОТОВУЮ запись (mint/clone/transfer_flattened) в слот-приёмник.
/// В отличие от install_root_capability НЕ трогает cap_list: производная
/// запись уже несёт мембрану (свою новую — у приёмника IPC, или чужую —
/// у clone).
pub fn put_linked_record<UMAP: MemoryInterfaceUserspace>(
    gtcb: &GTcb<UMAP>,
    slot: u64,
    record: LinkedRecord<UMAP>,
    ns: Option<&Namespace>,
) -> Result<(), CapspaceError> {
    // РЕФКАУНТ ГЕЙТОВ: маршрут гейта (если запись — flatten-копия
    // гейт-капы: передача по IPC, кросс-задачный mint/clone) снимается
    // ДО вставки. Chained-записи дают None — собственных ссылок они не
    // берут (их жизнь ограничена tombstone родителя).
    let gate_route = record.gate_route_of();
    let mut caps = gtcb.capspace().lock();
    if let Some(existing) = caps.get(&slot) {
        // Живой слот — занят; затумбстоуненный — recycle на месте телом
        // входящей записи (см. LinkedRecord — жизненный цикл слотов).
        if existing.is_live() {
            return Err(CapspaceError::SlotOccupied);
        }
        existing.recycle_as(&record);
        if let Some((gate_id, generation)) = gate_route {
            crate::ipc::gate::gate_cap_retain(gate_id, generation);
        }
        return Ok(());
    }
    // НОВОЯ запись: зарядить квоту (при отказе аллокации — вернуть учёт).
    reserve_cap_object(ns)?;
    if let Err(e) = caps.insert(slot, record) {
        if let Some(ns) = ns {
            ns.release_cap_object();
        }
        return Err(CapspaceError::Slab(e));
    }
    // Вставка удалась — запись владеет ссылкой; при Slab-откате ссылка
    // не берётся (владение начинается с успешной установки).
    if let Some((gate_id, generation)) = gate_route {
        crate::ipc::gate::gate_cap_retain(gate_id, generation);
    }
    Ok(())
}

/// Достаёт или создаёт мембрану слота-приёмника (для минта и IPC-пересылки).
/// Уже существующая мембрана переиспользуется как есть: потолок прав может
/// быть уже запрошенного — сузит итоговые права при resolve(), расширить
/// её отсюда нельзя (монотонность мембран).
pub fn ensure_slot_membrane<UMAP: MemoryInterfaceUserspace>(
    gtcb: &GTcb<UMAP>,
    slot: u64,
    ceiling: crate::access::capability::DirectCapabilityRights,
    ns: Option<&Namespace>,
) -> Result<NonNull<CapabilityMembrane>, CapspaceError> {
    let mut membranes = gtcb.cap_list().lock();
    if let Some(existing) = membranes.get(&slot) {
        return Ok(NonNull::from(existing));
    }
    // НОВОЯ мембрана: зарядить квоту (при отказе аллокации — вернуть учёт).
    reserve_cap_object(ns)?;
    if let Err(e) = membranes.insert(slot, CapabilityMembrane::new_root(ceiling)) {
        if let Some(ns) = ns {
            ns.release_cap_object();
        }
        return Err(CapspaceError::Slab(e));
    }
    Ok(NonNull::from(
        membranes
            .get(&slot)
            .expect("мембрана только что вставлена"),
    ))
}

/// Снимает capability со слота (ЛОГИЧЕСКИ — tombstone НА МЕСТЕ).
///
/// ПАМЯТЬ СЛОТА НЕ ОСВОБОЖДАЕТСЯ: remove() из RBSlabIO здесь запрещён —
/// слот ушёл бы в slab-freelist, а Chained-потомки держат сырой NonNull
/// на запись (переиспользование памяти под чужую запись = ABA/UAF и
/// эскалация прав). Снятая запись остаётся в дереве с live=false;
/// потомки протухают по tombstone (bump generation) или по ревоку
/// собственной мембраны ниже. Переустановка слота — через
/// install_root/put, рекайклящие мёртвый слот на месте.
///
/// - если слот владеет своей мембраной (корневая установка или пересылка
///   по IPC) — мембрана ревокается: все производные копии (mint/clone,
///   сделанные из этого слота) логически протухают ещё до снятия записи;
/// - если мембрана ЧУЖАЯ (слот - приёмник clone) — чужой revoke() не
///   трогаем, снимается только сама запись (её потомки протухают по
///   tombstone).
pub fn take_slot<UMAP: MemoryInterfaceUserspace>(
    gtcb: &GTcb<UMAP>,
    slot: u64,
) -> Result<(), CapspaceError> {
    let owns_membrane = {
        let caps = gtcb.capspace().lock();
        let record = caps.get(&slot).ok_or(CapspaceError::SlotEmpty)?;
        if !record.is_live() {
            // Повторный destroy затумбстоуненного слота — прежняя
            // семантика SlotEmpty (id не переустанавливается молча).
            return Err(CapspaceError::SlotEmpty);
        }
        let record_membrane = record.membrane_ptr().as_ptr();
        let own_membrane = gtcb
            .cap_list()
            .lock()
            .get(&slot)
            .map(|m| m as *const CapabilityMembrane as *mut CapabilityMembrane);
        own_membrane == Some(record_membrane)
    };

    let caps = gtcb.capspace().lock();
    let record = caps.get(&slot).ok_or(CapspaceError::SlotEmpty)?;

    if owns_membrane {
        // Мембрана гарантированно существует: она создаётся вместе с
        // первой записью слота и никогда не удаляется.
        gtcb
            .cap_list()
            .lock()
            .get(&slot)
            .expect("собственная мембрана слота не может исчезнуть")
            .revoke();
    }

    // РЕФКАУНТ ГЕЙТОВ: запись умирает — вернуть её ссылку (если это была
    // гейт-капа). Последняя ссылка уничтожает гейт автоматически
    // (ipc::gate::gate_cap_release: alive=false + gen++ + id в пул).
    // Маршрут снимается ДО tombstone; мембраны сознательно не
    // проверяются (идентичность, не авторитет — см.
    // LinkedRecord::gate_route_of): мембранно-ревокнутая, но живая
    // запись всё ещё владеет ссылкой. Протухшие записи (зигота
    // переиспользована) дают None — ссылкой на текущую жизнь слота они
    // не владеют.
    if let Some((gate_id, generation)) = record.gate_route_of() {
        crate::ipc::gate::gate_cap_release(gate_id, generation);
    }

    // Tombstone на месте: потомки обнаружат смерть по live/generation.
    record.tombstone();
    Ok(())
}

/// Ревокает слот, НЕ снимая запись (лёгкая "убить всё в слоте" операция):
/// ревок собственной мембраны делает недействительной и саму запись слота,
/// и все производные. Для слота-приёмника clone ревокать чужую мембрану
/// нельзя — возвращается SlotEmpty-подобная семантика (см. ошибку).
pub fn revoke_slot<UMAP: MemoryInterfaceUserspace>(
    gtcb: &GTcb<UMAP>,
    slot: u64,
) -> Result<(), CapspaceError> {
    let owns_membrane = {
        let caps = gtcb.capspace().lock();
        let record = caps.get(&slot).ok_or(CapspaceError::SlotEmpty)?;
        if !record.is_live() {
            // Затумбстоуненный слот: ревокать нечего (прежде слот был
            // физически пуст — семантика сохранена).
            return Err(CapspaceError::SlotEmpty);
        }
        let record_membrane = record.membrane_ptr().as_ptr();
        let own_membrane = gtcb
            .cap_list()
            .lock()
            .get(&slot)
            .map(|m| m as *const CapabilityMembrane as *mut CapabilityMembrane);
        own_membrane == Some(record_membrane)
    };

    if !owns_membrane {
        return Err(CapspaceError::SlotEmpty);
    }

    gtcb
        .cap_list()
        .lock()
        .get(&slot)
        .expect("собственная мембрана слота не может исчезнуть")
        .revoke();
    Ok(())
}
