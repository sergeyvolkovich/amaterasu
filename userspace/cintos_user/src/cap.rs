//! cap — capability-операции юзерспейса (NR 16..26 + монтаж NR 7/8).
//!
//! Всё создание кап адресуется TaskTCB-капами ([`TaskCap`]) в cspace
//! ВЫЗЫВАЮЩЕГО (ambient authority закрыт: голые task_cap-id ядро не
//! принимает — `caller_controls_both`). Пересылка кап между задачами —
//! ТОЛЬКО через IPC map items (NR 24 CAP_TRANSFER удалён навсегда):
//! [`crate::ipc::CapDesc`] + приёмное окно получателя.
//!
//! Хендлы — типы [`crate::handle`]: слоты [`Slot`], id кап [`CapId`],
//! задачи [`TaskCap`], адреса [`Va`]/[`Phys`], счётчик [`Pages`].
//! Перепутать слот с капой/VA — ошибка компиляции, не runtime.
//!
//! Authority по операциям (namespace-права ВЫЗЫВАЮЩЕГО):
//!   - CAP_MANAGE: mmio/shared/irq/revoke/destroy/фолт-эндпоинт;
//!   - CAP_MINT: mint/clone;
//!   - MEMORY_ALLOC: ipc_pool; монтаж региона — MMIO_MAP у группы.
//!
//! Типичные потоки:
//! ```text
//! SHM:  mem::alloc_pages → create_shared → IPC (CapDesc SEND) →
//!       peer: mount_region → ... → unmount_region
//! MMIO: create_mmio (owner — себя или peer'а по его TaskTCB-капе) →
//!       owner: mount_region → unmount_region
//! ```

use crate::abi::nr;
use crate::fault;
use crate::handle::{CapId, Pages, Phys, Slot, TaskCap, Va};
use crate::syscall::{self, SyscallError};

// ─── Права ──────────────────────────────────────────────────────────────────

/// Прямые права DirectCapability-капы (wire-биты ядра: Clone=1,
/// Mint=2, Send=4). Mint не расширяет: копия ⊆ источника, иначе
/// E_RIGHTS_EXCEEDED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u64);

impl Rights {
    /// Clone: копия в той же мембране (CAP_CLONE).
    pub const CLONE: Self = Self(1 << 0);
    /// Mint: производная копия с сужением (CAP_MINT).
    pub const MINT: Self = Self(1 << 1);
    /// Send: пересылка map item'ом по IPC.
    pub const SEND: Self = Self(1 << 2);
    /// Полный набор (как у bootstrap-кап).
    pub const ALL: Self = Self(0b111);

    /// Из wire-битов (граница C-ABI/auxv; неизвестные биты маскируются).
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & 0b111)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    /// Сужение: убрать биты `other` (подготовка к mint производной).
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Групповые права неймспейса (зеркало NamespaceRights ядра, u16).
/// Потолок прав: создать неймспейс/выдать права можно только
/// подмножеством СВОИХ (иначе E_RIGHTS_DENIED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceRights(u64);

impl NamespaceRights {
    /// Спавн задач в неймспейс (TASK_CREATE/FROM_MEM).
    pub const TASK_CREATE: Self = Self(1 << 0);
    /// Бюджет памяти группы (ALLOC_PAGES и производные).
    pub const MEMORY_ALLOC: Self = Self(1 << 1);
    /// Монтаж MMIO/shared-регионов (MOUNT_CAP_REGION).
    pub const MMIO_MAP: Self = Self(1 << 2);
    /// Занятие IRQ/MSI-линий.
    pub const IRQ_BIND: Self = Self(1 << 3);
    pub const IPC_SEND: Self = Self(1 << 4);
    pub const CAP_TRANSFER: Self = Self(1 << 5);
    pub const CAP_MINT: Self = Self(1 << 6);
    pub const CAP_MANAGE: Self = Self(1 << 7);
    pub const DMA_ATTACH: Self = Self(1 << 8);
    pub const STATS_READ: Self = Self(1 << 9);
    pub const FAULT_HANDLE: Self = Self(1 << 10);
    /// Полный набор (bootstrap: корневой неймспейс).
    pub const ALL: Self = Self((1 << 11) - 1);

    /// Из wire-битов (граница C-ABI/auxv; неизвестные биты маскируются).
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & 0x7FF)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl core::ops::BitOr for NamespaceRights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for NamespaceRights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Триггер IRQ/MSI-линии (CAP_CREATE_IRQ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqTrigger {
    Edge,
    Level,
}

impl IrqTrigger {
    pub const fn bits(self) -> u64 {
        match self {
            Self::Edge => 0,
            Self::Level => 1,
        }
    }
}

// ─── Создание кап ───────────────────────────────────────────────────────────

/// CAP_CREATE_NAMESPACE(16): создать неймспейс (группу задач) +
/// корневую капу в `dst` ВЫЗЫВАЮЩЕГО. Возврат — [`CapId`] капы
/// неймспейса. `max_cap_objects` — квота cspace-записей/мембран:
/// капы бессмертны (tombstone/recycle), без лимита задача раздувает
/// kernel slab.
pub fn create_namespace(
    dst: Slot,
    max_task_count: u64,
    max_memory_bytes: u64,
    persistency_badge: u64,
    rights: NamespaceRights,
    max_cap_objects: u64,
) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall6(
            nr::CAP_CREATE_NAMESPACE,
            dst.raw(),
            max_task_count,
            max_memory_bytes,
            persistency_badge,
            rights.bits(),
            max_cap_objects,
        )
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_CREATE_IPC_POOL(17): капа на пул памяти IPC для задачи `owner`
/// ([`TaskCap`] в cspace вызывающего); капа кладётся в её слот `dst`.
pub fn create_ipc_pool(owner: TaskCap, dst: Slot) -> Result<CapId, SyscallError> {
    let code = unsafe { syscall::syscall2(nr::CAP_CREATE_IPC_POOL, owner.raw(), dst.raw()) };
    syscall::check(code).map(CapId::new)
}

/// CAP_CREATE_MMIO(18): капа на диапазон физической памяти
/// `[phys_origin, phys_origin + page_count * PAGE_SIZE)`; капа кладётся
/// в слот `dst` cspace `owner`. Диапазон обязан быть в allow-list ядра
/// (phys_guard), иначе E_RIGHTS_DENIED. Монтаж — [`mount_region`].
pub fn create_mmio(
    owner: TaskCap,
    phys_origin: Phys,
    page_count: Pages,
    dst: Slot,
) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall4(
            nr::CAP_CREATE_MMIO,
            owner.raw(),
            dst.raw(),
            phys_origin.raw(),
            page_count.raw(),
        )
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_CREATE_IRQ(19): капа на ЛОГИЧЕСКУЮ линию платформы (GSI/MSI).
/// Линия обязана быть свободна (иначе E_BUSY); успех — линия занята
/// владельцем, замаскирована до первого IRQ_WAIT, капа в `dst`
/// владельца. Специализация для тика таймера — [`crate::timer::claim_tick_line`].
pub fn create_irq(
    owner: TaskCap,
    line: u64,
    trigger: IrqTrigger,
    dst: Slot,
) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall4(
            nr::CAP_CREATE_IRQ,
            owner.raw(),
            dst.raw(),
            line,
            trigger.bits(),
        )
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_MINT(20): производная копия капы `src_slot` задачи `src_task`
/// в `dst_slot` задачи `dst_task` с правами ⊆ источника (обе стороны —
/// [`TaskCap`] в cspace ВЫЗЫВАЮЩЕГО). Возврат — [`CapId`] новой капы.
pub fn mint(
    src_task: TaskCap,
    src_slot: Slot,
    dst_task: TaskCap,
    dst_slot: Slot,
    rights: Rights,
) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall5(
            nr::CAP_MINT,
            src_task.raw(),
            src_slot.raw(),
            dst_task.raw(),
            dst_slot.raw(),
            rights.bits(),
        )
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_CLONE(21): копия капы в пределах той же мембраны (требует
/// право Clone у источника). Возврат — [`CapId`] копии.
pub fn clone(
    src_task: TaskCap,
    src_slot: Slot,
    dst_task: TaskCap,
    dst_slot: Slot,
) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall4(
            nr::CAP_CLONE,
            src_task.raw(),
            src_slot.raw(),
            dst_task.raw(),
            dst_slot.raw(),
        )
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_REVOKE(22): ревок мембраны слота — протухают сама запись и все
/// производные. Слот остаётся занятым (не резолвится).
pub fn revoke(task: TaskCap, slot: Slot) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall2(nr::CAP_REVOKE, task.raw(), slot.raw()) };
    syscall::check(code).map(|_| ())
}

/// CAP_DESTROY(23): ревок + tombstone записи НА МЕСТЕ (remove
/// запрещён — Chained-потомки держат указатель на запись; слот
/// переиспользуется через recycle при следующей установке).
pub fn destroy(task: TaskCap, slot: Slot) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall2(nr::CAP_DESTROY, task.raw(), slot.raw()) };
    syscall::check(code).map(|_| ())
}

/// CAP_CREATE_SHARED(25): капа на разделяемый регион СОБСТВЕННОЙ
/// памяти `[src_vaddr, src_vaddr + pages * PAGE_SIZE)` (ALLOC_PAGES →
/// сюда). Физику резолвит ядро; пересылка — IPC map item'ом, монтаж
/// получателем — [`mount_region`]. Возврат — [`CapId`].
pub fn create_shared(src_vaddr: Va, pages: Pages, dst: Slot) -> Result<CapId, SyscallError> {
    let code = unsafe {
        syscall::syscall3(nr::CAP_CREATE_SHARED, src_vaddr.raw(), pages.raw(), dst.raw())
    };
    syscall::check(code).map(CapId::new)
}

/// CAP_CREATE_FAULT_ENDPOINT(26): фолт-эндпоинт — фиксирует ТЕКУЩУЮ
/// задачу как обработчика (делегирует [`crate::fault::create_endpoint`];
/// привязка к цели — `fault::set_endpoint`).
pub fn create_fault_endpoint(dst: Slot) -> Result<(), SyscallError> {
    fault::create_endpoint(dst)
}

// ─── Монтаж регионов (группа памяти NR 7/8) ─────────────────────────────────

/// MOUNT_CAP_REGION(7): смонтировать капу-регион из СВОЕГО cspace
/// (пришедшую по IPC map item'у — слот из приёмного окна). Возврат —
/// [`Va`]. Группе нужен MMIO_MAP; адресация слотом (не голым id) —
/// ревок источника реально запрещает монтирование. Снять —
/// [`unmount_region`].
pub fn mount_region(cap_slot: Slot) -> Result<Va, SyscallError> {
    let code = unsafe { syscall::syscall1(nr::MOUNT_CAP_REGION, cap_slot.raw()) };
    syscall::check(code).map(Va::new)
}

/// UNMOUNT_CAP_REGION(8): снять отображение по базовому [`Va`]
/// (возврат [`mount_region`]).
pub fn unmount_region(vaddr: Va) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall1(nr::UNMOUNT_CAP_REGION, vaddr.raw()) };
    syscall::check(code).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_bit_arithmetic() {
        let r = Rights::CLONE | Rights::SEND;
        assert_eq!(r.bits(), 0b101);
        assert!(r.contains(Rights::CLONE));
        assert!(!r.contains(Rights::MINT));
        assert_eq!(r.without(Rights::SEND), Rights::CLONE);
        assert!(Rights::ALL.contains(Rights::MINT));
        assert!(!Rights::SEND.is_empty());
        assert!(Rights(0).is_empty());

        // from_bits маскирует неизвестные биты (граница C-ABI).
        assert_eq!(Rights::from_bits(0b10111), Rights::CLONE | Rights::MINT | Rights::SEND);

        let mut m = Rights::MINT;
        m |= Rights::SEND;
        assert_eq!(m, Rights::SEND | Rights::MINT);
    }

    #[test]
    fn namespace_rights_wire_bits() {
        // Биты — wire-формат ядра (NamespaceRights u16), менять нельзя.
        assert_eq!(NamespaceRights::TASK_CREATE.bits(), 1);
        assert_eq!(NamespaceRights::MMIO_MAP.bits(), 4);
        assert_eq!(NamespaceRights::CAP_MANAGE.bits(), 1 << 7);
        assert_eq!(NamespaceRights::FAULT_HANDLE.bits(), 1 << 10);
        assert_eq!(NamespaceRights::ALL.bits(), 0x7FF);
        assert!(NamespaceRights::ALL.contains(
            NamespaceRights::TASK_CREATE | NamespaceRights::MEMORY_ALLOC
        ));
        assert_eq!(NamespaceRights::from_bits(0xFFFF), NamespaceRights::ALL);
    }

    #[test]
    fn irq_trigger_wire() {
        assert_eq!(IrqTrigger::Edge.bits(), 0);
        assert_eq!(IrqTrigger::Level.bits(), 1);
    }
}
