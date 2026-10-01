//! mem — сырая память задачи (группа NR 5..8 ABI).
//!
//! ALLOC_PAGES выделяет страницы СРАЗУ замапленными в адресное
//! пространство задачи — это НЕ mmap: физических адресов задача не
//! узнаёт, фреймы выбирает ядро (возврат — [`Va`]). FREE_PAGES
//! снимает аллокацию по базовому VA; регион под IOMMU-пином
//! (DMA-buf) освободить нельзя — E_BUSY (сначала UnmapDma).
//!
//! Типичные продолжения: [`crate::cap::create_shared`] (SHM: отправка
//! peer'у map item'ом → его `cap::mount_region`) и
//! [`crate::cap::create_mmio`] (устройства: капа на диапазон →
//! `cap::mount_region`). Куча поверх ALLOC_PAGES — [`crate::heap`].

use crate::abi::nr;
use crate::handle::{Pages, Va};
use crate::syscall::{self, SyscallError};

/// Выделить `pages` страниц; возврат — базовый [`Va`] (выровнен на
/// страницу). Ядро само выбирает фреймы и мапит в VMA задачи.
pub fn alloc_pages(pages: Pages) -> Result<Va, SyscallError> {
    let code = unsafe { syscall::syscall1(nr::ALLOC_PAGES, pages.raw()) };
    syscall::check(code).map(Va::new)
}

/// Снять аллокацию по базовому [`Va`] (тому, что вернул
/// [`alloc_pages`]). Пин IOMMU → E_BUSY.
pub fn free_pages(vaddr: Va) -> Result<(), SyscallError> {
    let code = unsafe { syscall::syscall1(nr::FREE_PAGES, vaddr.raw()) };
    syscall::check(code).map(|_| ())
}
