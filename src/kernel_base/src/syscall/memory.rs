//! Домен memory-сисколлов: динамическая память и MMIO задачи.
//!
//!   5 ALLOC_PAGES { pages } — выделить `pages` страниц (квота группы
//!     заряжается через VmapRegion::alloc_with_quota), возврат — VA.
//!   6 FREE_PAGES { vaddr } — снять аллокацию по её базовому VA
//!     (размапинг, возврат фреймов, возврат квоты).
//!   7 MOUNT_CAP_REGION { cap_id } — отобразить MMIO-регион из
//!     capability (глобальный id, получен от CAP_CREATE_MMIO) в свежее
//!     окно задачи; фреймы НЕ выделяются. Возврат — VA.
//!   8 UNMOUNT_CAP_REGION { vaddr } — снять MMIO-отображение (без
//!     возврата фреймов — они не принадлежат задаче).
//!
//! Прежние имена Extend/DecreaseMemoryRegion отражали несуществующий
//! API (расширить bump-регион нельзя — VA-окно не смежно); заглушки
//! E_NOT_IMPLEMENTED заменены на честные операции над VmapRegion.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    traits::{
        ArchImplementation,
        memory::{MemoryFlags, MemoryPTR, PAGE_SIZE},
        syscall::{SyscallDomain, syscall_result as res},
    },
};

#[derive(SyscallArguments)]
pub struct SyscallAllocPages {
    pages: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallFreePages {
    vaddr: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallMountCapRegion {
    /// СЛОТ cspace ВЫЗЫВАЮЩЕГО с MMIO-капабилити (ранее — голый
    /// глобальный id: обходил capability-модель — ревок не влиял на
    /// монтирование, чужие регионы мапились по угадываемым id).
    cap_slot: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallUnmountCapRegion {
    /// Базовый VA смонтированного региона (возврат MOUNT_CAP_REGION).
    vaddr: u64,
}

pub struct DomainMemory<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainMemory<A, Handler> {
    pub const fn new(hanlder: &'static KernelCTL<A>) -> Self {
        Self(hanlder, PhantomData)
    }
}

fn alloc_result(r: Result<crate::umap::VmapHandle, crate::umap::VmapError>) -> u64 {
    match r {
        Ok(handle) => handle.virt_base() as u64,
        Err(crate::umap::VmapError::ZeroPages) => res::E_INVALID_ARG,
        Err(crate::umap::VmapError::OutOfVirtualSpace) => res::E_IDS_EXHAUSTED,
        Err(crate::umap::VmapError::AddressOverflow) => res::E_INVALID_ARG,
        Err(crate::umap::VmapError::Frame(_)) => res::E_SLAB,
        Err(crate::umap::VmapError::NotTracked) => res::E_NOT_FOUND,
        Err(crate::umap::VmapError::ExternalMismatch) => res::E_INVALID_ARG,
        Err(crate::umap::VmapError::Quota(_)) => res::E_QUOTA,
        Err(crate::umap::VmapError::QuotaMissing) => res::E_INTERNAL,
        Err(crate::umap::VmapError::Slab(_)) => res::E_SLAB,
    }
}

fn free_result(r: Result<(), crate::umap::VmapError>) -> u64 {
    match r {
        Ok(()) => res::OK,
        Err(crate::umap::VmapError::NotTracked) => res::E_NOT_FOUND,
        Err(crate::umap::VmapError::ExternalMismatch) => res::E_INVALID_ARG,
        Err(e) => alloc_result(Err(e)),
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainMemory<A, SyscallAllocPages> {
    const SYSCALL_ID: usize = 5;
    type Args = SyscallAllocPages;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.pages == 0 || args.pages > (1 << 20) {
            return res::E_INVALID_ARG;
        }
        let Some(frames) = crate::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        let access = self.0.permission_backend.lock();
        // Групповой потолок: память в этой группе вообще можно выделять?
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::MEMORY_ALLOC)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        // Квота группы: аллокация заряжается и возвращается при free.
        // NX ПО УМОЛЧАНИЮ: куча задачи не должна быть исполняемой
        // (W+X на выданных страницах = тривиальная посада кода; исполняемое
        // ставит только ELF-загрузчик, со своими флагами сегментов).
        let namespace = access.task_namespace(current);
        alloc_result(gtcb.vmap().alloc_with_quota(
            gtcb.userspace_map(),
            frames,
            args.pages as usize,
            MemoryFlags::NO_EXECUTE, // RW + user + NX
            match namespace {
                Some(ns) => ns,
                None => return res::E_INTERNAL,
            },
        ))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainMemory<A, SyscallFreePages> {
    const SYSCALL_ID: usize = 6;
    type Args = SyscallFreePages;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.vaddr % PAGE_SIZE as u64 != 0 {
            return res::E_INVALID_ARG;
        }
        let Some(frames) = crate::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        let access = self.0.permission_backend.lock();
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        let namespace = access.task_namespace(current);
        free_result(gtcb.vmap().free(
            gtcb.userspace_map(),
            frames,
            crate::umap::VmapHandle::from_base(args.vaddr as usize),
            namespace,
        ))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainMemory<A, SyscallMountCapRegion> {
    const SYSCALL_ID: usize = 7;
    type Args = SyscallMountCapRegion;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let Some(frames) = crate::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        let access = self.0.permission_backend.lock();
        // Право класса ресурса: MMIO в этой группе мапить можно.
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::MMIO_MAP)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        // РЕЗОЛВ ЧЕРЕЗ CAPABILITY ВЫЗЫВАЮЩЕГО (designation-is-right), а
        // НЕ по глобальному id: прежний путь get_object(cap_id) обходил
        // cspace — ревок capability/мембраны не влиял на монтирование
        // (зигота жива — мапится), а ЛЮБАЯ задача с MMIO_MAP монтировала
        // чужие/отозванные регионы по угадываемым последовательным id.
        let region = {
            let caps = gtcb.capspace().lock();
            let record = caps.get(&args.cap_slot).ok_or(res::E_SLOT_EMPTY)?;
            let (object, _) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
            match object {
                crate::access::capability::CapabilityObject::MemoryMMIORegion {
                    region_origin,
                    region_page_count,
                } => (*region_origin, *region_page_count),
                _ => return res::E_INVALID_ARG,
            }
        };
        let Some(ptr) = MemoryPTR::new(region.0, region.1) else {
            return res::E_INVALID_ARG;
        };

        alloc_result(gtcb.vmap().map_external(
            gtcb.userspace_map(),
            frames,
            ptr,
            // NX ПО УМОЛЧАНИЮ: смонтированные данные (MMIO/shm) не должны
            // быть исполняемыми (W+X на чужих фреймах — классика ROP-посадки).
            MemoryFlags::NO_EXECUTE, // RW + user + NX
        ))
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainMemory<A, SyscallUnmountCapRegion> {
    const SYSCALL_ID: usize = 8;
    type Args = SyscallUnmountCapRegion;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.vaddr % PAGE_SIZE as u64 != 0 {
            return res::E_INVALID_ARG;
        }
        let Some(frames) = crate::traits::memory::init_hooks::memory_allocator() else {
            return res::E_INTERNAL;
        };

        let access = self.0.permission_backend.lock();
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::MMIO_MAP)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let gtcb = unsafe { gtcb_ptr.as_ref() };

        free_result(gtcb.vmap().unmap_external(
            gtcb.userspace_map(),
            frames,
            crate::umap::VmapHandle::from_base(args.vaddr as usize),
        ))
    }
}
