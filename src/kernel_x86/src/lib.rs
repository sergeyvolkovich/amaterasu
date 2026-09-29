//! x86_64 бэкенд NOMAD: реализация `ArchImplementation` поверх
//! страничных таблиц x86_64 (paging) и драйвера Intel VT-d (iommu,
//! построенного на крейте intel-iommu).
//!
//! Архитектура слоёв:
//!   kernel_base (архитектурно-независимые трейты)
//!     └── kernel_x86 (этот крейт)
//!           ├── paging: X86KMap/X86Umap — MemoryInterfaceKernel/Userspace
//!           ├── irq: X86IrqContext — IRQArchDefinedContext
//!           ├── syscall: реестр сисколлов без alloc + per-CPU GS base
//!           └── iommu: VtdUnit/VtdDomain — IommuUnit/IommuDomain
//!               (форматы/регистры/walkers — из крейта intel-iommu, CC0)

#![cfg_attr(not(test), no_std)]

pub mod apic;
pub mod boot;
pub mod cswitch;
pub mod fault;
pub mod ioapic;
pub mod iommu;
pub mod irq;
pub mod paging;
pub mod pic;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod timer;

use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::iommu::IommuError;
use kernel_base::traits::memory::FrameAllocator;
use kernel_base::traits::syscall::SyscallDomain;
use kernel_base::traits::ArchImplementation;
use spin::Once;

/// Шим для `derive(SyscallArguments)`: макрос жёстко прописывает путь
/// `crate::traits::syscall::SyscallArguments`, а трейт живёт в kernel_base.
pub mod traits {
    pub use kernel_base::traits::syscall;
}

pub use crate::iommu::{IommuDomainHandle, IommuUnitHandle};
pub use crate::iommu::intel::{VtdDomain, VtdUnit};
pub use crate::irq::{X86CpuContext, X86InterruptId, X86IrqContext, X86PageFaultFlags, irq_enabled};
pub use crate::paging::{X86KMap, X86Umap, pte_bits};

/// Единственный IOMMU-юнит платформы (Intel VT-d ИЛИ AMD-Vi — по
/// boot-таблице). Заполняется `X86Backend::init_iommu_from_boot`.
static IOMMU_UNIT: Once<IommuUnitHandle> = Once::new();

/// Бэкенд x86_64: тип-пустышка, вся логика живёт в реализациях трейтов.
pub struct X86Backend;

impl X86Backend {
    /// Инициализирует IOMMU из boot-таблиц: ACPI -> DMAR (Intel VT-d)
    /// или IVRS (AMD-Vi), первый юнит, обёрнутый в IommuUnitHandle.
    ///
    /// Энумерация PCIe — задача userspace; ядру таблица нужна только ради
    /// DRHD/IVHD (база регистров + сегмент). Повторный вызов — no-op.
    pub fn init_iommu_from_boot(
        boot: &crate::boot::BootBackend,
        frames: &'static (dyn FrameAllocator + Sync),
    ) -> Result<(), IommuError> {
        if IOMMU_UNIT.get().is_some() {
            return Ok(());
        }
        let unit = match boot {
            crate::boot::BootBackend::Acpi(tables) => {
                if let Some(dmar) = tables.find_table(b"DMAR") {
                    // SAFETY: настоящая DMAR-таблица, MMIO-окно DRHD в HHDM.
                    IommuUnitHandle::Intel(unsafe { VtdUnit::new_from_dmar(dmar, frames) }?)
                } else if let Some(ivrs) = tables.find_table(b"IVRS") {
                    // SAFETY: настоящая IVRS-таблица, MMIO-окно IVHD в HHDM.
                    IommuUnitHandle::Amd(unsafe {
                        crate::iommu::amd::AmdUnit::new_from_ivrs(ivrs, frames)
                    }?)
                } else {
                    return Err(IommuError::NoIommuUnits);
                }
            }
        };
        IOMMU_UNIT.call_once(|| unit);
        Ok(())
    }
}

impl ArchImplementation for X86Backend {
    type Umap = X86Umap;
    type KMap = X86KMap;
    type IRQContext = X86IrqContext;
    type Iommu = IommuUnitHandle;

    /// Чип прерываний платформы: IO-APIC + LAPIC + MSI (см. irq::X86IrqChip).
    /// Инициализируется `irq::init_from_boot` из MADT; до этого — None
    /// (IRQ-сисколлы отвечают E_INTERNAL — «подсистема не поднята»).
    type IrqChip = crate::irq::X86IrqChip;

    fn init_base_state() -> Self {
        X86Backend
    }

    /// Оборачивает загрузочные таблицы страниц (текущий CR3) — ядро
    /// продолжает работать на них до `create_new_kmap` + `activate`.
    fn reclaim_memory(_allocator: &dyn FrameAllocator) -> Self::KMap {
        let (frame, _) = x86_64::registers::control::Cr3::read();
        X86KMap::from_existing(frame.start_address().as_u64() as usize)
    }

    /// Свежая обнулённая таблица ядра. Кадр берётся через kernel_base-хук
    /// кадро-аллокатора: порядок KernelCTL::new_and_init гарантирует, что
    /// init_allocator и HHDM уже подняты.
    fn create_new_kmap() -> Self::KMap {
        let root = match X86KMap::allocate_root_via_hooks() {
            Ok(r) => r,
            Err(e) => {
                kernel_base::kernel_log!(
                    "create_new_kmap: allocate_root не удался: {:?}\n",
                    e
                );
                panic!("create_new_kmap: не удалось выделить PML4");
            }
        };
        X86KMap::from_existing(root)
    }

    fn irq_enable() {
        crate::irq::irq_enable();
    }

    fn irq_disable() {
        crate::irq::irq_disable();
    }

    fn register_syscalls<D: SyscallDomain + 'static>(handle: D) {
        // Типовая эразура без alloc: значение домена уходит в статический
        // слот реестра (kernel_x86::syscall). Контракт D::Umap == X86Umap
        // задаётся kernel_base::init_syscalls<A> — домены создаются над тем
        // же ArchImplementation, что и этот реестр.
        syscall::register_erased_syscall(handle)
            .expect("syscall registration failed (collision/size)");
    }

    fn set_ktls_block(ptr: &LocalKernelCTL<Self::Umap>) {
        // SAFETY: контракт set_ktls_block — один вызов на ядро при старте.
        unsafe { syscall::set_ktls_block(ptr) };
    }

    fn get_local_base() -> &'static mut LocalKernelCTL<Self::Umap> {
        // SAFETY: GS base установлен set_ktls_block на этом ядре.
        unsafe { syscall::get_local_base() }
    }

    fn iommu() -> Option<&'static Self::Iommu> {
        IOMMU_UNIT.get()
    }

    fn irq_chip() -> Option<&'static Self::IrqChip> {
        crate::irq::chip()
    }

    /// Umap = UserspaceMap для x86 (один тип).
    fn create_task_umap(
        kmap: &X86KMap,
        allocator: &(dyn kernel_base::traits::memory::FrameAllocator + Sync),
    ) -> Result<X86Umap, kernel_base::traits::memory::ErrorCode> {
        kernel_base::traits::memory::MemoryInterfaceKernel::create_userspace_mapping(kmap, allocator, 0..0)
    }

    /// SysFrame (cswitch): слово 3 (rdi+0, rsi+8, rdx+16, **результат+24**)
    /// — туда syscall_entry кладёт RAX. Синхронизировано с кон-стой
    /// `const _: () = assert!(...)` в cswitch. Имя трейта —
    /// RESUME_RESULT_WORD: generic-слой не знает, КАКОЙ регистр это
    /// на конкретной архитектуре.
    const RESUME_RESULT_WORD: usize = 3;

    /// SysFrame (cswitch): слово 13 (+104) — точка продолжения (RIP).
    /// Слова 0..18 порта: rdi,rsi,rdx,rax,rbx,rbp,r8,r9,r10,r12..r15,
    /// **rip(+104)**, cs, rflags, rsp, ss. Нужны фолт-механизму
    /// (ipc::fault): FAULT_REPLY возобновляет упавшую с нового адреса.
    const RESUME_RIP_WORD: usize = 13;
    /// SysFrame (cswitch): слово 16 (+128) — пользовательский стек (RSP)
    /// — см. RESUME_RIP_WORD (эмуляция/сигнальный трамплин при ответе).
    const RESUME_RSP_WORD: usize = 16;
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Глобальная сериализация тестов: paging- и iommu-тесты меняют
    /// глобальные статики kernel_base (HHDM-offset, лимит замапленной
    /// памяти) — параллельный запуск cargo test их перемешивает.
    use spin::mutex::SpinMutex;
    pub static GLOBAL: SpinMutex<()> = SpinMutex::new(());

    /// Странично-ВЫРОВНЕННЫЙ leaks-нутый буфер: HHDM-офсет обязан быть
    /// кратен странице (инвариант set_hhdm_offset; slab-математика
    /// align_down опирается на него).
    pub fn page_aligned_leak(pages: usize) -> &'static mut [u8] {
        use std::alloc::{alloc_zeroed, Layout};
        const PAGE_SIZE: usize = kernel_base::traits::memory::PAGE_SIZE;
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).expect("layout");
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "oom in test alloc");
        unsafe { core::slice::from_raw_parts_mut(ptr, pages * PAGE_SIZE) }
    }

    /// Поднимает slab-хуки kernel_base для тестов slab-реестров IOMMU
    /// (v2). Один раз на процесс; "физика" — бесконечный bump от страницы
    /// 1 (тесты выставляют свой HHDM-offset на leaks-буфер, слэб-страницы
    /// приземляются в текущий буфер; ранее выделенные остаются валидными —
    /// leaks живут до конца процесса, deallocate — no-op).
    ///
    /// ВАЖНО: вызывать ПОСЛЕ page_aligned_leak + set_hhdm_offset теста.
    pub fn init_slab_once() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use kernel_base::traits::memory::{
            init_hooks, FrameAllocator, MemoryPTR, PAGE_SIZE,
        };
        use std::sync::Once as StdOnce;

        struct SlabFrames(AtomicUsize);
        static SLAB_FRAMES: SlabFrames = SlabFrames(AtomicUsize::new(1));
        impl FrameAllocator for SlabFrames {
            fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
                let first = self.0.fetch_add(count, Ordering::SeqCst);
                MemoryPTR::new(first * PAGE_SIZE, count)
            }
            fn deallocate_pages(&self, _ptr: MemoryPTR) {}
        }

        static ONCE: StdOnce = StdOnce::new();
        ONCE.call_once(|| {
            kernel_base::traits::memory::init_hooks::init_allocator(&SLAB_FRAMES);
        });
    }
}
