//! x86_64 страничные таблицы: реализация [`MemoryInterfaceKernel`] и
//! [`MemoryInterfaceUserspace`] поверх 4-уровневой иерархии
//! (PML4 -> PDPT -> PD -> PT).
//!
//! Дизайн:
//!   - каждая таблица страниц — 4 КиБ-выровненный массив 512 u64-записей,
//!     живущий в ФИЗИЧЕСКОЙ памяти; доступ идёт через HHDM
//!     (`phys_to_virt`, см. kernel_base::traits::memory) — ядро работает
//!     со всеми таблицами без переключения CR3;
//!   - `X86KMap` — таблица ядра (без USER-бита); `X86Umap` — таблица
//!     задачи: верхняя половина PML4 копируется из таблицы ядра (ядро
//!     видно из процесса, но SUPERVISOR-семантика PTE не даёт ring3
//!     читать его), нижняя — пользовательская (USER);
//!   - флаги `MemoryFlags` мапятся на биты PTE: READ_ONLY -> нет Writable,
//!     SUPERVISOR -> не влияет на кмаг (там USER не ставится в принципе),
//!     NO_EXECUTE -> NX (бит 63; порт обязан включить EFER.NXE);
//!   - поддержаны листья 4 КиБ / 2 МиБ / 1 ГиБ (MemoryFlags::FLAG_SIZE*);
//!     HHDM ядро строит 1 ГиБ-листьями (см. build_identity_hhdm).
//!
//! Тестируемость: вся логика маппинга оперирует памятью через HHDM-offset,
//! поэтому на хосте (`cargo test`) она прогоняется на leaks-нутой
//! "физической памяти" с фиктивным FrameAllocator. Privileged-инструкции
//! (CR3, INVLPG) в тестах не выполняются: `is_active()` под cfg(test)
//! всегда false. Все тесты объединены в один (HHDM-offset и лимит
//! замапленной памяти — глобальные статики, параллельные тесты мешали бы
//! друг другу).

use core::alloc::Layout;
use core::ops::Range;

use kernel_base::traits::memory::{
    ErrorCode, FrameAllocator, MemoryFlags, MemoryInterfaceKernel, MemoryInterfaceUserspace,
    MemoryPTR, PAGE_SIZE, StartupModel, init_hooks, mapped_phys_limit, phys_to_virt, virt_to_phys,
};

// ─── Биты PTE (x86_64 long mode) ─────────────────────────────────────────────

pub mod pte_bits {
    /// Present (P).
    pub const PRESENT: u64 = 1 << 0;
    /// Writable (R/W).
    pub const WRITABLE: u64 = 1 << 1;
    /// User/supervisor (U/S) — доступен ring3.
    pub const USER: u64 = 1 << 2;
    /// Accessed (A).
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty (D).
    pub const DIRTY: u64 = 1 << 6;
    /// Page Size (PS) — лист 2 МиБ/1 ГиБ.
    pub const HUGE: u64 = 1 << 7;
    /// No Execute (NX, EFER.NXE должен быть включён портом).
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// Маска физического адреса в записи (биты 51:12).
    pub const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
}

/// Индекс PML4, с которого начинается верхняя (ядерная) половина.
const KERNEL_HALF_START_INDEX: usize = 256;

/// Размер листа, закодированный в MemoryFlags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafSize {
    P4K,
    P2M,
    P1G,
}

impl LeafSize {
    fn shift(self) -> usize {
        match self {
            LeafSize::P4K => 12,
            LeafSize::P2M => 21,
            LeafSize::P1G => 30,
        }
    }

    fn from_flags(flags: MemoryFlags) -> LeafSize {
        if flags.contains(MemoryFlags::FLAG_SIZE1GB) {
            LeafSize::P1G
        } else if flags.contains(MemoryFlags::FLAG_SIZE2MB) {
            LeafSize::P2M
        } else {
            LeafSize::P4K
        }
    }
}

/// Биты листа из MemoryFlags. `user` — ставить ли U/S (умап — да, кмаг — нет).
fn leaf_bits(flags: MemoryFlags, user: bool) -> u64 {
    let mut bits = pte_bits::PRESENT | pte_bits::ACCESSED | pte_bits::DIRTY;
    if !flags.contains(MemoryFlags::READ_ONLY) {
        bits |= pte_bits::WRITABLE;
    }
    if user {
        bits |= pte_bits::USER;
    }
    if flags.contains(MemoryFlags::NO_EXECUTE) {
        bits |= pte_bits::NO_EXECUTE;
    }
    bits
}

/// SAFETY-инвариант: `phys` — адрес 4 КиБ-выровненной таблицы страниц,
/// замапленной через HHDM, и на момент вызова эта физическая память жива.
unsafe fn table_at(phys: usize) -> &'static mut [u64; 512] {
    let virt = phys_to_virt(phys);
    unsafe { &mut *(virt as *mut [u64; 512]) }
}

fn zero_table(phys: usize) {
    let virt = phys_to_virt(phys);
    // SAFETY: страница выделена кадро-аллокатором и никем больше не занята.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE) };
}

/// Аллокация и обнуление одной страницы под таблицу через kernel_base-хук
/// кадро-аллокатора (требует init_allocator + поднятый HHDM — порядок
/// KernelCTL::new_and_init это гарантирует).
fn alloc_zeroed_table_via_hooks() -> Result<usize, ErrorCode> {
    let layout =
        Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).map_err(|_| ErrorCode::InvalidLayout)?;
    let ptr = unsafe { init_hooks::mapper_allocator(layout) }.ok_or(ErrorCode::OutOfMemory)?;

    let phys = virt_to_phys(ptr.as_ptr() as usize);

    zero_table(phys);

    Ok(phys)
}

/// Выделяет `pages` физических кадров, проверяя реальную границу HHDM.
fn alloc_frames(allocator: &dyn FrameAllocator, pages: usize) -> Result<MemoryPTR, ErrorCode> {
    let region = allocator
        .allocate_pages(pages)
        .ok_or(ErrorCode::OutOfMemory)?;
    let end = region
        .phys_base()
        .checked_add(region.pages().saturating_mul(PAGE_SIZE))
        .ok_or(ErrorCode::OutOfMappedBounds)?;
    if end > mapped_phys_limit() {
        allocator.deallocate_pages(region);
        return Err(ErrorCode::OutOfMappedBounds);
    }
    Ok(region)
}

/// Аллокатор одной обнулённой таблицы страниц. Подаётся снаружи: у
/// display_map FrameAllocator-параметра нет (используем хуки kernel_base),
/// а у umap-операций есть явный FrameAllocator.
type TableAlloc<'a> = dyn Fn() -> Result<usize, ErrorCode> + 'a;

/// Мапит один лист (`size`) по адресу `virt`. Промежуточные уровни
/// аллоцируются по необходимости (записи Present|Writable|ACCESSED[|User]).
fn map_leaf(
    root_phys: usize,
    alloc_table: &TableAlloc<'_>,
    virt: usize,
    phys: usize,
    bits: u64,
    size: LeafSize,
    user: bool,
) -> Result<(), ErrorCode> {
    let shift = size.shift();
    let mut table_phys = root_phys;
    let mut level_shift = 39usize;
    while level_shift > shift {
        let index = (virt >> level_shift) & 0x1ff;
        // SAFETY: table_phys получен из живых записей/аллокатора выше.
        let table = unsafe { table_at(table_phys) };
        let entry = table[index];
        table_phys = if entry & pte_bits::PRESENT == 0 {
            let new_table = alloc_table()?;
            table[index] = new_table as u64
                | pte_bits::PRESENT
                | pte_bits::WRITABLE
                | pte_bits::ACCESSED
                | if user { pte_bits::USER } else { 0 };
            new_table
        } else {
            (entry & pte_bits::ADDR_MASK) as usize
        };
        level_shift -= 9;
    }

    let index = (virt >> shift) & 0x1ff;
    let table = unsafe { table_at(table_phys) };
    let mut entry = (phys as u64 & pte_bits::ADDR_MASK) | bits;
    if size != LeafSize::P4K {
        entry |= pte_bits::HUGE;
    }
    table[index] = entry;
    Ok(())
}

/// Снимает маппинг листа `size` с `virt`. Идемпотентна: отсутствующие
/// уровни/записи считаются уже размапленными.
fn unmap_leaf(root_phys: usize, virt: usize, size: LeafSize) {
    let shift = size.shift();
    let mut table_phys = root_phys;
    let mut level_shift = 39usize;
    while level_shift > shift {
        let index = (virt >> level_shift) & 0x1ff;
        let entry = unsafe { table_at(table_phys) }[index];
        if entry & pte_bits::PRESENT == 0 {
            return; // промежуточного уровня нет — маппинга точно нет
        }
        table_phys = (entry & pte_bits::ADDR_MASK) as usize;
        level_shift -= 9;
    }
    let index = (virt >> shift) & 0x1ff;
    // SAFETY: table_phys получен из живых записей выше.
    unsafe {
        table_at(table_phys)[index] = 0;
    }
}

/// Активна ли эта таблица на текущем ядре. В тестах CR3 не читается
/// (privileged-инструкция уронила бы хост-процесс).
#[cfg(not(test))]
fn is_active(root_phys: usize) -> bool {
    let (frame, _) = x86_64::registers::control::Cr3::read();
    frame.start_address().as_u64() as usize == root_phys
}

/// Дочемапливает физический диапазон `[phys_base, phys_base+len)` в HHDM
/// **текущей** таблицы страниц (CR3), 4К-листами.
///
/// Зачем: Limine (протокол rev.3) отражает в HHDM только usable/модули/
/// FB/reclaimable — reserved-регионы низа BIOS (RSDP) и ACPI-области
/// остаются НЕзамапленными, и первое же `phys_to_virt(rsdp)` даёт page
/// fault (поймано в QEMU: PT-запись = 0). Функция идемпотентна:
/// существующие записи не трогает, huge-листы на пути пропускает
/// (диапазон уже покрыт), недостающие промежуточные таблицы выделяет
/// через переданный FrameManager и обнуляет.
///
/// ВНИМАНИЕ: писать можно только в таблицы текущего CR3 ДО того, как
/// ядро сменит таблицу (после activate таблицы загрузчика возвращаются
/// в FrameAllocator). Вызывается из бут-пути до new_and_init.
///
/// NX не ставим: EFER.NXE на этом этапе ещё не гарантированно включён,
/// бит 63 без NXE = reserved-bit fault.
pub fn hhdm_ensure_mapped(
    frames: &dyn FrameAllocator,
    phys_base: usize,
    len: usize,
) -> Result<(), ErrorCode> {
    if len == 0 {
        return Ok(());
    }
    let first = phys_base & !(PAGE_SIZE - 1);
    let end = (phys_base + len)
        .checked_add(PAGE_SIZE - 1)
        .ok_or(ErrorCode::InvalidLayout)?
        & !(PAGE_SIZE - 1);

    #[cfg(not(test))]
    let cr3 = {
        let (frame, _) = x86_64::registers::control::Cr3::read();
        frame.start_address().as_u64() as usize
    };
    #[cfg(test)]
    let cr3 = 0; // хост-тесты эту функцию не гоняют (нужен реальный CR3)

    let mut phys = first;
    while phys < end {
        let virt = phys_to_virt(phys);
        let mut table_phys = cr3;
        let mut level_shift = 39usize;
        // Спуск PML4 -> PDPT -> PD; отсутствующий уровень создаём,
        // huge-лист означает «уже покрыто».
        while level_shift > 12 {
            let idx = (virt >> level_shift) & 0x1ff;
            // SAFETY: table_phys — либо CR3, либо адрес из живой записи
            // существующей таблицы; новая таблица выделена аллокатором.
            let table = unsafe { table_at(table_phys) };
            let entry = table[idx];
            if entry & pte_bits::PRESENT == 0 {
                let page = frames.allocate_pages(1).ok_or(ErrorCode::OutOfMemory)?;
                let new_table = page.phys_base();
                zero_table(new_table);
                table[idx] =
                    new_table as u64 | pte_bits::PRESENT | pte_bits::WRITABLE | pte_bits::ACCESSED;
                table_phys = new_table;
            } else if entry & pte_bits::HUGE != 0 {
                break; // 2М/1Г лист уже покрывает эту страницу
            } else {
                table_phys = (entry & pte_bits::ADDR_MASK) as usize;
            }
            level_shift -= 9;
        }
        if level_shift == 12 {
            let idx = (virt >> 12) & 0x1ff;
            // SAFETY: спуск выше дошёл до PT.
            let table = unsafe { table_at(table_phys) };
            if table[idx] & pte_bits::PRESENT == 0 {
                table[idx] = (phys as u64 & pte_bits::ADDR_MASK)
                    | pte_bits::PRESENT
                    | pte_bits::WRITABLE
                    | pte_bits::ACCESSED
                    | pte_bits::DIRTY;
            }
        }
        phys += PAGE_SIZE;
    }
    Ok(())
}

#[cfg(test)]
fn is_active(_root_phys: usize) -> bool {
    false
}

/// INVLPG, если страница могла осесть в TLB текущего ядра.
fn flush_if_active(root_phys: usize, virt: usize) {
    if is_active(root_phys) {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(virt as u64));
    }
}

// ─── X86KMap: таблица ядра ───────────────────────────────────────────────────

/// Страничная таблица ядра. Хранит ФИЗИЧЕСКИЙ адрес PML4.
pub struct X86KMap {
    root_phys: usize,
}

impl X86KMap {
    /// Оборачивает УЖЕ СУЩЕСТВУЮЩУЮ таблицу (например, загрузочную по CR3).
    pub fn from_existing(root_phys: usize) -> Self {
        Self { root_phys }
    }

    /// Физический адрес PML4.
    pub fn root_phys(&self) -> usize {
        self.root_phys
    }

    /// Выделяет и обнуляет страницу под PML4 через kernel_base-хуки
    /// (init_allocator + HHDM), возвращает ФИЗИЧЕСКИЙ адрес. Используется
    /// `ArchImplementation::create_new_kmap`, у которого нет параметра-
    /// аллокатора.
    pub fn allocate_root_via_hooks() -> Result<usize, ErrorCode> {
        alloc_zeroed_table_via_hooks()
    }
}

impl MemoryInterfaceKernel for X86KMap {
    const PAGE_SIZE: usize = PAGE_SIZE;
    type UserspaceMap = X86Umap;

    fn translate_kernel(&self, virt: usize) -> Option<usize> {
        translate_page(self.root_phys, virt)
    }

    fn init(allocator: &(dyn FrameAllocator + Sync), _model: StartupModel) -> Self {
        // Один кадр под обнулённый PML4; ядро наслаивает маппинги display_map.
        let region = alloc_frames(allocator, 1).expect("no frame for kernel PML4");
        zero_table(region.phys_base());
        Self {
            root_phys: region.phys_base(),
        }
    }

    fn create_userspace_mapping(
        &self,
        allocator: &(dyn FrameAllocator + Sync),
        _kernel_display_region: Range<usize>,
    ) -> Result<Self::UserspaceMap, ErrorCode> {
        let region = alloc_frames(allocator, 1)?;
        let new_root = region.phys_base();
        zero_table(new_root);

        // Верхняя половина PML4 копируется ПО ЗНАЧЕНИЮ ЗАПИСЕЙ: ядерные
        // маппинги (HHDM, .text и т.д.) разделяются с задачей по ссылке на
        // нижние уровни; SUPERVISOR-семантика PTE не даёт ring3 к ним
        // обращаться. Нижняя половина остаётся пустой — пользовательские
        // страницы ставятся через umap-операции.
        let src = unsafe { table_at(self.root_phys) };
        let dst = unsafe { table_at(new_root) };
        dst[KERNEL_HALF_START_INDEX..].copy_from_slice(&src[KERNEL_HALF_START_INDEX..]);

        Ok(X86Umap {
            root_phys: new_root,
        })
    }

    fn display_map(&self, p_display_region: MemoryPTR, virt_addr: usize, flags: MemoryFlags) {
        let size = LeafSize::from_flags(flags);
        let step = 1usize << size.shift();
        let bits = leaf_bits(flags, false);
        let alloc_table = || alloc_zeroed_table_via_hooks();

        // Число ЛИСТЬЕВ: размер региона (в 4К-страницах, как его описывает
        // MemoryPTR) делённый на размер листа. Для 1 ГиБ-листа регион из
        // 262144 страниц — ровно один лист (так display_map зовёт
        // build_identity_hhdm).
        let leaves = p_display_region.pages().saturating_mul(PAGE_SIZE) / step;
        debug_assert!(leaves > 0, "display_map: пустой регион");

        for i in 0..leaves {
            let virt = virt_addr + i * step;
            let phys = p_display_region.phys_base() + i * step;
            // Bootstrap-путь kernel_base не recoverable: отказ аллокации
            // промежуточной таблицы — паника, как и во всём init.
            map_leaf(self.root_phys, &alloc_table, virt, phys, bits, size, false)
                .expect("display_map: не удалось аллоцировать таблицу страниц");
        }
    }

    fn activate(&self) {
        // Диагностика (бут-путь): полный обход для типовых VA ядра.
        {
            let pml4 = unsafe { table_at(self.root_phys) };
            kernel_base::kernel_log!(
                "activate: root={:#x} pml4[256]={:#x} pml4[511]={:#x}\n",
                self.root_phys,
                pml4[256],
                pml4[511]
            );
            let walk = |va: usize, label: &str| {
                let mut table_phys = self.root_phys;
                let mut shift = 39;
                while shift >= 12 {
                    let idx = (va >> shift) & 0x1ff;
                    let entry = unsafe { table_at(table_phys) }[idx];
                    kernel_base::kernel_log!(
                        "activate: {label} va={va:#x} L{shift}[{idx}]={entry:#x}\n",
                    );
                    if entry & pte_bits::PRESENT == 0 {
                        return;
                    }
                    if shift > 12 && entry & pte_bits::HUGE != 0 {
                        return;
                    }
                    table_phys = (entry & pte_bits::ADDR_MASK) as usize;
                    shift -= 9;
                }
            };
            walk(0xffffffff80260600, "stack"); // текущий RSP бут-стека
            walk(0xffffffff80209000, "text"); // код ядра
            // Дамп PT страницы, покрывающей .text/.bss VMA (PD[1] → PT).
            if let Some(pdpt) = pml4[511]
                .checked_sub(0)
                .map(|_| (pml4[511] & pte_bits::ADDR_MASK) as usize)
            {
                let pdpt_ref = unsafe { table_at(pdpt) };
                if pdpt_ref[510] & pte_bits::PRESENT != 0 {
                    let pd = (pdpt_ref[510] & pte_bits::ADDR_MASK) as usize;
                    let pd_ref = unsafe { table_at(pd) };
                    if pd_ref[1] & pte_bits::PRESENT != 0 {
                        let pt = (pd_ref[1] & pte_bits::ADDR_MASK) as usize;
                        let pt_ref = unsafe { table_at(pt) };
                        let present = pt_ref
                            .iter()
                            .filter(|e| **e & pte_bits::PRESENT != 0)
                            .count();
                        let first_missing = pt_ref
                            .iter()
                            .position(|e| *e & pte_bits::PRESENT == 0)
                            .unwrap_or(999);
                        kernel_base::kernel_log!(
                            "activate: PT@{:#x} present={}/512 first_missing={:#x}\n",
                            pt,
                            present,
                            first_missing
                        );
                    }
                }
            }
        }
        // SAFETY: root_phys — валидная 4 КиБ-выровненная таблица, в которой
        // уже есть маппинг исполняемого кода (контракт MemoryInterfaceKernel::activate).
        unsafe {
            let frame = x86_64::structures::paging::PhysFrame::from_start_address(
                x86_64::PhysAddr::new(self.root_phys as u64),
            )
            .expect("PML4 must be 4 KiB aligned");
            x86_64::registers::control::Cr3::write(
                frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
            // Диагностика: доказательство, что после переключения таблиц
            // ядро продолжает исполняться (код+стек+HHDM живы).
            kernel_base::kernel_log!("activate: CR3={:#x} переключен\n", self.root_phys);
        }
    }
}

// ─── X86Umap: таблица задачи ─────────────────────────────────────────────────

/// Страничная таблица задачи (пустая нижняя половина + скопированная
/// верхняя половина ядра).
pub struct X86Umap {
    root_phys: usize,
}

impl X86Umap {
    /// Физический адрес PML4 задачи (для записи в CR3 планировщиком).
    pub fn root_phys(&self) -> usize {
        self.root_phys
    }

    /// Оборачивает СУЩЕСТВУЮЩУЮ таблицу (например, при загрузке образа
    /// до привязки задачи; тесты используют маркер-адрес).
    pub fn from_existing(root_phys: usize) -> Self {
        Self { root_phys }
    }
}

impl MemoryInterfaceUserspace for X86Umap {
    fn allocate_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        count: usize,
    ) -> Result<MemoryPTR, ErrorCode> {
        if count == 0 {
            return Err(ErrorCode::InvalidLayout);
        }
        alloc_frames(allocator, count)
    }

    fn deallocate_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        region: MemoryPTR,
        count: usize,
    ) -> Result<(), ErrorCode> {
        let take = MemoryPTR::new(region.phys_base(), count).ok_or(ErrorCode::InvalidLayout)?;
        allocator.deallocate_pages(take);
        Ok(())
    }

    fn map_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
    ) -> Result<MemoryPTR, ErrorCode> {
        if !virt.is_multiple_of(PAGE_SIZE) {
            return Err(ErrorCode::InvalidLayout);
        }
        let bits = leaf_bits(MemoryFlags::empty(), true);
        let alloc_table = || {
            let page = alloc_frames(allocator, 1)?;
            zero_table(page.phys_base());
            Ok(page.phys_base())
        };
        for i in 0..p_base.pages() {
            map_leaf(
                self.root_phys,
                &alloc_table,
                virt + i * PAGE_SIZE,
                p_base.phys_base() + i * PAGE_SIZE,
                bits,
                LeafSize::P4K,
                true,
            )?;
            flush_if_active(self.root_phys, virt + i * PAGE_SIZE);
        }
        Ok(p_base)
    }

    fn unmap_memory_region(
        &self,
        _allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
    ) -> Result<(), ErrorCode> {
        for i in 0..p_base.pages() {
            unmap_leaf(self.root_phys, virt + i * PAGE_SIZE, LeafSize::P4K);
            flush_if_active(self.root_phys, virt + i * PAGE_SIZE);
        }
        Ok(())
    }

    fn map_memory_region_flags(
        &self,
        allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
        flags: MemoryFlags,
    ) -> Result<MemoryPTR, ErrorCode> {
        if !virt.is_multiple_of(PAGE_SIZE) {
            return Err(ErrorCode::InvalidLayout);
        }
        // USER всегда: страницы задач отображаются для ring3 (загрузчик
        // образов и umap-аллокации); SUPERVISOR-семантика ядерной половины
        // задаётся копией PML4, а не флагами здесь.
        let bits = leaf_bits(flags, true);
        let alloc_table = || {
            let page = alloc_frames(allocator, 1)?;
            zero_table(page.phys_base());
            Ok(page.phys_base())
        };
        for i in 0..p_base.pages() {
            map_leaf(
                self.root_phys,
                &alloc_table,
                virt + i * PAGE_SIZE,
                p_base.phys_base() + i * PAGE_SIZE,
                bits,
                LeafSize::P4K,
                true,
            )?;
            flush_if_active(self.root_phys, virt + i * PAGE_SIZE);
        }
        Ok(p_base)
    }

    fn translate(&self, virt: usize) -> Option<usize> {
        translate_page(self.root_phys, virt)
    }

    /// USER-семантика copyin/copyout: нижняя половина + PRESENT|USER на
    /// всех уровнях (+ WRITABLE для записи). См. трейт — почему это
    /// обязательно: верхняя половина таблиц задачи ДЕЛИТСЯ с ядром, и
    /// голый обход таблиц транслировал бы ядерные VA задачи.
    fn translate_user(&self, virt: usize, for_write: bool) -> Option<usize> {
        translate_page_user(self.root_phys, virt, for_write)
    }

    fn root_table(&self) -> Option<usize> {
        Some(self.root_phys)
    }
}

/// Обход таблиц: трансляция VA -> физика (база кадра | смещение внутри).
/// Huge-листы (2 МиБ/1 ГиБ) поддержаны. Публично: планировщику и ядру
/// для доступа к памяти задачи (translate трейта обёртка над этим).
pub fn translate_page(root_phys: usize, virt: usize) -> Option<usize> {
    let mut table_phys = root_phys;
    // Уровни сверху вниз: 39 (PML4), 30 (PDPT), 21 (PD), 12 (PT).
    let mut shift = 39usize;
    loop {
        let entry = *unsafe { table_at(table_phys) }.get((virt >> shift) & 0x1ff)?;
        if entry & pte_bits::PRESENT == 0 {
            return None;
        }
        // Huge-лист (PS=1) на уровне выше PT.
        if shift > 12 && entry & pte_bits::HUGE != 0 {
            let frame = (entry & pte_bits::ADDR_MASK) as usize;
            let off_mask = (1usize << shift) - 1;
            return Some(frame | (virt & off_mask));
        }
        if shift == 12 {
            return Some((entry & pte_bits::ADDR_MASK) as usize | (virt & 0xfff));
        }
        table_phys = (entry & pte_bits::ADDR_MASK) as usize;
        shift -= 9;
    }
}

/// Обход таблиц с USER-семантикой (copyin/copyout): каждый уровень пути
/// обязан нести PRESENT|USER (и WRITABLE — при for_write: самый слабый
/// R/W по пути выигрывает). Нижняя половина только (вся верхняя —
/// ядерные отображения). Публично: X86Umap::translate_user.
pub fn translate_page_user(root_phys: usize, virt: usize, for_write: bool) -> Option<usize> {
    // Диапазон-гейт: каноническая нижняя половина (граница — та же, что
    // у is_user_va; верхняя — ядерные отображения, общие с умапом).
    if virt >= kernel_base::traits::memory::USER_SPACE_LIMIT {
        return None;
    }
    let need = pte_bits::PRESENT | pte_bits::USER;
    let mut table_phys = root_phys;
    // Уровни сверху вниз: 39 (PML4), 30 (PDPT), 21 (PD), 12 (PT).
    let mut shift = 39usize;
    loop {
        let entry = *unsafe { table_at(table_phys) }.get((virt >> shift) & 0x1ff)?;
        if entry & need != need {
            return None;
        }
        if for_write && entry & pte_bits::WRITABLE == 0 {
            return None;
        }
        // Huge-лист (PS=1) на уровне выше PT.
        if shift > 12 && entry & pte_bits::HUGE != 0 {
            let frame = (entry & pte_bits::ADDR_MASK) as usize;
            let off_mask = (1usize << shift) - 1;
            return Some(frame | (virt & off_mask));
        }
        if shift == 12 {
            return Some((entry & pte_bits::ADDR_MASK) as usize | (virt & 0xfff));
        }
        table_phys = (entry & pte_bits::ADDR_MASK) as usize;
        shift -= 9;
    }
}

// ─── Тесты (хост): фиктивная физическая память через HHDM ───────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::page_aligned_leak;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use kernel_base::traits::memory::{GIB, set_hhdm_offset, set_mapped_phys_limit};

    /// "Физическая память" теста: leaks-нутый буфер, физический адрес 0 —
    /// его начало; HHDM-offset = виртуальный адрес буфера, так что
    /// phys_to_virt(p) попадает в буфер. Кадры выдаются последовательно
    /// с страницы 1 (страница 0 оставлена для прямых маппингов теста).
    struct TestFrames(AtomicUsize);

    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(100));

    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            let first = self.0.fetch_add(count, Ordering::SeqCst);
            MemoryPTR::new(first * PAGE_SIZE, count)
        }

        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    fn frames() -> &'static TestFrames {
        &FRAMES
    }

    /// Читает листовый PTE по иерархии (без аллокаций). Останавливается на
    /// первом листе (4K-уровень либо HUGE-запись выше).
    fn walk_entry(root: usize, virt: usize) -> Option<u64> {
        let mut table = root;
        for shift in [39, 30, 21, 12] {
            let entry = unsafe { table_at(table) }[(virt >> shift) & 0x1ff];
            if shift == 12 || entry & pte_bits::HUGE != 0 {
                return Some(entry);
            }
            if entry & pte_bits::PRESENT == 0 {
                return None;
            }
            table = (entry & pte_bits::ADDR_MASK) as usize;
        }
        None
    }

    /// Канонический адрес в верхней (ядерной) половине: первый индекс PML4
    /// ядерной половины (256).
    const KERNEL_VIRT: usize = 0xFFFF_8000_0000_0000;

    #[test]
    fn paging_lifecycle() {
        // Единый тест: HHDM-offset и лимит замапленной памяти — глобальные
        // статики kernel_base; плюс глобальный лок против iommu-теста.
        let _guard = crate::test_support::GLOBAL.lock();
        let mem = page_aligned_leak(4 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        set_mapped_phys_limit(2 * GIB);
        // display_map аллоцирует промежуточные таблицы через kernel_base-хуки.
        kernel_base::traits::memory::init_hooks::init_allocator(frames());

        // ── Фаза 1: кмаг, 4 КиБ-лист, флаги ──
        let kmap = X86KMap::init(frames(), StartupModel::OneOne);
        assert_ne!(kmap.root_phys(), 0);

        let user_virt = 0x1000_0000usize;
        kmap.display_map(
            MemoryPTR::new(0x2000, 1).unwrap(),
            user_virt,
            MemoryFlags::empty(),
        );
        let entry = walk_entry(kmap.root_phys(), user_virt).unwrap();
        assert_eq!(entry & pte_bits::ADDR_MASK, 0x2000);
        assert_ne!(entry & pte_bits::PRESENT, 0);
        assert_ne!(entry & pte_bits::WRITABLE, 0);
        assert_eq!(entry & pte_bits::USER, 0);

        // Проверка цепочки уровней: каждый промежуточный PTE указывает на
        // следующую таблицу, лист на физическую 0x2000.
        let pdpt = (unsafe { table_at(kmap.root_phys()) }[(user_virt >> 39) & 0x1ff]
            & pte_bits::ADDR_MASK) as usize;
        let pd =
            (unsafe { table_at(pdpt) }[(user_virt >> 30) & 0x1ff] & pte_bits::ADDR_MASK) as usize;
        let pt =
            (unsafe { table_at(pd) }[(user_virt >> 21) & 0x1ff] & pte_bits::ADDR_MASK) as usize;
        let leaf = unsafe { table_at(pt) }[(user_virt >> 12) & 0x1ff];
        assert_eq!(leaf, entry);

        // Сама wiring HHDM: запись "в физическую 0x2000" через HHDM видна
        // в буфере по смещению 0x2000.
        let data_virt = phys_to_virt(0x2000) as *mut u64;
        unsafe { data_virt.write_volatile(0xDEAD_BEEF) };
        assert_eq!(
            unsafe { core::ptr::read_volatile(mem.as_ptr().add(0x2000) as *const u64) },
            0xDEAD_BEEF
        );

        // RO + NX переписывают ту же запись (display_map идемпотентен по
        // виртуальному адресу).
        kmap.display_map(
            MemoryPTR::new(0x3000, 1).unwrap(),
            user_virt,
            MemoryFlags::READ_ONLY | MemoryFlags::NO_EXECUTE,
        );
        let entry = walk_entry(kmap.root_phys(), user_virt).unwrap();
        assert_eq!(entry & pte_bits::ADDR_MASK, 0x3000);
        assert_eq!(entry & pte_bits::WRITABLE, 0);
        assert_ne!(entry & pte_bits::NO_EXECUTE, 0);

        // ── Фаза 2: 1 ГиБ huge-лист (как build_identity_hhdm) ──
        kmap.display_map(
            MemoryPTR::new(0, GIB / PAGE_SIZE).unwrap(),
            KERNEL_VIRT,
            MemoryFlags::SUPERVISOR | MemoryFlags::FLAG_SIZE1GB,
        );
        let huge = walk_entry(kmap.root_phys(), KERNEL_VIRT).unwrap();
        assert_eq!(huge & pte_bits::ADDR_MASK, 0);
        assert_ne!(huge & pte_bits::HUGE, 0);
        assert_ne!(huge & pte_bits::PRESENT, 0);

        // ── Фаза 3: умап = копия верхней половины + пользовательские листы ──
        // Ядерный 4K-маппинг ставим в СЛЕДУЮЩЕМ 1 ГиБ-регионе (PDPT-индекс 1),
        // чтобы не пересекаться с huge-листом из фазы 2 (PDPT-индекс 0) —
        // перекрытия адресов код не детектит сознательно.
        let kernel_display_virt = KERNEL_VIRT + GIB;
        kmap.display_map(
            MemoryPTR::new(0x4000, 1).unwrap(),
            kernel_display_virt,
            MemoryFlags::SUPERVISOR,
        );
        let umap = kmap
            .create_userspace_mapping(frames(), 0..0)
            .expect("umap creation");

        let kernel_idx = (kernel_display_virt >> 39) & 0x1ff;
        assert_eq!(
            unsafe { table_at(kmap.root_phys()) }[kernel_idx],
            unsafe { table_at(umap.root_phys()) }[kernel_idx],
            "верхняя половина PML4 должна быть скопирована"
        );

        let uphys = MemoryPTR::new(0x6000, 2).unwrap();
        umap.map_memory_region(frames(), uphys, user_virt).unwrap();
        for i in 0..2 {
            let entry = walk_entry(umap.root_phys(), user_virt + i * PAGE_SIZE).unwrap();
            assert_eq!(entry & pte_bits::ADDR_MASK, (0x6000 + i * PAGE_SIZE) as u64);
            assert_ne!(entry & pte_bits::USER, 0);
            assert_ne!(entry & pte_bits::WRITABLE, 0);
        }

        // Размаппинг снимает записи и идемпотентен.
        umap.unmap_memory_region(frames(), uphys, user_virt)
            .unwrap();
        assert_eq!(walk_entry(umap.root_phys(), user_virt).unwrap(), 0);
        umap.unmap_memory_region(frames(), uphys, user_virt)
            .unwrap();

        // ── Фаза 4: allocate_memory_region уважает границу HHDM ──
        // Поднимаем лимит так, чтобы текущий счётчик кадров упёрся в него
        // через несколько аллокаций.
        let next = FRAMES.0.load(Ordering::SeqCst);
        set_mapped_phys_limit(next * PAGE_SIZE + 3 * PAGE_SIZE);
        let mut ok = 0;
        loop {
            match umap.allocate_memory_region(frames(), 1) {
                Ok(_) => ok += 1,
                Err(ErrorCode::OutOfMappedBounds) => break,
                Err(e) => panic!("неожиданная ошибка {e:?}"),
            }
        }
        assert_eq!(ok, 3, "должны уместиться ровно 3 страницы до границы");
    }
}
