//! Обёртка над UMAP (`MemoryInterfaceUserspace`): аллокация виртуальных
//! страниц и отслеживание аллокаций.
//!
//! Зачем: сам UMAP-трейт оперирует физическими регионами и маппингами
//! (allocate/map/unmap/deallocate), но ничего не знает про то, КАКИЕ
//! виртуальные диапазоны уже заняты у задачи. Это приводило к тому, что
//! каждый вызывающий должен был бы сам вести учёт виртуальных адресов.
//!
//! Слой `umap` закрывает это двумя типами:
//!
//!   - `VirtualPageTracker` — чистый учёт: окно виртуального адресного
//!     пространства задачи (base + pages), bump-выделение диапазонов,
//!     реестр аллокаций (virt_base -> VmapEntry) со счётчиками.
//!   - `VmapRegion` — код-обёртка над трекером + UMAP: `alloc()` в одной
//!     операции резервирует виртуальный диапазон, выделяет физические
//!     фреймы у FrameAllocator, строит маппинг через UMAP и записывает
//!     аллокацию в реестр; `free()` выполняет обратную последовательность.
//!     Есть вариант `alloc_with_quota()`, синхронно заряжающий квоту
//!     памяти namespace (и возвращающий её при любой неудаче) — связка с
//!     групповым учётом ресурсов.
//!
//! ОСОЗНАННОЕ ОГРАНИЧЕНИЕ: bump-аллокатор виртуальных адресов. Освобождённые
//! (и не удавшиеся) диапазоны VA НЕ переиспользуются — окно задачи выбирается
//! большим (по умолчанию 64 ГиБ), а точное переиспользование требует
//! итератора по дереву/списка свободных диапазонов, которого у RBSlabIO
//! пока нет. Учёт аллокаций при этом полный: lookup/stats/free работают
//! строго по реестру.
//!
//! ПОРЯДОК ЛОКОВ: `VmapRegion` держит один SpinMutex на трекер и под ним
//! вызывает UMAP/FrameAllocator. Эти вызовы не заходят обратно в AccessManager,
//! поэтому вызывать `alloc/free` под permission_backend-локом безопасно
//! (поддерживаем глобальный порядок AccessManager -> VmapRegion).

use attachable_slab_allocator::SlabError;
use spin::mutex::SpinMutex;

use crate::{
    access::namespace::{Namespace, NamespaceError},
    collection::RBSlabIO,
    traits::memory::{
        ErrorCode, FrameAllocator, MemoryFlags, MemoryInterfaceUserspace, MemoryPTR, PAGE_SIZE,
    },
};

/// Окно виртуального адресного пространства задачи по умолчанию:
/// [4 ГиБ, 68 ГиБ). Ниже 4 ГиБ обычно живут код/стек загрузчика и ядро,
/// поэтому пользовательские маппины стартуем выше.
pub const DEFAULT_TASK_VMAP_BASE: usize = 0x0000_0001_0000_0000;
/// 64 ГиБ окна = 16М страниц по 4 КиБ.
pub const DEFAULT_TASK_VMAP_PAGES: usize = 64 * 1024 * 1024 * 1024 / PAGE_SIZE;

/// Ручка на аллокацию виртуальных страниц. По сути — виртуальный адрес
/// начала диапазона (он же ключ реестра), обёрнутый в тип, чтобы
/// перепутать его с "просто числом" было сложнее.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmapHandle {
    virt_base: usize,
}

impl VmapHandle {
    pub fn virt_base(&self) -> usize {
        self.virt_base
    }

    /// Восстановление хендла по базовому VA (сисколл FREE_PAGES/
    /// UNMOUNT_CAP_REGION получают голый адрес от userspace).
    pub fn from_base(virt_base: usize) -> Self {
        Self { virt_base }
    }
}

#[derive(Debug)]
pub enum VmapError {
    /// Запрос на 0 страниц.
    ZeroPages,
    /// Виртуальное окно задачи исчерпано (bump-аллокатор дошёл до конца).
    OutOfVirtualSpace,
    /// Переполнение адресной арифметики.
    AddressOverflow,
    /// Ошибка нижнего слоя (физические фреймы / маппинг UMAP).
    Frame(ErrorCode),
    /// Аллокация с таким виртуальным адресом не числится в реестре
    /// (повторный free, чужой адрес).
    NotTracked,
    /// Операция применима только к внешним (MMIO) маппингам — или
    /// наоборот: внешний маппинг нельзя освободить как обычную память.
    ExternalMismatch,
    /// Ошибка квоты namespace (лимит/underflow).
    Quota(NamespaceError),
    /// Аллокация была сделана с квотой, а free() не получил namespace —
    /// квота бы утекла, поэтому отказ.
    QuotaMissing,
    /// Ошибка slab-аллокатора при записи в реестр.
    Slab(SlabError),
    /// Регион активно замаплен в IOMMU-домен (dma_pins > 0): free
    /// вернёт фреймы в пул под DMA-двигателем — use-after-free.
    /// Сначала UnmapDma по всем привязкам, потом free.
    DmaPinned,
}

/// Трекинговая запись одной аллокации виртуальных страниц.
#[derive(Debug, Clone, Copy)]
pub struct VmapEntry {
    /// Размер аллокации в страницах.
    pub pages: usize,
    /// Флаги, с которыми запрашивалась память (снимок для учёта; сам
    /// маппинг строит UMAP-реализация).
    pub flags: MemoryFlags,
    /// Физическая база выделенного региона (0 до/если маппинг не удался).
    pub phys_base: usize,
    /// Сколько байт заряжено в квоту namespace (0 — квота не заряжалась).
    pub quota_bytes: usize,
    /// Внешний маппинг (MMIO): фреймы НЕ принадлежат задаче — free()
    /// запрещён, только unmap_external().
    pub external: bool,
    /// Число активных DMA-привязок региона (MapDmaVa). Пока > 0,
    /// free() запрещён — фреймы читает/пишет устройство.
    pub dma_pins: u32,
}

/// Снимок состояния трекера — то, что интересно учёту и отладке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmapStats {
    pub allocation_count: usize,
    pub allocated_pages: usize,
    /// Сколько страниц виртуального окна уже раздал bump-аллокатор
    /// (включая освободённые — VA не переиспользуются).
    pub pages_dispensed: usize,
    pub window_pages: usize,
}

/// Чистый учёт виртуальных страниц задачи.
///
/// Мутации — через `&mut self` (владелец — SpinMutex в VmapRegion), так
/// что атомарность на полях не нужна.
pub struct VirtualPageTracker {
    window_base: usize,
    window_pages: usize,
    /// Смещение (в страницах) следующего выдаваемого диапазона от окна.
    next_free_offset: usize,
    allocation_count: usize,
    allocated_pages: usize,
    /// Реестр аллокаций: виртуальный адрес начала -> запись.
    allocations: RBSlabIO<usize, VmapEntry, false>,
}

impl VirtualPageTracker {
    pub fn new(window_base: usize, window_pages: usize) -> Result<Self, SlabError> {
        Ok(Self {
            window_base,
            window_pages,
            next_free_offset: 0,
            allocation_count: 0,
            allocated_pages: 0,
            allocations: RBSlabIO::new()?,
        })
    }

    /// Границы виртуального окна (base, pages).
    pub fn window(&self) -> (usize, usize) {
        (self.window_base, self.window_pages)
    }

    pub fn stats(&self) -> VmapStats {
        VmapStats {
            allocation_count: self.allocation_count,
            allocated_pages: self.allocated_pages,
            pages_dispensed: self.next_free_offset,
            window_pages: self.window_pages,
        }
    }

    /// Просмотр записи аллокации без снятия с учёта.
    pub fn lookup(&self, virt_base: usize) -> Option<VmapEntry> {
        self.allocations.get(&virt_base).copied()
    }

    /// Поиск аллокации, целиком содержащей [va, va + pages*PAGE_SIZE).
    /// Реестр ключован virt_base, а записи базу не хранят — обходим
    /// дерево (for_each_kv): аллокаций у задачи десятки, не тысячи.
    pub fn find_containing(&self, va: usize, pages: usize) -> Option<(usize, VmapEntry)> {
        let end = va.checked_add(pages.checked_mul(PAGE_SIZE)?)?;
        let mut found: Option<(usize, VmapEntry)> = None;
        self.allocations.for_each_kv(|base, entry| {
            if found.is_some() {
                return;
            }
            let Some(region_end) = base.checked_add(entry.pages.saturating_mul(PAGE_SIZE)) else {
                return;
            };
            if va >= *base && end <= region_end {
                found = Some((*base, *entry));
            }
        });
        found
    }

    /// Наращивает счётчик DMA-привязок (насыщение u32).
    pub fn pin_dma(&mut self, virt_base: usize) -> Result<u32, VmapError> {
        // Сами счётчики — в записи; запись Copy, поэтому правка идёт
        // через remove+insert (интрузивное дерево &mut V не даёт).
        let mut entry = self.allocations.remove(&virt_base).ok_or(VmapError::NotTracked)?.1;
        entry.dma_pins = entry.dma_pins.saturating_add(1);
        let pins = entry.dma_pins;
        self.allocations
            .insert(virt_base, entry)
            .map_err(VmapError::Slab)?;
        Ok(pins)
    }

    /// Снимает одну DMA-привязку. Unpin несуществующей записи — ошибка
    /// (рассинхрон доменной привязки и umap), но запись не портим.
    pub fn unpin_dma(&mut self, virt_base: usize) -> Result<u32, VmapError> {
        let mut entry = self.allocations.remove(&virt_base).ok_or(VmapError::NotTracked)?.1;
        entry.dma_pins = entry.dma_pins.saturating_sub(1);
        let pins = entry.dma_pins;
        self.allocations
            .insert(virt_base, entry)
            .map_err(VmapError::Slab)?;
        Ok(pins)
    }

    /// Резервирует `pages` виртуальных страниц, возвращает виртуальный
    /// адрес начала. Запись в реестр делает `track` ПОСЛЕ успешного
    /// маппинга — так неудачная аллокация не оставляет мусорных записей.
    fn reserve(&mut self, pages: usize) -> Result<usize, VmapError> {
        if pages == 0 {
            return Err(VmapError::ZeroPages);
        }
        let new_offset = self
            .next_free_offset
            .checked_add(pages)
            .ok_or(VmapError::AddressOverflow)?;
        if new_offset > self.window_pages {
            return Err(VmapError::OutOfVirtualSpace);
        }
        let virt = self
            .window_base
            .checked_add(self.next_free_offset.checked_mul(PAGE_SIZE).ok_or(VmapError::AddressOverflow)?)
            .ok_or(VmapError::AddressOverflow)?;
        self.next_free_offset = new_offset;
        Ok(virt)
    }

    /// Записывает аллокацию в реестр (вызывать после успешного маппинга).
    fn track(&mut self, virt_base: usize, entry: VmapEntry) -> Result<(), VmapError> {
        self.allocations
            .insert(virt_base, entry)
            .map_err(VmapError::Slab)?;
        self.allocation_count += 1;
        self.allocated_pages += entry.pages;
        Ok(())
    }

    /// Снимает аллокацию с учёта, возвращает её запись.
    fn release(&mut self, virt_base: usize) -> Result<VmapEntry, VmapError> {
        let (_, entry) = self
            .allocations
            .remove(&virt_base)
            .ok_or(VmapError::NotTracked)?;
        self.allocation_count -= 1;
        self.allocated_pages -= entry.pages;
        Ok(entry)
    }
}

/// Код-обёртка: связывает трекер виртуальных страниц с конкретной UMAP-
/// реализацией (методы принимают `umap: &UMAP`, чтобы обёртку можно было
/// хранить внутри GTcb, не двигая сам UMAP).
pub struct VmapRegion {
    tracker: SpinMutex<VirtualPageTracker>,
}

impl VmapRegion {
    pub fn new(
        window_base: usize,
        window_pages: usize,
    ) -> Result<Self, SlabError> {
        Ok(Self {
            tracker: SpinMutex::new(VirtualPageTracker::new(window_base, window_pages)?),
        })
    }

    /// Аллокация виртуальных страниц без квоты namespace.
    pub fn alloc<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        pages: usize,
        flags: MemoryFlags,
    ) -> Result<VmapHandle, VmapError> {
        self.alloc_impl(umap, frames, pages, flags, None)
    }

    /// Аллокация с зарядкой квоты памяти namespace (см. Namespace::try_alloc_memory).
    /// Квота возвращается при ЛЮБОЙ неудаче дальнейших шагов.
    pub fn alloc_with_quota<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        pages: usize,
        flags: MemoryFlags,
        quota: &Namespace,
    ) -> Result<VmapHandle, VmapError> {
        self.alloc_impl(umap, frames, pages, flags, Some(quota))
    }

    fn alloc_impl<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        pages: usize,
        flags: MemoryFlags,
        quota: Option<&Namespace>,
    ) -> Result<VmapHandle, VmapError> {
        let quota_bytes = quota
            .map(|_| pages.checked_mul(PAGE_SIZE).ok_or(VmapError::AddressOverflow))
            .transpose()?;

        // Квота заряжается ПЕРВЫМ делом: если группа исчерпала лимит,
        // дальше даже пробовать нечего.
        if let (Some(ns), Some(bytes)) = (quota, quota_bytes) {
            ns.try_alloc_memory(bytes).map_err(VmapError::Quota)?;
        }

        let mut tracker = self.tracker.lock();

        let virt = match tracker.reserve(pages) {
            Ok(virt) => virt,
            Err(e) => {
                drop(tracker);
                Self::rollback_quota(quota, quota_bytes);
                return Err(e);
            }
        };

        // 1. Физические фреймы у FrameAllocator.
        let phys = match umap.allocate_memory_region(frames, pages) {
            Ok(region) => region,
            Err(e) => {
                drop(tracker);
                Self::rollback_quota(quota, quota_bytes);
                return Err(VmapError::Frame(e));
            }
        };

        // 2. Маппинг в зарезервированный виртуальный диапазон.
        let mapped = match umap.map_memory_region(frames, phys, virt) {
            Ok(mapped) => mapped,
            Err(e) => {
                // Фреймы, не дошедшие до маппинга, возвращаем в пул.
                let _ = umap.deallocate_memory_region(frames, phys, pages);
                drop(tracker);
                Self::rollback_quota(quota, quota_bytes);
                return Err(VmapError::Frame(e));
            }
        };

        // 3. Учёт. Если реестр не принял запись — раскручиваем всё назад,
        // чтобы аллокация не существовала "наполовину".
        let entry = VmapEntry {
            pages,
            flags,
            phys_base: mapped.phys_base(),
            quota_bytes: quota_bytes.unwrap_or(0),
            external: false,
            dma_pins: 0,
        };
        if let Err(e) = tracker.track(virt, entry) {
            let _ = umap.unmap_memory_region(frames, mapped, virt);
            let _ = umap.deallocate_memory_region(frames, phys, pages);
            drop(tracker);
            Self::rollback_quota(quota, quota_bytes);
            return Err(e);
        }

        Ok(VmapHandle { virt_base: virt })
    }

    fn rollback_quota(quota: Option<&Namespace>, quota_bytes: Option<usize>) {
        if let (Some(ns), Some(bytes)) = (quota, quota_bytes) {
            let _ = ns.free_memory(bytes);
        }
    }

    /// Освобождение аллокации: снятие с учёта, размапинг, возврат фреймов
    /// в пул и возврат квоты (если аллокация была заряжена).
    pub fn free<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        handle: VmapHandle,
        quota: Option<&Namespace>,
    ) -> Result<(), VmapError> {
        let entry = {
            let mut tracker = self.tracker.lock();
            let entry = tracker.release(handle.virt_base())?;
            if entry.dma_pins > 0 {
                // Вернуть запись на место: откат free без side-эффектов —
                // release() уже снял счётчики, восстанавливаем.
                let _ = tracker.track(handle.virt_base(), entry);
                return Err(VmapError::DmaPinned);
            }
            if entry.external {
                // MMIO нельзя вернуть в пул фреймов — только unmap_external.
                let _ = tracker.track(handle.virt_base(), entry);
                return Err(VmapError::ExternalMismatch);
            }
            entry
        };

        let region = MemoryPTR::new(entry.phys_base, entry.pages).ok_or(VmapError::NotTracked)?;

        umap.unmap_memory_region(frames, region, handle.virt_base())
            .map_err(VmapError::Frame)?;
        umap.deallocate_memory_region(frames, region, entry.pages)
            .map_err(VmapError::Frame)?;

        if entry.quota_bytes != 0 {
            let ns = quota.ok_or(VmapError::QuotaMissing)?;
            ns.free_memory(entry.quota_bytes).map_err(VmapError::Quota)?;
        }

        Ok(())
    }

    /// Просмотр записи аллокации (отслеживание: кто/что занято).
    pub fn lookup(&self, virt_base: usize) -> Option<VmapEntry> {
        self.tracker.lock().lookup(virt_base)
    }

    /// Поиск аллокации, целиком содержащей [va, va + pages*PAGE_SIZE).
    /// Возвращает (virt_base записи, запись) — основа MapDmaVa:
    /// физика региона = phys_base + (va - virt_base).
    pub fn find_containing(&self, va: usize, pages: usize) -> Option<(usize, VmapEntry)> {
        self.tracker.lock().find_containing(va, pages)
    }

    /// Наращивает счётчик DMA-привязок региона. Возвращает новое
    /// значение (насыщение u32 — анти-переполнение при повторных
    /// маппингах одного региона).
    pub fn pin_dma(&self, virt_base: usize) -> Result<u32, VmapError> {
        self.tracker.lock().pin_dma(virt_base)
    }

    /// Снимает одну DMA-привязку (парная к pin_dma, зовёт UnmapDma).
    pub fn unpin_dma(&self, virt_base: usize) -> Result<u32, VmapError> {
        self.tracker.lock().unpin_dma(virt_base)
    }

    /// Маппинг ВНЕШНЕГО (MMIO) физического региона в свежезарезервированное
    /// окно задачи: фреймы НЕ выделяются и НЕ возвращаются в пул — только
    /// отображение + учёт. Освобождение — парным [`unmap_external`].
    /// Вызывается сисколлом MountCapRegion по MMIO-капабилити.
    pub fn map_external<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        phys: MemoryPTR,
        flags: MemoryFlags,
    ) -> Result<VmapHandle, VmapError> {
        let pages = phys.pages();
        let mut tracker = self.tracker.lock();
        let virt = tracker.reserve(pages)?;
        let mapped = match umap.map_memory_region_flags(frames, phys, virt, flags) {
            Ok(m) => m,
            Err(e) => return Err(VmapError::Frame(e)),
        };
        let entry = VmapEntry {
            pages,
            flags,
            phys_base: mapped.phys_base(),
            quota_bytes: 0,
            external: true,
            dma_pins: 0,
        };
        if let Err(e) = tracker.track(virt, entry) {
            let _ = umap.unmap_memory_region(frames, mapped, virt);
            return Err(e);
        }
        Ok(VmapHandle { virt_base: virt })
    }

    /// Снятие внешнего (MMIO) маппинга: размапинг + снятие с учёта,
    /// БЕЗ возврата фреймов (они не наши). Обычные аллокации
    /// освобождаются через [`free`].
    pub fn unmap_external<UMAP: MemoryInterfaceUserspace>(
        &self,
        umap: &UMAP,
        frames: &dyn FrameAllocator,
        handle: VmapHandle,
    ) -> Result<(), VmapError> {
        let entry = {
            let mut tracker = self.tracker.lock();
            let entry = tracker.release(handle.virt_base())?;
            if !entry.external {
                let _ = tracker.track(handle.virt_base(), entry);
                return Err(VmapError::ExternalMismatch);
            }
            entry
        };
        let region = MemoryPTR::new(entry.phys_base, entry.pages).ok_or(VmapError::NotTracked)?;
        umap.unmap_memory_region(frames, region, handle.virt_base())
            .map_err(VmapError::Frame)
    }

    /// Снимок учёта аллокаций.
    pub fn stats(&self) -> VmapStats {
        self.tracker.lock().stats()
    }

    /// Границы виртуального окна (base, pages).
    pub fn window(&self) -> (usize, usize) {
        self.tracker.lock().window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{init_hooks, set_hhdm_offset, MemoryFlags, PAGE_SIZE};

    static std_once: std::sync::Once = std::sync::Once::new();
    fn ensure_slab() {
        std_once.call_once(|| {
            let mem = unsafe {
                // Странично выровненный leaks-буфер под HHDM + slab-страницы
                // (тот же приём, что в idalloc::tests).
                let layout =
                    std::alloc::Layout::from_size_align(16 * 1024 * 1024, PAGE_SIZE)
                        .expect("layout");
                let ptr = std::alloc::alloc_zeroed(layout);
                assert!(!ptr.is_null(), "oom");
                core::slice::from_raw_parts_mut(ptr, 16 * 1024 * 1024 / PAGE_SIZE)
            };
            set_hhdm_offset(mem.as_ptr() as usize);
            struct TestFrames;
            impl crate::traits::memory::FrameAllocator for TestFrames {
                fn allocate_pages(
                    &self,
                    _count: usize,
                ) -> Option<crate::traits::memory::MemoryPTR> {
                    None
                }
                fn deallocate_pages(&self, _ptr: crate::traits::memory::MemoryPTR) {}
            }
            init_hooks::init_allocator(&TestFrames);
        });
    }

    #[test]
    fn dma_pin_find_and_gate() {
        // ГАРД: ensure_slab двигает глобальные slab-хуки (см. idalloc).
        let _guard = crate::test_guard::GLOBAL.lock();
        ensure_slab();
        let mut tracker = VirtualPageTracker::new(0x0000_0001_0000_0000, 64).expect("tracker");
        let virt = tracker.reserve(4).expect("reserve");
        tracker
            .track(
                virt,
                VmapEntry {
                    pages: 4,
                    flags: MemoryFlags::empty(),
                    phys_base: 0x0000_0002_0000_0000,
                    quota_bytes: 0,
                    external: false,
                    dma_pins: 0,
                },
            )
            .expect("track");

        // find_containing: внутри / со сдвигом / за границей / мимо.
        assert_eq!(tracker.find_containing(virt, 4).map(|(b, _)| b), Some(virt));
        assert_eq!(
            tracker.find_containing(virt + PAGE_SIZE, 3).map(|(b, _)| b),
            Some(virt)
        );
        assert!(tracker.find_containing(virt, 5).is_none());
        assert!(tracker.find_containing(virt + 4 * PAGE_SIZE, 1).is_none());

        // pin/unpin: счётчик, парность, отказ на неотслеживаемом.
        assert_eq!(tracker.pin_dma(virt).unwrap(), 1);
        assert_eq!(tracker.pin_dma(virt).unwrap(), 2);
        assert_eq!(tracker.unpin_dma(virt).unwrap(), 1);
        assert_eq!(tracker.unpin_dma(virt).unwrap(), 0);
        assert!(tracker.unpin_dma(virt + 8 * PAGE_SIZE).is_err());
    }
}
