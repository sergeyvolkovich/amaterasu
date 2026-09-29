use core::slice::from_raw_parts_mut;

use llfree::{
    Alloc, Class, Classing, FRAME_SIZE, FrameId, HUGE_FRAMES, HUGE_ORDER, Init, LLFree, MetaData,
    Request,
};

use crate::{
    frame_manager::{MemoryMarker, UsableMemoryRegion},
    traits::memory::{FrameAllocator, MemoryPTR},
};

pub struct FrameManager {
    manager: LLFree<'static>,
    page_size: usize,
    /// Физический адрес кадра №0 (выровнен по huge-странице)
    base: usize,
    cpu_count: usize,
    /// Вырезанный под метаданные LLFree физический диапазон
    /// [begin, end) — исключается из phys_guard::dma_allowed
    /// (DMA/монтирование по метаданным аллокатора = компрометация
    /// менеджера кадров). Заполняется в init.
    meta_range: (usize, usize),
}

const fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

fn is_usable(r: &UsableMemoryRegion) -> bool {
    r.r#type == MemoryMarker::Usable && r.pages > 0
}

impl FrameManager {
    /// `phys_offset` - смещение для доступа к физической памяти
    /// (0 при identity-маппинге, иначе HHDM offset).
    /// Массив `mem_regions` сортируется, а из региона под метаданные они вырезаются.
    pub fn init(
        page_size: usize,
        mem_regions: &mut [UsableMemoryRegion],
        cpu_count: usize,
        phys_offset: usize,
    ) -> Result<Self, llfree::Error> {
        assert!(page_size == FRAME_SIZE);
        let huge_bytes = HUGE_FRAMES * page_size;

        mem_regions.sort_unstable_by_key(|r| r.begin);

        // 1. Границы usable-памяти. base выравниваем вниз до huge-страницы.
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for r in mem_regions.iter().filter(|r| is_usable(r)) {
            debug_assert!(r.begin % page_size == 0);
            lo = lo.min(r.begin);
            hi = hi.max(r.begin + r.pages * page_size);
        }
        assert!(lo < hi, "no usable memory regions");

        let base = lo & !(huge_bytes - 1);
        let total_frames = (hi - base) / page_size;

        // 2. Размер метаданных: секции с начала страницы, итог кратен huge-странице,
        //    чтобы остаток региона остался huge-выровненным.
        let (classing, _) = Classing::simple(cpu_count);
        let ms = LLFree::metadata_size(&classing, total_frames);
        let trees_off = align_up(ms.local, page_size);
        let lower_off = trees_off + align_up(ms.trees, page_size);
        let meta_bytes = align_up(lower_off + align_up(ms.lower, page_size), huge_bytes);
        let meta_pages = meta_bytes / page_size;

        // 3. Вырезаем метаданные из huge-выровненного Usable-региона (иначе из любого подходящего)
        let idx = mem_regions
            .iter()
            .position(|r| is_usable(r) && r.begin % huge_bytes == 0 && r.pages >= meta_pages)
            .or_else(|| {
                mem_regions
                    .iter()
                    .position(|r| is_usable(r) && r.pages >= meta_pages)
            })
            .expect("no usable region big enough for allocator metadata");

        let region = &mut mem_regions[idx];
        let meta_base = region.begin;
        region.begin += meta_bytes;
        region.pages -= meta_pages;

        let ptr = (phys_offset + meta_base) as *mut u8;
        let meta = unsafe {
            MetaData {
                local: from_raw_parts_mut(ptr, ms.local),
                trees: from_raw_parts_mut(ptr.add(trees_off), ms.trees),
                lower: from_raw_parts_mut(ptr.add(lower_off), ms.lower),
            }
        };

        // 4. Всё занято; всё, что не Usable (и метаданные), таким и останется
        let manager = LLFree::new(total_frames, Init::AllocAll, &classing, meta)?;

        // 5. Освобождаем Usable-память, склеивая смежные регионы
        let mut expected_free = 0;
        let (mut cs, mut ce) = (0usize, 0usize);
        for r in mem_regions.iter().filter(|r| is_usable(r)) {
            let s = (r.begin - base) / page_size;
            let e = s + r.pages;
            expected_free += r.pages;
            if cs != ce && ce == s {
                ce = e;
            } else {
                if cs != ce {
                    Self::free_range(&manager, cs, ce)?;
                }
                cs = s;
                ce = e;
            }
        }
        if cs != ce {
            Self::free_range(&manager, cs, ce)?;
        }

        debug_assert_eq!(manager.stats().free_frames, expected_free);

        Ok(Self {
            manager,
            base,
            cpu_count,
            page_size,
            meta_range: (meta_base, meta_base + meta_bytes),
        })
    }

    /// Физический диапазон [begin, end) метаданных аллокатора (см.
    /// phys_guard — регистрируется как forbidden на буте).
    pub fn metadata_range(&self) -> (usize, usize) {
        self.meta_range
    }

    /// Свободные кадры в пуле (диагностика бут-пути).
    pub fn free_frames(&self) -> usize {
        self.manager.stats().free_frames
    }

    /// Разбивает [start, end) на максимальные выровненные блоки и освобождает их
    fn free_range(m: &LLFree<'static>, start: usize, end: usize) -> Result<(), llfree::Error> {
        let mut f = start;
        while f < end {
            let mut order = HUGE_ORDER;
            while order > 0 && (f & ((1 << order) - 1) != 0 || f + (1 << order) > end) {
                order -= 1;
            }
            m.put(FrameId(f), Self::make_request(order, None))?;
            f += 1 << order;
        }
        Ok(())
    }

    /// Та же логика классов, что в Classing::simple: 0 - small, 1 - huge
    fn make_request(order: usize, local: Option<usize>) -> Request {
        Request::new(order, Class((order >= HUGE_ORDER) as u8), local)
    }

    /// Освобождает произвольный физический диапазон [phys, phys + pages*4096)
    /// СТЕПЕНЬЮ-ДВОЙКИ-ВЫРОВНЕННЫМИ чанками (как init-фаза free_range).
    ///
    /// ЗАЧЕМ: `FrameAllocator::deallocate_pages` трактует `pages` как
    /// мощность двойки (округляет вверх) — для reclaim-регионов с
    /// НЕ-степенным числом страниц он освобождал бы ЧУЖИЕ кадры за
    /// пределами региона. Этот метод режет диапазон на легальные
    /// buddy-блоки и освобождает каждый отдельно.
    ///
    /// Выравнивание чанков — по ИНДЕКСУ кадра относительно `self.base`
    /// (base huge-выровнен, поэтому для порядков <= HUGE_ORDER абсолютная
    /// и относительная alignment совпадают).
    pub fn free_range_phys(&self, cpu_id: usize, phys: usize, pages: usize) {
        if pages == 0 {
            return;
        }
        let start = (phys - self.base) / self.page_size;
        let end = start + pages;
        let mut f = start;
        while f < end {
            let mut order = HUGE_ORDER;
            while order > 0 && (f & ((1 << order) - 1) != 0 || f + (1 << order) > end) {
                order -= 1;
            }
            let _ = self.manager.put(FrameId(f), Self::make_request(order, Some(cpu_id % self.cpu_count)));
            f += 1 << order;
        }
    }

    fn request(&self, order: usize, cpu_id: usize) -> Request {
        Self::make_request(order, Some(cpu_id % self.cpu_count))
    }

    /// Возвращает физический адрес блока из 2^order страниц
    pub fn allocate_pages(&self, cpu_id: usize, order: usize) -> Result<usize, llfree::Error> {
        let (frame, _class) = self.manager.get(None, self.request(order, cpu_id))?;
        Ok(self.base + frame.0 * self.page_size)
    }

    pub fn free_pages(
        &self,
        cpu_id: usize,
        phys: usize,
        order: usize,
    ) -> Result<(), llfree::Error> {
        let frame = FrameId((phys - self.base) / self.page_size);
        self.manager.put(frame, self.request(order, cpu_id))
    }
}

impl FrameAllocator for FrameManager {
    /// Интерфейс FrameAllocator оперирует количеством страниц, а FrameManager
    /// — buddy-порядками. count округляется вверх до минимального покрывающего
    /// порядка: «лишние» страницы 2^order − count остаются собственностью этой
    /// аллокации (никому больше не выдаются) и освобождаются вместе с ней.
    fn allocate_pages(&self, count: usize) -> Option<crate::traits::memory::MemoryPTR> {
        if count == 0 {
            return None;
        }
        let order = count.checked_next_power_of_two()?.trailing_zeros() as usize;
        if order > HUGE_ORDER {
            // llfree не выдаёт один непрерывный блок крупнее huge-страницы.
            return None;
        }
        // Ядро вызывает этот интерфейс до/вне пер-ядерного контекста, поэтому
        // cpu_id = 0; порту с локальностью нужен свой обёрточный аллокатор.
        let phys = self.allocate_pages(0, order).ok()?;
        MemoryPTR::new(phys, count)
    }

    fn deallocate_pages(&self, ptr: crate::traits::memory::MemoryPTR) {
        // Порядок восстанавливается тем же отображением count -> order, что
        // и при аллокации, поэтому put() зеркалит исходный get().
        let count = ptr.pages();
        if count == 0 {
            return;
        }
        let order = count.next_power_of_two().trailing_zeros() as usize;
        if order > HUGE_ORDER {
            // Такой блок не мог быть выдан allocate_pages выше — игнорируем.
            return;
        }
        let _ = self.free_pages(0, ptr.phys_base(), order);
    }
}
