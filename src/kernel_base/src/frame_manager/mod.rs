use crate::traits::memory::{GIB, MAPPED_PHYS_LIMIT, MemoryPTR, PAGE_SIZE};

pub mod phys_frame_manager;

/// Тип физического региона памяти, как его описал загрузчик.
///
/// Названия и семантика ориентированы на типичную карту памяти
/// UEFI/Multiboot2/Limine — расширяйте/переименовывайте под конкретный
/// формат, который парсит ваш загрузчик, если он отличается.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryMarker {
    /// Свободная память, доступная под нужды ядра прямо сейчас.
    Usable,
    /// Занята платформой (MMIO-окна, зарезервировано прошивкой и т.п.) —
    /// никогда не отдавать во FrameAllocator.
    Reserved,
    /// ACPI-таблицы. Можно вернуть во FrameAllocator после того, как ACPI
    /// распарсен и таблицы больше не нужны.
    AcpiReclaimable,
    /// ACPI NVS — трогать нельзя никогда, используется прошивкой при
    /// переходах в сон/из сна.
    AcpiNvs,
    /// Битая память, о которой сообщил загрузчик — никогда не использовать.
    BadMemory,
    /// Временные структуры самого загрузчика (его page tables, memory map,
    /// сам BootInfo и т.п.). Становится свободной сразу после того, как
    /// ядро их прочитало — см. цикл реклейма в `KernelCTL::new_and_init`.
    BootloaderReclaimable,
    /// Занята самим ядром и загруженными модулями (initrd и т.п.).
    KernelAndModules,
    /// Память под framebuffer.
    Framebuffer,
}

/// Описание одного физического региона из карты памяти загрузчика.
///
/// `begin`/`pages` — в тех же единицах, что и `MemoryPTR` (номер страницы,
/// не байт), чтобы регион можно было напрямую конвертировать в `MemoryPTR`
/// через `as_memory_ptr()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsableMemoryRegion {
    pub begin: usize,
    pub pages: usize,
    pub r#type: MemoryMarker,
}

impl UsableMemoryRegion {
    /// Физический адрес конца региона (невключительно).
    ///
    /// ПРЕДПОЛОЖЕНИЕ: `begin + pages * PAGE_SIZE` не переполняет `usize` —
    /// верно для любой реалистичной карты памяти. Если регионы приходят из
    /// недоверенного источника, замените на `checked_mul`/`checked_add`.
    pub fn end(&self) -> usize {
        self.begin + self.pages * PAGE_SIZE
    }

    pub fn is_usable(&self) -> bool {
        self.r#type == MemoryMarker::Usable
    }

    /// Временные структуры загрузчика (page tables, memory map, ACPI-таблицы
    /// после парсинга) — то, что можно вернуть во FrameAllocator сразу после
    /// того, как ядро их прочитало.
    pub fn is_reclaimable(&self) -> bool {
        matches!(
            self.r#type,
            MemoryMarker::BootloaderReclaimable | MemoryMarker::AcpiReclaimable
        )
    }

    /// Конвертирует регион в `MemoryPTR` для передачи во FrameAllocator.
    /// `None`, если регион не выровнен по странице (некорректная карта
    /// памяти от загрузчика) — стоит проверять, а не `expect`, поскольку
    /// эти данные приходят снаружи ядра.
    pub fn as_memory_ptr(&self) -> Option<MemoryPTR> {
        MemoryPTR::new(self.begin, self.pages)
    }
}

/// Верхняя граница физического адреса, которую реально нужно покрыть HHDM.
///
/// Берём максимум среди ВСЕХ регионов карты памяти, а не только `Usable` —
/// framebuffer, ACPI-таблицы и т.п. тоже занимают физические адреса и должны
/// быть достижимы через HHDM (например, чтобы отобразить в память MMIO
/// фреймбуфера). Результат округляется вверх до целого числа гигабайт (так
/// как `build_identity_hhdm` строит HHDM 1GB-страницами) и не превышает
/// `MAPPED_PHYS_LIMIT` — жёсткий потолок, на который рассчитана текущая
/// таблица страниц.
///
/// Используется и в ветке, где HHDM строим сами (`build_identity_hhdm`,
/// передать результат как `up_to`), и в ветке, где HHDM уже поднял
/// загрузчик — там это лучшая доступная оценка того, докуда бутлоадер
/// реально замапил память (сам он размер своего маппинга не сообщает,
/// только offset через `BootInfo::hhdm_offset()`), нужная для
/// `set_mapped_phys_limit`.
pub fn compute_mapped_limit(memory_regions: &[UsableMemoryRegion]) -> usize {
    let highest = memory_regions.iter().map(|r| r.end()).max().unwrap_or(0);

    let rounded = highest
        .checked_add(GIB - 1)
        .map(|v| (v / GIB) * GIB)
        .unwrap_or(MAPPED_PHYS_LIMIT);

    rounded.min(MAPPED_PHYS_LIMIT)
}
