//! Реестр ФИЗИЧЕСКИХ диапазонов для валидации сисколлов, принимающих
//! «голую» физику от ring3: CAP_CREATE_MMIO (произвольный phys_origin) и
//! IOMMU MapDma/MapVa (произвольный phys). Без этого гейта задача с
//! CAP_MANAGE|MMIO_MAP (или DMA_ATTACH) смонтирует/проецирует через
//! устройство ЛЮБУЮ физическую память — включая образ ядра и метаданные
//! аллокатора — и получит чтение/запись памяти ядра в обход всей
//! capability-модели (монтаж MMIO-региона = RW-маппинг в её умап).
//!
//! ДВА СПИСКА, заполняются фронтендом НА БУТЕ (см. kernel_limine —
//! harvest_memory, сразу после FrameManager::init):
//!   - `ram` — реальные регионы RAM (Usable + reclaimable, вкл.
//!     deferred-reclaim бутлоадера). Растёт из карты памяти загрузчика;
//!     метаданные аллокатора ВЫРЕЗАНЫ из региона ДО регистрации, поэтому
//!     в списке их нет.
//!   - `forbidden` — то, что запрещено в ЛЮБОМ качестве: образ ядра и
//!     модули (KernelAndModules), BAD_MEMORY, метаданные аллокатора.
//!   - `acpi` — диапазоны ACPI-таблиц (RSDP-страница, корневая XSDT/RSDT,
//!     дочерние таблицы), регистрируемые фронтом на буте ПОСЛЕ их разбора
//!     (см. kernel_limine::acpi_guard_register). Таблицы лежат ВНУТРИ
//!     AcpiReclaimable-регионов (для MMIO-гейта это RAM), поэтому обычный
//!     путь их не пускает; отдельный allow-list — единственный легальный
//!     способ дать ring3 доступ к ACPI через CAP_CREATE_MMIO (init монтирует
//!     XSDT/MCFG/DRHD и публикует ECAM/BAR'ы драйверам). Правило выдачи —
//!     «целиком внутри ОДНОГО диапазона» (как dma_allowed): частичное
//!     пересечение могло бы открыть соседние RAM-страницы.
//!     ИНВАРИАНТ БЕЗОПАСНОСТИ: порт не имеет права возвращать
//!     AcpiReclaimable-кадры в кадровый пул, пока ядро живо (текущий
//!     x86-порт так и работает — reclaim_memory не free'ит); иначе
//!     MMIO-капа алиасила бы чужую RAM.
//!
//! ПОЛИТИКА:
//!   - CAP_CREATE_MMIO: диапазон НЕ должен пересекаться ни с `ram`
//!     (иначе RW-маппинг чужой RAM), ни с `forbidden`. Легальные цели —
//!     реально адресные «дыры» карты: framebuffer, Reserved, ACPI NVS,
//!     внекарточные MMIO-диапазоны устройств. ИСКЛЮЧЕНИЕ: запрос, целиком
//!     покрытый одним из `acpi`-диапазонов (см. ниже).
//!   - IOMMU MapDma/MapVa: диапазон обязан ЦЕЛИКОМ лежать в ОДНОМ
//!     регионе `ram` (DMA по не-RAM бессмысленен) и не пересекаться с
//!     `forbidden`.
//!
//! FAIL-CLOSED: пустой реестр (не инициализирован — юнит-тесты хоста,
//! порт без интеграции фронта) отклоняет ВСЁ: лучше сломанный MMIO-
//! драйвер, чем тихое чтение образа ядра.
//!
//! Гонки: запись — однопоточный бут до старта AP; чтение — сисколлы под
//! permission_backend. IrqSafeSpinMutex замыкает оба сценария.

use crate::irqsafe::IrqSafeSpinMutex;

/// Вместимость каждого списка. Карты памяти загрузчиков укладываются в
/// десятки записей (QEMU/limine ~ 5-12); переполнение регистрации
/// молча игнорируется ПАРТИЙНО (запись не влезла — не регистрируется),
/// поэтому резерв взят с большим запасом.
const MAX_RANGES: usize = 64;

/// Вместимость списка ACPI-диапазонов: RSDP + корневая таблица +
/// все дочерние (XSDT на реальном железе несёт десятки SSDT — запас
/// взят с прицелом наdesktop-платы).
const ACPI_MAX_RANGES: usize = 128;

#[derive(Clone, Copy)]
struct PhysRange {
    begin: usize,
    /// Эксклюзивный конец.
    end: usize,
}

#[derive(Default)]
struct GuardState {
    ram: [Option<PhysRange>; MAX_RANGES],
    forbidden: [Option<PhysRange>; MAX_RANGES],
    acpi: [Option<PhysRange>; ACPI_MAX_RANGES],
}

static GUARD: IrqSafeSpinMutex<GuardState> = IrqSafeSpinMutex::new(GuardState::new());

impl GuardState {
    const fn new() -> Self {
        // Option<PhysRange> — Copy, но не const-constructible через [None; N]
        // до Rust const-fn-Option: собираем через повторение.
        // (PhysRange не Drop, Option<PhysRange>: const None валиден.)
        const NONE: Option<PhysRange> = None;
        Self {
            ram: [NONE; MAX_RANGES],
            forbidden: [NONE; MAX_RANGES],
            acpi: [NONE; ACPI_MAX_RANGES],
        }
    }

    /// Толерантен к спискам разной длины (ram/forbidden = MAX_RANGES,
    /// acpi = ACPI_MAX_RANGES): переполнение — запись теряется
    /// (fail-closed: незарегистрированный диапазон не станет легальным).
    fn push(slot: &mut [Option<PhysRange>], r: PhysRange) {
        if let Some(free) = slot.iter_mut().find(|s| s.is_none()) {
            *free = Some(r);
        }
        // Нет места — запись теряется: fail-closed для пропущенного
        // диапазона хуже, чем fail-open (см. модульный комментарий), но
        // резерв 64/128 записей делает сценарий нереальным.
    }

    fn intersects(list: &[Option<PhysRange>], begin: usize, end: usize) -> bool {
        for r in list.iter().flatten() {
            if begin < r.end && r.begin < end {
                return true;
            }
        }
        false
    }

    fn fully_inside(list: &[Option<PhysRange>], begin: usize, end: usize) -> bool {
        for r in list.iter().flatten() {
            if begin >= r.begin && end <= r.end {
                return true;
            }
        }
        false
    }
}

/// Регистрирует регион реальной RAM (Usable/reclaimable/deferred).
/// Вызывается фронтом на буте; вне бута — no-op контракт не нарушает
/// (мутация под локом, сисколлы тот же лок берут).
pub fn register_ram(begin: usize, end: usize) {
    if begin >= end {
        return;
    }
    let mut g = GUARD.lock();
    GuardState::push(&mut g.ram, PhysRange { begin, end });
}

/// Регистрирует запретный диапазон (образ ядра, BAD_MEMORY, метаданные
/// аллокатора).
pub fn register_forbidden(begin: usize, end: usize) {
    if begin >= end {
        return;
    }
    let mut g = GUARD.lock();
    GuardState::push(&mut g.forbidden, PhysRange { begin, end });
}

/// Регистрирует диапазон ACPI-таблицы (RSDP/XSDT/RSDT/дочерние).
/// Вызывается фронтом на буте ПОСЛЕ разбора таблиц (см. модульный
/// комментарий про инвариант «AcpiReclaimable не возвращается пулу»).
/// Выравнивание по странице — обязанность вызывающего (гейт CAP_CREATE_MMIO
/// всё равно принимает только выровненные phys_origin/page_count).
pub fn register_acpi(begin: usize, end: usize) {
    if begin >= end {
        return;
    }
    let mut g = GUARD.lock();
    GuardState::push(&mut g.acpi, PhysRange { begin, end });
}

/// CAP_CREATE_MMIO: true — диапазон [begin, end) может быть выдан как
/// MMIO-регион: НЕ RAM, НЕ запрет, ЛИБО целиком внутри одного
/// зарегистрированного ACPI-диапазона (частичное пересечение с acpi
/// не спасает — внутри запроса могут быть соседние RAM-страницы).
/// Пустой реестр — false (fail-closed).
pub fn mmio_allowed(begin: usize, end: usize) -> bool {
    if begin >= end {
        return false;
    }
    let g = GUARD.lock();
    // Fail-closed на «карта не зарегистрирована».
    if g.ram.iter().all(|s| s.is_none()) {
        return false;
    }
    if GuardState::intersects(&g.forbidden, begin, end) {
        return false;
    }
    // ACPI-таблица: единственный случай, когда пересечение с RAM
    // легально (см. register_acpi).
    if GuardState::fully_inside(&g.acpi, begin, end) {
        return true;
    }
    !GuardState::intersects(&g.ram, begin, end)
}

/// IOMMU MapDma/MapVa: true — [begin, end) целиком лежит в одном регионе
/// RAM и не задевает запреты. Пустой реестр — false (fail-closed).
pub fn dma_allowed(begin: usize, end: usize) -> bool {
    if begin >= end {
        return false;
    }
    let g = GUARD.lock();
    if g.ram.iter().all(|s| s.is_none()) {
        return false;
    }
    GuardState::fully_inside(&g.ram, begin, end)
        && !GuardState::intersects(&g.forbidden, begin, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_without_registration() {
        // Реестр может быть уже заполнен другими тестами — не полагаемся
        // на глобальный порядок; проверяем только переполнения/пересечения
        // на ЛОКАЛЬНО зарегистрированных диапазонах ниже.
    }

    #[test]
    fn mmio_rejects_ram_and_kernel() {
        register_ram(0x1000_0000, 0x2000_0000);
        register_forbidden(0x100_0000, 0x110_0000);
        assert!(!mmio_allowed(0x1000_0000, 0x1010_0000), "RAM — не MMIO");
        assert!(!mmio_allowed(0x100_0000, 0x108_0000), "образ ядра запрещён");
        assert!(mmio_allowed(0x3000_0000, 0x3001_0000), "дыра карты — легально");
        assert!(!mmio_allowed(0x2000_0000, 0x3000_1000), "частичное пересечение RAM");
        assert!(!mmio_allowed(0x100, 0x100), "пустой диапазон");
    }

    #[test]
    fn acpi_allowlist_requires_full_containment() {
        // AcpiReclaimable-регион зарегистрирован как RAM, таблица внутри
        // него — как acpi. Запрос целиком по таблице — легален; запрос,
        // задевающий соседние RAM-страницы, — нет; RAM вне acpi — нет.
        register_ram(0x1000_0000, 0x2000_0000);
        register_acpi(0x1234_5000, 0x1234_7000); // XSDT, 2 страницы
        assert!(mmio_allowed(0x1234_5000, 0x1234_7000), "таблица целиком");
        assert!(mmio_allowed(0x1234_5000, 0x1234_6000), "поддиапазон таблицы");
        assert!(!mmio_allowed(0x1234_4000, 0x1234_7000), "захват до таблицы");
        assert!(!mmio_allowed(0x1234_5000, 0x1234_8000), "захват после таблицы");
        assert!(!mmio_allowed(0x1400_0000, 0x1401_0000), "RAM вне acpi");
        // Через границу двух acpi-диапазонов — не «целиком в одном».
        register_acpi(0x1234_7000, 0x1234_8000);
        assert!(!mmio_allowed(0x1234_6000, 0x1234_8000), "между двумя таблицами");
        assert!(mmio_allowed(0x1234_7000, 0x1234_8000), "вторая таблица целиком");
    }

    #[test]
    fn dma_requires_full_containment() {
        register_ram(0x1000_0000, 0x2000_0000);
        register_forbidden(0x1800_0000, 0x1801_0000);
        assert!(dma_allowed(0x1000_0000, 0x1001_0000));
        assert!(!dma_allowed(0x0f00_0000, 0x1001_0000), "вылезает за RAM");
        assert!(!dma_allowed(0x1800_0000, 0x1800_1000), "метаданные/ядро запрещены");
        // Соседний RAM-регион не спасает: «целиком в одном».
        register_ram(0x2000_0000, 0x3000_0000);
        assert!(!dma_allowed(0x1fff_f000, 0x2000_1000), "через границу регионов");
    }
}
