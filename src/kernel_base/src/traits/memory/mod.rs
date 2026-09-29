use core::ops::Range;
use core::sync::atomic::{AtomicUsize, Ordering};

use bitflags::bitflags;

pub const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = PAGE_SIZE - 1;

/// Значение HHDM-offset на случай, если мы сами строим HHDM
/// (`boot_info.is_hhdm() == false`, см. `build_identity_hhdm`).
/// Если же HHDM уже поднят загрузчиком, реальный offset берётся из
/// `BootInfo::hhdm_offset()` и попадает сюда через `set_hhdm_offset` —
/// в общем случае бутлоадер вправе выбрать любой offset, и он не обязан
/// совпадать с этой константой.
pub const DEFAULT_HHDM_OFFSET: usize = 0xFFFF800000000000;

// 512 ГБ в байтах. Это жесткий лимит вашей текущей таблицы страниц.
pub const MAPPED_PHYS_LIMIT: usize = 512 * 1024 * 1024 * 1024;

pub const GIB: usize = 1024 * 1024 * 1024;
pub const PAGES_PER_GIB: usize = GIB / PAGE_SIZE;

/// Верхняя (эксклюзивная) граница юзерспейс-адресов: каноническая нижняя
/// половина x86_64. Всё выше — ядерные отображения (higher-half ядро,
/// HHDM-окно), и верхняя половина PML4 задачи ДЕЛИТСЯ с ядром (см.
/// X86Umap: «пустая нижняя половина + скопированная верхняя половина
/// ядра»). Следствие: translate() ядерного VA ИЗ УМАПА ЗАДАЧИ УСПЕШЕН,
/// а U/S-бит защищает только прямой доступ ring3 — копирование же
/// ядром (read_from_user/write_to_user через translate + phys_to_virt)
/// бит U/S игнорирует. Поэтому каждый путь копирования
/// userspace<->kernel обязан отсекать верхнюю половину через
/// [`is_user_va`], иначе ring3 получает примитивы чтения/записи памяти
/// ядра через IPC/debug-сисколлы (msg_ptr/tgt_ptr = ядерный VA).
pub const USER_SPACE_LIMIT: usize = 0x0000_8000_0000_0000;

/// true, если VA лежит в нижней (пользовательской) половине адресного
/// пространства. Центральная точка copyin/copyout-гейта: вызывать ДО
/// первого translate() пользовательского буфера.
#[inline]
pub fn is_user_va(va: usize) -> bool {
    va < USER_SPACE_LIMIT
}

/// true, если весь диапазон [va, va+len) лежит в пользовательской
/// половине. Пустой диапазон считаем валидным (нечего копировать).
/// ВАЖНО: проверять именно диапазон, а не только стартовый VA — буфер,
/// начинающийся в юзерспейсе и пересекающий USER_SPACE_LIMIT, в хвосте
/// читает/пишет уже ядерные страницы. Переполнение конца (огромный len,
/// замалчиваемое в release-сборке) трактуется как отказ — иначе len,
/// заворачивающий адрес в нижнюю половину, прошёл бы гейт.
#[inline]
pub fn is_user_range(va: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if !is_user_va(va) {
        return false;
    }
    match va.checked_add(len - 1) {
        Some(end) => is_user_va(end),
        None => false,
    }
}

const _: () = assert!(
    MAPPED_PHYS_LIMIT.is_multiple_of(GIB),
    "MAPPED_PHYS_LIMIT должен быть кратен 1 ГиБ для маппинга HHDM гигабайтными страницами"
);

/// Реально замапленная через HHDM верхняя граница физической памяти.
///
/// Отличается от `MAPPED_PHYS_LIMIT` тем, что `MAPPED_PHYS_LIMIT` — это
/// жёсткий потолок ВОЗМОЖНОСТЕЙ таблицы страниц (512 ГБ), а это значение —
/// сколько из этих 512 ГБ реально построено (`build_identity_hhdm`) или,
/// если HHDM поднял загрузчик сам, сколько физической памяти он, по нашим
/// расчётам (см. `frame_manager::compute_mapped_limit`), покрыл. Именно это
/// значение обязана проверять `mapper_allocator`, иначе можно "пройти"
/// проверку по устаревшему статичному потолку и получить page fault на
/// физическом адресе, для которого HHDM-страница ещё не построена.
///
/// Выставляется через `set_mapped_phys_limit` в самом начале инициализации,
/// синхронно с `set_hhdm_offset`.
static MAPPED_PHYS_LIMIT_RUNTIME: AtomicUsize = AtomicUsize::new(MAPPED_PHYS_LIMIT);

pub fn set_mapped_phys_limit(limit: usize) {
    debug_assert!(
        limit <= MAPPED_PHYS_LIMIT,
        "нельзя объявить замапленным больше, чем способна выразить таблица страниц"
    );
    MAPPED_PHYS_LIMIT_RUNTIME.store(limit, Ordering::Release);
}

pub fn mapped_phys_limit() -> usize {
    MAPPED_PHYS_LIMIT_RUNTIME.load(Ordering::Acquire)
}

/// Реальный HHDM-offset, с которым сейчас работают `phys_to_virt`/`virt_to_phys`.
///
/// ВАЖНО: это состояние должно быть выставлено вызовом `set_hhdm_offset`
/// САМЫМ первым делом при старте (до `reclaim_memory`, до аллокаций кучи,
/// до чего угодно, что переводит физические адреса в виртуальные) —
/// см. `KernelCTL::new_and_init`. Пока это не сделано, используется
/// `DEFAULT_HHDM_OFFSET`, что корректно только для ветки, где HHDM строим
/// мы сами на этот же адрес.
static HHDM_OFFSET: AtomicUsize = AtomicUsize::new(DEFAULT_HHDM_OFFSET);

/// Вызывать один раз, в самом начале инициализации, если
/// `boot_info.is_hhdm()` вернул `true` — с реальным значением
/// `boot_info.hhdm_offset()`. Если HHDM строим сами (ветка `else`),
/// вызывать не нужно: остаётся `DEFAULT_HHDM_OFFSET`, на который и
/// рассчитан `build_identity_hhdm`.
///
/// ИНВАРИАНТ: offset кратен PAGE_SIZE. Вся адресная арифметика ядра
/// (в т.ч. slab-аллокатор: `align_down(узел, 4096)` для поиска хедера)
/// опирается на то, что ВИРТУАЛЬНЫЙ адрес страницы = физический +
/// выровненный офсет.
pub fn set_hhdm_offset(offset: usize) {
    assert!(
        offset.is_multiple_of(PAGE_SIZE),
        "hhdm offset must be page-aligned (slab free math + PTE addr math rely on it)"
    );
    HHDM_OFFSET.store(offset, Ordering::Release);
}

#[cfg(test)]
pub(crate) mod test_alloc {
    use super::PAGE_SIZE;

    /// Странично-ВЫРОВНЕННЫЙ leaks-нутый буфер для тестов (std).
    /// `vec![..]` даёт только 16-байт выравнивание — этого мало: HHDM-офсет
    /// обязан быть кратен странице (см. set_hhdm_offset).
    pub fn page_aligned_leak(pages: usize) -> &'static mut [u8] {
        use std::alloc::{Layout, alloc_zeroed};
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).expect("layout");
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "oom in test alloc");
        unsafe { core::slice::from_raw_parts_mut(ptr, pages * PAGE_SIZE) }
    }
}

pub fn hhdm_offset() -> usize {
    HHDM_OFFSET.load(Ordering::Acquire)
}

#[inline]
pub fn phys_to_virt(phys: usize) -> usize {
    phys.wrapping_add(HHDM_OFFSET.load(Ordering::Acquire))
}

#[inline]
pub fn virt_to_phys(virt: usize) -> usize {
    virt.wrapping_sub(HHDM_OFFSET.load(Ordering::Acquire))
}

/// Описатель выделенных страниц.
/// Внутри хранится ФИЗИЧЕСКИЙ адрес, так как FrameAllocator работает с фреймами.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPTR {
    phys_base: usize,
    pages: usize,
}

impl MemoryPTR {
    pub fn new(phys_base: usize, pages: usize) -> Option<Self> {
        if pages == 0 || (phys_base & PAGE_MASK) != 0 {
            return None;
        }

        let bytes = pages.checked_mul(PAGE_SIZE)?;
        phys_base.checked_add(bytes)?; // Защита от переполнения

        Some(Self { phys_base, pages })
    }

    pub fn phys_base(self) -> usize {
        self.phys_base
    }
    pub fn pages(self) -> usize {
        self.pages
    }

    pub fn virt_base(self) -> usize {
        phys_to_virt(self.phys_base)
    }
}

pub enum StartupModel {
    // Для глобальных хуков нужен 'static и Sync
    OneOne,
    HhdpPremapped,
}

#[derive(Debug)]
pub enum ErrorCode {
    OutOfMemory,
    InvalidLayout,
    OutOfMappedBounds, // Специфично для ваших 512 ГБ
    NotInitialized,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryFlags: u16 {
        const READ_ONLY = 1 << 0;
        const SUPERVISOR = 1 << 1;
        const NO_EXECUTE = 1 << 2;

        const FLAG_SIZE4KB = 0 << 3;
        const FLAG_SIZE2MB = 1 << 3;
        // было FLAG_SIZE512KB — страницы такого размера не существует
        // ни на x86_64 (4K/2M/1G), ни на aarch64 (4K/16K/2M/1G).
        // Судя по использованию в маппинге 512 ГБ HHDM, здесь имелась в виду 1GB-страница.
        const FLAG_SIZE1GB = 2 << 3;
    }
}

pub trait FrameAllocator {
    /// Возвращает ФИЗИЧЕСКИЙ адрес выделенных страниц.
    fn allocate_pages(&self, count: usize) -> Option<MemoryPTR>;
    fn deallocate_pages(&self, ptr: MemoryPTR);
}

pub trait MemoryInterfaceUserspace {
    fn allocate_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        count: usize,
    ) -> Result<MemoryPTR, ErrorCode>;

    fn deallocate_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        region: MemoryPTR,
        count: usize,
    ) -> Result<(), ErrorCode>;

    fn map_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
    ) -> Result<MemoryPTR, ErrorCode>;

    fn unmap_memory_region(
        &self,
        allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
    ) -> Result<(), ErrorCode>;

    /// Мапит регион с правами: `MemoryFlags::READ_ONLY`/`NO_EXECUTE`
    /// учитываются реализацией, `MemoryFlags::empty()` = RW. Дефолт
    /// игнорирует флаги (для простых портов) — переопределяется там, где
    /// биты PTE управляемы. Используется загрузчиком образов
    /// (exec: сегменты R-X/RW согласно PF_-флагам ELF).
    fn map_memory_region_flags(
        &self,
        allocator: &dyn FrameAllocator,
        p_base: MemoryPTR,
        virt: usize,
        _flags: MemoryFlags,
    ) -> Result<MemoryPTR, ErrorCode> {
        self.map_memory_region(allocator, p_base, virt)
    }

    /// Физический адрес корневой таблицы задачи (CR3-аналог) — для SVA-
    /// путей IOMMU (first-stage/GCR3 root = таблица процесса). None —
    /// реализация не табличная.
    fn root_table(&self) -> Option<usize> {
        None
    }

    /// Транслирует виртуальный адрес задачи в ФИЗИЧЕСКИЙ (обход таблиц
    /// задачи, huge-листы учитываются: возвращается база кадра | смещение).
    /// `None` — адрес не отображён.
    ///
    /// Нужен ядру для прямого доступа к памяти задачи без переключения
    /// CR3: например, запись маски сработавших IRQ в буфер, указатель на
    /// который передал userspace (см. task::irq_wait).
    fn translate(&self, virt: usize) -> Option<usize>;

    /// USER-семантика copyin/copyout (defense-in-depth поверх
    /// [`is_user_range`]): адрес обязан лежать в НИЖНЕЙ половине И быть
    /// отображённым с U/S (и R/W на всех уровнях — для записи).
    /// Причина: верхняя половина умапа задачи ДЕЛИТСЯ с ядром — голая
    /// табличная трансляция там УСПЕШНА, а U/S-бит ядро, копирующее
    /// буфер, не проверяет. Без этого гейта translate по ядерному VA
    /// из ring3 даёт чтение/запись памяти ядра через IPC/debug-сисколлы.
    /// Дефолт — обычная трансляция (фейки тестов нетабличные); порты с
    /// таблицами обязаны переопределить.
    fn translate_user(&self, virt: usize, for_write: bool) -> Option<usize> {
        let _ = for_write;
        self.translate(virt)
    }
}

pub trait MemoryInterfaceKernel {
    const PAGE_SIZE: usize;

    type UserspaceMap: MemoryInterfaceUserspace;

    fn init(allocator: &(dyn FrameAllocator + Sync), model: StartupModel) -> Self;

    fn create_userspace_mapping(
        &self,
        allocator: &(dyn FrameAllocator + Sync),
        kernel_display_region: Range<usize>,
    ) -> Result<Self::UserspaceMap, ErrorCode>;

    fn display_map(&self, p_display_region: MemoryPTR, virt_addr: usize, flags: MemoryFlags);

    /// Трансляция VA → ФИЗИЧЕСКИЙ адрес в ЭТОЙ таблице (huge-листы
    /// учитываются: возвращается база кадра | смещение).
    ///
    /// Нужна бут-путём ядра до activate(): актуальная физика секций
    /// (загрузчик мог разместить образ НЕ по ELF-LMA — Limine кладёт
    /// ядро по своему базису, напр. 0x1fe0c000 при LMA 0x200000).
    /// None — реализация не табличная/адрес не отображён.
    fn translate_kernel(&self, virt: usize) -> Option<usize> {
        let _ = virt;
        None
    }

    /// Переключает процессор на эту таблицу страниц (загрузка CR3 на x86_64,
    /// TTBR0_EL1/TTBR1_EL1 на aarch64). Без вызова этого метода построенный
    /// через `display_map` маппинг ни на что не влияет — исполнение
    /// продолжается через старые (загрузочные) таблицы.
    ///
    /// ВАЖНО: вызывать только после того, как в таблице уже есть маппинг
    /// для текущего исполняемого кода (HHDM и/или релоцированное ядро),
    /// иначе следующая же инструкция вызовет page fault.
    fn activate(&self);
}

/// Строит identity-style HHDM-маппинг: диапазон `[0, up_to)` физической
/// памяти маппится по адресу `phys_to_virt(phys)`, 1GB-страницами.
///
/// `up_to` обычно берут из `frame_manager::compute_mapped_limit()` (реальная
/// верхняя граница по карте памяти от загрузчика, не выше `MAPPED_PHYS_LIMIT`)
/// — не обязательно маппить все 512 ГБ, если физической памяти в системе
/// меньше. `up_to` должен быть кратен `GIB`.
///
/// Вызывать один раз при старте (когда `!boot_info.is_hhdm()`), ДО
/// переключения на новую таблицу страниц через `kmap.activate()`, и до
/// `set_mapped_phys_limit(up_to)`.
///
/// Эта функция ничего не аллоцирует у `allocator` — она лишь описывает уже
/// существующие физические страницы (`MemoryPTR::new` — просто конструктор
/// дескриптора), поэтому `allocator` используется исключительно для
/// прохождения по промежуточным уровням таблицы страниц внутри `display_map`.
pub fn build_identity_hhdm<K: MemoryInterfaceKernel>(kmap: &K, up_to: usize) {
    debug_assert_eq!(up_to % GIB, 0, "up_to должен быть кратен 1 ГиБ");
    debug_assert!(up_to <= MAPPED_PHYS_LIMIT);

    let mut phys = 0usize;

    while phys < up_to {
        let region = MemoryPTR::new(phys, PAGES_PER_GIB)
            .expect("HHDM-чанк по построению всегда выровнен на 1 ГиБ");

        kmap.display_map(
            region,
            phys_to_virt(phys),
            MemoryFlags::SUPERVISOR | MemoryFlags::NO_EXECUTE | MemoryFlags::FLAG_SIZE1GB,
        );

        phys += GIB;
    }
}

pub mod init_hooks {

    use core::{
        alloc::Layout,
        ptr::{self, NonNull},
    };

    // ВАЖНО: макрос `define_allocation_hooks!` в своём расширении пишет
    // голое имя `Result` (с ОДНИМ generic-аргументом) и резолвит его
    // в области вызова. Поэтому здесь обязан быть импортирован alias
    // крейта `Result<T> = core::result::Result<T, SlabError>`, а НЕ
    // `core::result::Result` (иначе E0107: expected 2 generic arguments).
    use attachable_slab_allocator::{Result, define_allocation_hooks};
    use spin::Once;

    use crate::traits::memory::{
        FrameAllocator, MemoryPTR, PAGE_SIZE, mapped_phys_limit, virt_to_phys,
    };

    /// Заголовок для аллокаций с выравниванием больше страницы.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct OveralignHeader {
        phys_base: usize,
        pages: usize,
    }

    static MEMORY_ALLOCATOR: Once<&'static (dyn FrameAllocator + Sync)> = Once::new();

    pub fn init_allocator(allocator: &'static (dyn FrameAllocator + Sync)) {
        MEMORY_ALLOCATOR.call_once(|| allocator);
    }

    /// Глобальный кадровый аллокатор (после init_allocator). Нужен
    /// сисколл-доменам (alloc/free страниц задачи, MMIO-маппинги):
    /// у них нет другого пути к FrameManager — домены конструируются
    /// только над KernelCTL.
    pub fn memory_allocator() -> Option<&'static (dyn FrameAllocator + Sync)> {
        MEMORY_ALLOCATOR.get().copied()
    }

    fn pages_for_bytes(bytes: usize) -> Option<usize> {
        if bytes == 0 {
            return Some(0);
        }
        bytes.checked_add(PAGE_SIZE - 1).map(|x| x / PAGE_SIZE)
    }

    fn align_up(value: usize, align: usize) -> Option<usize> {
        debug_assert!(align.is_power_of_two());
        let mask = align - 1;
        value.checked_add(mask).map(|v| v & !mask)
    }

    fn dangling_for(layout: Layout) -> Option<NonNull<u8>> {
        NonNull::new(layout.align().max(1) as *mut u8)
    }

    /// Выделяет страницы через зарегистрированный FrameAllocator и возвращает
    /// виртуальный адрес через HHDM. Для выравниваний > страницы резервирует
    /// страницу под заголовок `OveralignHeader`.
    ///
    /// # Safety
    /// Вызывается только как глобальный аллокационный хук
    /// (`define_allocation_hooks!`) аллокатором кучи; предполагается, что
    /// HHDM уже поднят (`set_hhdm_offset`/`build_identity_hhdm`) и
    /// `init_allocator` уже вызван.
    pub unsafe fn mapper_allocator(layout: Layout) -> Option<NonNull<u8>> {
        unsafe {
            if layout.size() == 0 {
                return dangling_for(layout);
            }

            let allocator = MEMORY_ALLOCATOR
                .get()
                .copied()
                .expect("frame allocator must be initialized");

            let pages = pages_for_bytes(layout.size())?;
            let phys_region = allocator.allocate_pages(pages)?;

            // ЖЕСТКАЯ ПРОВЕРКА: Убеждаемся, что физический адрес попадает в РЕАЛЬНО
            // замапленный диапазон (может быть меньше жёсткого потолка таблицы,
            // если физической памяти в системе меньше 512 ГБ).
            // Если нет - освобождаем и паникуем/возвращаем None, иначе будет Page Fault.
            if phys_region.phys_base() + (phys_region.pages() * PAGE_SIZE) > mapped_phys_limit() {
                allocator.deallocate_pages(phys_region);
                return None;
            }

            let virt_base = phys_region.virt_base();

            // Быстрый путь: выравнивание <= 4096
            if layout.align() <= PAGE_SIZE {
                return NonNull::new(virt_base as *mut u8);
            }

            // Медленный путь: выравнивание > 4096
            // Первая аллокация не может удовлетворить выравнивание —
            // возвращаем её в пул, иначе она утекает (вторая аллокация ниже
            // затеняет эту переменную, больше ничто на неё не ссылается).
            allocator.deallocate_pages(phys_region);

            let total = layout.size().checked_add(layout.align())?;
            let pages = pages_for_bytes(total)?;
            let phys_region = allocator.allocate_pages(pages)?;

            if phys_region.phys_base() + (phys_region.pages() * PAGE_SIZE) > mapped_phys_limit() {
                allocator.deallocate_pages(phys_region);
                return None;
            }

            let virt_base = phys_region.virt_base();

            // Резервируем одну страницу под заголовок
            let aligned_virt = align_up(virt_base.checked_add(PAGE_SIZE)?, layout.align())?;
            let end = aligned_virt.checked_add(layout.size())?;
            let alloc_end = virt_base.checked_add(phys_region.pages() * PAGE_SIZE)?;

            if end > alloc_end {
                allocator.deallocate_pages(phys_region);
                return None;
            }

            let header_virt = aligned_virt.checked_sub(PAGE_SIZE)?;
            let header_ptr = header_virt as *mut OveralignHeader;

            // Сохраняем ФИЗИЧЕСКИЙ адрес в заголовке, чтобы потом корректно освободить
            ptr::write(
                header_ptr,
                OveralignHeader {
                    phys_base: phys_region.phys_base(),
                    pages: phys_region.pages(),
                },
            );

            NonNull::new(aligned_virt as *mut u8)
        }
    }

    /// Обратная сторона `mapper_allocator`: восстанавливает физический адрес
    /// (из заголовка для overaligned-выделений) и возвращает страницы в пул.
    ///
    /// # Safety
    /// `ptr` должен указывать на блок, выделенный `mapper_allocator` с тем же
    /// `layout`; парные вызовы alloc/dealloc не должны пересекаться.
    pub unsafe fn mapper_deallocator(ptr: NonNull<u8>, layout: Layout) -> Result<()> {
        unsafe {
            if layout.size() == 0 {
                return Ok(());
            }

            let allocator = MEMORY_ALLOCATOR
                .get()
                .copied()
                .expect("frame allocator must be initialized");

            let virt_ptr = ptr.as_ptr() as usize;

            let (phys_base, pages) = if layout.align() <= PAGE_SIZE {
                // Конвертируем виртуальный указатель обратно в физический
                let phys = virt_to_phys(virt_ptr);
                let pages = pages_for_bytes(layout.size()).expect("invalid layout on free");
                (phys, pages)
            } else {
                // Читаем заголовок, который лежит на страницу раньше выровненного указателя
                let header_virt = virt_ptr
                    .checked_sub(PAGE_SIZE)
                    .expect("invalid overaligned ptr");
                let header_ptr = header_virt as *const OveralignHeader;
                let header = ptr::read(header_ptr);
                (header.phys_base, header.pages)
            };

            let region = MemoryPTR::new(phys_base, pages).expect("invalid region on free");
            allocator.deallocate_pages(region);

            Ok(())
        }
    }

    define_allocation_hooks!(mapper_allocator, mapper_deallocator);
}
