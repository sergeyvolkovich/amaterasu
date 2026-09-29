#![cfg_attr(not(test), no_std)]

use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

use spin::mutex::SpinMutex;

use crate::{
    access::AccessManager,
    bootinfo::BootInfo,
    frame_manager::{compute_mapped_limit, phys_frame_manager::FrameManager},
    lctl::LocalKernelCTL,
    task::TaskManager,
    traits::{
        ArchImplementation,
        memory::{
            DEFAULT_HHDM_OFFSET, MemoryFlags, MemoryInterfaceKernel, MemoryPTR,
            PAGE_SIZE, build_identity_hhdm, init_hooks, set_hhdm_offset, set_mapped_phys_limit,
        },
    },
};

pub mod access;
pub mod bootinfo;
pub mod collection;
pub mod frame_manager;
pub mod idalloc;
pub mod ipc;
pub mod irq;
pub mod irqsafe;
pub mod lctl;
pub mod log;
pub mod phys_guard;
pub mod syscall;
pub mod task;
pub mod traits;
pub mod umap;

/// Сериализация тестов: kernel_base-тесты меняют глобальные статики
/// (HHDM-offset, slab-хуки) — параллельный запуск cargo test их
/// перемешивает. Гарант берётся тестом на весь тест.
#[cfg(test)]
pub mod test_guard {
    use spin::mutex::SpinMutex;
    pub static GLOBAL: SpinMutex<()> = SpinMutex::new(());
}

const MAX_CORES: usize = 255;

unsafe extern "C" {
    static __bss_begin: *const u8;
    static __bss_end: *const u8;

    static __text_begin: *const u8;
    static __text_end: *const u8;

    static __rodata_begin: *const u8;
    static __rodata_end: *const u8;

    static __data_begin: *const u8;
    static __data_end: *const u8;

    // Физические (LMA) адреса загрузки секций. Обязан экспортировать
    // линкер-скрипт порта: для relocated-ядер (higher-half VMA) —
    // `VMA - KERNEL_VBASE`, для identity-ядер — совпадают с VMA.
    // Без них маппинг секций в новую таблицу до activate() невозможен:
    // «sym_addr!(__bss_begin)» для relocated-ядра — это ВИРТУАЛЬНЫЙ адрес,
    // и старый код прибавлял к нему HHDM-offset с переполнением.
    static __text_phys: *const u8;
    static __rodata_phys: *const u8;
    static __data_phys: *const u8;
    static __bss_phys: *const u8;

    // Секция .limine_requests (статические структуры запросов протокола
    // Limine). Ядро читает их и ПОСЛЕ смены таблиц страниц (например,
    // SMP-ответ при бут-инициализации планировщика) — без маппинга этой
    // секции в новую таблицу activate() оставляет их на мёртвых
    // загрузочных страницах (QEMU: PF на 0xffffffff80200078).
    static __requests_phys: *const u8;
    static __requests_begin: *const u8;
    static __requests_end: *const u8;
}

/// Выделяет `&'static mut [u8; N]` из статического пула (без аллокатора):
/// для Box::leak-замен в boot-пути (KernelCTL, планировщики).
#[doc(hidden)]
pub fn kernel_static_leak<const N: usize>() -> &'static mut [u8; N] {
    struct Pool(UnsafeCell<MaybeUninit<[u8; 65536]>>);
    // SAFETY: однопоточный boot-путь до старта AP (см. контракт выше).
    unsafe impl Sync for Pool {}
    static POOL: Pool = Pool(UnsafeCell::new(MaybeUninit::uninit()));
    static OFFSET: AtomicUsize = AtomicUsize::new(0);
    let size = core::mem::size_of::<[u8; N]>();
    let off = OFFSET.fetch_add(size, core::sync::atomic::Ordering::AcqRel);
    assert!(off + size <= 65536, "static pool exhausted");
    let ptr = unsafe { (*POOL.0.get()).as_mut_ptr() as *mut u8 }.wrapping_add(off);
    unsafe { &mut *(ptr as *mut [u8; N]) }
}


pub struct KernelCTL<ArchBackend: ArchImplementation> {
    // Оба поля — часть контракта с портом: порт читает их из своего кода
    // инициализации/обработчиков (внутри kernel_base они пока не читаются).
    #[allow(dead_code)]
    arch_backend: ArchBackend,

    permission_backend: SpinMutex<AccessManager<ArchBackend::Umap>>,
    task_manager: SpinMutex<TaskManager<ArchBackend::Umap>>,

    #[allow(dead_code)]
    kctl: SpinMutex<ArchBackend::KMap>,

    cores_count: AtomicUsize,
    cores_acc: [UnsafeCell<MaybeUninit<LocalKernelCTL<ArchBackend::Umap>>>; MAX_CORES],
}

unsafe impl<ArchBackend: ArchImplementation> Sync for KernelCTL<ArchBackend> {}

/// АДРЕС линкер-символа как usize.
///
/// Линкер-символы (`__text_begin`, `__text_phys`, ...) объявлены как
/// `static X: *const u8`. Выражение `X as usize` при этом ЧИТАЕТ 8 байт
/// ПО АДРЕСУ СИМВОЛА (т.е. содержимое секции — мусор, а для *_phys —
/// вообще физический адрес без HHDM → page fault; поймано в QEMU на
/// маппинге секций: чтение 0x239000). Только `addr_of!` даёт сам адрес.
macro_rules! sym_addr {
    ($s:ident) => {
        core::ptr::addr_of!($s) as usize
    };
}

impl<ArchBackend: ArchImplementation> KernelCTL<ArchBackend> {
    /// Конструирует KernelCTL В МЕСТЕ (placement): поля пишутся напрямую
    /// в `storage`, без гигантских by-value копий через стек.
    ///
    /// ЗАЧЕМ: прежний `Self { .. }` строил ~10 КиБ на стеке, плюс
    /// `core::array::from_fn` — темп-массив 255×40 Б, возврат по значению
    /// и `.write()` в вызывателе — ещё копии: DEBUG-сборка тратила десятки
    /// КиБ бут-стека на пустые копирования (одна из причин «раздутого»
    /// BOOT_STACK). Порт обязан предоставить статический слот
    /// (например, из `kernel_static_leak`).
    pub fn init_into(
        storage: &'static mut core::mem::MaybeUninit<KernelCTL<ArchBackend>>,
        frame_allocator: &'static FrameManager,
        boot_info: &BootInfo,
    ) -> &'static KernelCTL<ArchBackend> {
        if boot_info.is_hhdm() {
            let offset = boot_info
                .hhdm_offset()
                .expect("BootFlags::MemoryRellocationHHDM выставлен, но hhdm_offset() == None");
            set_hhdm_offset(offset);
        }

        let mapped_limit = compute_mapped_limit(boot_info.memory_regions());

        set_mapped_phys_limit(mapped_limit);
        kernel_log!("kctl: mapped_limit={:#x}\n", mapped_limit);

        let arch_backend = ArchBackend::init_base_state();
        let reclaimed_memory = ArchBackend::reclaim_memory(frame_allocator);

        // 5. Инициализируем аллокатор кучи ПЕРЕД созданием новых таблиц страниц,
        // так как ArchBackend::create_new_kmap() может аллоцировать память.
        init_hooks::init_allocator(frame_allocator);

        let new_memory = SpinMutex::new(ArchBackend::create_new_kmap());

        {
            let w_lock = new_memory.lock();

            // HHDM строится в НОВУЮ таблицу ВСЕГДА — именно она станет
            // активной после activate(). Раньше при is_hhdm() (HHDM от
            // загрузчика) HHDM в новую таблицу не строился вовсе: после
            // переключения CR3 ядро тут же теряло весь прямой доступ к
            // физической памяти. is_hhdm() говорит лишь о том, откуда
            // взят offset (уже установлен set_hhdm_offset выше).
            build_identity_hhdm(&*w_lock, mapped_limit);

            // (sym_addr! не требует unsafe — обычное чтение адресов)
            {
                // Безопасное вычисление размеров через usize для линкер-символов
                let bss_size = (sym_addr!(__bss_end)) - (sym_addr!(__bss_begin));
                let rodata_size = (sym_addr!(__rodata_end)) - (sym_addr!(__rodata_begin));
                let data_size = (sym_addr!(__data_end)) - (sym_addr!(__data_begin));
                let text_size = (sym_addr!(__text_end)) - (sym_addr!(__text_begin));

                // Округление вверх до размера страницы
                let page_align = |size: usize| size.div_ceil(PAGE_SIZE);

                if boot_info.is_kernel_relocated() {
                    // Ядро загружено на higher-half VMA (например, Limine).
                    // Секции мапим ФАКТИЧЕСКАЯ-физика -> VMA.
                    //
                    // ВАЖНО-1: ELF-LMA (символы *_phys) НЕ равны фактическому
                    // размещению! Limine грузит образ по своему базису
                    // (например, phys 0x1fe0c000 при LMA 0x200000 — поймано
                    // в QEMU: после activate() исполнялись нулевые байты,
                    // т.к. PTE указывали на пустую физику по LMA).
                    //
                    // ВАЖНО-2 (поймано в QEMU на ядре с .bss 6.8 МиБ):
                    // загрузчик НЕ обязан размещать сегменты ФИЗИЧЕСКИ
                    // НЕПРЕРЫВНО — Limine кладёт PT_LOAD с межстраничными
                    // разрывами. Непрерывное «физика первой страницы + N»
                    // отображало хвост .data (GOT!) и .bss на ЧУЖУЮ физику:
                    // рантайм-GOT содержал не те указатели — первый же
                    // непрямой вызов уводил ядро в #PF. Источник истины для
                    // КАЖДОЙ страницы — ТЕКУЩАЯ (загрузочная) таблица:
                    // translate_kernel(va) страницы → её фактическая физика.
                    // Fallback — LMA (загрузчики, кладущие образ точно по
                    // LMA; для них непрерывность выполняется по построению).
                    let sections = [
                        (
                            sym_addr!(__requests_phys),
                            sym_addr!(__requests_begin),
                            sym_addr!(__requests_end) - sym_addr!(__requests_begin),
                            MemoryFlags::READ_ONLY | MemoryFlags::NO_EXECUTE,
                        ),
                        (
                            sym_addr!(__text_phys),
                            sym_addr!(__text_begin),
                            text_size,
                            MemoryFlags::READ_ONLY,
                        ),
                        (
                            sym_addr!(__rodata_phys),
                            sym_addr!(__rodata_begin),
                            rodata_size,
                            MemoryFlags::READ_ONLY | MemoryFlags::NO_EXECUTE,
                        ),
                        (
                            sym_addr!(__data_phys),
                            sym_addr!(__data_begin),
                            // .data + хвостовой BSS data-сегмента + .bss —
                            // ОДНИМ диапазоном [__data_begin, __bss_end):
                            // стык на границе 4К (memsz > filesz у PT_LOAD)
                            // иначе оставляет незамапленную страницу (QEMU:
                            // PF на va=..243008 — static из хвостового BSS
                            // .data-сегмента). Страницы идут ПОСТРАНИЧНО
                            // (см. ВАЖНО-2).
                            sym_addr!(__bss_end) - sym_addr!(__data_begin),
                            MemoryFlags::NO_EXECUTE,
                        ),
                    ];
                    for (phys_lma, virt, size, flags) in sections {
                        if size == 0 {
                            continue;
                        }
                        let base = virt & !(PAGE_SIZE - 1);
                        let pages = page_align(size);
                        let mut first_phys_logged = false;
                        for i in 0..pages {
                            let va = base + i * PAGE_SIZE;
                            let phys = reclaimed_memory
                                .translate_kernel(va)
                                .map(|p| p & !(PAGE_SIZE - 1))
                                .unwrap_or(phys_lma + i * PAGE_SIZE);
                            if i == 0 && phys != phys_lma && !first_phys_logged {
                                first_phys_logged = true;
                                kernel_log!(
                                    "kctl: секция va={:#x}: LMA {:#x} != факт {:#x} ({} стр.)\n",
                                    virt,
                                    phys_lma,
                                    phys,
                                    pages
                                );
                            }
                            if let Some(ptr) = MemoryPTR::new(phys, 1) {
                                w_lock.display_map(ptr, va, flags);
                            }
                        }
                    }
                } else {
                    // Identity-связанное ядро (VMA == физика): линкер-символы
                    // содержат ФИЗИЧЕСКИЕ адреса. Секции мапятся и в HHDM-окно
                    // (удобный доступ ядра), и идентично (чтобы исполнение
                    // продолжилось на тех же низких адресах после activate()).
                    let sections = [
                        (
                            sym_addr!(__bss_begin),
                            bss_size,
                            MemoryFlags::NO_EXECUTE,
                        ),
                        (
                            sym_addr!(__rodata_begin),
                            rodata_size,
                            MemoryFlags::NO_EXECUTE | MemoryFlags::READ_ONLY,
                        ),
                        (
                            sym_addr!(__data_begin),
                            data_size,
                            MemoryFlags::NO_EXECUTE,
                        ),
                        (
                            sym_addr!(__text_begin),
                            text_size,
                            MemoryFlags::READ_ONLY,
                        ),
                    ];
                    for (phys, size, flags) in sections {
                        if size == 0 {
                            continue;
                        }
                        if let Some(ptr) = MemoryPTR::new(phys, page_align(size)) {
                            // идентичный маппинг (исполнение продолжается тут)
                            w_lock.display_map(ptr, phys, flags);
                            // и копия в HHDM-окно
                            w_lock.display_map(ptr, phys + DEFAULT_HHDM_OFFSET, flags);
                        }
                    }
                }
            }

            w_lock.activate();
            kernel_log!("kctl: activate() завершён\n");
        }

        // Возвращаем память в пул. Если MemoryPTR не реализует Drop с освобождением,
        // нужно раскомментировать deallocate_pages.
        // frame_allocator.deallocate_pages(reclaimed_memory);
        drop(reclaimed_memory);

        for region in boot_info.memory_regions() {
            if !region.is_reclaimable() {
                continue;
            }

            // Регион освобождается СТЕПЕНЬЮ-ДВОЙКИ-ВЫРОВНЕННЫМИ чанками
            // (free_range_phys): прежний путь «MemoryPTR всего региона →
            // deallocate_pages» округлял страницы до next_power_of_two и
            // при НЕ-степенном размере региона освобождал ЧУЖИЕ страницы
            // за его пределами (кадры соседнего региона/резерва).
            frame_allocator.free_range_phys(0, region.begin, region.pages);
        }
        kernel_log!("kctl: reclaim регионов завершён\n");

        // Поля пишутся НА МЕСТО в storage (никаких by-value «Self{..}
        // на стеке → копия в storage»): в DEBUG-сборке это снимает
        // ~3×10 КиБ стек-трафика. cores_acc заполняется поэлементно —
        // от from_fn остался бы темп-массив на стеке.
        // SAFETY: storage — эксклюзивный &'static mut слот; ядро ещё
        // однопоточно (AP не подняты), ничего не читает объект до возврата.
        let this: &mut KernelCTL<ArchBackend> =
            unsafe { &mut *storage.as_mut_ptr() };
        this.arch_backend = arch_backend;
        this.permission_backend = SpinMutex::new(AccessManager::new().unwrap());
        this.task_manager = SpinMutex::new(TaskManager::new());
        this.kctl = new_memory;
        this.cores_count = AtomicUsize::new(1);
        for slot in this.cores_acc.iter_mut() {
            *slot = UnsafeCell::new(MaybeUninit::uninit());
        }

        let bsp_state = LocalKernelCTL::new();
        let bsp_slot = unsafe { &mut *this.cores_acc[0].get() };
        let handle = bsp_slot.write(bsp_state);

        ArchBackend::set_ktls_block(handle);
        kernel_log!("kctl: KTLS установлен, init_into готов\n");

        // SAFETY: все поля инициализированы; ссылка живёт столько же,
        // сколько static-слот (т.е. вечно).
        unsafe { &*(this as *const KernelCTL<ArchBackend>) }
    }
    /// Доступ к IOMMU платформы через порт (None — IOMMU нет/не инициализирован).
    /// Сам IOMMU-код здесь не живёт: только трейты в traits::iommu.
    pub fn iommu(&self) -> Option<&'static ArchBackend::Iommu> {
        ArchBackend::iommu()
    }

    /// Доступ к менеджеру доступа (capability-сторона) для arch-доменов
    /// сисколлов вне kernel_base: их хэндлеры резолвят capability и
    /// проверяют групповые права тем же порядком локов.
    pub fn permission_backend(&self) -> &SpinMutex<AccessManager<ArchBackend::Umap>> {
        &self.permission_backend
    }

    /// Доступ к менеджеру задач (для arch-доменов, создающих/уничтожающих
    /// задачи; порядок локов AccessManager -> TaskManager обязателен).
    pub fn task_manager(&self) -> &SpinMutex<TaskManager<ArchBackend::Umap>> {
        &self.task_manager
    }

    /// Ядерная таблица страниц (для создания умапов задач: верхняя
    /// половина копируется из неё).
    pub fn kernel_map(&self) -> &SpinMutex<ArchBackend::KMap> {
        &self.kctl
    }

    /// Доступ к arch-бэкенду (для capability-фасадов порта: IommuTokenLayer
    /// и т.п. — реализованы на ArchBackend).
    pub fn arch_backend(&self) -> &ArchBackend {
        &self.arch_backend
    }

    pub fn write_core_state(&self) -> usize {
        let current_core_id = self.cores_count.fetch_add(1, Relaxed);

        assert!(
            current_core_id < MAX_CORES,
            "too many cores: increase MAX_CORES"
        );

        let data = LocalKernelCTL::new();

        let slot = unsafe { &mut *self.cores_acc[current_core_id].get() };
        let handle = slot.write(data);

        ArchBackend::set_ktls_block(handle);

        current_core_id
    }
}
