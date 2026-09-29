//! NOMAD x86_64 boot frontend: Limine.
//!
//! АРХИТЕКТУРА БУТ-ПУТИ (фазовая, с дисциплиной стека):
//!
//!   `_start` ([naked]-трамплин)  — ТОЛЬКО смена стека (mov rsp) и jmp.
//!     Никакого кадра Rust до смены стека: прежняя версия делала `mov rsp`
//!     внутри обычной `_start` ПОСЛЕ пролога компилятора — кадр оставался
//!     на стеке Limine, а локалы по +офсетам(%rsp) указывали ВЫШЕ верха
//!     BOOT_STACK, в .bss-статики (SCHEDULERS!). `install_scheduler`
//!     затирал их нулями → fm/kctl в _start обнулялись → #PF на spawn
//!     (QEMU: CR2=0x50 в llfree, поймано [BT]-бэктрейсом обработчика).
//!   `boot_main` — обычная функция УЖЕ на собственном стеке, фазы-сёстры
//!     (глубина ≤ 2), состояние — в статиках модуля:
//!       early_arch_init → expect_hhdm → harvest_memory → harvest_bootinfo
//!       → iommu_early_init → kernel_up → exec_up → smp_up → time_up → run
//!
//! Дисциплина стека:
//!   - гигантские объекты НЕ ходят по стеку by-value: планировщики —
//!     const-инициализированный массив SCHEDULERS (19.5 КиБ × 64, ноль
//!     копий), KernelCTL — placement-инициализация `init_into` (было
//!     ~3×10 КиБ стек-трафика в DEBUG);
//!   - BOOT_STACK заливается паттерном и измеряется (high-water) +
//!     канарейка у дна, проверяется idle-циклом планировщика;
//!   - AP-стеки планировщика заливаются в setup_cpu_area, отчёт — в
//!     ap_online.
#![no_std]
#![no_main]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_base::bootinfo::{BootInfo, BootInfoBuilder, BootModule};
use kernel_base::frame_manager::phys_frame_manager::FrameManager;
use kernel_base::frame_manager::{MemoryMarker, UsableMemoryRegion};
use kernel_base::kernel_log;
use kernel_base::traits::memory::MemoryInterfaceUserspace as _;
use kernel_base::traits::scheduller::TaskExecStatus;
use kernel_base::{KernelCTL, traits::ArchImplementation};
use kernel_sched::RoundRobinScheduler;
use kernel_x86::X86Backend;
use kernel_x86::boot::BootBackend;
use kernel_x86::cswitch;

use kernel_exec::elf::{EM_X86_64, ElfFormat};
use kernel_exec::registry::FormatRegistry;

use limine::{
    BaseRevision, memory_map,
    request::{
        FramebufferRequest, HhdmRequest, MemoryMapRequest, ModuleRequest, MpRequest, RsdpRequest,
    },
};

// ─── Limine-запросы (в начале образа — секция limine_requests) ──────────────

#[used]
#[unsafe(link_section = "limine_requests")]
static START_MARKER: limine::request::RequestsStartMarker =
    limine::request::RequestsStartMarker::new();
#[used]
#[unsafe(link_section = "limine_requests")]
static BASE_REV: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = "limine_requests")]
static HHDM: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = "limine_requests")]
static MEMMAP: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[unsafe(link_section = "limine_requests")]
static RSDP: RsdpRequest = RsdpRequest::new();

#[used]
#[unsafe(link_section = "limine_requests")]
static MODULES: ModuleRequest = ModuleRequest::new();
#[used]
#[unsafe(link_section = "limine_requests")]
static FB: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = "limine_requests")]
static SMP: MpRequest = MpRequest::new();

// End-marker: в теле функции (эмитится ПОСЛЕ модульных статиков —
// вынос на уровень модуля перевернул порядок и Limine видел конец
// запросов первым, парсинг запросов не происходил вовсе).

// ─── Статические данные до аллокатора ───────────────────────────────────────

/// Карта памяти: заполняется из Limine (static mut — до многопоточности).
static mut MEM_REGIONS: [UsableMemoryRegion; 64] = [UsableMemoryRegion {
    begin: 0,
    pages: 0,
    r#type: MemoryMarker::Reserved,
}; 64];
static MEM_REGION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Максимальное число boot-модулей, переносимых в BootInfo
/// (init, IPC-пара, timer_server, shm-пара, mt-пара, C-демо + запас).
const MAX_BOOT_MODULES: usize = 12;

/// Имена boot-модулей (NUL-терминированные копии для CStr).
static mut MODULE_NAMES: [[u8; 64]; MAX_BOOT_MODULES] = [[0; 64]; MAX_BOOT_MODULES];

/// Boot-модули: физический адрес + размер + имя (static mut — boot-путь).
static mut BOOT_MODULES: [BootModule<'static>; MAX_BOOT_MODULES] =
    [const { BootModule::new(0, 0, c"") }; MAX_BOOT_MODULES];

/// Размер рабочей части бут-стека (без канарейки).
///
/// ВЫБРАН ПО ЗАМЕРУ (high-water печатается в `run` перед входом в цикл
/// планировщика): пик DEBUG-сборки с полным бут-путём (activate,
/// reclaim, спавн 9 серверов, SMP) — ≈27 КиБ; 64 КиБ = запас ×2.4.
/// Прежние 512 КиБ компенсировали by-value копии KernelCTL (10 КиБ × 3)
/// и планировщиков (19.5 КиБ × 2) через стек — с placement-инициализацией
/// (init_into) и const-инициализацией SCHEDULERS этого трафика больше нет.
const BOOT_STACK_BYTES: usize = 64 * 1024;

/// Собственный стартовый стек BSP в .bss (не в reclaimable-памяти
/// загрузчика!): стек Limine живёт в BOOTLOADER_RECLAIMABLE регионах —
/// после возврата их в FrameAllocator (reclaim в KernelCTL::init_into)
/// эти страницы могут быть выданы под чужие данные прямо под работающим
/// ядром.
///
/// Канарейка — в САМОМ НИЗУ (стек растёт вниз: перелив бьёт по ней
/// первым; idle-цикл планировщика проверяет её каждый проход).
///
/// ВАЖНО: repr(C) обязателен! Без него repr(Rust) ПЕРЕСТАВЛЯЕТ поля
/// (bytes вперёд, canary в конец) — канарейка уезжает за верх стека в
/// чужие .bss-статики (поймано в QEMU: «CINTOS01» затирал KERNEL_CTL,
/// тот записывал поверх указатель на POOL, и проверка канарейки
/// навсегда видела «НАРУШЕНА» при целой границе стека).
#[repr(C, align(16))]
struct BootStack {
    canary: [u8; 16], // [..8] — магия, [8..] — запас до 16-выравнивания
    bytes: [u8; BOOT_STACK_BYTES],
}
const BOOT_CANARY: &[u8; 8] = b"CINTOS01";
static mut BOOT_STACK: BootStack = BootStack {
    canary: [0; 16],
    bytes: [0; BOOT_STACK_BYTES],
};

/// Реестр форматов исполняемых образов (заполняется в однопоточном
/// boot-пути ДО spawn_boot_servers: без него spawn падает на
/// expect("exec registry not set by port")).
static mut EXEC_REGISTRY: FormatRegistry = FormatRegistry::new();
static ELF_FORMAT: ElfFormat = ElfFormat::new(EM_X86_64);

/// SAFETY-обёртка: доступ однопоточен в boot-пути (BSP до старта AP),
/// AP-ядра используют уже инициализированные поля только на чтение.
struct BootCell<T>(UnsafeCell<MaybeUninit<T>>);
unsafe impl<T> Sync for BootCell<T> {}
impl<T> BootCell<T> {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
    #[allow(clippy::mut_from_ref)]
    unsafe fn get_mut(&self) -> &mut MaybeUninit<T> {
        unsafe { &mut *self.0.get() }
    }
    unsafe fn get_ref(&self) -> &MaybeUninit<T> {
        unsafe { &*self.0.get() }
    }
}

/// FrameManager на месте (без аллокатора).
static FRAME_MANAGER: BootCell<FrameManager> = BootCell::uninit();

/// BootInfo на месте (мал: ~176 Б).
static BOOT_INFO: BootCell<BootInfo<'static>> = BootCell::uninit();

/// Указатель на KernelCTL (устанавливает BSP до старта AP).
static KERNEL_CTL: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

fn kernel_ctl() -> &'static KernelCTL<X86Backend> {
    // SAFETY: устанавливается BSP до bootstrap AP-ядер.
    unsafe {
        KERNEL_CTL
            .load(Ordering::Acquire)
            .cast::<KernelCTL<X86Backend>>()
            .as_ref()
    }
    .expect("KernelCTL not initialized")
}

/// Планировщики по ядрам: CONST-инициализация — ноль стек-трафика.
///
/// Прежде `install_scheduler` писал `BootCell::write(RoundRobinScheduler::new())`
/// — 19.5-КиБ значение строилось на стеке и КОПИРОВАЛОСЬ в статику на
/// каждом ядре (BSP + каждый AP). `new()` — const fn (IrqSafeSpinMutex::new
/// и heapless::Vec::new — тоже), поэтому массив живёт в .bss уже
/// проинициализированным; установка = безопасный `&SCHEDULERS[core]`.
static SCHEDULERS: [RoundRobinScheduler; 64] = [const { RoundRobinScheduler::new() }; 64];

/// Отложенные BOOTLOADER_RECLAIMABLE-регионы (физбаза, страницы): при
/// SMP>1 не отдаются в пул до онлайна всех AP (паркованные Limine AP и
/// бут-таблицы живут в них; освобождает arch-бэкенд — smp::bringup_aps).
static mut DEFERRED_RECLAIM: heapless::Vec<(usize, usize), 64> = heapless::Vec::new();

// ─── Точка входа: naked-трамплин смены стека ────────────────────────────────

/// Смена стартового стека БЕЗ кадра Rust.
///
/// Прежняя версия выполняла `mov rsp` внутри обычной `_start` ПОСЛЕ
/// пролога компилятора: кадр (≈18 КиБ локалов/spill-слотов) оставался на
/// стеке Limine, а обращения к локалам по +офсетам(%rsp) после смены
/// указывали ВЫШЕ верха BOOT_STACK — в .bss KERNEL_CTL/SCHEDULERS.
/// Первый же пишущий конфликт (init SCHEDULERS[0]) обнулял fm/kctl →
/// NULL-дереф на следующем использовании (QEMU: self=0 в
/// FrameManager::request, CR2=0x150; ранее то же проявлялось как
/// «#PF в RoundRobinScheduler::new» и «128 КиБ исчерпывались»).
///
/// Здесь кадр вообще не строится: чистый asm → смена rsp → jmp.
/// `sub sp, 8` — ABI-выравнивание входа (эквивалент push адреса
/// возврата: вход boot_main с rsp ≡ 8 mod 16).
#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // ВАЖНО: `mov rax, {sym}` в Intel-синтаксисе Rust asm! — это
        // ЧТЕНИЕ ПАМЯТИ по адресу символа (moffs-загрузка), а не запись
        // его адреса! Адрес даёт только rip-relative lea (поймано в
        // QEMU: rsp = 0x80008 без базы → push в неприсутствующую
        // страницу 0x7ffc8 → #PF → triple fault до первого kernel_log).
        "lea rax, [rip + {stack}]",
        "add rax, {total}",
        "sub rax, 8",
        "mov rsp, rax",
        "xor ebp, ebp",
        "jmp {main}",
        stack = sym BOOT_STACK,
        total = const core::mem::size_of::<BootStack>(),
        main = sym boot_main,
    )
}

// ─── Фазы бут-пути (все — на BOOT_STACK, соседние кадры) ────────────────────

/// Главная функция ядра на собственном стеке (после naked-трамплина).
#[inline(never)]
fn boot_main() -> ! {
    // High-water замер: заливаем стек паттерном ДО любой другой работы
    // (глубина использования отсчитывается от дна).
    boot_stack_paint();

    early_arch_init();
    let hhdm = expect_hhdm();
    let fm = harvest_memory(hhdm);
    let boot_info = harvest_bootinfo(hhdm);
    iommu_early_init(boot_info, fm);
    let kctl = kernel_up(fm, boot_info);
    exec_up(kctl, boot_info, fm);
    smp_up(fm);
    time_up();
    run()
}

/// 0.5. Ранние аппаратные таблицы + отладочный канал: GDT/IDT до
/// KernelCTL (load_gdt обнуляет GS base — см. cswitch), COM1 до первого
/// kernel_log!. Без этого любой сбой до подъёма init — невидимый triple
/// fault. IRQ-хуки kernel_base — до первого источника IRQ (таймер).
fn early_arch_init() {
    cswitch::early_boot_init();
    kernel_x86::serial::init();
    kernel_base::log::set_console_hook(kernel_x86::serial::console_hook);
    kernel_base::irqsafe::set_irq_hooks(
        kernel_x86::irq::irq_save_state,
        kernel_x86::irq::irq_restore_state,
    );
    kernel_log!("cintos: boot start (Limine protocol)\n");
}

/// 1-2. Base revision + HHDM (вся адресная арифметика ядра — от него).
fn expect_hhdm() -> usize {
    // Конец цепочки запросов Limine: в теле функции — эмитится ПОСЛЕ
    // модульных статиков секции (см. комментарий у SMP-запроса).
    #[used]
    #[unsafe(link_section = "limine_requests")]
    static END_MARKER: limine::request::RequestsEndMarker =
        limine::request::RequestsEndMarker::new();

    if !BASE_REV.is_supported() {
        kernel_log!("boot: Limine base revision не поддерживается\n");
        halt();
    }
    let hhdm = HHDM.get_response().expect("no HHDM response").offset() as usize;
    kernel_base::traits::memory::set_hhdm_offset(hhdm);
    hhdm
}

/// 3-4. Карта памяти Limine → MEM_REGIONS (+ защита reclaim-регионов при
/// SMP) + FrameManager (LLFree) на месте.
fn harvest_memory(hhdm: usize) -> &'static FrameManager {
    let memmap_resp = MEMMAP.get_response().expect("no memmap response");
    let count = memmap_resp.entries().len().min(64);
    let smp_aps = SMP
        .get_response()
        .map(|smp| {
            smp.cpus()
                .iter()
                .filter(|c| c.lapic_id != smp.bsp_lapic_id())
                .count()
        })
        .unwrap_or(0);
    // SAFETY: однопоточный boot-путь (static mut до старта AP).
    let deferred = unsafe { &mut *core::ptr::addr_of_mut!(DEFERRED_RECLAIM) };
    let regions = unsafe { &mut *core::ptr::addr_of_mut!(MEM_REGIONS) };
    for (i, entry) in memmap_resp.entries().iter().take(count).enumerate() {
        let marker = match entry.entry_type {
            memory_map::EntryType::USABLE => MemoryMarker::Usable,
            memory_map::EntryType::RESERVED => MemoryMarker::Reserved,
            memory_map::EntryType::ACPI_RECLAIMABLE => MemoryMarker::AcpiReclaimable,
            memory_map::EntryType::ACPI_NVS => MemoryMarker::AcpiNvs,
            memory_map::EntryType::BAD_MEMORY => MemoryMarker::BadMemory,
            memory_map::EntryType::BOOTLOADER_RECLAIMABLE => {
                if smp_aps > 0 {
                    // Защита до онлайна AP: помечаем Reserved (не выдаётся
                    // аллокатором и не reclaim'ится init_into).
                    let _ = deferred.push((entry.base as usize, entry.length as usize / 4096));
                    MemoryMarker::Reserved
                } else {
                    MemoryMarker::BootloaderReclaimable
                }
            }
            memory_map::EntryType::EXECUTABLE_AND_MODULES => MemoryMarker::KernelAndModules,
            memory_map::EntryType::FRAMEBUFFER => MemoryMarker::Framebuffer,
            _ => MemoryMarker::Reserved,
        };
        regions[i] = UsableMemoryRegion {
            begin: entry.base as usize,
            pages: (entry.length as usize) / 4096,
            r#type: marker,
        };
    }
    MEM_REGION_COUNT.store(count, Ordering::Release);

    let cpu_count = SMP.get_response().map(|smp| smp.cpus().len()).unwrap_or(1);
    // ВАЖНО: FrameManager::init СОРТИРУЕТ переданный массив in-place —
    // отдаём ему ТОЛЬКО реальные записи [..count], иначе нулевые слоты
    // массива уедут в начало после сортировки, и срез BootInfo
    // [0..count] (который строится НИЖЕ по тому же массиву) окажется
    // из одних нулей → compute_mapped_limit = 0 → mapped_phys_limit = 0
    // → OutOfMemory на первой же аллокации init_into (поймано в QEMU).
    // SAFETY: однопоточный boot-путь.
    let fm: &'static FrameManager = unsafe {
        BootCell::get_mut(&FRAME_MANAGER).write(
            FrameManager::init(4096, &mut regions[..count], cpu_count, hhdm)
                .expect("frame manager init"),
        );
        BootCell::get_ref(&FRAME_MANAGER).assume_init_ref()
    };
    kernel_log!(
        "frame: {} свободных кадров, cpu={}\n",
        fm.free_frames(),
        cpu_count
    );

    // PHYS-GUARD: реестр диапазонов для валидации CAP_CREATE_MMIO и
    // IOMMU MapDma/MapVa (см. kernel_base::phys_guard). Регистрация
    // ПОСЛЕ FrameManager::init: init вЫРЕЗАЕТ метаданные аллокатора из
    // usable-региона in-place — срез [..count] уже отражает финальную
    // разметку RAM. BootloaderReclaimable, ушедший в DEFERRED_RECLAIM
    // (помечен Reserved), тоже RAM — берём из deferred-списка.
    for r in regions[..count].iter() {
        let end = r.begin + r.pages * 4096;
        match r.r#type {
            MemoryMarker::Usable
            | MemoryMarker::BootloaderReclaimable
            | MemoryMarker::AcpiReclaimable => {
                kernel_base::phys_guard::register_ram(r.begin, end);
            }
            MemoryMarker::KernelAndModules | MemoryMarker::BadMemory => {
                kernel_base::phys_guard::register_forbidden(r.begin, end);
            }
            // Reserved/Framebuffer/AcpiNvs — не RAM: легальные цели
            // MMIO-капабилити (framebuffer!), DMA туда не пускаем
            // просто потому, что они не в списке ram.
            _ => {}
        }
    }
    for (base, pages) in deferred.iter() {
        kernel_base::phys_guard::register_ram(*base, base + pages * 4096);
    }
    let (meta_lo, meta_hi) = fm.metadata_range();
    kernel_base::phys_guard::register_forbidden(meta_lo, meta_hi);

    fm
}

/// 5-7. BootInfo (RSDP/ACPI, boot-модули, FB) → статический слот.
fn harvest_bootinfo(hhdm: usize) -> &'static BootInfo<'static> {
    // SAFETY: MEM_REGIONS заполнен фазой выше; однопоточный boot-путь.
    let (regions, count) = unsafe {
        (
            &*core::ptr::addr_of!(MEM_REGIONS),
            MEM_REGION_COUNT.load(Ordering::Acquire),
        )
    };
    let mut builder = BootInfoBuilder::new()
        .memory_regions(unsafe {
            core::slice::from_raw_parts(core::ptr::addr_of!(regions[0]), count)
        })
        .flags(kernel_base::bootinfo::BootFlags::KernelRelocated)
        .set_hhdm(hhdm);

    if let Some(rsdp) = RSDP.get_response() {
        builder = builder.hw_model(kernel_base::bootinfo::BootHWModel::AcpiRsdp {
            version: 2,
            begin: rsdp.address(),
        });
    }

    // Модули: имена копируем в статические NUL-буферы, образы — как
    // физические адреса (spawn-путь читает их через HHDM). Без этого
    // переноса boot_modules() пуст и init-сервер никогда не стартует.
    let mut modules_count = 0usize;
    if let Some(resp) = MODULES.get_response() {
        // SAFETY: однопоточный boot-путь (static mut до старта AP).
        let names = unsafe { &mut *core::ptr::addr_of_mut!(MODULE_NAMES) };
        let mods = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_MODULES) };
        for (i, file) in resp.modules().iter().enumerate().take(MAX_BOOT_MODULES) {
            let path = file.path().to_bytes();
            let name_len = path.len().min(names[i].len() - 1);
            names[i][..name_len].copy_from_slice(&path[..name_len]);
            // names[i][name_len] == 0: буфер обнулён статически.
            //
            // ВАЖНО: CStr строится ДО ПЕРВОГО NUL (from_bytes_until_nul):
            // прежний from_bytes_with_nul_unchecked брал СЛИЦОМ 64-байтовый
            // слот — контракт требует NUL в ПОСЛЕДНЕМ байте, поэтому имя
            // «растягивалось» до 63 байт с внедрёнными NUL — heapless-
            // String::<48> молча отвергала его (push_str → Err), имена
            // серверов были пустыми, ростер не находил peer'ов
            // (поймано диагностикой exec: имя='...\0\0...').
            // SAFETY: слот только что заполнен NUL-байтом на конце.
            let name = unsafe {
                let slot: *const [u8; 64] = core::ptr::addr_of!(names[i]);
                core::ffi::CStr::from_bytes_until_nul(&*slot).expect("NUL-терминатор имени модуля")
            };
            // file.addr() — виртуальный адрес (HHDM загрузчика);
            // spawn ждёт ФИЗИЧЕСКИЙ.
            let phys = (file.addr() as usize).wrapping_sub(hhdm);
            mods[i] = BootModule::new(phys, file.size() as usize, name);
            modules_count += 1;
        }
    }
    if modules_count > 0 {
        // SAFETY: static mut, однопоточный boot-путь.
        let mods = unsafe { &*core::ptr::addr_of!(BOOT_MODULES) };
        builder = builder
            .boot_modules(unsafe { core::slice::from_raw_parts(mods.as_ptr(), modules_count) });
        kernel_log!("limine: {} boot-модулей\n", modules_count);
    }

    // Framebuffer: ядро не пишет — параметры уходят init-серверу через
    // auxv (AT_CINTOS_FB_*), образ мапится ядром в пространство задачи
    // (запись в FB ведёт userspace-инит, см. cintos-user::fb).
    if let Some(fb) = FB.get_response().and_then(|r| r.framebuffers().next()) {
        let addr = fb.addr() as usize;
        // Протокол Limine отдаёт физический адрес; на всякий случай
        // нормализуем возможный HHDM-адрес к физике.
        let phys = if addr >= hhdm { addr - hhdm } else { addr };
        builder = builder.framebuffer(kernel_base::bootinfo::Framebuffer {
            addr: phys,
            width: fb.width() as u32,
            height: fb.height() as u32,
            pitch: fb.pitch() as u32,
            bpp: fb.bpp(),
        });
        kernel_log!(
            "limine: fb {}x{} pitch={} bpp={} phys={:#x}\n",
            fb.width(),
            fb.height(),
            fb.pitch(),
            fb.bpp(),
            phys
        );
    }

    // SAFETY: однопоточный boot-путь; BootInfo после этого не мутирует.
    unsafe {
        BootCell::get_mut(&BOOT_INFO).write(builder.build());
        BootCell::get_ref(&BOOT_INFO).assume_init_ref()
    }
}

/// 7.4-7.5. FrameManager для ACPI-парсера + IOMMU — ДО init_into: reclaim
/// внутри него возвращает AcpiReclaimable-регионы в FrameAllocator, а
/// DMAR/IVRS живут именно там. Аллокации драйвера идут через переданный
/// FrameManager (slab-хуки ещё не нужны).
fn iommu_early_init(boot_info: &BootInfo, fm: &'static FrameManager) {
    kernel_x86::boot::acpi::set_frame_allocator(fm);
    // PHYS-GUARD (acpi): регистрация диапазонов таблиц ДО детекта —
    // та же HHDM-дочерчивка, что у BootBackend::detect, а после неё
    // init сможет получить CAP_CREATE_MMIO по XSDT/MCFG/DRHD.
    acpi_guard_register(boot_info);
    // SAFETY: RSDP от загрузчика (замаплен HHDM), структуры ACPI валидны.
    match unsafe { BootBackend::detect(boot_info.hw_model()) } {
        Ok(backend) => match X86Backend::init_iommu_from_boot(&backend, fm) {
            Ok(()) => kernel_log!("iommu: инициализирован по boot-таблицам\n"),
            Err(e) => kernel_log!("iommu: не инициализирован: {:?}\n", e),
        },
        Err(e) => kernel_log!("boot: ACPI-детект не удался: {:?}\n", e),
    }
}

/// PHYS-GUARD: регистрация диапазонов ACPI-таблиц (RSDP-страница,
/// корневая XSDT/RSDT, дочерние таблицы) в kernel_base::phys_guard.
/// Таблицы лежат внутри AcpiReclaimable-регионов (для гейта это RAM),
/// поэтому без отдельного allow-list CAP_CREATE_MMIO по ним не проходит;
/// allow-list открывает init-серверу легальный путь к ACPI (MCFG -> ECAM,
/// DRHD -> IOMMU, FADT -> таймер/питание).
///
/// ИНВАРИАНТ: кадры таблиц не возвращаются кадровому пулу (x86-порт не
/// free'ит AcpiReclaimable) — иначе MMIO-капа алиасила бы чужую RAM
/// (см. комментарий в phys_guard).
fn acpi_guard_register(boot_info: &BootInfo) {
    use kernel_base::traits::memory::{phys_to_virt, virt_to_phys};
    use kernel_x86::boot::acpi::{AcpiTables, Rsdp};

    let root_phys = match boot_info.hw_model() {
        kernel_base::bootinfo::BootHWModel::AcpiRsdp { begin, .. } => {
            // SAFETY: RSDP по физическому адресу от загрузчика (HHDM;
            // hhdm_ensure_mapped внутри отработает после set_frame_allocator).
            let Ok(rsdp) = (unsafe { Rsdp::from_physical(*begin) }) else {
                kernel_log!("guard/acpi: RSDP не разобран — allow-list пуст\n");
                return;
            };
            // RSDP 2.0 — 36 байт; страница целиком.
            page_span_acpi(*begin, 36);
            match rsdp.root_table_phys() {
                Ok(root) => root,
                Err(e) => {
                    kernel_log!("guard/acpi: корневой таблицы нет: {:?}\n", e);
                    return;
                }
            }
        }
        kernel_base::bootinfo::BootHWModel::AcpiXsdt { begin }
        | kernel_base::bootinfo::BootHWModel::AcpiRsdt { begin } => *begin,
        _ => return,
    };

    // from_physical валидирует чек-сумму и дочерчивает HHDM (тот же
    // путь, что у BootBackend::detect в iommu_early_init — идемпотентно).
    let Ok(tables) = (unsafe { AcpiTables::from_physical(root_phys) }) else {
        kernel_log!("guard/acpi: корневая таблица {:#x} битая\n", root_phys);
        return;
    };
    // Длина корневой: u32 по смещению 4 её заголовка (уже дочерчено).
    let root_len =
        unsafe { ((phys_to_virt(root_phys) + 4) as *const u32).read_volatile() } as usize;
    page_span_acpi(root_phys, root_len);

    // Дочерние таблицы (только чек-суммно-валидные — фильтр tables()).
    let mut count = 0usize;
    for table in tables.tables() {
        let phys = virt_to_phys(table.as_ptr() as usize);
        page_span_acpi(phys, table.len());
        count += 1;
    }
    kernel_log!(
        "guard/acpi: зарегистрировано диапазонов: {} (корень {:#x})\n",
        count + 2,
        root_phys
    );
}

/// Регистрирует странично-выровненный диапазон [phys, phys+len) как ACPI
/// (phys_guard::register_acpi).
fn page_span_acpi(phys: usize, len: usize) {
    const PAGE: usize = 4096;
    let begin = phys & !(PAGE - 1);
    let Some(end) = (phys + len).checked_add(PAGE - 1) else {
        return;
    };
    let end = end & !(PAGE - 1);
    if end > begin {
        kernel_base::phys_guard::register_acpi(begin, end);
    }
}

/// Диагностика аллокатора (та же траектория, что и slab-хуки/spawn):
/// пробная аллокация + освобождение + свободные кадры.
fn alloc_selfcheck(fm: &FrameManager, tag: &str) {
    let probe = kernel_base::traits::memory::FrameAllocator::allocate_pages(fm, 1);
    kernel_log!(
        "diag({tag}): probe={:?} free={} mapped_limit={:#x}\n",
        probe.map(|p| p.phys_base()),
        fm.free_frames(),
        kernel_base::traits::memory::mapped_phys_limit()
    );
    if let Some(p) = probe {
        kernel_base::traits::memory::FrameAllocator::deallocate_pages(fm, p);
    }
}

/// 7.6-8. KernelCTL (placement-инициализация) + сисколлы + BSP-планировщик.
fn kernel_up(
    fm: &'static FrameManager,
    boot_info: &'static BootInfo,
) -> &'static KernelCTL<X86Backend> {
    alloc_selfcheck(fm, "до");

    // Placement: статический слот + init_into (поля пишутся на месте,
    // без by-value гиганта через стек — см. KernelCTL::init_into).
    let storage: &'static mut [u8; core::mem::size_of::<KernelCTL<X86Backend>>()] =
        kernel_base::kernel_static_leak();
    // SAFETY: слот из kernel_static_leak эксклюзивен; KernelCTL не
    // читается никем до возврата init_into (ядро однопоточно).
    let slot: &'static mut MaybeUninit<KernelCTL<X86Backend>> =
        unsafe { &mut *(storage.as_mut_ptr() as *mut MaybeUninit<KernelCTL<X86Backend>>) };
    let kctl = KernelCTL::<X86Backend>::init_into(slot, fm, boot_info);

    KERNEL_CTL.store(
        kctl as *const KernelCTL<X86Backend> as *mut (),
        Ordering::Release,
    );

    kernel_log!("boot: init_syscalls...\n");
    kernel_base::syscall::init_syscalls(kctl);
    // Домен kernel_exec: TASK_CREATE (ELF-спавн по TaskImage-капе) —
    // загрузка образов живёт в kernel_exec, поэтому домен регистрирует
    // он сам, а не kernel_base.
    kernel_exec::syscall::init_exec_syscalls(kctl);
    kernel_log!("boot: init_syscalls готов\n");

    // BSP-планировщик (const-инициализированный массив — только ссылка).
    install_scheduler(0);

    alloc_selfcheck(fm, "после");
    kctl
}

/// 9-10. Реестр форматов + системные серверы + диспетчеризация.
fn exec_up(
    kctl: &'static KernelCTL<X86Backend>,
    boot_info: &'static BootInfo,
    fm: &'static FrameManager,
) {
    // SAFETY: однопоточный boot-путь (static mut).
    unsafe {
        let registry = &mut *core::ptr::addr_of_mut!(EXEC_REGISTRY);
        registry.register(&ELF_FORMAT);
        kernel_exec::spawn::set_exec_registry(&*registry);
    }
    match kernel_exec::spawn_boot_servers(kctl, boot_info, fm) {
        Ok(servers) => {
            for s in &servers {
                kernel_log!(
                    "exec: сервер {} cap={} entry={:#x} rsp={:#x}\n",
                    s.name.as_str(),
                    s.task_cap_id,
                    s.entry,
                    s.stack_top
                );
            }
            // Регистрация серверов в планировщике BSP: TaskManager знает
            // задачу, но LocalKernelCTL-планировщик — нет (bootstrap-задачи
            // регистрирует порт; SCHED_REGISTER_TASK — путь для потомков).
            // Без этого yield возвращает NoAction и init никогда не
            // получает квант.
            let lctl = X86Backend::get_local_base();
            for s in &servers {
                let _ = lctl.scheduler_register_task(s.task_cap_id, s.entry as u64, 0, 0);
            }
            kernel_log!("sched: {} серверов зарегистрированы\n", servers.len());
        }
        Err(e) => kernel_log!("exec: серверы не запущены: {:?}\n", e),
    }

    // Диспетчеризация: стеки + MSR SYSCALL/SYSRET (после init_syscalls —
    // с этого момента `syscall` из ring3 валиден) + хук переключения
    // задач (yield/усыпление: вход в выбранную планировщиком) + хук
    // фолт-доставки (seL4/KeyKOS: исключения ring3 с обработчиком идут
    // в юзерспейс через ipc::fault — ядро само является отправителем).
    cswitch::late_boot_init(kctl.kernel_map().lock().root_phys(), scheduler_loop_entry);
    cswitch::set_switch_hook(sched_switch_to);
    kernel_x86::fault::set_dispatch_hook(fault_dispatch_x86);
    // Kill-хук порта: ring3-фолт без обработчика / неканоничный кадр
    // возврата — виновная задача уничтожается (общий destroy_task_full),
    // система продолжает планирование.
    kernel_x86::fault::set_task_kill_hook(task_kill_x86);
    // Хук смерти задачи (v2 IOMMU): destroy_task_full вызывает его после
    // успешного уничтожения — порт отзывает IOMMU-объекты погибшей задачи
    // (PASID-контексты/пространства/домены). БЕЗ него SVA-пространство
    // переживало бы владельца: PASIDTE.FLRTP указывал бы на освобождённые
    // таблицы страниц процесса (IOMMU ходил бы по переиспользованной памяти).
    kernel_base::syscall::syscall_task::set_task_destroy_hook(
        kernel_x86::iommu::on_task_destroy_current,
    );
}

/// 11. SMP: подъём AP-ядер — ВСЯ механика в arch-бэкенде
///     (kernel_x86::smp): трамплины, per-CPU области, отложенный reclaim
///     защищённых регионов. Фронтенд даёт только политику: хук ставит
///     планировщик и уходит в цикл диспетчеризации этого ядра.
fn smp_up(fm: &'static FrameManager) {
    if let Some(smp) = SMP.get_response() {
        // SAFETY: static mut читается после boot-фазы BSP (AP ещё не
        // подняты — никто не пишет).
        let deferred: &[(usize, usize)] = unsafe { &*core::ptr::addr_of!(DEFERRED_RECLAIM) };
        let (online, all) = kernel_x86::smp::bringup_aps(
            smp.cpus(),
            smp.bsp_lapic_id(),
            deferred,
            fm,
            Some(ap_online),
        );
        kernel_log!(
            "smp: BSP онлайн (lapic {}), AP поднято {}, reclaim {}\n",
            smp.bsp_lapic_id(),
            online,
            if all {
                "выполнен"
            } else {
                "ОТЛОЖЕН (не все AP)"
            }
        );
    }
}

/// 11.5-11.8. ТАЙМЕР: PIT на 100 Гц + хук линии 0 (учёт статистики ядром +
/// доставка тика юзерспейс-таймер-серверу через WaitIrq — L4-модель
/// «таймер — сервис юзерспейса»). Источник стартует после подъёма AP:
/// до этого BOOTLOADER_RECLAIMABLE-транзакции smp::bringup_aps не
/// должны прерываться тиками. Затем — маскируемые прерывания (BSP):
/// тик таймера периодически входит в irq_common, ведёт учёт
/// (cpu_ticks/uptime) и будит ждущих. AP остаются с IF=0 (их циклы
/// диспетчеризации поллят готовность; межъядерные IPI — отдельный этап).
fn time_up() {
    kernel_x86::timer::start_periodic_tick(100);
    X86Backend::irq_enable();
    kernel_log!("irq: STI (BSP) — тики таймера активны\n");
}

/// 12. Отчёт по стекам + вход в цикл планировщика BSP (не возвращается;
///     вернуться в него можно только через cswitch::return_to_scheduler —
///     self-exit задачи).
fn run() -> ! {
    let used = boot_stack_high_water();
    kernel_log!(
        "boot: бут-стек: пик ≈{} КиБ из {} КиБ, канарейка {}\n",
        used / 1024,
        BOOT_STACK_BYTES / 1024,
        if boot_canary_ok() {
            "цела"
        } else {
            "НАРУШЕНА"
        }
    );
    if !boot_canary_ok() {
        // Диагностика повреждения: сами байты + первые байты рабочей
        // части (если они тоже не 0x5A — писали ВНИЗ стека; если 0x5A —
        // прилетело ТОЧНО в канарейку, т.е. по её адресу жив чужой
        // объект/запись).
        // SAFETY: чтение static mut (диагностика, однопоточно).
        let (canary, bottom) = unsafe {
            let s = &*core::ptr::addr_of!(BOOT_STACK);
            let mut c = [0u8; 16];
            c.copy_from_slice(&s.canary);
            let mut b = [0u8; 16];
            b.copy_from_slice(&s.bytes[..16]);
            (c, b)
        };
        kernel_log!(
            "boot: canary@{:p} = {:02x?}, bytes[0..16] = {:02x?}\n",
            core::ptr::addr_of!(BOOT_STACK),
            canary,
            bottom
        );
    }
    scheduler_loop_entry()
}

// ─── Диспетчеризация ────────────────────────────────────────────────────────

/// Цикл планировщика: поллит готовые задачи, входит в выбранную
/// (dispatch_user/resume_user не возвращаются до уступки/смерти задачи)
/// и возвращает управление сюда же после её смерти или усыпания всех.
#[unsafe(no_mangle)]
extern "C" fn scheduler_loop_entry() -> ! {
    loop {
        // Канарейка бут-стека: перелив через дно (рост вниз) задел её
        // первым — ловим молчаливую порчу памяти на месте.
        if !boot_canary_ok() {
            kernel_log!("FATAL: канарейка бут-стека затёрта — перелив стека BSP\n");
            halt();
        }
        let lctl = X86Backend::get_local_base();
        if let TaskExecStatus::ChangeTask(id) = lctl.scheduler_yield() {
            enter_task(id as u64);
        } else {
            // Нет готовых задач: короткая пауза и повторный опрос
            // (кооперативная модель — без таймер-IRQ).
            for _ in 0..10_000 {
                unsafe {
                    asm!("pause");
                }
            }
        }
    }
}

/// Вход в задачу, выбранную планировщиком: первый запуск (без кадра) —
/// dispatch_user по entry/стартовому стеку; повторный (кадр в TCB от
/// уступки/усыпания) — resume_user: задача продолжает С МЕСТА остановки.
/// Используется и циклом планировщика, и хуком переключения cswitch
/// (уступка текущей внутри сисколла).
fn enter_task(next_id: u64) -> ! {
    let kctl = kernel_ctl();
    let lctl = X86Backend::get_local_base();
    // Поиск TCB + снятие контекста — под локом менеджера задач (гонка
    // с destroy исключена: тот же лок).
    let tasks = kctl.task_manager().lock();
    let Some(tcb) = tasks.get_tcb(next_id) else {
        drop(tasks);
        kernel_log!("sched: задача {} исчезла до диспетчеризации\n", next_id);
        // SAFETY: контракт cswitch (возврат в цикл планировщика).
        unsafe { cswitch::return_to_scheduler() }
    };
    // SAFETY: TCB жив под локом task_manager; GTcb живёт в том же слэбе.
    let Some(root) = (unsafe { tcb.gtcb_owner().as_ref().userspace_map().root_table() }) else {
        drop(tasks);
        kernel_log!("sched: у задачи {} нет таблицы страниц\n", next_id);
        // SAFETY: контракт cswitch.
        unsafe { cswitch::return_to_scheduler() }
    };
    // Кадр возобновления изымается ДО снятия текущей (take — одноразовый).
    let resume = tcb.take_resume();
    let (entry, _code, _stack) = tcb.runtime();
    let user_rsp = tcb.initial_stack_top() as usize;
    lctl.set_current_task(NonNull::from(tcb));
    drop(tasks);

    match resume {
        Some(full) => {
            // Возобновление: ПОЛНЫЙ слот возобновления (слова 18/19 —
            // RCX/R11 для задач, упавших по фолту и возвращённых
            // FAULT_REPLY; у сисколл-кадров — нули, безвредно).
            cswitch::resume_user(root, &full)
        }
        None => {
            kernel_log!(
                "sched: вход в задачу {} entry={:#x} rsp={:#x}\n",
                next_id,
                entry,
                user_rsp
            );
            cswitch::dispatch_user(root, entry as usize, user_rsp)
        }
    }
}

/// Хук переключения cswitch: диспетчер сисколлов сохранил кадр
/// уступившей/уснувшей задачи в её TCB и выбрал следующую — вход в неё.
/// Не возвращается (вход в задачу либо возврат в цикл планировщика).
fn sched_switch_to(next_id: u64) -> ! {
    enter_task(next_id)
}

/// Хук фолт-доставки порта: монорфизация архитектурно-независимого
/// ipc::fault::deliver_fault над X86Backend (фронтенд владеет KernelCTL,
/// порт — нет; тот же паттерн, что у SwitchHook). Зовётся из пути
/// исключения (crate::kernel_x86::fault::user_fault_entry): доставляет
/// фолт-сообщение обработчику и блокирует упавшую на fault-объекте.
fn fault_dispatch_x86(
    lctl: &mut kernel_base::lctl::LocalKernelCTL<kernel_x86::paging::X86Umap>,
    faulting_task_cap: u64,
    info: &kernel_base::ipc::fault::FaultInfo,
) -> bool {
    let kctl = kernel_ctl();
    kernel_base::ipc::fault::deliver_fault::<X86Backend>(kctl, lctl, faulting_task_cap, info)
}

// Проверка сигнатуры хука на компиляции (раскладка трейта в ядре).
const _: fn(
    &mut kernel_base::lctl::LocalKernelCTL<kernel_x86::paging::X86Umap>,
    u64,
    &kernel_base::ipc::fault::FaultInfo,
) -> bool = fault_dispatch_x86;

/// Хук kill-путей порта (ring3-фолт без обработчика, неканоничный кадр
/// возврата в ring3): уничтожает задачу общим ядром уничтожения
/// (syscall::syscall_task::destroy_task_full) — транзакция TaskManager +
/// очистка планировщика/IPC/IRQ/фолт-реестров, как у SCHED_DESTROY_TASK.
fn task_kill_x86(
    lctl: &mut kernel_base::lctl::LocalKernelCTL<kernel_x86::paging::X86Umap>,
    task_cap_id: u64,
) {
    let kctl = kernel_ctl();
    let code = kernel_base::syscall::syscall_task::destroy_task_full::<X86Backend>(
        kctl, lctl, task_cap_id,
    );
    if kernel_base::traits::syscall::syscall_result::is_error(code) {
        kernel_log!("kill: destroy task {} вернул {:#x}\n", task_cap_id, code);
    }
}

/// Хук AP-онлайна (политика фронта): планировщик этого ядра + цикл
/// диспетчеризации. Не возвращается (контракт smp::ApOnlineHook).
fn ap_online(core_slot: usize) -> ! {
    install_scheduler(core_slot);
    // High-water отчёт по стеку цикла планировщика этого AP (залит
    // паттерном в setup_cpu_area; сюда AP уже успел поработать).
    kernel_log!(
        "smp: AP {} онлайн, стек цикла: пик ≈{} КиБ из {} КиБ\n",
        core_slot,
        cswitch::sched_stack_used(core_slot) / 1024,
        32
    );
    scheduler_loop_entry()
}

/// Ставит round-robin планировщик на текущее ядро.
///
/// Планировщики — const-инициализированный статический массив: установка
/// сводится к безопасной ссылке (никаких 19.5-КиБ конструкций на стеке
/// — прежний BootCell::write(RoundRobinScheduler::new()) строил и
/// копировал гиганта на КАЖДОМ ядре).
fn install_scheduler(core_id: usize) {
    if core_id >= SCHEDULERS.len() {
        kernel_log!("smp: ядро {} сверх лимита — без планировщика\n", core_id);
        return;
    }
    let lctl = X86Backend::get_local_base();
    lctl.install_scheduler(&SCHEDULERS[core_id]);
    kernel_log!("sched: RR поставлен на ядро {}\n", core_id);
}

// ─── Инструментировка бут-стека ─────────────────────────────────────────────

/// Заливает рабочую часть BOOT_STACK паттерном (для high-water замера).
/// Вызывается первым делом в boot_main: заливается всё ниже текущего
/// rsp с запасом 256 Б (кадры boot_main/фаз остаются незалитыми — их
/// вклад и так виден по границе паттерна).
fn boot_stack_paint() {
    const PATTERN: u8 = cswitch::STACK_PATTERN;

    let probe = 0u8;
    let sp = &probe as *const u8 as usize;
    // SAFETY: static mut в однопоточном boot-пути; заливка строго ниже
    // живых кадров (запас 256 Б).
    unsafe {
        let stack = &mut *core::ptr::addr_of_mut!(BOOT_STACK);
        stack.canary[..8].copy_from_slice(BOOT_CANARY);
        let top = stack.bytes.as_mut_ptr().add(stack.bytes.len()) as usize;
        let paint_end = top.min(sp.saturating_sub(256));
        let start = stack.bytes.as_mut_ptr() as usize;
        if paint_end > start {
            core::ptr::write_bytes(start as *mut u8, PATTERN, paint_end - start);
        }
    }
}

/// High-water бут-стека: сколько байт от дна было затронуто (стек растёт
/// вниз — ищем первый незалитый байт от НИЗА). Паттерн в данных даёт
/// лёгкую недооценку — значение ориентировки «≈».
fn boot_stack_high_water() -> usize {
    // SAFETY: чтение static mut в однопоточном контексте (до старта AP);
    // после — тоже ок: запись только у дна, читаем до первого паттерна.
    unsafe {
        let stack = &*core::ptr::addr_of!(BOOT_STACK);
        for (i, b) in stack.bytes.iter().enumerate() {
            if *b != cswitch::STACK_PATTERN {
                return stack.bytes.len() - i;
            }
        }
        stack.bytes.len()
    }
}

/// Целостность канарейки у дна бут-стека.
fn boot_canary_ok() -> bool {
    // SAFETY: чтение static mut (16 байт у дна) — гонок нет (только BSP
    // работает на этом стеке; AP-стеки свои).
    unsafe {
        let stack = &*core::ptr::addr_of!(BOOT_STACK);
        stack.canary[..8] == BOOT_CANARY[..]
    }
}

// ─── Глобальный bump-аллокатор для boot-пути (Box/Vec из alloc) ─────────────
// Ядро после init_allocator пользуется slab-хуками kernel_base; этот
// аллокатор нужен для связей до/мимо (Heapless fallback, fmt и т.п.).
struct BootAlloc;

// SAFETY: HEAP статический, OFFSET атомарный; выравнивание вычисляем
// с запасом (+align) внутри размера.
unsafe impl core::alloc::GlobalAlloc for BootAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static HEAP: [u8; 2 * 1024 * 1024] = [0; 2 * 1024 * 1024];
        static OFFSET: AtomicUsize = AtomicUsize::new(0);
        let heap_ptr = core::ptr::addr_of!(HEAP);
        let base = core::ptr::addr_of!(HEAP).cast_mut() as *mut u8;
        let heap_len = core::mem::size_of_val(unsafe { &*heap_ptr });
        // Резервируем size+align, выравнивая старт.
        let off = OFFSET.fetch_add(layout.size() + layout.align(), Ordering::AcqRel);
        if off + layout.size() > heap_len {
            return core::ptr::null_mut();
        }
        let raw = base.wrapping_add(off) as usize;
        let aligned = (raw + layout.align() - 1) & !(layout.align() - 1);
        aligned as *mut u8
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // bump: не освобождаем
    }
}

#[global_allocator]
static GLOBAL: BootAlloc = BootAlloc;

fn halt() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    // Полная картина паники — в serial (единственный канал, видимый до
    // подъёма init) и в кольцо лога (увидит init, если уже жив).
    let mut w = kernel_x86::serial::SerialWriter;
    let _ = writeln!(w, "KERNEL PANIC: {}", info);
    kernel_log!("KERNEL PANIC: {}\n", info);
    halt()
}
