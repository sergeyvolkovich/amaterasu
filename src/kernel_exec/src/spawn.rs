//! Загрузчик образов системных серверов и стартовый стек аргументов.
//!
//! Системные серверы — первые процессы NOMAD: ядро на старте берёт
//! boot-модули (BootInfo::boot_modules), выбирает формат через
//! `kernel_base::exec::FormatRegistry` (ELF64 с OSABI 0xC1), грузит
//! сегменты в свежий умап задачи, строит НАЧАЛЬНЫЙ СТЕК с аргументами и
//! стартовым набором capability (self-TCB + root-неймспейс на
//! фиксированных слотах 0/1) и регистрирует задачу.
//!
//! Смена формата исполняемых файлов = регистрация другого `ExecFormat`
//! в реестре (см. kernel_base::exec) — загрузчику всё равно, ELF это
//! или что-то другое: он работает только с `ImageInfo`.
//!
//! РАСКЛАДКА НАЧАЛЬНОГО СТЕКА (совместима с SysV-конвенцией; crt0
//! cintos-user читает ровно это, начальный RSP указывает на argc):
//!
//! ```text
//! stack_top (высокие адреса)
//! ├─ строки argv/envp (NUL-терминированные)
//! ├─ выравнивание (padding)
//! ├─ auxv: пары (tag: u64, val: u64), завершается AT_NULL
//! ├─ envp: указатели [+ NULL]
//! ├─ argv: указатели [+ NULL]
//! └─ argc: u64           <- начальный RSP (выровнен на 16)
//! ```
//!
//! AUXV-теги NOMAD (кастомный диапазон 0xC170_0000+):
//!   - `AT_NOMAD_SELF_CAP`  — id TaskTCB-капабилити задачи (для
//!     DestroyTask(self) в crt0::exit);
//!   - `AT_NOMAD_NS_CAP`    — id корневой capability неймспейса задачи;
//!   - стандартные: `AT_PAGESZ` (7), `AT_ENTRY` (9).
//!
//! Bootstrap-слоты cspace: слот 0 = self-TCB, слот 1 = корневой
//! неймспейс. Оба — корневые записи с полными правами.

use core::ptr::NonNull;

use kernel_base::bootinfo::BootInfo;
extern crate alloc;
use crate::registry::{ExecError, FormatRegistry, ImageInfo};
use kernel_base::task::tcb::GTcb;
use kernel_base::traits::memory::{
    FrameAllocator, MemoryFlags, MemoryInterfaceUserspace, MemoryPTR,
    PAGE_SIZE, phys_to_virt,
};
use kernel_base::umap::{VmapError, VmapRegion};

use kernel_base::traits::ArchImplementation;
use kernel_base::KernelCTL;
use kernel_base::kernel_log;

/// AUXV-теги NOMAD (кастомный диапазон).
pub const AT_NULL: u64 = 0;
pub const AT_PAGESZ: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_NOMAD_SELF_CAP: u64 = 0xC170_0001;
pub const AT_NOMAD_NS_CAP: u64 = 0xC170_0002;
pub const AT_NOMAD_FB_ADDR: u64 = 0xC170_0003;
pub const AT_NOMAD_FB_PITCH: u64 = 0xC170_0004;
pub const AT_NOMAD_FB_WIDTH: u64 = 0xC170_0005;
pub const AT_NOMAD_FB_HEIGHT: u64 = 0xC170_0006;
pub const AT_NOMAD_FB_BPP: u64 = 0xC170_0007;
/// Физический адрес RSDP (ACPI): init монтирует таблицы через
/// CAP_CREATE_MMIO — их диапазоны зарегистрированы в phys_guard на буте
/// (см. phys_guard::register_acpi). 0/отсутствие тега — ACPI не найден.
pub const AT_NOMAD_ACPI_RSDP: u64 = 0xC170_0008;

/// Фиксированный VA фреймбуфера в пространстве сервера: выше окна
/// VmapRegion задач (DEFAULT_TASK_VMAP_BASE = 4 ГиБ + 64 ГиБ окна),
/// ниже ядерной половины.
pub const FB_VA_BASE: usize = 0x0000_0020_0000_0000;

/// Глубина начального стека задачи (страниц) НИЖЕ блока argc/argv/
/// envp/auxv. Ядро обязано оставить задаче место под кадры: Rust
/// генерирует stack-probes на большой кадр сразу у входа в функцию,
/// и при исчерпании окна — #PF записи ниже стека (P=0, W, U).
pub const INITIAL_STACK_DEPTH_PAGES: usize = 32; // 128 КиБ

/// Bootstrap-слоты cspace системного сервера.
pub const BOOT_SLOT_SELF: u64 = 0;
pub const BOOT_SLOT_NAMESPACE: u64 = 1;
/// Первый слот peer-TaskTCB: i-й boot-сервер — слот 2+i (IPC-адресация).
pub const BOOT_SLOT_PEER_BASE: u64 = 2;

/// Слот cspace ДИНАМИЧЕСКИ созданной задачи (TASK_CREATE), куда ядро
/// кладёт TaskTCB СОЗДАТЕЛЯ: ребёнок получает адрес IPC-ответа сразу,
/// не требуя от родителя отдельных map item'ов. У boot-серверов слот 2
/// занят peer-ростером — константа касается только динамических задач.
pub const BOOT_SLOT_PARENT: u64 = 2;
/// Первый слот капабилитей на boot-образы (TaskImage) init-сервера:
/// j-й образ реестра — слот 32+j. Выше peer-окна (2..2+N≤14) и выше
/// слотов трансферного окна демо (16+).
pub const BOOT_SLOT_IMAGE_BASE: u64 = 32;
/// Базовое имя boot-модуля (basename пути), получающего TaskImage-капы
/// и, стало быть, право спавна через TASK_CREATE. Только init:
/// динамические потомки таких кап не получают — спавн ограничен
/// деревом init'а (сейчас все boot-серверы и так в корневом неймспейсе
/// с полными правами, но TaskImage-капы раздаём уже по минимуму).
pub const INIT_MODULE_NAME: &str = "init";

/// Basename пути модуля Limine ("boot():/boot/modules/init" -> "init").
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

/// Заглушка для мест "не должно случиться под локом": slab-ошибка как
/// наименее семантичный из вариантов AccessError.
const fn slab_unreachable() -> kernel_base::access::AccessError {
    kernel_base::access::AccessError::Slab(attachable_slab_allocator::SlabError::OutOfMemory)
}

#[derive(Debug)]
pub enum SpawnError {
    Exec(ExecError),
    /// Кадры/маппинг (в т.ч. страницы стека).
    Memory(kernel_base::traits::memory::ErrorCode),
    /// Ошибка трекера виртуальных страниц (стек).
    Vmap(VmapError),
    /// Ошибка slab/учёта при создании задачи или капабилити.
    Access(kernel_base::access::AccessError),
    /// Ошибка создания задачи (TaskManager-транзакция).
    CreateTask(kernel_base::task::CreateTaskManagerError),
    /// Нет ни одного загружаемого boot-модуля.
    NoServers,
    /// Реестр форматов пуст.
    NoFormats,
}

impl From<ExecError> for SpawnError {
    fn from(e: ExecError) -> Self {
        SpawnError::Exec(e)
    }
}

/// Статический реестр форматов (заполняет порт через [`set_registry`]).
static EXEC_REGISTRY: spin::Once<&'static FormatRegistry> = spin::Once::new();

/// Порт устанавливает свой реестр форматов при старте.
pub fn set_exec_registry(registry: &'static FormatRegistry) {
    EXEC_REGISTRY.call_once(|| registry);
}

/// Реестр форматов; pub(crate) — сисколл-домен kernel_exec::syscall
/// (TASK_CREATE) грузит образы тем же реестром, что и boot-спавн.
pub(crate) fn exec_registry() -> &'static FormatRegistry {
    EXEC_REGISTRY.get().copied().expect("exec registry not set by port")
}

/// Аргументы задачи: argv/envp (строки копируются в стартовый стек).
pub struct TaskArgs<'a> {
    pub argv: &'a [&'a str],
    pub envp: &'a [&'a str],
}

/// Результат раскладки начального стека.
#[derive(Debug, Clone, Copy)]
pub struct StackSetup {
    /// Адрес ячейки argc (начальный RSP задачи, выровнен на 16).
    pub stack_top: usize,
    /// Ручка трекера (для free при откате).
    pub handle: kernel_base::umap::VmapHandle,
}

/// Один AUXV-элемент.
#[derive(Debug, Clone, Copy)]
pub struct AuxEntry {
    pub tag: u64,
    pub val: u64,
}

/// Загружает сегменты образа в умап задачи (file-часть копируется через
/// HHDM, BSS обнуляется). Права сегментов — PF_-флаги.
///
/// p_vaddr НЕ обязан быть выровнен на страницу: страница мапится от
/// `vaddr & !(PAGE_SIZE-1)`, file-часть копируется со смещением внутри
/// страницы.
///
/// # Разделяемые страницы (архитектурный инвариант)
///
/// Соседние PT_LOAD-сегменты могут делить страницу: линкер кладёт
/// .data вплотную к хвосту .rodata (или .rodata к .text) внутри той же
/// страницы. Аллокация «своих» фреймов на каждый сегмент ПОРТИЛА такую
/// страницу: второй сегмент получал свежие нулевые фреймы и
/// перемапливал PTE — хвост первого сегмента на общей странице
/// терялся (в QEMU: jump-table scan_auxv в .rodata читалась нулями →
/// вызов адреса самой таблицы → #PF по NX → triple fault). Правильный
/// контракт:
///   - фрейм на страницу выделяется ОДИН раз и переиспользуется
///     (уже отображённые страницы находятся через `umap.translate`);
///   - права общей страницы = ОБЪЕДИНЕНИЕ прав покрывающих сегментов:
///     записываема, если хоть один сегмент разрешает запись;
///     исполняема, если хоть один разрешает exec;
///   - file-часть сегмента копируется строго в его байтовый диапазон,
///     BSS ([vaddr+filesz, vaddr+memsz)) обнуляется явно.
pub fn load_image<U: MemoryInterfaceUserspace>(
    umap: &U,
    frames: &dyn FrameAllocator,
    image: &[u8],
    registry: &FormatRegistry,
) -> Result<ImageInfo, SpawnError> {
    use kernel_base::traits::memory::ErrorCode;

    let mut info = registry.parse(image)?;

    // phdr-порядок не обязан быть сортированным по vaddr — сортируем
    // сами (sweep идёт по возрастанию VA).
    info.segments.sort_by_key(|s| s.vaddr);

    // Байтовые диапазоны сегментов обязаны быть дизъюнктны: общие
    // страницы допустимы, общие байты — нет (битый образ).
    for pair in info.segments.windows(2) {
        let a_end = pair[0]
            .vaddr
            .checked_add(pair[0].mem_size)
            .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
        if pair[1].vaddr < a_end {
            return Err(SpawnError::Memory(ErrorCode::InvalidLayout));
        }
    }

    let page_mask = PAGE_SIZE - 1;
    // ВЕРХНЯЯ ГРАНИЦА: сегменты обязаны лежать в НИЖНЕЙ (пользовательской)
    // половине. Образ с vaddr в ядерной половине иначе направил бы
    // загрузку в ЖИВУЮ память ядра: translate-переиспользование ниже
    // нашло бы общие с ядром фреймы, и file-копия/BSS-обнуление писали
    // бы поверх ядра (hardening: пока образы — boot-модули, но граница
    // обязана быть в самом загрузчике).
    for seg in &info.segments {
        let seg_end = seg
            .vaddr
            .checked_add(seg.mem_size)
            .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
        if seg.vaddr >= kernel_base::traits::memory::USER_SPACE_LIMIT
            || seg_end > kernel_base::traits::memory::USER_SPACE_LIMIT
        {
            return Err(SpawnError::Memory(ErrorCode::InvalidLayout));
        }
    }
    // ENTRY обязан лежать в ИСПОЛНЯЕМОМ сегменте образа: иначе —
    // прыжок по недоверенному e_entry в никуда (NX-страница → фолт
    // без keeper'а) или в данные (исполнение мусора).
    if !info.segments.iter().any(|s| {
        s.executable
            && info.entry >= s.vaddr
            && info.entry < s.vaddr.saturating_add(s.mem_size)
    }) {
        return Err(SpawnError::Exec(ExecError::BadHeader(
            "entry point вне исполняемого PT_LOAD-сегмента",
        )));
    }
    let first = info
        .segments
        .first()
        .ok_or(SpawnError::Exec(ExecError::NoLoadSegments))?;
    let last = info.segments.last().expect("segments non-empty");
    let span_start = first.vaddr & !page_mask;
    let span_end = last
        .vaddr
        .checked_add(last.mem_size)
        .and_then(|end| end.checked_add(page_mask))
        .map(|end| end & !page_mask)
        .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
    if span_end <= span_start {
        return Err(SpawnError::Memory(ErrorCode::InvalidLayout));
    }

    // Sweep по страницам образа в возрастающем порядке. Каждая страница
    // обрабатывается ровно один раз: фрейм → содержимое → маппинг.
    let mut page_va = span_start;
    while page_va < span_end {
        // Концы диапазонов сегментов (переполнение отсечено проверкой
        // дизъюнктности/пары — но здесь всё равно checked).
        let mut writable = false;
        let mut executable = false;
        for seg in &info.segments {
            let seg_end = seg
                .vaddr
                .checked_add(seg.mem_size)
                .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
            if seg.vaddr < page_va + PAGE_SIZE && page_va < seg_end {
                writable |= seg.writable;
                executable |= seg.executable;
            }
        }
        let mut flags = MemoryFlags::empty();
        if !writable {
            flags |= MemoryFlags::READ_ONLY;
        }
        if !executable {
            flags |= MemoryFlags::NO_EXECUTE;
        }

        // Фрейм страницы: переиспользуем уже отображённый (разделяемая
        // страница от предыдущего сегмента) или аллоцируем свежий.
        // USER-семантика: только страницы с U/S-битом считаются «нашими»
        // (нижняя половина + user-маппинг). Голый translate находил бы и
        // ЯДЕРНЫЕ страницы общей верхней половины — переиспользование
        // фрейма ядра под образ задачи = порча ядра (см. верхнюю границу
        // выше — это второй рубеж обороны).
        let phys = match umap.translate_user(page_va, false) {
            Some(p) => p & !page_mask,
            None => {
                let region = frames
                    .allocate_pages(1)
                    .ok_or(SpawnError::Memory(ErrorCode::OutOfMemory))?;
                let phys = region.phys_base();
                // Свежий фрейм: обнуляем (BSS по умолчанию + не отдаём
                // userspace мусор от ядра).
                // SAFETY: фрейм выделен под нас, HHDM покрывает его.
                unsafe {
                    core::ptr::write_bytes(phys_to_virt(phys) as *mut u8, 0, PAGE_SIZE);
                }
                phys
            }
        };

        // Копируем file-части и обнуляем BSS-части всех сегментов на
        // этой странице (байтовые диапазоны дизъюнктны — порядок
        // безопасен).
        for seg in &info.segments {
            let seg_file_end = seg
                .vaddr
                .checked_add(seg.file_size)
                .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
            let seg_mem_end = seg
                .vaddr
                .checked_add(seg.mem_size)
                .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
            // Пересечение байтов сегмента со страницей.
            let from = seg.vaddr.max(page_va);
            let to = seg_mem_end.min(page_va + PAGE_SIZE);
            if to <= from {
                continue;
            }
            // file-часть внутри страницы: [from, min(to, file_end)).
            let file_to = to.min(seg_file_end);
            if file_to > from {
                let img_off = seg
                    .file_offset
                    .checked_add(from - seg.vaddr)
                    .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
                // SAFETY: диапазон внутри образа проверен парсером
                // (file_offset+file_size <= image.len()); назначение —
                // наш фрейм через HHDM.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        image.as_ptr().add(img_off),
                        (phys_to_virt(phys) + (from - page_va)) as *mut u8,
                        file_to - from,
                    );
                }
            }
            // BSS-часть внутри страницы: [max(from, file_end), to).
            let bss_from = from.max(seg_file_end);
            if to > bss_from {
                // SAFETY: байты принадлежат сегменту на нашем фрейме.
                unsafe {
                    core::ptr::write_bytes(
                        (phys_to_virt(phys) + (bss_from - page_va)) as *mut u8,
                        0,
                        to - bss_from,
                    );
                }
            }
        }

        // Отображение страницы с объединёнными правами.
        let ptr = MemoryPTR::new(phys, 1)
            .ok_or(SpawnError::Memory(ErrorCode::InvalidLayout))?;
        umap.map_memory_region_flags(frames, ptr, page_va, flags)
            .map_err(SpawnError::Memory)?;

        page_va += PAGE_SIZE;
    }
    Ok(info)
}

/// Строит начальный стек задачи: argc/argv/envp/auxv (+ строки) в
/// верхнем окне виртуального пространства, выделенном через VmapRegion.
/// Возвращает адрес ячейки argc (начальный RSP, кратен 16).
///
/// Раскладка (снизу вверх от RSP): argc; argv-массив (NULL-терминированный);
/// envp-массив (NULL-терминированный); auxv-пары; строки; выравнивание.
// Аргументов 8 — единая транзакция «выделить окно, разложить, вернуть RSP»;
// промежуточный тип-пачка усложнил бы чтение. Локальное отключение lint.
#[allow(clippy::too_many_arguments)]
pub fn build_initial_stack<U: MemoryInterfaceUserspace>(
    vmap: &VmapRegion,
    umap: &U,
    frames: &dyn FrameAllocator,
    args: &TaskArgs<'_>,
    aux: &[AuxEntry],
    entry: usize,
    self_cap: u64,
    ns_cap: u64,
) -> Result<StackSetup, SpawnError> {
    // ── 1. Размер ──
    let strings_size: usize = args
        .argv
        .iter()
        .chain(args.envp.iter())
        .map(|s| s.len() + 1)
        .sum();
    // auxv: переданные пары + 4 кастомных NOMAD/стандартных + AT_NULL.
    let auxv: heapless::Vec<AuxEntry, 16> = {
        let mut v = heapless::Vec::new();
        let _ = v.push(AuxEntry { tag: AT_PAGESZ, val: PAGE_SIZE as u64 });
        let _ = v.push(AuxEntry { tag: AT_ENTRY, val: entry as u64 });
        let _ = v.push(AuxEntry { tag: AT_NOMAD_SELF_CAP, val: self_cap });
        let _ = v.push(AuxEntry { tag: AT_NOMAD_NS_CAP, val: ns_cap });
        for a in aux {
            let _ = v.push(*a);
        }
        let _ = v.push(AuxEntry { tag: AT_NULL, val: 0 });
        v
    };
    let auxv_size = auxv.len() * 16;
    let arrays_size = (args.argv.len() + 1 + args.envp.len() + 1) * 8;
    let argc_size = 8;
    let fixed_bottom = argc_size + arrays_size + auxv_size;
    let payload = strings_size + fixed_bottom;
    // ГЛУБИНА стека: payload-страницы — только под argc/argv/envp/auxv и
    // строки; задача растёт стеком ВНИЗ от RSP, и без запаса глубины
    // первый же stack-probe Rust-кода (кадр console_loop ~0x2138,
    // main ~0x428) уходит ниже окна → #PF (поймано в QEMU: probe2 на
    // 0xFFFFFA38, err=0x6). 32 страницы = 128 КиБ — комфортный минимум
    // для системного сервера (fmt-механизмы Rust прожорливы).
    let pages = INITIAL_STACK_DEPTH_PAGES + payload.div_ceil(PAGE_SIZE) + 1; // +1 на выравнивание

    // ── 2. Выделение окна через трекер задачи ──
    let handle = vmap
        .alloc(umap, frames, pages, MemoryFlags::empty())
        .map_err(SpawnError::Vmap)?;
    let entry_info = vmap
        .lookup(handle.virt_base())
        .ok_or(SpawnError::Vmap(VmapError::NotTracked))?;
    let va_base = handle.virt_base();
    let phys_base = entry_info.phys_base;

    // ── 3. Строки: от ВЕРХА окна вниз ──
    let window_top = va_base + pages * PAGE_SIZE;
    let mut top = window_top;
    let mut env_ptrs = heapless::Vec::<usize, 16>::new();
    for s in args.envp {
        top -= s.len() + 1;
        // SAFETY: строки укладываются в подсчитанный объём.
        unsafe {
            let p = phys_to_virt(phys_base + (top - va_base)) as *mut u8;
            core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
            *p.add(s.len()) = 0;
        }
        let _ = env_ptrs.push(top);
    }
    let mut argv_ptrs = heapless::Vec::<usize, 16>::new();
    for s in args.argv {
        top -= s.len() + 1;
        // SAFETY: см. выше.
        unsafe {
            let p = phys_to_virt(phys_base + (top - va_base)) as *mut u8;
            core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
            *p.add(s.len()) = 0;
        }
        let _ = argv_ptrs.push(top);
    }

    // ── 4. RSP: фиксированный блок (argc+массивы+auxv) сразу под строками ──
    let rsp = (top - fixed_bottom) & !0xfusize;
    let argc_addr = rsp;
    let argv_addr = rsp + argc_size;
    let envp_addr = argv_addr + (args.argv.len() + 1) * 8;
    let auxv_addr = envp_addr + (args.envp.len() + 1) * 8;
    // Границы: auxv заканчивается не выше нижней строки.
    debug_assert!(auxv_addr + auxv_size <= top);
    debug_assert_eq!(rsp % 16, 0);

    // ── 5. Запись фиксированного блока через HHDM-зеркало ──
    // SAFETY: весь блок в [rsp, top) лежит в выделенных страницах.
    unsafe {
        let w = |addr: usize, val: u64| {
            (phys_to_virt(phys_base + (addr - va_base)) as *mut u64).write_volatile(val);
        };

        w(argc_addr, args.argv.len() as u64);

        let mut addr = argv_addr;
        for p in &argv_ptrs {
            w(addr, *p as u64);
            addr += 8;
        }
        w(addr, 0); // argv NULL

        let mut addr = envp_addr;
        for p in &env_ptrs {
            w(addr, *p as u64);
            addr += 8;
        }
        w(addr, 0); // envp NULL

        let mut addr = auxv_addr;
        for a in &auxv {
            w(addr, a.tag);
            w(addr + 8, a.val);
            addr += 16;
        }
    }

    Ok(StackSetup {
        stack_top: rsp,
        handle,
    })
}

/// Информация о запущенном системном сервере.
#[derive(Debug, Clone)]
pub struct SpawnedServer {
    /// Имя boot-модуля (скопировано — bootinfo-времена жизни не тащим).
    pub name: heapless::String<48>,
    /// id TaskTCB-капабилити задачи.
    pub task_cap_id: u64,
    /// Адрес входа (e_entry).
    pub entry: usize,
    /// Начальный RSP (ячейка argc).
    pub stack_top: usize,
}

/// Спавнит системные серверы из boot-модулей: загрузка образа, создание
/// задачи в корневом неймспейсе, bootstrap-капабилити (слот 0 = self,
/// слот 1 = неймспейс), стартовый стек. Планировщик НЕ вызывается —
/// порт получает список и регистрирует задачи сам.
///
/// ДВЕ ФАЗЫ (peer-обвязка IPC):
///   1. Спавн всех серверов (образ + задача + слоты 0/1 + FB в auxv);
///   2. Peer-капабилитеты: КАЖДОМУ серверу в слот 2+j кладётся
///      TaskTCB-капабилити j-го сервера (ростер = порядок модулей) —
///      адресация IPC-отправки слотами cspace; стартовый стек каждого
///      получает РОСТЕР в argv: argv[0] = своё имя, argv[1+i] = имя
///      i-го сервера (слот peer = 2 + i).
///
/// Отказ ОДНОГО модуля (битый образ, OOM) не срывает остальные: плохой
/// модуль пропускается, ошибка сохраняется; Err возвращается только
/// если не поднялся ни один сервер.
pub fn spawn_boot_servers<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    boot: &BootInfo,
    frames: &'static (dyn FrameAllocator + Sync),
) -> Result<heapless::Vec<SpawnedServer, 12>, SpawnError> {
    if exec_registry().is_empty() {
        return Err(SpawnError::NoFormats);
    }

    // РЕЕСТР ОБРАЗОВ (TASK_CREATE): каждый boot-модуль получает
    // стабильный module_id = индекс записи. Регистрируются ВСЕ модули —
    // включая неспавнившиеся бутом: init сможет поднять их через
    // TASK_CREATE (самовосстановление ростера). Ошибка реестра
    // (переполнение/длинное имя) не срывает бут-спавн — модуль просто
    // недоступен для динамического спавна.
    for module in boot.boot_modules() {
        let name = module.name().to_str().unwrap_or("server");
        if crate::modules::register_boot_module(name, module.addr(), module.size()).is_none() {
            kernel_log!(
                "exec: реестр образов полон/имя >48Б — '{}' без TASK_CREATE\n",
                name
            );
        }
    }

    // Lock order: AccessManager -> TaskManager (единый порядок ядра).
    let mut access = kctl.permission_backend().lock();
    let mut tasks = kctl.task_manager().lock();

    // Корневой неймспейс: полные групповые права (bootstrap). Квота
    // cap-объектов щедрая — boot-серверы снабжаются TaskTCB-капами
    // ростера + peer-капабилити, но всё же конечная (защита slab).
    let namespace_id = access
        .create_namespace(
            16,
            64 * 1024 * 1024,
            0,
            kernel_base::access::namespace::NamespaceRights::all(),
            4096,
        )
        .map_err(SpawnError::Access)?;
    let ns_ptr = access
        .get_namespace_ptr(namespace_id)
        .ok_or(SpawnError::Access(slab_unreachable()))?;

    // ФАЗА 1: спавн (без стартового стека — ростер ещё не известен).
    let fb = boot.framebuffer();
    // Физический адрес RSDP — всем серверам в auxv (AT_NOMAD_ACPI_RSDP):
    // монтирование таблиц — CAP_CREATE_MMIO по acpi-allow-list phys_guard.
    let rsdp_phys: Option<u64> = match boot.hw_model() {
        kernel_base::bootinfo::BootHWModel::AcpiRsdp { begin, .. } => Some(*begin as u64),
        _ => None,
    };
    let mut pending: heapless::Vec<PendingServer, 12> = heapless::Vec::new();
    let mut last_err: Option<SpawnError> = None;

    for module in boot.boot_modules() {
        let name = module.name().to_str().unwrap_or("server");
        match spawn_one_server::<A>(
            kctl,
            frames,
            namespace_id,
            ns_ptr,
            module,
            fb,
            rsdp_phys,
            &mut access,
            &mut tasks,
            name,
        ) {
            Ok(server) => {
                let _ = pending.push(server);
            }
            // Плохой модуль не должен срывать загрузку остальных
            // серверов: фиксируем ошибку и продолжаем.
            Err(e) => last_err = Some(e),
        }
    }

    if pending.is_empty() {
        return Err(last_err.unwrap_or(SpawnError::NoServers));
    }

    // ФАЗА 2: peer-капабилитеты + стартовые стеки с ростером.
    let roster: heapless::Vec<&str, 12> = pending.iter().map(|s| s.name.as_str()).collect();
    let mut spawned: heapless::Vec<SpawnedServer, 12> = heapless::Vec::new();
    for (i, server) in pending.iter().enumerate() {
        // Слоты 2+j: TaskTCB каждого сервера ростера (включая себя —
        // симметрия адресации; отправка себе запрещена ядром).
        let Some(server_gtcb_ptr) = access.get_task_tcb(server.task_cap_id) else {
            continue;
        };
        // SAFETY: задачи не запущены, лок access удерживается.
        let server_gtcb = unsafe { server_gtcb_ptr.as_ref() };
        for (j, peer) in pending.iter().enumerate() {
            let Some(peer_zygote) = access.get_zygote(peer.task_cap_id) else {
                continue;
            };
            // Ошибка установки peer-слота не роняет сервер: слот
            // останется пуст — отправка этому peer вернёт E_SLOT_EMPTY.
            let _ = kernel_base::access::capspace::install_root_capability(
                server_gtcb,
                BOOT_SLOT_PEER_BASE + j as u64,
                peer_zygote,
                kernel_base::access::capability::DirectCapabilityRights::all(),
                access.task_namespace(server.task_cap_id),
            );
        }

        // TaskImage-капы: ТОЛЬКО init-серверу (см. INIT_MODULE_NAME) —
        // authority динамического спавна (TASK_CREATE). Слоты 32+j.
        // Ошибка отдельной капы не роняет сервер (как у peer-слотов):
        // спавн этого образа просто вернёт E_SLOT_EMPTY.
        if basename(server.name.as_str()) == INIT_MODULE_NAME {
            install_image_caps::<A>(
                &mut access,
                server_gtcb,
                server.task_cap_id,
            );
        }

        // Стартовый стек: argv = [имя своё, ростер…].
        let mut argv: heapless::Vec<&str, 13> = heapless::Vec::new();
        let _ = argv.push(server.name.as_str());
        for name in roster.iter() {
            let _ = argv.push(name);
        }
        let envp: [&str; 0] = [];
        let stack = build_initial_stack(
            server_gtcb.vmap(),
            server_gtcb.userspace_map(),
            frames,
            &TaskArgs { argv: &argv, envp: &envp },
            &server.aux,
            server.entry,
            server.task_cap_id,
            server.ns_cap_id,
        )?;

        tasks
            .register_task(&access, server.task_cap_id, server.entry as u64, server.code_size as u64, 0)
            .map_err(|_| SpawnError::Access(slab_unreachable()))?;
        if let Some(tcb) = tasks.get_tcb(server.task_cap_id) {
            tcb.set_initial_stack_top(stack.stack_top as u64);
        }

        let mut out_name = heapless::String::<48>::new();
        let _ = out_name.push_str(server.name.as_str());
        let _ = spawned.push(SpawnedServer {
            name: out_name,
            task_cap_id: server.task_cap_id,
            entry: server.entry,
            stack_top: stack.stack_top,
        });
        let _ = i;
    }

    Ok(spawned)
}

/// Сервер, дожидающийся фазы 2 (стартовый стек + peer-обвязка).
struct PendingServer {
    name: heapless::String<48>,
    task_cap_id: u64,
    ns_cap_id: u64,
    entry: usize,
    code_size: usize,
    /// auxv-записи (FB-параметры и пр.) — уходят в стартовый стек.
    aux: heapless::Vec<AuxEntry, 16>,
}

/// ФАЗА 1 спавна: загрузка одного boot-модуля как системного сервера
/// (образ + задача + слоты 0/1 + FB-маппинг в auxv). Стартовый стек,
/// peer-обвязка и регистрация — фаза 2 spawn_boot_servers (нужен
/// полный ростер). Вызывается под локами AccessManager -> TaskManager,
/// захваченными вызывающим.
// Единая транзакция загрузки сервера; пачка параметров — это контекст
// уже захваченных локов и bootstrap-состояния, разбивать его на структуру
// здесь только размывало бы инвариант порядка локов.
#[allow(clippy::too_many_arguments)]
fn spawn_one_server<'a, A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    frames: &'static (dyn FrameAllocator + Sync),
    namespace_id: u64,
    ns_ptr: NonNull<kernel_base::access::namespace::Namespace>,
    module: &kernel_base::bootinfo::BootModule<'a>,
    fb: Option<&kernel_base::bootinfo::Framebuffer>,
    rsdp_phys: Option<u64>,
    access: &mut kernel_base::access::AccessManager<A::Umap>,
    tasks: &mut kernel_base::task::TaskManager<A::Umap>,
    name: &str,
) -> Result<PendingServer, SpawnError> {
    // Образ модуля: физический адрес + размер (замаплен HHDM).
    // SAFETY: boot-модули лежат в замапленной загрузчиком памяти.
    let image = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(module.addr()) as *const u8,
            module.size(),
        )
    };

    // Умап задачи из текущей ядерной таблицы (верхняя половина общая).
    let umap = A::create_task_umap(&kctl.kernel_map().lock(), frames)
        .map_err(SpawnError::Memory)?;
    let gtcb = GTcb::new(umap, None);

    // Загрузка сегментов.
    let info = load_image(gtcb.userspace_map(), frames, image, exec_registry())?;

    // Задача (капабилити + TCB) в корневом неймспейсе.
    let task_cap_id = tasks
        .create_task(access, namespace_id, gtcb)
        .map_err(SpawnError::CreateTask)?;

    // Bootstrap-капабилити: слот 0 = self-TCB, слот 1 = неймспейс.
    // SAFETY: задачи не запущены, лок access удерживается.
    let server_gtcb_ptr = access
        .get_task_tcb(task_cap_id)
        .ok_or(SpawnError::Access(slab_unreachable()))?;
    let server_gtcb = unsafe { server_gtcb_ptr.as_ref() };

    let self_zygote = access
        .get_zygote(task_cap_id)
        .ok_or(SpawnError::Access(slab_unreachable()))?;
    kernel_base::access::capspace::install_root_capability(
        server_gtcb,
        BOOT_SLOT_SELF,
        self_zygote,
        kernel_base::access::capability::DirectCapabilityRights::all(),
        access.task_namespace(task_cap_id),
    )
    .map_err(|_| SpawnError::Access(slab_unreachable()))?;

    let ns_cap_id = access
        .create_new_object(kernel_base::access::capability::CapabilityObject::new_task_group_namespace(ns_ptr, namespace_id))
        .map_err(SpawnError::Access)?;
    let ns_zygote = access
        .get_zygote(ns_cap_id)
        .ok_or(SpawnError::Access(slab_unreachable()))?;
    kernel_base::access::capspace::install_root_capability(
        server_gtcb,
        BOOT_SLOT_NAMESPACE,
        ns_zygote,
        kernel_base::access::capability::DirectCapabilityRights::all(),
        access.task_namespace(task_cap_id),
    )
    .map_err(|_| SpawnError::Access(slab_unreachable()))?;

    // Фреймбуфер: образ MMIO мапится в пространство задачи по
    // фиксированному VA (FB_VA_BASE), параметры — через auxv
    // (AT_NOMAD_FB_*). Запись в FB ведёт userspace; ядро только
    // пробрасывает. Отказ маппинга НЕ срывает сервер: init получит
    // fb_addr=0 и перейдёт в headless-режим. Стек строится в фазе 2
    // (ростер argv) — aux сохраняется в PendingServer.
    let mut aux: heapless::Vec<AuxEntry, 16> = heapless::Vec::new();
    if let Some(fb) = fb {
        let fb_bytes = fb.pitch as usize * fb.height as usize;
        let base = fb.addr & !(PAGE_SIZE - 1);
        let off = fb.addr - base;
        let pages = (off + fb_bytes).div_ceil(PAGE_SIZE);
        match MemoryPTR::new(base, pages) {
            Some(ptr) => {
                match server_gtcb.userspace_map().map_memory_region_flags(
                    frames,
                    ptr,
                    FB_VA_BASE,
                    MemoryFlags::empty(), // RW, user
                ) {
                    Ok(_) => {
                        let _ = aux.push(AuxEntry { tag: AT_NOMAD_FB_ADDR, val: (FB_VA_BASE + off) as u64 });
                        let _ = aux.push(AuxEntry { tag: AT_NOMAD_FB_PITCH, val: fb.pitch as u64 });
                        let _ = aux.push(AuxEntry { tag: AT_NOMAD_FB_WIDTH, val: fb.width as u64 });
                        let _ = aux.push(AuxEntry { tag: AT_NOMAD_FB_HEIGHT, val: fb.height as u64 });
                        let _ = aux.push(AuxEntry { tag: AT_NOMAD_FB_BPP, val: fb.bpp as u64 });
                    }
                    Err(e) => kernel_log!(
                        "exec: fb map не удался ({}x{}): {:?} — headless\n",
                        fb.width, fb.height, e
                    ),
                }
            }
            None => kernel_log!("exec: fb база {:#x} невыровнена — headless\n", fb.addr),
        }
    }
    // ACPI: физический адрес RSDP — отправная точка для XSDT→MCFG/DRHD.
    // Само монтирование — CAP_CREATE_MMIO по acpi-allow-list phys_guard
    // (диапазоны регистрируются портом на буте до этого места).
    if let Some(p) = rsdp_phys {
        let _ = aux.push(AuxEntry { tag: AT_NOMAD_ACPI_RSDP, val: p });
    }

    // Runtime-метаданные фазы 2 (entry + размеры).
    let code_size = info
        .segments
        .iter()
        .map(|s| s.mem_size)
        .max()
        .unwrap_or(0);

    let mut server_name = heapless::String::<48>::new();
    let _ = server_name.push_str(name);
    Ok(PendingServer {
        name: server_name,
        task_cap_id,
        ns_cap_id,
        entry: info.entry,
        code_size,
        aux,
    })
}

/// Устанавливает TaskImage-капабилити ВСЕХ зарегистрированных образов в
/// cspace init-сервера (слоты BOOT_SLOT_IMAGE_BASE + j) — authority для
/// сисколла TASK_CREATE. Вызывается на фазе 2 бут-спавна ТОЛЬКО для
/// модуля с basename == INIT_MODULE_NAME; у остальных boot-серверов и
/// всех динамических потомков кап на образы нет.
///
/// Ошибка отдельной капы (квота/slab/занятый слот) не фатальна: капа
/// откатывается, спавн этого образа из ring3 вернёт E_SLOT_EMPTY.
/// Вызывается под локами AccessManager -> TaskManager (фаза 2).
fn install_image_caps<A: ArchImplementation>(
    access: &mut kernel_base::access::AccessManager<A::Umap>,
    server_gtcb: &kernel_base::task::tcb::GTcb<A::Umap>,
    server_task_cap: u64,
) {
    for j in 0..crate::modules::module_count() {
        // Новый capability-объект на образ j.
        let cap_id = match access.create_new_object(
            kernel_base::access::capability::CapabilityObject::TaskImage { module_id: j as u32 },
        ) {
            Ok(id) => id,
            Err(e) => {
                kernel_log!(
                    "exec: TaskImage[{}] не создан: {:?} — образ недоступен для спавна\n",
                    j,
                    e
                );
                continue;
            }
        };
        let Some(zygote) = access.get_zygote(cap_id) else {
            let _ = access.destroy_object(cap_id);
            continue;
        };
        if let Err(e) = kernel_base::access::capspace::install_root_capability(
            server_gtcb,
            BOOT_SLOT_IMAGE_BASE + j as u64,
            zygote,
            kernel_base::access::capability::DirectCapabilityRights::all(),
            access.task_namespace(server_task_cap),
        ) {
            let _ = access.destroy_object(cap_id);
            kernel_log!(
                "exec: TaskImage[{}] не установлен в слот {}: {:?}\n",
                j,
                BOOT_SLOT_IMAGE_BASE + j as u64,
                e
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod test_alloc_fallback {
    extern crate std;
    use kernel_base::traits::memory::PAGE_SIZE;

    /// Странично выровненный leaks-нутый буфер (инвариант HHDM).
    pub fn page_aligned_leak(pages: usize) -> &'static mut [u8] {
        use std::alloc::{alloc_zeroed, Layout};
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).expect("layout");
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "oom in test alloc");
        unsafe { core::slice::from_raw_parts_mut(ptr, pages * PAGE_SIZE) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use kernel_base::traits::memory::set_hhdm_offset;
    use std::boxed::Box;
    use test_alloc_fallback::page_aligned_leak;

    struct TestFrames(AtomicUsize);

    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1000));

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

    #[test]
    fn vmap_region_drop_repro() {
        let _guard = crate::test_alloc_fallback::GLOBAL_TEST.lock();
        let mem = page_aligned_leak(16 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        kernel_base::traits::memory::set_mapped_phys_limit(16 * 1024 * 1024);
        kernel_base::traits::memory::init_hooks::init_allocator(frames());

        // Раскладка не трогает таблицы страниц — фейковая умапа.
        #[derive(Clone, Copy)]
        struct FakeUmap;
        impl MemoryInterfaceUserspace for FakeUmap {
            fn allocate_memory_region(
                &self,
                a: &dyn FrameAllocator,
                c: usize,
            ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
                a.allocate_pages(c)
                    .ok_or(kernel_base::traits::memory::ErrorCode::OutOfMemory)
            }
            fn deallocate_memory_region(
                &self,
                a: &dyn FrameAllocator,
                r: MemoryPTR,
                c: usize,
            ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
                a.deallocate_pages(r);
                let _ = c;
                Ok(())
            }
            fn map_memory_region(
                &self,
                _a: &dyn FrameAllocator,
                p: MemoryPTR,
                _v: usize,
            ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
                Ok(p)
            }
            fn unmap_memory_region(
                &self,
                _a: &dyn FrameAllocator,
                _p: MemoryPTR,
                _v: usize,
            ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
                Ok(())
            }
            fn translate(&self, _v: usize) -> Option<usize> {
                None
            }
        }
        let umap = FakeUmap;
        let vmap = VmapRegion::new(
            kernel_base::umap::DEFAULT_TASK_VMAP_BASE,
            kernel_base::umap::DEFAULT_TASK_VMAP_PAGES,
        )
        .expect("vmap");
        let handle = vmap
            .alloc(&umap, frames(), 2, MemoryFlags::empty())
            .expect("alloc");
        assert!(vmap.lookup(handle.virt_base()).is_some());
        // Drop vmap: RBSlabIO::drop корректно возвращает слоты slab
        // (drop_value_and_free_slot: ровно один drop_in_place + free_slot).
    }

    #[test]
    fn initial_stack_layout_matches_sysv() {
        let _guard = crate::test_alloc_fallback::GLOBAL_TEST.lock();
        let mem = page_aligned_leak(16 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        kernel_base::traits::memory::set_mapped_phys_limit(16 * 1024 * 1024);
        // Slab-аллокатор kernel_base (RBSlabIO внутри vmap) работает через
        // хуки, требующие init_allocator + HHDM.
        kernel_base::traits::memory::init_hooks::init_allocator(frames());

        // Раскладка стека не трогает таблицы страниц (только выделение VA
        // через vmap и запись через HHDM-зеркало физики) — root здесь не
        // участвует; X86Umap::from_existing(0) как маркер.
        // Раскладка не трогает таблицы страниц — фейковая умапа.
        #[derive(Clone, Copy)]
        struct FakeUmap;
        impl MemoryInterfaceUserspace for FakeUmap {
            fn allocate_memory_region(
                &self,
                a: &dyn FrameAllocator,
                c: usize,
            ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
                a.allocate_pages(c)
                    .ok_or(kernel_base::traits::memory::ErrorCode::OutOfMemory)
            }
            fn deallocate_memory_region(
                &self,
                a: &dyn FrameAllocator,
                r: MemoryPTR,
                c: usize,
            ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
                a.deallocate_pages(r);
                let _ = c;
                Ok(())
            }
            fn map_memory_region(
                &self,
                _a: &dyn FrameAllocator,
                p: MemoryPTR,
                _v: usize,
            ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
                // Раскладка-тест: реального маппинга нет, phys_base валиден.
                Ok(p)
            }
            fn unmap_memory_region(
                &self,
                _a: &dyn FrameAllocator,
                _p: MemoryPTR,
                _v: usize,
            ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
                Ok(())
            }
            fn translate(&self, _v: usize) -> Option<usize> {
                None
            }
        }
        let umap = FakeUmap;
        // Тест фокусируется на раскладке байт: VA/физика зеркальны через HHDM.
        let vmap = VmapRegion::new(kernel_base::umap::DEFAULT_TASK_VMAP_BASE, kernel_base::umap::DEFAULT_TASK_VMAP_PAGES)
            .expect("vmap");

        let argv = ["init", "--verbose"];
        let envp = ["PATH=/cintos"];
        let stack = build_initial_stack(
            &vmap,
            &umap,
            frames(),
            &TaskArgs { argv: &argv, envp: &envp },
            &[],
            0x401_000,
            0x2A,
            0x2B,
        )
        .expect("stack");

        let rsp = stack.stack_top;
        let read = |addr: usize| -> u64 {
            // SAFETY: адрес внутри выделенного стека (HHDM-зеркало).
            unsafe {
                core::ptr::read_volatile(
                    (phys_to_virt(phys_base_for(&vmap, &stack)) + (addr - va_base_for(&vmap, &stack)))
                        as *const u64,
                )
            }
        };

        // argc на RSP.
        assert_eq!(read(rsp), 2, "argc");
        // RSP выровнен на 16.
        assert_eq!(rsp % 16, 0, "RSP кратен 16");

        // argv-массив: два указателя + NULL.
        let a0 = read(rsp + 8) as usize;
        let a1 = read(rsp + 16) as usize;
        let a_null = read(rsp + 24);
        assert_eq!(a_null, 0, "argv NULL-терминатор");
        // Указатели ведут на строки с NUL.
        let s0 = {
            // SAFETY: строка внутри выделенного стека.
            unsafe {
                let p = (phys_to_virt(phys_base_for(&vmap, &stack)) + (a0 - va_base_for(&vmap, &stack)))
                    as *const u8;
                let mut end = 0usize;
                while *p.add(end) != 0 {
                    end += 1;
                }
                core::str::from_utf8(core::slice::from_raw_parts(p, end)).unwrap()
            }
        };
        assert_eq!(s0, "init");

        // envp-массив (NULL-терминированный): слоты rsp+32 (env ptr), rsp+40 (NULL).
        let e0 = read(rsp + 32) as usize;
        assert_ne!(e0, 0, "env ptr");
        assert_eq!(read(rsp + 40), 0, "env NULL-терминатор");
        // envp строка читается.
        let env0 = {
            // SAFETY: строка внутри выделенного стека.
            unsafe {
                let p = (phys_to_virt(phys_base_for(&vmap, &stack)) + (e0 - va_base_for(&vmap, &stack)))
                    as *const u8;
                let mut end = 0usize;
                while *p.add(end) != 0 {
                    end += 1;
                }
                core::str::from_utf8(core::slice::from_raw_parts(p, end)).unwrap()
            }
        };
        assert_eq!(env0, "PATH=/cintos");

        // auxv: пары сразу после envp-NULL — rsp+48.
        assert_eq!(read(rsp + 48), AT_PAGESZ, "первый тег auxv");
        assert_eq!(read(rsp + 56), 4096, "AT_PAGESZ value");
        assert_eq!(read(rsp + 64), AT_ENTRY, "второй тег");
        assert_eq!(read(rsp + 72), 0x401_000, "AT_ENTRY value");
        assert_eq!(read(rsp + 80), AT_NOMAD_SELF_CAP);
        assert_eq!(read(rsp + 88), 0x2A, "self cap");
        assert_eq!(read(rsp + 96), AT_NOMAD_NS_CAP);
        assert_eq!(read(rsp + 104), 0x2B, "ns cap");
        assert_eq!(read(rsp + 112), AT_NULL, "auxv завершён");
        let _ = a1;
    }

    fn phys_base_for(_v: &VmapRegion, _s: &StackSetup) -> usize {
        // Стек выделен через vmap.alloc поверх TestFrames; физика лежит в
        // последней аллокации. Читаем через lookup по handle.
        let entry = _v.lookup(_s.handle.virt_base()).expect("tracked");
        entry.phys_base
    }

    fn va_base_for(_v: &VmapRegion, _s: &StackSetup) -> usize {
        _s.handle.virt_base()
    }

    // ── Регрессия: разделяемые страницы PT_LOAD-сегментов ──────────────────
    //
    // Линкер кладёт .data вплотную к хвосту .rodata внутри одной страницы.
    // Старый load_image аллоцировал «свои» фреймы на каждый сегмент —
    // общий страница перемапливалась на нулевой фрейм, хвост первого
    // сегмента терялся (в QEMU это убивало init на jump-table scan_auxv).
    // Контракт: фрейм на страницу один, права — объединение прав
    // покрывающих сегментов, содержимое обоих сегментов сохранено.

    /// Мок-умапа, отслеживающая маппинги (VA-страница → физика + флаги)
    /// и честно отвечающая на translate.
    #[derive(Default)]
    struct SharedUmap {
        maps: std::sync::Mutex<std::vec::Vec<(usize, usize, MemoryFlags)>>,
    }

    impl MemoryInterfaceUserspace for SharedUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _c: usize,
        ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
            unreachable!("load_image аллоцирует через frames напрямую")
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _r: MemoryPTR,
            _c: usize,
        ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
            Ok(())
        }
        fn map_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            p: MemoryPTR,
            v: usize,
        ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
            self.map_memory_region_flags(_a, p, v, MemoryFlags::empty())
        }
        fn map_memory_region_flags(
            &self,
            _a: &dyn FrameAllocator,
            p: MemoryPTR,
            v: usize,
            flags: MemoryFlags,
        ) -> Result<MemoryPTR, kernel_base::traits::memory::ErrorCode> {
            assert_eq!(p.pages(), 1, "sweep мапит постранично");
            assert_eq!(v % PAGE_SIZE, 0, "VA выровнен");
            self.maps
                .lock()
                .unwrap()
                .push((v, p.phys_base(), flags));
            Ok(p)
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn FrameAllocator,
            _p: MemoryPTR,
            _v: usize,
        ) -> Result<(), kernel_base::traits::memory::ErrorCode> {
            Ok(())
        }
        fn translate(&self, v: usize) -> Option<usize> {
            let maps = self.maps.lock().unwrap();
            maps.iter()
                .find(|(va, _, _)| *va == v & !(PAGE_SIZE - 1))
                .map(|&(_, phys, _)| phys)
        }
    }

    /// Мини-сборщик NOMAD-ELF64: PT_LOAD-сегменты (vaddr, data, memsz, pflags).
    /// ВАЖНО: phdr-таблица — единый блок [64..64+56·n), данные — СЗАДИ
    /// неё (чередование phdr/данных затирает данные предыдущих сегментов
    /// при n>1 — ловушка, на которую наступил первый вариант билдера).
    fn mini_elf(segs: &[(usize, &[u8], usize, u32)]) -> std::vec::Vec<u8> {
        let phoff = 64;
        let mut buf = std::vec![0u8; phoff + segs.len() * 56];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // LSB
        buf[6] = 1; // EV_CURRENT
        buf[7] = crate::elf::CINTOS_OSABI;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        buf[18..20].copy_from_slice(&crate::elf::EM_X86_64.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // entry
        buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes()); // e_phoff
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
        for (i, &(vaddr, data, memsz, pflags)) in segs.iter().enumerate() {
            let off = phoff + i * 56;
            let file_off = buf.len() as u64; // данные — в конце образа
            buf[off..off + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            buf[off + 4..off + 8].copy_from_slice(&pflags.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&file_off.to_le_bytes());
            buf[off + 16..off + 24].copy_from_slice(&(vaddr as u64).to_le_bytes());
            buf[off + 32..off + 40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            buf[off + 40..off + 48].copy_from_slice(&(memsz as u64).to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn load_image_shared_page_keeps_both_segments() {
        let _guard = crate::test_alloc_fallback::GLOBAL_TEST.lock();
        let mem = page_aligned_leak(16 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        kernel_base::traits::memory::set_mapped_phys_limit(16 * 1024 * 1024);

        // Локальный bump-аллокатор (глобальный TestFrames расшарен между
        // тестами — счётчик может уйти за буфер).
        static LOCAL: AtomicUsize = AtomicUsize::new(0);
        struct LocalFrames;
        impl FrameAllocator for LocalFrames {
            fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
                let first = LOCAL.fetch_add(count, Ordering::SeqCst);
                MemoryPTR::new(first * PAGE_SIZE, count)
            }
            fn deallocate_pages(&self, _ptr: MemoryPTR) {}
        }

        let registry: &'static FormatRegistry = Box::leak(Box::new({
            let mut r = FormatRegistry::new();
            let f: &'static crate::elf::ElfFormat =
                Box::leak(Box::new(crate::elf::ElfFormat::new(crate::elf::EM_X86_64)));
            r.register(f);
            r
        }));

        // Сегмент A (R+X): 0x1000..0x1100 — только страница 0x1000.
        // Сегмент B (R+W): 0x1100..0x2300 (filesz 0x100 + BSS 0x1100) —
        // делит страницу 0x1000 с A и пересекает границу на страницу 0x2000.
        let a_data: &[u8] = &[0xCC; 0x100];
        let b_data: &[u8] = &[0xAB; 0x100];
        let image = mini_elf(&[
            (0x1000, a_data, 0x100, 0x5),  // PF_R|PF_X
            (0x1100, b_data, 0x1200, 0x6), // PF_R|PF_W, BSS 0x1100
        ]);

        let umap = SharedUmap::default();
        let info = load_image(&umap, &LocalFrames, &image, registry).expect("load");

        assert_eq!(info.segments.len(), 2);
        assert_eq!(info.segments[0].vaddr, 0x1000, "сегменты отсортированы");

        let maps = umap.maps.lock().unwrap();
        // Три страницы диапазона — 0x1000, 0x2000 — но 0x1000 ровно один раз.
        assert_eq!(maps.len(), 2, "страница 0x1000 НЕ перемапливается");
        let (va0, phys0, flags0) = maps[0];
        let (va1, phys1, flags1) = maps[1];
        assert_eq!(va0, 0x1000);
        assert_eq!(va1, 0x2000);

        // Права: страница 0x1000 покрыта A(RX) и B(RW) → записываема И
        // исполняема (объединение) → ни READ_ONLY, ни NO_EXECUTE.
        assert!(!flags0.contains(MemoryFlags::READ_ONLY), "0x1000: writable от B");
        assert!(!flags0.contains(MemoryFlags::NO_EXECUTE), "0x1000: exec от A");
        // Страница 0x2000 — только B (RW, не исп.) → NO_EXECUTE, не RO.
        assert!(!flags1.contains(MemoryFlags::READ_ONLY), "0x2000: writable");
        assert!(flags1.contains(MemoryFlags::NO_EXECUTE), "0x2000: NX от B");

        // Содержимое страницы 0x1000: хвост A (0x1000..0x1100) И начало B
        // (0x1100..0x1200) на ОДНОМ фрейме; BSS B (0x1200..0x1300) нули.
        let read = |off: usize| -> u8 {
            // SAFETY: страница загружена через HHDM-зеркало фрейма.
            unsafe { core::ptr::read_volatile((phys_to_virt(phys0) + off) as *const u8) }
        };
        assert_eq!(read(0x00), 0xCC, "байты сегмента A на общей странице");
        assert_eq!(read(0x0FF), 0xCC, "конец A");
        assert_eq!(read(0x100), 0xAB, "начало B на общей странице");
        assert_eq!(read(0x1FF), 0xAB, "конец file-части B");
        assert_eq!(read(0x200), 0, "BSS B обнулён");

        // Разные фреймы у разных страниц.
        assert_ne!(phys0, phys1, "страницы 0x1000 и 0x2000 — разные фреймы");
    }
}
