//! crt0: точка входа задачи NOMAD.
//!
//! Ядро при создании задачи строит стартовый стек (раскладка —
//! kernel_x86::exec::build_initial_stack) и ставит начальный RSP на
//! ячейку argc. `_start` сохраняет указатель стека, парсит
//! argc/argv/envp/auxv ([`parse_initial_stack`]), публикует их в
//! статике (доступ через [`args()`], [`envp()`], [`auxv_get()`] и
//! [`bootstrap()`]) и зовёт C-шиму `main(argc, argv)`, которую rustc
//! генерирует для бина БЕЗ `#![no_main]`; шима ведёт к [`lang_start`]
//! (`start` lang item) и пользовательскому `fn main()`. Возврат из
//! main = self-exit через SCHED_DESTROY_TASK со своим cap id.
//!
//! C-путь (staticlib): C-сервер определяет main(long argc, char** argv)
//! — та же 2-арговая сигнатура (include/nomad.h); envp не передаётся.
//!
//! Bootstrap-capability системного сервера (см. AT_NOMAD_* в abi::auxv):
//!   слот 0 cspace — TaskTCB самой задачи;
//!   слот 1 cspace — корневой неймспейс.
//! Значения (id) передаются в auxv и доступны через [`bootstrap()`].

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::abi;
use crate::handle::{CapId, TaskCap};
use crate::syscall;

/// Состояние, собранное `_start` (единственный раз до main).
struct RuntimeState {
    stack: AtomicPtr<u64>,
    envp: AtomicPtr<*const u8>,
    self_cap: AtomicU64,
    ns_cap: AtomicU64,
    page_size: AtomicU64,
    entry: AtomicU64,
    acpi_rsdp: AtomicU64,
}

static STATE: RuntimeState = RuntimeState {
    stack: AtomicPtr::new(core::ptr::null_mut()),
    envp: AtomicPtr::new(core::ptr::null_mut()),
    self_cap: AtomicU64::new(0),
    ns_cap: AtomicU64::new(0),
    page_size: AtomicU64::new(0),
    entry: AtomicU64::new(0),
    acpi_rsdp: AtomicU64::new(0),
};

/// Naked-точка входа: ELF e_entry указывает сюда. Начальный RSP ядра
/// уже указывает на argc; адрес передаём в RDI, затем выравниваем стек
/// для вызова Rust-функции. (В тестах на хосте не экспортируем:
/// std-харнесс несёт свой `_start`.)
///
/// # Safety
/// Вызывается только железом как e_entry образа; начальный RSP обязан
/// указывать на раскладку аргументов ядра (см. kernel_x86::exec).
#[cfg_attr(not(test), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    // naked_asm: options(noreturn) не нужен — naked всегда noreturn.
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym crt_entry,
    )
}

/// Разобранный начальный стек задачи (сырые указатели; валидны, пока
/// жив начальный стек — он ядром не переиспользуется).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialStack {
    pub argc: usize,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub auxv: *const u64,
}

/// Чистый разбор раскладки ядра:
/// `[argc][argv..NULL][envp..NULL][auxv-пары..AT_NULL]`.
/// Указатели — в начальный стек задачи; строки не материализуются.
/// Чистая функция — тестируется на хосте.
pub fn parse_initial_stack(stack: *mut u64) -> InitialStack {
    // SAFETY: раскладка гарантирована ядром (kernel_x86::exec);
    // argv/envp NUL-терминированы, auxv завершён AT_NULL.
    unsafe {
        let argc = *stack as usize;
        let mut p = stack.add(1);
        let argv = p as *const *const u8;
        while *p != 0 {
            p = p.add(1);
        }
        let envp = p.add(1) as *const *const u8;
        let mut q = envp as *const u64;
        while *q != 0 {
            q = q.add(1);
        }

        InitialStack {
            argc,
            argv,
            envp,
            auxv: q.add(1),
        }
    }
}

/// Rust-вход: разбор стека, публикация состояния, вызов main, self-exit.
unsafe extern "C" fn crt_entry(stack: *mut u64) -> ! {
    // ── Разбор стартового стека и публикация состояния ──
    let init = parse_initial_stack(stack);
    STATE.stack.store(stack, Ordering::Release);
    STATE.envp.store(init.envp.cast_mut(), Ordering::Release);
    let aux = unsafe { scan_auxv(init.auxv) };
    STATE.self_cap.store(aux.self_cap, Ordering::Release);
    STATE.ns_cap.store(aux.namespace_cap, Ordering::Release);
    STATE.page_size.store(aux.page_size, Ordering::Release);
    STATE.entry.store(aux.entry, Ordering::Release);
    STATE.acpi_rsdp.store(aux.acpi_rsdp, Ordering::Release);
    FB_STATE.addr.store(aux.fb_addr, Ordering::Release);
    FB_STATE.pitch.store(aux.fb_pitch, Ordering::Release);
    FB_STATE.width.store(aux.fb_width, Ordering::Release);
    FB_STATE.height.store(aux.fb_height, Ordering::Release);
    FB_STATE.bpp.store(aux.fb_bpp, Ordering::Release);

    // ── main(argc, argv) ──
    // Бин БЕЗ `#![no_main]`: rustc генерирует C-шиму main, которая
    // зовёт `start` lang item ([lang_start]) с пользовательским main
    // (Termination применён rustc). envp доступен через envp(),
    // auxv — через auxv_get(). C-серверы определяют main с той же
    // 2-арговой сигнатурой (include/nomad.h).
    unsafe extern "C" {
        fn main(argc: i32, argv: *const *const u8) -> i32;
    }
    let code = unsafe { main(init.argc as i32, init.argv) };
    exit(code);
}

/// no_std-замена `std::process::Termination` (в текущем nightly трейт
/// переехал в std — из core удалён, а `start` lang item требует его
/// как границу generic'а). Определяем `termination` lang item сами:
/// `report` возвращает ГОТОВЫЙ код выхода i32 (std-версия возвращает
/// ExitCode; ядро коды выхода пока игнорирует — см. exit).
/// Бины могут писать `fn main()`, `fn main() -> i32`, `-> u32`;
/// свои типы — имплементируйте этот трейт.
#[cfg(not(test))]
#[lang = "termination"]
pub trait Termination {
    fn report(self) -> i32;
}

#[cfg(not(test))]
impl Termination for () {
    fn report(self) -> i32 {
        0
    }
}

#[cfg(not(test))]
impl Termination for i32 {
    fn report(self) -> i32 {
        self
    }
}

#[cfg(not(test))]
impl Termination for u32 {
    fn report(self) -> i32 {
        self as i32
    }
}

/// `start` lang item: rustc для бина без `#![no_main]` генерирует
/// C-шиму main(argc, argv), вызывающую эту функцию с пользовательским
/// main. Требование компилятора (E0718): функция ОБЯЗАНА быть generic
/// с одним параметром, ограниченным `termination` lang item — по нему
/// rustc адаптирует сигнатуру main. Форма зеркалирует std::rt
/// (включая сигPIPE-заглушку: наш runtime ничего не делает с
/// сигналами). argc/argv уже опубликованы crt_entry в STATE — здесь
/// не нужны; код выхода — Termination::report.
///
/// cfg(not(test)): в хост-тестах `start`/`termination` несёт сам std —
/// второй lang item соборку не пропустит (паттерн паник-хендлера ниже).
#[cfg(not(test))]
#[lang = "start"]
fn lang_start<T: Termination + 'static>(
    main: fn() -> T,
    argc: isize,
    argv: *const *const u8,
    sigpipe: u8,
) -> isize {
    let _ = (argc, argv, sigpipe);
    exit(main().report())
}

/// Читает auxv-срез (пары tag/val до AT_NULL): возвращает
/// [`AuxValues`]. Неизвестные теги пропускаются. Чистая функция —
/// тестируется на хосте.
pub fn scan_auxv_slice(auxv: &[u64]) -> AuxValues {
    let mut out = AuxValues::default();
    let mut i = 0;
    while i + 1 < auxv.len() {
        let (tag, val) = (auxv[i], auxv[i + 1]);
        match tag {
            abi::auxv::AT_NULL => break,
            abi::auxv::AT_NOMAD_SELF_CAP => out.self_cap = val,
            abi::auxv::AT_NOMAD_NS_CAP => out.namespace_cap = val,
            abi::auxv::AT_PAGESZ => out.page_size = val,
            abi::auxv::AT_ENTRY => out.entry = val,
            abi::auxv::AT_NOMAD_FB_ADDR => out.fb_addr = val,
            abi::auxv::AT_NOMAD_FB_PITCH => out.fb_pitch = val,
            abi::auxv::AT_NOMAD_FB_WIDTH => out.fb_width = val,
            abi::auxv::AT_NOMAD_FB_HEIGHT => out.fb_height = val,
            abi::auxv::AT_NOMAD_FB_BPP => out.fb_bpp = val,
            abi::auxv::AT_NOMAD_ACPI_RSDP => out.acpi_rsdp = val,
            _ => {}
        }
        i += 2;
    }
    out
}

/// Значения auxv, интересные crt0.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AuxValues {
    pub self_cap: u64,
    pub namespace_cap: u64,
    pub page_size: u64,
    pub entry: u64,
    /// VA фреймбуфера в пространстве задачи (0 — не замаплен).
    pub fb_addr: u64,
    pub fb_pitch: u64,
    pub fb_width: u64,
    pub fb_height: u64,
    pub fb_bpp: u64,
    /// Физический адрес RSDP (0 — ACPI не передан ядром).
    pub acpi_rsdp: u64,
}

/// # Safety
/// `auxv` обязан указывать на валидный массив пар, завершённый AT_NULL.
unsafe fn scan_auxv(auxv: *const u64) -> AuxValues {
    // Безопасно читаем пары до AT_NULL: их число ограничено ядром,
    // AT_NULL гарантирован раскладкой.
    let mut out = AuxValues::default();
    let mut p = auxv;
    unsafe {
        loop {
            let (tag, val) = (*p, *p.add(1));
            match tag {
                abi::auxv::AT_NULL => break,
                abi::auxv::AT_NOMAD_SELF_CAP => out.self_cap = val,
                abi::auxv::AT_NOMAD_NS_CAP => out.namespace_cap = val,
                abi::auxv::AT_PAGESZ => out.page_size = val,
                abi::auxv::AT_ENTRY => out.entry = val,
                abi::auxv::AT_NOMAD_FB_ADDR => out.fb_addr = val,
                abi::auxv::AT_NOMAD_FB_PITCH => out.fb_pitch = val,
                abi::auxv::AT_NOMAD_FB_WIDTH => out.fb_width = val,
                abi::auxv::AT_NOMAD_FB_HEIGHT => out.fb_height = val,
                abi::auxv::AT_NOMAD_FB_BPP => out.fb_bpp = val,
                abi::auxv::AT_NOMAD_ACPI_RSDP => out.acpi_rsdp = val,
                _ => {}
            }
            p = p.add(2);
        }
    }
    out
}

/// Позиция стартового стека (ячейка argc). None до `_start`.
pub fn stack_base() -> Option<*const u64> {
    let p = STATE.stack.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(p) }
}

/// argc/argv текущей задачи (None — до `_start` либо argc == 0).
pub fn args() -> Option<usize> {
    let stack = stack_base()?;
    // SAFETY: раскладка стека гарантирована ядром.
    let argc = unsafe { *stack } as usize;
    Some(argc)
}

/// argv[i] — указатель на NUL-строку стартового стека (None — вне
/// диапазна/до `_start`).
pub fn argv_at(i: usize) -> Option<*const u8> {
    let stack = stack_base()?;
    // SAFETY: раскладка стека гарантирована ядром.
    let argc = unsafe { *stack } as usize;
    if i >= argc {
        return None;
    }
    // SAFETY: argv начинается на [stack+1]; слот валиден.
    Some(unsafe { *stack.add(1 + i) } as *const u8)
}

/// envp текущей задачи: массив указателей на NUL-строки, завершённый
/// NULL (None — до `_start`; пустое окружение — валидный ненулевой
/// указатель на NULL-слот). В main НЕ передаётся (шима rustc
/// 2-арговая) — берите отсюда.
pub fn envp() -> Option<*const *const u8> {
    let p = STATE.envp.load(Ordering::Acquire);
    if p.is_null() { None } else { Some(p) }
}

/// Значение auxv-тега (None — до `_start` либо тег отсутствует).
/// Прохо­дит по сырому массиву пар стартового стека заново —
/// избранные значения кэшируются STATE, но полный словарь не хранится
/// (стек задачи живёт дольше `_start`, повторный проход дёшев).
pub fn auxv_get(tag: u64) -> Option<u64> {
    let stack = stack_base()?;
    // SAFETY: раскладка стека гарантирована ядром.
    let argc = unsafe { *stack } as usize;
    // argv[0..argc], NULL, envp..., NULL, auxv пары...
    let mut p = unsafe { stack.add(1 + argc + 1) };
    // SAFETY: envp завершается NULL (контракт раскладки).
    unsafe {
        while *p != 0 {
            p = p.add(1);
        }
        p = p.add(1);
        loop {
            let (t, v) = (*p, *p.add(1));
            if t == abi::auxv::AT_NULL {
                return None;
            }
            if t == tag {
                return Some(v);
            }
            p = p.add(2);
        }
    }
}

/// Публикация FB-параметров из auxv (после `_start`).
static FB_STATE: FbAux = FbAux {
    addr: AtomicU64::new(0),
    pitch: AtomicU64::new(0),
    width: AtomicU64::new(0),
    height: AtomicU64::new(0),
    bpp: AtomicU64::new(0),
};

struct FbAux {
    addr: AtomicU64,
    pitch: AtomicU64,
    width: AtomicU64,
    height: AtomicU64,
    bpp: AtomicU64,
}

/// Bootstrap-данные системного сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrap {
    /// TaskTCB-капа этой задачи (self-exit).
    pub self_cap: TaskCap,
    /// Id корневой capability неймспейса.
    pub namespace_cap: CapId,
    /// Размер страницы ядра (auxv AT_PAGESZ).
    pub page_size: u64,
    /// Адрес входа (auxv AT_ENTRY).
    pub entry: u64,
}

/// Bootstrap-набор ядра (None — теги не переданы / не задача NOMAD).
pub fn bootstrap() -> Option<Bootstrap> {
    let self_cap = STATE.self_cap.load(Ordering::Acquire);
    if self_cap == 0 {
        return None;
    }
    Some(Bootstrap {
        self_cap: TaskCap::new(self_cap),
        namespace_cap: CapId::new(STATE.ns_cap.load(Ordering::Acquire)),
        page_size: STATE.page_size.load(Ordering::Acquire),
        entry: STATE.entry.load(Ordering::Acquire),
    })
}

/// Физический адрес RSDP из auxv (None — ACPI не передан ядром / до
/// `_start`). Init использует его как отправную точку: XSDT -> MCFG/DRHD
/// монтируются CAP_CREATE_MMIO по acpi-allow-list ядра (phys_guard).
pub fn acpi_rsdp_phys() -> Option<u64> {
    match STATE.acpi_rsdp.load(Ordering::Acquire) {
        0 => None,
        v => Some(v),
    }
}

/// Параметры фреймбуфера из auxv (None — FB не замаплен: fb_addr = 0).
/// Публикуется crt0::_start; ядро мапит образ MMIO по фиксированному VA
/// и передаёт параметры тегами AT_NOMAD_FB_* (см. kernel_exec::spawn).
pub fn fb_aux() -> Option<crate::fb::FbInfo> {
    let addr = FB_STATE.addr.load(Ordering::Acquire);
    if addr == 0 {
        return None;
    }
    Some(crate::fb::FbInfo {
        addr: addr as usize,
        pitch: FB_STATE.pitch.load(Ordering::Acquire) as usize,
        width: FB_STATE.width.load(Ordering::Acquire) as u32,
        height: FB_STATE.height.load(Ordering::Acquire) as u32,
        bpp: FB_STATE.bpp.load(Ordering::Acquire) as u8,
    })
}

/// Self-exit: уничтожение собственной задачи через SCHED_DESTROY_TASK со
/// своим cap id (после этого RAX неважен — задача не вернётся).
pub fn exit(code: i32) -> ! {
    let self_cap = STATE.self_cap.load(Ordering::Acquire);
    if self_cap != 0 {
        // Код возврата пока некуда класть (SCHED_DESTROY_TASK принимает
        // только cap id) — semantic TODO ядра; сам выход работает.
        let _ = code;
        unsafe {
            syscall::syscall1(abi::nr::SCHED_DESTROY_TASK, self_cap);
        }
    }
    // Без bootstrap-capability (kernel-отладка) — клин.
    loop {
        core::hint::spin_loop();
    }
}

/// Паник-хендлер userspace: аварийный self-exit. Бинарные обвязки НЕ
/// определяют свой panic handler — этот единственный в графе.
/// (В тестовом харнессе на хосте действует харнесс-обработчик.)
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    exit(0xDEAD_u32 as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::auxv;

    #[test]
    fn auxv_scan_finds_bootstrap_caps() {
        // Ядро кладёт: стандартные пары, кастомные теги, AT_NULL.
        let auxv_data = [
            auxv::AT_PAGESZ,
            4096,
            auxv::AT_ENTRY,
            0x401_000,
            auxv::AT_NOMAD_SELF_CAP,
            0x2A,
            auxv::AT_NOMAD_NS_CAP,
            0x2B,
            0xDEAD_BEEF, // неизвестный тег — пропускается
            1,
            auxv::AT_NULL,
            0,
        ];
        let aux = scan_auxv_slice(&auxv_data);
        assert_eq!(aux.self_cap, 0x2A);
        assert_eq!(aux.namespace_cap, 0x2B);
        assert_eq!(aux.page_size, 4096);
        assert_eq!(aux.entry, 0x401_000);
    }

    #[test]
    fn auxv_scan_handles_missing_tags() {
        // Только AT_NULL: все нули.
        let aux = scan_auxv_slice(&[auxv::AT_NULL, 0]);
        assert_eq!(aux, AuxValues::default());
        // Обрезанный срез (нет пары) — не паникуем, просто останавливаемся.
        let aux = scan_auxv_slice(&[auxv::AT_PAGESZ]);
        assert_eq!(aux, AuxValues::default());
    }

    #[test]
    fn bootstrap_gates_on_self_cap() {
        // bootstrap() в тестах на хосте: STATE пуст — None.
        assert!(bootstrap().is_none());
    }

    #[test]
    fn parse_initial_stack_layout() {
        // Имитация раскладки ядра: argc=2, два argv, NULL, envp из одной
        // строки, NULL, пара AT_PAGESZ, AT_NULL. «Указатели» на строки —
        // произвольные ненулевые u64 (парсер содержимое строк не читает).
        let mut buf: [u64; 10] = [0; 10];
        buf[0] = 2;
        buf[1] = 0x1000;
        buf[2] = 0x2000;
        // buf[3] — argv-NULL (0 из инициализации)
        buf[4] = 0x3000;
        // buf[5] — envp-NULL
        buf[6] = auxv::AT_PAGESZ;
        buf[7] = 4096;
        buf[8] = auxv::AT_NULL;
        let base = buf.as_mut_ptr();
        let init = parse_initial_stack(base);
        assert_eq!(init.argc, 2);
        // SAFETY: смещения в пределах buf (10 ячеек).
        let (argv, envp, auxvp) = unsafe { (base.add(1), base.add(4), base.add(6)) };
        assert_eq!(init.argv, argv as *const *const u8);
        assert_eq!(init.envp, envp as *const *const u8);
        assert_eq!(init.auxv, auxvp as *const u64);
        let aux = unsafe { scan_auxv(init.auxv) };
        assert_eq!(aux.page_size, 4096);
    }

    #[test]
    fn parse_initial_stack_empty_envp() {
        // argc=1, envp пуст (NULL сразу за argv-NULL), auxv с SELF_CAP.
        let buf: [u64; 8] = [
            1,      // argc
            0x1000, // argv[0]
            0,      // argv NULL
            0,      // envp NULL (пустое окружение)
            auxv::AT_NOMAD_SELF_CAP,
            0x2A,
            auxv::AT_NULL,
            0,
        ];
        let init = parse_initial_stack(buf.as_ptr() as *mut u64);
        assert_eq!(init.argc, 1);
        // SAFETY: envp указывает на NULL-слот массива buf.
        let empty = unsafe { (*init.envp).is_null() };
        assert!(empty);
        let aux = unsafe { scan_auxv(init.auxv) };
        assert_eq!(aux.self_cap, 0x2A);
    }
}
