//! crt0: точка входа задачи NOMAD.
//!
//! Ядро при создании задачи строит стартовый стек (раскладка —
//! kernel_x86::exec::build_initial_stack) и ставит начальный RSP на
//! ячейку argc. `_start` сохраняет указатель стека, парсит
//! argc/argv/envp/auxv, публикует их в статике (доступ через [`args()`]
//! и [`bootstrap()`]) и вызывает `main(argc, argv, envp)` бинаря.
//! Возврат из main = self-exit через SCHED_DESTROY_TASK со своим cap id.
//!
//! Bootstrap-capability системного сервера (см. AT_CINTOS_* в abi::auxv):
//!   слот 0 cspace — TaskTCB самой задачи;
//!   слот 1 cspace — корневой неймспейс.
//! Значения (id) передаются в auxv и доступны через [`bootstrap()`].

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::abi;
use crate::syscall;

/// Состояние, собранное `_start` (единственный раз до main).
struct RuntimeState {
    stack: AtomicPtr<u64>,
    self_cap: AtomicU64,
    ns_cap: AtomicU64,
    page_size: AtomicU64,
    entry: AtomicU64,
    acpi_rsdp: AtomicU64,
}

static STATE: RuntimeState = RuntimeState {
    stack: AtomicPtr::new(core::ptr::null_mut()),
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

/// Rust-вход: разбор стека, публикация состояния, вызов main, self-exit.
unsafe extern "C" fn crt_entry(stack: *mut u64) -> ! {
    // ── Разбор стартового стека ──
    // [argc][argv0..argvN][NULL][envp0..envpM][NULL][auxv pairs...]
    let argc = unsafe { *stack } as usize;

    // auxv: после envp NULL. Ищем с конца массивов: envp-NULL идёт за
    // argv-NULL; позиции вычисляем проходом.
    let mut p = unsafe { stack.add(1) };
    let argv: *const *const u8 = p.cast();
    // SAFETY: ядро гарантированно NUL-терминирует массив.
    unsafe {
        while *p != 0 {
            p = p.add(1);
        }
    }
    let envp: *const *const u8 = unsafe { p.add(1).cast() };
    let auxv: *const u64 = {
        let mut q: *const u64 = envp.cast();
        // SAFETY: envp-массив NUL-терминирован ядром.
        unsafe {
            while *q != 0 {
                q = q.add(1);
            }
            q.add(1)
        }
    };

    // Публикация состояния.
    STATE.stack.store(stack, Ordering::Release);
    let aux = unsafe { scan_auxv(auxv) };
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

    // ── main(argc, argv, envp) ──
    unsafe extern "C" {
        // Бинарная обвязка обязана определить: main(argc, argv, envp) -> i32.
        fn main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> i32;
    }
    let code = unsafe { main(argc, argv, envp) };
    exit(code);
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
            abi::auxv::AT_CINTOS_SELF_CAP => out.self_cap = val,
            abi::auxv::AT_CINTOS_NS_CAP => out.namespace_cap = val,
            abi::auxv::AT_PAGESZ => out.page_size = val,
            abi::auxv::AT_ENTRY => out.entry = val,
            abi::auxv::AT_CINTOS_FB_ADDR => out.fb_addr = val,
            abi::auxv::AT_CINTOS_FB_PITCH => out.fb_pitch = val,
            abi::auxv::AT_CINTOS_FB_WIDTH => out.fb_width = val,
            abi::auxv::AT_CINTOS_FB_HEIGHT => out.fb_height = val,
            abi::auxv::AT_CINTOS_FB_BPP => out.fb_bpp = val,
            abi::auxv::AT_CINTOS_ACPI_RSDP => out.acpi_rsdp = val,
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
                abi::auxv::AT_CINTOS_SELF_CAP => out.self_cap = val,
                abi::auxv::AT_CINTOS_NS_CAP => out.namespace_cap = val,
                abi::auxv::AT_PAGESZ => out.page_size = val,
                abi::auxv::AT_ENTRY => out.entry = val,
                abi::auxv::AT_CINTOS_FB_ADDR => out.fb_addr = val,
                abi::auxv::AT_CINTOS_FB_PITCH => out.fb_pitch = val,
                abi::auxv::AT_CINTOS_FB_WIDTH => out.fb_width = val,
                abi::auxv::AT_CINTOS_FB_HEIGHT => out.fb_height = val,
                abi::auxv::AT_CINTOS_FB_BPP => out.fb_bpp = val,
                abi::auxv::AT_CINTOS_ACPI_RSDP => out.acpi_rsdp = val,
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
    if p.is_null() {
        None
    } else {
        Some(p)
    }
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
    /// id TaskTCB-капабилити этой задачи (self-exit).
    pub self_cap: u64,
    /// id корневой capability неймспейса.
    pub namespace_cap: u64,
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
        self_cap,
        namespace_cap: STATE.ns_cap.load(Ordering::Acquire),
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
/// и передаёт параметры тегами AT_CINTOS_FB_* (см. kernel_exec::spawn).
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
            auxv::AT_CINTOS_SELF_CAP,
            0x2A,
            auxv::AT_CINTOS_NS_CAP,
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
}
