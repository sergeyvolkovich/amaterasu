//! Фолт-доставка из пути исключений x86_64 (мост idt → ipc::fault).
//!
//! ОТВЕТСТВЕННОСТЬ СЛОЁВ:
//!   - cswitch::idt_common/idt_c_handler — механика кадра исключения
//!     (GPR + nr/err + аппаратный кадр), условный swapgs, вызов сюда;
//!   - ЭТОТ МОДУЛЬ — политика «доставляемости»: вектор ∈ множеству
//!     юзерспейс-доставимых, фолт из ring3, у задачи есть обработчик;
//!     затем — хук ДОСТАВКИ (ставит фронтенд: kernel_limine владеет
//!     KernelCTL) и уход в цикл планировщика с сохранённым кадром;
//!   - kernel_base::ipc::fault — реестры/сообщение/семантика reply.
//!
//! ХУК ДОСТАВКИ: kernel_x86 не имеет доступа к KernelCTL (его держит
//! фронтенд), а доставка требует умапа обработчика (permission_backend)
//! — тот же паттерн, что у SwitchHook (cswitch::set_switch_hook):
//! фронтенд регистрирует монорфизированную для X86Backend обёртку над
//! архитектурно-независимым ipc::fault::deliver_fault.
//!
//! ВОЗВРАЩЕНИЕ ИЗ ФОЛТА: кадр исключения содержит RCX/R11 (SysFrame
//! их НЕ хранит — SYSCALL ими портится), поэтому упавшая задача
//! сохраняет РАСШИРЕННЫЙ кадр (SYSFRAME_WORDS + 2 слова: RCX/R11 —
//! слова 18/19 слота возобновления) и возобновляется с их
//! восстановлением (cswitch::resume_from_frame). Повтор упавшей
//! инструкции обязан видеть ВСЕ регистры нетронутыми.

use core::arch::asm;

use kernel_base::ipc::fault::{self, FaultInfo};
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::ArchImplementation as _;

use crate::cswitch::{self, IntFrame};
use crate::paging::X86Umap;
use crate::X86Backend;

/// Векторы, доставляемые в юзерспейс (подмножество 0..31; остальное —
/// фатально для ядра: NMI/MC/DF и ошибки ядра ретранслировать нельзя).
pub const DELIVERABLE_VECTORS: [u64; 9] = [
    0,  // #DE
    3,  // #BP (int3)
    4,  // #OF
    6,  // #UD
    13, // #GP
    14, // #PF
    16, // #MF
    17, // #AC
    19, // #XF
];

/// Хук доставки фолта (фронтенд → kernel_base::ipc::fault::deliver_fault).
/// Возврат true — упавшая заблокирована на fault-объекте (вызвавший
/// сохраняет кадр и уходит в планировщик); false — обработчика нет/
/// ресурсы: фатальный путь.
pub type FaultDispatchHook =
    fn(lctl: &mut LocalKernelCTL<X86Umap>, faulting_task_cap: u64, info: &FaultInfo) -> bool;

static mut FAULT_DISPATCH_HOOK: Option<FaultDispatchHook> = None;

/// ХУБ УНИЧТОЖЕНИЯ ЗАДАЧИ (фронтенд → destroy_task_full): kill-пути
/// порта — ring3-фолт БЕЗ доставимого обработчика, возврат в ring3 с
/// неканоничным кадром. Политика: ФАТАЛЬНО для ядра только исключение
/// с CS&3==0; любой ring3-фолт убивает ВИНОВНУЮ задачу, система
/// продолжает планирование (иначе ud2/NULL-разыменование/неканоничный
/// RSP без keeper'а навсегда останавливают CPU — полный DoS одним
/// ring3-потоком).
pub type TaskKillHook = fn(lctl: &mut LocalKernelCTL<X86Umap>, task_cap_id: u64);

static mut TASK_KILL_HOOK: Option<TaskKillHook> = None;

/// Регистрирует kill-хук (фронтенд — вместе с set_dispatch_hook).
pub fn set_task_kill_hook(hook: TaskKillHook) {
    // Rust-2024: static mut — только сырые указатели.
    let slot: *mut Option<TaskKillHook> = core::ptr::addr_of_mut!(TASK_KILL_HOOK);
    unsafe { slot.write(Some(hook)) };
}

fn task_kill_hook() -> Option<TaskKillHook> {
    let slot: *const Option<TaskKillHook> = core::ptr::addr_of!(TASK_KILL_HOOK);
    unsafe { slot.read() }
}

/// Убивает ТЕКУЩУЮ задачу (kill-хук) и уходит в цикл планировщика.
/// Вызывать из контекста исключения/сисколла с ядерным GS активным и
/// БЕЗ удержанных локов. Хук не установлен (ранний бут) — ничего не
/// делает (вызывающий продолжает фатальный путь).
///
/// # Safety
/// Контракт вызова user_fault_entry: исключение, IF=0, ядерный GS,
/// валидный кадр; уничтожаемая задача — текущая (lctl).
pub(crate) unsafe fn kill_current_and_schedule() -> ! {
    let lctl = X86Backend::get_local_base();
    if let Some(current) = lctl.current_task_cap_id() {
        kernel_base::kernel_log!(
            "kill: task {} уничтожена (ring3 fault / bad frame)\n",
            current
        );
        if let Some(hook) = task_kill_hook() {
            hook(lctl, current);
        }
    }
    // SAFETY: контракт модуля cswitch — ядерный GS активен, локов нет.
    unsafe { cswitch::return_to_scheduler() }
}

/// Регистрирует хук доставки (фронтенд — до первого входа в задачу).
pub fn set_dispatch_hook(hook: FaultDispatchHook) {
    // Rust-2024: static mut — только сырые указатели.
    let slot: *mut Option<FaultDispatchHook> = core::ptr::addr_of_mut!(FAULT_DISPATCH_HOOK);
    unsafe { slot.write(Some(hook)) };
}

fn dispatch_hook() -> Option<FaultDispatchHook> {
    let slot: *const Option<FaultDispatchHook> = core::ptr::addr_of!(FAULT_DISPATCH_HOOK);
    unsafe { slot.read() }
}

/// Точка входа доставки фолта из idt_c_handler (вектор НЕ устранён
/// зарегистрированным #PF-хуком). Возврат false — фолт не доставлен:
/// вызывающий продолжает фатальным путём (дамп + halt).
///
/// При успехе НЕ ВОЗВРАЩАЕТСЯ: сохраняет расширенный кадр упавшей в её
/// TCB (слот возобновления), блокирует её на fault-объекте (это делает
/// хук доставки) и уходит в цикл планировщика (return_to_scheduler:
/// CR3 ← ядерный корень, стек → планировщика). Возобновит упавшую
/// FAULT_REPLY через enter_task → resume_user.
///
/// # Safety (контракт вызова)
/// Вызывается только из idt_c_handler (исключение, IF=0, ядерный GS
/// уже активен условным swapgs стаба, кадр — валидный &mut IntFrame).
#[unsafe(no_mangle)]
pub(crate) unsafe fn user_fault_entry(frame: &IntFrame) -> bool {
    // Только фолты ring3: исключения ядра (CS&3==0) — фатальны всегда.
    if frame.cs & 3 != 3 {
        return false;
    }
    if !DELIVERABLE_VECTORS.contains(&frame.nr) {
        return false;
    }

    // SAFETY: контракт вызова — GS base установлен (ядро владеет
    // per-CPU областью с бута/AP-пути).
    let lctl = X86Backend::get_local_base();
    let Some(current) = lctl.current_task_cap_id() else {
        return false; // фолт без текущей задачи (не бывает из ring3)
    };

    // Биндинг есть? (листовой лок реестра; None — фатальный путь)
    if fault::fault_handler_of(current).is_none() {
        return false;
    }

    // CR2 — только для #PF (адрес фолта); для остальных — 0.
    let cr2: u64 = {
        let v;
        unsafe { asm!("mov {}, cr2", out(reg) v) };
        v
    };
    let info = FaultInfo {
        kind: frame.nr,
        addr: if frame.nr == 14 { cr2 } else { 0 },
        ip: frame.rip,
        sp: frame.rsp,
        err: frame.err,
    };

    let Some(hook) = dispatch_hook() else {
        return false; // фронтенд не провёл хук — фолты не поддержаны
    };
    if !hook(lctl, current, &info) {
        return false; // обработчик мёртв / реестры переполнены — фатально
    }

    // Доставка состоялась, упавшая блокирована на fault-объекте.
    // Сохраняем её РАСШИРЕННЫЙ кадр (SysFrame + RCX/R11 — повтор
    // упавшей инструкции обязан видеть все регистры) и FPU/SSE
    // (fxsave стаба idt_common в скретче — переживёт переключение),
    // уходим в цикл планировщика: возобновит её FAULT_REPLY
    // (enter_task → resume_user — fxrstor из TCB).
    if let Some(tcb) = lctl.get_current_task() {
        tcb.save_resume(&fault_frame_words(frame));
        cswitch::stash_fpu_to_tcb(lctl);
    }
    // SAFETY: контракт модуля cswitch — ядерный GS активен, локов не
    // держим (доставка завершилась), исключительный стек отбрасывается.
    unsafe { cswitch::return_to_scheduler() }
}

/// Расширенный кадр возобновления упавшей: слова 0..SYSFRAME_WORDS —
/// раскладка SysFrame (конвертация из IntFrame: порядок GPR у них
/// РАЗНЫЙ — IntFrame хранит rcx/r11, SysFrame нет), слова 18/19 —
/// RCX/R11 (см. cswitch::SYSFRAME_RCX_WORD/R11_WORD).
fn fault_frame_words(frame: &IntFrame) -> [u64; kernel_base::task::tcb::RESUME_WORDS] {
    let mut w = [0u64; kernel_base::task::tcb::RESUME_WORDS];
    w[0] = frame.rdi; // +0
    w[1] = frame.rsi; // +8
    w[2] = frame.rdx; // +16
    w[3] = frame.rax; // +24
    w[4] = frame.rbx; // +32
    w[5] = frame.rbp; // +40
    w[6] = frame.r8; // +48
    w[7] = frame.r9; // +56
    w[8] = frame.r10; // +64
    w[9] = frame.r12; // +72
    w[10] = frame.r13; // +80
    w[11] = frame.r14; // +88
    w[12] = frame.r15; // +96
    w[13] = frame.rip; // +104
    w[14] = frame.cs; // +112
    w[15] = frame.rflags; // +120
    w[16] = frame.rsp; // +128
    w[17] = frame.ss; // +136
    w[18] = frame.rcx; // +144: расширение фолта (SysFrame не хранит)
    w[19] = frame.r11; // +152: расширение фолта
    w
}
