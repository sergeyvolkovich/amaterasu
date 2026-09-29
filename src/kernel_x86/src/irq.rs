//! x86_64 контекст прерываний и page fault.
//!
//! Реализует `IRQArchDefinedContext` из kernel_base: переносимые
//! семантические интерфейсы (InterruptId, CpuContext, PageFaultFlags)
//! поверх x86-специфичных представлений (номер вектора u8, error code
//! page fault'а).

use kernel_base::traits::irq::{
    CpuContext, IRQArchDefinedContext, InterruptId, PageFaultFlags,
};

/// Номер вектора x86 (IRQ 0-255; 0-31 — исключения CPU).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86InterruptId(pub u8);

impl InterruptId for X86InterruptId {
    fn index(self) -> usize {
        self.0 as usize
    }
}

/// Минимальный снимок контекста CPU, достаточный для обработчиков
/// верхнего уровня. Полный interrupt frame (все регистры) появляется
/// вместе с IDT entry-стабами.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86CpuContext {
    pub instruction_pointer: usize,
    pub stack_pointer: usize,
}

impl CpuContext for X86CpuContext {
    fn stack_pointer(&self) -> usize {
        self.stack_pointer
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.stack_pointer = sp;
    }

    fn instruction_pointer(&self) -> usize {
        self.instruction_pointer
    }
}

/// Флаги ошибки page fault (raw error code page fault'а x86):
///   bit 0 — P (нарушение на present-странице),
///   bit 1 — W (запись),
///   bit 3 — RSVD (зарезервированный бит в PTE),
///   bit 4 — I/D (исполнение).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86PageFaultFlags(pub u64);

impl PageFaultFlags for X86PageFaultFlags {
    fn present(self) -> bool {
        self.0 & (1 << 0) != 0
    }

    fn write(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    fn user(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    fn fetch(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    fn reserved(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    fn raw(self) -> u64 {
        self.0
    }
}

/// Архитектурный контекст x86_64.
#[derive(Debug, Clone, Copy)]
pub struct X86IrqContext;

impl IRQArchDefinedContext for X86IrqContext {
    type InterruptId = X86InterruptId;
    type CpuContext = X86CpuContext;
    type PageFaultFlags = X86PageFaultFlags;
}

/// Разрешить маскируемые прерывания (STI).
pub fn irq_enable() {
    x86_64::instructions::interrupts::enable();
}

/// Запретить маскируемые прерывания (CLI).
pub fn irq_disable() {
    x86_64::instructions::interrupts::disable();
}

/// Прямо сейчас маскируемые прерывания разрешены?
pub fn irq_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

/// Хук для kernel_base::irqsafe: погасить прерывания, вернуть прежнее
/// состояние IF (вложенные секции корректно восстанавливают его).
pub fn irq_save_state() -> bool {
    let was = irq_enabled();
    x86_64::instructions::interrupts::disable();
    was
}

/// Хук для kernel_base::irqsafe: восстановить IF по сохранённому снимку.
pub fn irq_restore_state(was_enabled: bool) {
    if was_enabled {
        x86_64::instructions::interrupts::enable();
    }
}

// ─── Реестр обработчиков линий IRQ (векторы 32..95) ──────────────────────────
//
// ЗАКРЫТИЕ TODO(IDT): реестр и диспетчеризация. Векторы 32..95 (линии
// 0..63 — пространство irq_wait) получают индивидуальные entry-стабы
// (cswitch::load_idt) → irq_vector_dispatch → хук линии. Хук по
// умолчанию будит задачи, ожидающие линию через WaitIrq
// (kernel_base::task::irq_wait::on_irq_fired). Векторы 96..255 — тихий
// iretq (без источника прерываний система не должна на них падать).
//
// Трейт-мост ArchImplementation::register_irq_handle остаётся no-op:
// в дереве нет его вызывающих, а дженерик-эразура под произвольный
// IRQArchDefinedContext без alloc здесь — мёртвая сложность; конкретный
// реестр ниже — то, что реально использует порт.


use kernel_base::irqsafe::IrqSafeSpinMutex;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::ArchImplementation as _;

use crate::paging::X86Umap;

/// Хук линии IRQ: (номер линии 0..=63, per-core lctl). Вызывается из
/// IDT-диспетчера с отключёнными прерываниями — обязан быть коротким
/// и не паниковать.
pub type IrqLineHook = fn(line: u32, lctl: &mut LocalKernelCTL<X86Umap>);

/// Линии 0..63 (векторы 32..95) — пространство WaitIrq.
pub const IRQ_LINES: usize = 64;

static LINE_HOOKS: IrqSafeSpinMutex<[Option<IrqLineHook>; IRQ_LINES]> =
    IrqSafeSpinMutex::new([None; IRQ_LINES]);

/// Хук по умолчанию: разбудить ждущих линию (маска сработавших IRQ
/// дописывается реестром irq_wait в массивы задач).
fn default_line_hook(line: u32, lctl: &mut LocalKernelCTL<X86Umap>) {
    kernel_base::task::irq_wait::on_irq_fired(lctl, line);
}

/// Регистрирует хук линии (0..=63). Перозапись существующего — ОК
/// (политика «последний выиграл» для обновления обработчика).
pub fn register_irq_line_handler(line: u32, hook: IrqLineHook) -> Result<(), &'static str> {
    if line as usize >= IRQ_LINES {
        return Err("irq line out of range (0..=63)");
    }
    LINE_HOOKS.lock()[line as usize] = Some(hook);
    Ok(())
}

/// Точка входа IDT-диспетчеризации (cswitch): вектор 32..95 → линия.
/// Линии 0..15 (legacy PIC) подтверждаются specific-EOI ПОСЛЕ хука —
/// по контракту 8259A (ack до обработки дозволял бы вложенные IRQ
/// той же линии).
pub fn irq_vector_dispatch(vector: u8, lctl: &mut LocalKernelCTL<X86Umap>) {
    let line = (vector as u32).saturating_sub(32);
    if line as usize >= IRQ_LINES {
        return; // 96..255: тихо (стабы туда и не идут)
    }
    let hook = LINE_HOOKS.lock()[line as usize].unwrap_or(default_line_hook);
    hook(line, lctl);
    if line < 16 {
        crate::pic::send_eoi(line as u8);
    }
}

/// naked-мост из cswitch::irq_common: GS base уже ядерный (условный
/// swapgs выполнен стабом), номер вектора — в RDI. Берёт per-CPU lctl
/// через GS base и уходит в диспетчеризацию реестра линий.
pub(crate) unsafe extern "C" fn irq_vector_dispatch_erased(vector: u8) {
    // SAFETY: контракт irq_common — GS base ядерный на момент вызова.
    let lctl = crate::X86Backend::get_local_base();
    irq_vector_dispatch(vector, lctl);
}

// ─── Хук page fault (вектор 14) ──────────────────────────────────────────────
//
/// Обработчик #PF: (faulting-адрес, флаги ошибки, контекст). `true` —
/// фат устранён (iretq по кадру, исполнение продолжится на упавшей
/// инструкции), `false` — фатален (диагностика + halt, прежний путь).
pub type PfHook = fn(fault_addr: usize, flags: X86PageFaultFlags, ctx: &mut X86CpuContext) -> bool;

static PF_HOOK: IrqSafeSpinMutex<Option<PfHook>> = IrqSafeSpinMutex::new(None);

/// Регистрирует обработчик #PF (например, demand-paging ядра/задач).
pub fn register_pf_hook(hook: PfHook) {
    *PF_HOOK.lock() = Some(hook);
}

/// Вызывается idt_c_handler (cswitch) для вектора 14.
pub fn page_fault_dispatch(
    fault_addr: usize,
    err_code: u64,
    ctx: &mut X86CpuContext,
) -> bool {
    let hook = *PF_HOOK.lock();
    hook.is_some_and(|h| h(fault_addr, X86PageFaultFlags(err_code), ctx))
}
