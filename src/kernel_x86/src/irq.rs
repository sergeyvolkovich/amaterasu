//! x86_64 контекст прерываний, чип прерываний и диспетчеризация (v2).
//!
//! РЕАЛИЗУЕТ переносимый контракт kernel_base::traits::irq::IrqChip:
//!   - ЛОГИЧЕСКИЕ линии u32: проводные = GSI из MADT (0..Σentries по
//!     всем IO-APIC), message-backed (MSI) = выделенный диапазон
//!     [msi_line_base, msi_line_base + pool);
//!   - векторы IDT — собственность порта: GSI g → 32+g; MSI i →
//!     MSI_VECTOR_BASE + i; вектор 255 — спурьё LAPIC (молчит);
//!   - EOI: LAPIC (xAPIC/x2APIC) для всей доставки IO-APIC/MSI;
//!     legacy-PIC fallback, если MADT без IO-APIC.
//!
//! ABI-инвариант диспетчера: стаб IDT получает в RDI вектор и в RSI
//! указатель на кадр IRQ → irq_vector_dispatch → линия → хуки порта →
//! пробуждение ждущих (kernel_base::task::irq_wait) → EOI → хвост
//! преемпции: если тик таймера в этом же прерывании выбрал другую
//! задачу, а прерван был ring3 — кадр уходит в TCB, управление —
//! следующей задаче (cswitch::irq_preempt_tail). Обработчики НЕ
//! регистрируются per-line в этом файле для юзерспейс-линий: единственный
//! механизм доставки задачам — cap-нотификации irq_wait; хуки здесь —
//! для ВНУТРЕННИХ потребителей ядра (таймер).

use kernel_base::irqsafe::IrqSafeSpinMutex;
use kernel_base::traits::ArchImplementation as _;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::irq::{
    IrqChip, IrqHwError, MsiMessage, TriggerMode,
};

use crate::paging::X86Umap;

// ─── Контекст (без изменений v1) ─────────────────────────────────────────────

/// Номер вектора x86 (IRQ 0-255; 0-31 — исключения CPU).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86InterruptId(pub u8);

impl kernel_base::traits::irq::InterruptId for X86InterruptId {
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

impl kernel_base::traits::irq::CpuContext for X86CpuContext {
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

impl kernel_base::traits::irq::PageFaultFlags for X86PageFaultFlags {
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

impl kernel_base::traits::irq::IRQArchDefinedContext for X86IrqContext {
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

// ─── Чип прерываний (IrqChip) ────────────────────────────────────────────────

/// Ёмкость MSI-пространства (линий). Ограничена векторами: wired-векторы
/// 32..32+wired, MSI — от базиса до 254 (255 — спурьё).
pub const MSI_POOL_MAX: u32 = 64;

/// Реализация IrqChip поверх IO-APIC + LAPIC (+ MSI-сообщения LAPIC).
pub struct X86IrqChip {
    /// Число проводных линий (снимок ioapic::wired_line_count при init;
    /// снимок, а не глобальный запрос — диспетчер не читает пул).
    wired: u32,
    /// Начало MSI-пространства линий (= числу проводных линий).
    msi_line_base: u32,
    /// Реальная ёмкость MSI (≤ MSI_POOL_MAX; 0 — fallback без IO-APIC).
    msi_capacity: u32,
    /// Вектор MSI-линии i (базис, выровнен на 16).
    msi_vector_base: u32,
    /// Legacy-режим: IO-APIC не найден — PIC на 16 линиях, MSI нет.
    legacy: bool,
}

impl X86IrqChip {
    /// MSI-линия → вектор доставки.
    pub fn msi_vector(&self, line: u32) -> Option<u8> {
        if self.msi_capacity == 0 {
            return None;
        }
        let i = line.checked_sub(self.msi_line_base)?;
        if i >= self.msi_capacity {
            return None;
        }
        Some((self.msi_vector_base + i) as u8)
    }

    /// Legacy-режим (PIC fallback без IO-APIC)?
    pub fn legacy(&self) -> bool {
        self.legacy
    }
}

impl IrqChip for X86IrqChip {
    fn wired_line_count(&self) -> u32 {
        self.wired
    }

    fn msi_line_base(&self) -> u32 {
        self.msi_line_base
    }

    fn msi_capacity(&self) -> u32 {
        self.msi_capacity
    }

    fn trigger_mode(&self, line: u32) -> TriggerMode {
        // Программная истина — RTE-бит уровня; для MSI всегда edge.
        if self.legacy || line >= self.msi_line_base {
            return TriggerMode::Edge;
        }
        match crate::ioapic::controller_of(line).and_then(|c| c.rte_bits(line)) {
            Some(bits) if bits & (1 << 15) != 0 => TriggerMode::Level,
            _ => TriggerMode::Edge,
        }
    }

    fn set_trigger(&self, line: u32, mode: TriggerMode) -> Result<(), IrqHwError> {
        if self.legacy {
            // PIC: режим фиксирован железом (edge), программировать нечем.
            return Ok(());
        }
        if line >= self.msi_line_base {
            return Ok(()); // MSI всегда edge
        }
        // Пере-программирование RTE с сохранением вектора/дестинейшена:
        // полярность — active-high (ISA-конвенция), маска сохраняется.
        let Some(apic) = crate::ioapic::controller_of(line) else {
            return Err(IrqHwError::OutOfRange);
        };
        let prev = apic.rte_bits(line).ok_or(IrqHwError::OutOfRange)?;
        crate::ioapic::program_route(
            line,
            false,
            mode == TriggerMode::Level,
            prev & (1 << 16) != 0,
        );
        Ok(())
    }

    fn mask(&self, line: u32) -> Result<(), IrqHwError> {
        if self.legacy {
            crate::pic::mask(line as u8);
            return Ok(());
        }
        if line >= self.msi_line_base {
            // MSI: per-векторного маскирования у LAPIC нет; доставка
            // вектора без ждущих безопасно роняется диспетчером.
            return Ok(());
        }
        crate::ioapic::mask_gsi(line);
        Ok(())
    }

    fn unmask(&self, line: u32) -> Result<(), IrqHwError> {
        if self.legacy {
            crate::pic::unmask(line as u8);
            return Ok(());
        }
        if line >= self.msi_line_base {
            return Ok(());
        }
        crate::ioapic::unmask_gsi(line);
        Ok(())
    }

    fn msi_message(&self, line: u32) -> Result<MsiMessage, IrqHwError> {
        let vector = self.msi_vector(line).ok_or(IrqHwError::OutOfRange)?;
        // Bare MSI (без Interrupt Remapping): address = 0xFEE00000 |
        // (dest_apic << 12) — physical destination mode, redirect off;
        // data = вектор, edge, assert.
        let dest = crate::apic::bsp_lapic_id() & 0xFF;
        Ok(MsiMessage {
            address: 0xFEE0_0000u64 | ((dest as u64) << 12),
            data: vector as u32,
        })
    }
}

// ─── Инициализация из boot-таблиц ────────────────────────────────────────────

static CHIP: spin::Once<X86IrqChip> = spin::Once::new();
/// Разобранный MADT (для override-запросов: ISA-линия таймера и т.п.).
static MADT: spin::Once<crate::boot::madt::MadtIrq> = spin::Once::new();

/// Override ISA→GSI из MADT (None — конформинг: GSI = линия, edge/high).
pub fn isa_override(isa: u8) -> Option<crate::boot::madt::IsoEntry> {
    MADT.get().and_then(|m| m.isa_override(isa))
}

/// Чип платформы (None — init_from_boot ещё не звался).
pub fn chip() -> Option<&'static X86IrqChip> {
    CHIP.get()
}

/// Инициализация IRQ-подсистемы x86 из ACPI: MADT → IO-APIC-пул,
/// LAPIC (включение + глушение LVT), колбэк маскирования для
/// kernel_base (teardown), переносимая капа чипа. Повторный вызов —
/// no-op (Once).
///
/// # Safety
/// Адреса в `BootBackend` обязаны указывать на замапленную HHDM память
/// с валидными ACPI-таблицами (контракт BootInfo / boot::BootBackend).
pub unsafe fn init_from_boot(boot: &crate::boot::BootBackend) -> bool {
    CHIP.call_once(|| {
        let madt = boot
            .find_table(b"APIC")
            .and_then(crate::boot::madt::parse);
        MADT.call_once(|| madt.unwrap_or_else(crate::boot::madt::MadtIrq::empty));

        // LAPIC: без него нет ни EOI, ни MSI — без него только legacy-PIC.
        let lapic_ok = crate::apic::init();

        match (madt, lapic_ok) {
            (Some(m), true) => {
                // SAFETY: phys IO-APIC из MADT — замапленные HHDM окна.
                let pool = unsafe {
                    crate::ioapic::init_from_madt(
                        m.ioapics.iter().flatten().map(|d| (d.phys, d.gsi_base)),
                    )
                };
                if pool.is_some() {
                    let wired = crate::ioapic::wired_line_count();
                    // Векторы MSI: базис = align16(32 + wired), пул ограничен
                    // 254 (спурьё 255 не входит в доставку).
                    let vec_base = (32 + wired).div_ceil(16) * 16;
                    let pool_capacity = MSI_POOL_MAX.min(255u32.saturating_sub(vec_base));
                    // Колбэк маскирования teardown'а (kernel_base).
                    kernel_base::irq::set_mask_callback(mask_line_for_teardown);
                    return X86IrqChip {
                        wired,
                        msi_line_base: wired,
                        msi_capacity: pool_capacity,
                        msi_vector_base: vec_base,
                        legacy: false,
                    };
                }
                // IO-APIC не встал — PIC fallback.
                X86IrqChip {
                    wired: 16,
                    msi_line_base: 16,
                    msi_capacity: 0,
                    msi_vector_base: 0,
                    legacy: true,
                }
            }
            _ => X86IrqChip {
                wired: 16,
                msi_line_base: 16,
                msi_capacity: 0,
                msi_vector_base: 0,
                legacy: true,
            },
        }
    });
    CHIP.get().is_some()
}

/// Колбэк маскирования для teardown'а kernel_base (fn(u32) — без типов
/// порта): проводные линии маскируются в IO-APIC/PIC, MSI — no-op.
fn mask_line_for_teardown(line: u32) {
    if let Some(chip) = chip() {
        let _ = chip.mask(line);
    }
}

// ─── Хуки внутренних потребителей (таймер и т.п.) ────────────────────────────

/// Хук линии ядра: (номер линии, per-core lctl, прерван ли ring3).
/// Вызывается из IDT-диспетчера с отключёнными прерываниями — обязан
/// быть коротким. Флаг from_user — решение о контексте прерывания: тик
/// таймера крутит карусель планировщика ТОЛЬКО когда заставший контекст
/// — ring3 (ротация на ядерном контексте разъехалась бы с семантикой
/// «текущей» середи́ны сисколла).
pub type IrqLineHook = fn(line: u32, lctl: &mut LocalKernelCTL<X86Umap>, from_user: bool);

/// Реестр хуков ПОРТА (внутренние потребители, не юзерспейс-линии).
/// Фиксированный массив — потребители ядра перечислимы (сегодня: таймер);
/// юзерспейс-линии идут через irq_wait, им хуки не нужны.
const MAX_LINE_HOOKS: usize = 8;
static LINE_HOOKS: IrqSafeSpinMutex<[(u32, Option<IrqLineHook>); MAX_LINE_HOOKS]> =
    IrqSafeSpinMutex::new([(u32::MAX, None); MAX_LINE_HOOKS]);

/// Регистрирует хук линии (перезапись существующего — «последний выиграл»).
pub fn register_line_hook(line: u32, hook: IrqLineHook) -> Result<(), &'static str> {
    let mut hooks = LINE_HOOKS.lock();
    if let Some(slot) = hooks.iter_mut().find(|(l, _)| *l == line) {
        slot.1 = Some(hook);
        return Ok(());
    }
    let slot = hooks
        .iter_mut()
        .find(|(_, h)| h.is_none())
        .ok_or("line hooks exhausted")?;
    *slot = (line, Some(hook));
    Ok(())
}

// ─── Диспетчеризация ─────────────────────────────────────────────────────────

/// Точка входа IDT-диспетчеризации (cswitch::irq_common; прерывания
/// выключены, GS base ядерный): вектор → линия → хуки → ждущие → EOI.
/// `from_user` — прерван ring3 (по CS кадра): единственный контекст,
/// где тик таймера имеет право крутить карусель планировщика.
pub fn irq_vector_dispatch(
    vector: u8,
    lctl: &mut LocalKernelCTL<X86Umap>,
    from_user: bool,
) {
    // Спурьё LAPIC: EOI не нужен, линия не назначена.
    if vector == crate::apic::SPURIOUS_VECTOR {
        return;
    }
    let v = vector as u32;

    // Вектор → линия: legacy-PIC (32..47 → 0..15), IO-APIC (32+wired),
    // MSI (msi_vector_base..). Чип может быть ещё не поднят (ранний IRQ
    // до init_from_boot / платформа без ACPI) — тогда PIC-семантика.
    enum Eoi {
        Pic,
        Lapic,
    }

    let (line, eoi): (u32, Eoi) = match chip() {
        None => {
            if (32..48).contains(&v) {
                (v - 32, Eoi::Pic)
            } else {
                return;
            }
        }
        Some(c) if c.legacy() => {
            if (32..48).contains(&v) {
                (v - 32, Eoi::Pic)
            } else {
                return;
            }
        }
        Some(c) => {
            if v < 32 {
                return;
            } else if v < 32 + c.wired_line_count() {
                (v - 32, Eoi::Lapic)
            } else if v >= c.msi_vector_base && v < c.msi_vector_base + c.msi_capacity {
                (c.msi_line_base + (v - c.msi_vector_base), Eoi::Lapic)
            } else {
                return; // немаршрутизируемый вектор (спурьё IO-APIC и т.п.)
            }
        }
    };

    // Хуки внутренних потребителей (таймер: учёт кванта + дедлайны +
    // карусель планировщика на ring3-тиках).
    {
        let hooks = LINE_HOOKS.lock();
        for (l, h) in hooks.iter() {
            if *l == line {
                if let Some(hook) = h {
                    hook(line, lctl, from_user);
                }
            }
        }
    }

    // Пробуждение ждущих юзерспейс-задач (cap-нотификации irq_wait).
    kernel_base::task::irq_wait::on_irq_fired(lctl, line);

    // EOI ПОСЛЕ обработки (контракт «ack после хендлера»; для level-линий
    // запись LAPIC EOI снимает remote IRR в RTE).
    match eoi {
        Eoi::Pic => {
            if line < 16 {
                crate::pic::send_eoi(line as u8);
            }
        }
        Eoi::Lapic => crate::apic::eoi(),
    }
}

/// naked-мост из cswitch::irq_common: GS base уже ядерный (условный
/// swapgs выполнен стабом), номер вектора — в RDI, кадр IrqFrame — в
/// RSI. Берёт per-CPU lctl через GS base, уходит в диспетчеризацию, а
/// для ring3-входов выполняет хвост преемпции (тики таймера откладывают
/// решение в lctl.preempt_next; здесь оно исполняется над кадром).
pub(crate) unsafe extern "C" fn irq_vector_dispatch_erased(
    vector: u8,
    frame: *mut crate::cswitch::IrqFrame,
) {
    // SAFETY: контракт irq_common — кадр лежит на текущем стеке (низ
    // кадра = RSP на момент call), валиден до возврата моста.
    let from_user = unsafe { (*frame).cs } & 3 == 3;
    // SAFETY: контракт irq_common — GS base ядерный на момент вызова.
    let lctl = crate::X86Backend::get_local_base();
    irq_vector_dispatch(vector, lctl, from_user);
    // Хвост преемпции: только ring3-входы (для ядерных тик не крутит
    // карусель — флаг всегда пуст, но берём безусловно для симметрии).
    if from_user {
        // SAFETY: кадр всё ещё валиден (тот же стек, мы не возвращались).
        crate::cswitch::irq_preempt_tail(unsafe { &mut *frame });
    }
}

// ─── Хук page fault (вектор 14) ──────────────────────────────────────────────

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

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Инварианты раскладки векторов: без IO-APIC (legacy) — 16 линий,
    /// MSI нет; с IO-APIC — MSI-базис выровнен и не пересекает спурьё.
    #[test]
    fn vector_layout_invariants() {
        // Legacy-чип: линии 0..15, MSI нет.
        let legacy = X86IrqChip {
            wired: 16,
            msi_line_base: 16,
            msi_capacity: 0,
            msi_vector_base: 0,
            legacy: true,
        };
        assert_eq!(legacy.wired_line_count(), 16);
        assert_eq!(legacy.msi_capacity(), 0);
        assert!(legacy.msi_vector(16).is_none());

        // QEMU-подобный чип: 24 GSI → MSI-базис линий 24, векторы с 48.
        let qemu = X86IrqChip {
            wired: 24,
            msi_line_base: 24,
            msi_capacity: MSI_POOL_MAX.min(255 - 48),
            msi_vector_base: 48,
            legacy: false,
        };
        assert_eq!(qemu.wired_line_count(), 24);
        assert_eq!(qemu.msi_line_base(), 24);
        assert_eq!(qemu.msi_vector(24), Some(48), "первая MSI-линия");
        assert_eq!(qemu.msi_vector(24 + 63), Some(48 + 63));
        assert!(qemu.msi_vector(23).is_none(), "проводная — не MSI");
        assert!(qemu.msi_vector(24 + 64).is_none(), "за пулом");
        // Последний MSI-вектор не задевает спурьё (255).
        assert!(48 + 63 < 255);
    }

    #[test]
    fn msi_message_format_bare() {
        let qemu = X86IrqChip {
            wired: 24,
            msi_line_base: 24,
            msi_capacity: 8,
            msi_vector_base: 48,
            legacy: false,
        };
        let msg = qemu.msi_message(26).expect("msi message");
        // Bare MSI: адрес 0xFEE00000 | dest<<12, data = вектор.
        assert_eq!(msg.address & 0xFFFF_F000, 0xFEE0_0000);
        assert_eq!(msg.data, 50, "линия 26 → вектор 48+2");
        assert!(msg.address & 0x8 == 0, "redirect hint off");
        assert!(msg.address & 0x4 == 0, "physical dest mode");
    }

    #[test]
    fn line_hook_registration_and_replacement() {
        fn dummy(_line: u32, _lctl: &mut LocalKernelCTL<X86Umap>, _from_user: bool) {}
        // Хук первой линии — свободный слот; повторно — тот же слот.
        assert!(register_line_hook(999, dummy).is_ok());
        assert!(register_line_hook(999, dummy).is_ok());
        // Вычистка за собой (тесты шарят статику).
        let mut hooks = LINE_HOOKS.lock();
        for slot in hooks.iter_mut() {
            if slot.0 == 999 {
                *slot = (u32::MAX, None);
            }
        }
    }
}
