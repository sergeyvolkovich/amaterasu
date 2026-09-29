//! LAPIC (Local APIC): включение, EOI, идентификатор ядра.
//!
//! Поддерживаются оба режима, в которых QEMU/железо может прийти к ядру:
//!   - xAPIC (MMIO-окно, обычно 0xFEE00000): регистры через HHDM
//!     (`phys_to_virt(base) + offset`) — тот же паттерн, что у IOMMU;
//!     HHDM-окно замаплено на ВСЕ reserved-регионы карты (см. intel.rs),
//!     отдельного маппинга не требуется;
//!   - x2APIC (MSR 0x800..): обнаруживается по биту 10 IA32_APIC_BASE;
//!     EOI/id/спурьё идут через MSR.
//!
//! ЕДИНИСТВЕННОЕ, что нужно ядру от LAPIC в v2: EOI после обработки
//! прерывания (диспетчер irq.rs), чтение ID (RTE-дестинейшены IO-APIC
//! и MSI-сообщения адресуются на BSP) и глушение LVT-источников, которые
//! загрузчик мог оставить активными (LINT0/1, таймер, perf, thermal).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use x86_64::registers::model_specific::Msr;

/// IA32_APIC_BASE (MSR 0x1B): база MMIO-окна LAPIC + флаги режимов.
const MSR_APIC_BASE: u32 = 0x1B;
/// Бит 11 IA32_APIC_BASE: глобальное разрешение APIC.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// Бит 10: x2APIC-режим.
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// x2APIC MSR-база (id 0x802, version 0x803, EOI 0x80B, spurious 0x80F).
const MSR_X2APIC_ID: u32 = 0x802;
const MSR_X2APIC_EOI: u32 = 0x80B;
const MSR_X2APIC_SPURIOUS: u32 = 0x80F;

/// Вектор спурифика (совпадает с 255 — вне IRQ-пространства диспетчера).
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// Бит 8 регистра spurious: программное разрешение APIC.
const APIC_SW_ENABLE: u32 = 1 << 8;

/// Смещения регистров xAPIC (MMIO-окна) относительно базы.
const REG_ID: usize = 0x20;
const REG_EOI: usize = 0xB0;
const REG_SPURIOUS: usize = 0xF0;
/// LVT-регистры: CMCI, timer, thermal, perf, LINT0, LINT1.
const REG_LVT_CMCI: usize = 0x2F0;
const REG_LVT_TIMER: usize = 0x320;
const REG_LVT_THERMAL: usize = 0x330;
const REG_LVT_PERF: usize = 0x340;
const REG_LVT_LINT0: usize = 0x350;
const REG_LVT_LINT1: usize = 0x360;

/// Бит 16 LVT-регистра: маскирование источника.
const LVT_MASK: u32 = 1 << 16;

static LAPIC_MMIO_BASE: AtomicUsize = AtomicUsize::new(0);
static X2APIC: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static BSP_LAPIC_ID: AtomicU32 = AtomicU32::new(0);

#[inline]
fn mmio_read(offset: usize) -> u32 {
    let base = LAPIC_MMIO_BASE.load(Ordering::Relaxed);
    // SAFETY: base — MMIO-окно LAPIC из IA32_APIC_BASE, замаплено HHDM;
    // чтение 32-битного регистра — атомарная операция шины.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

#[inline]
fn mmio_write(offset: usize, value: u32) {
    let base = LAPIC_MMIO_BASE.load(Ordering::Relaxed);
    // SAFETY: см. mmio_read.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) }
}

/// Возвращает физическую базу LAPIC и режим x2APIC. None — APIC
/// отсутствует (CPUID leaf 1, EDX bit 9) — QEMU/железо x86_64 всегда
/// имеют, но защита от излишнего доверия бесплатна.
fn detect() -> Option<(usize, bool)> {
    // CPUID leaf 1: EDX bit 9 = APIC present.
    let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
    if leaf1.edx & (1 << 9) == 0 {
        return None;
    }
    // SAFETY: MSR APIC_BASE существует на всех x86_64 с APIC.
    let base = unsafe { Msr::new(MSR_APIC_BASE).read() };
    if base & APIC_BASE_ENABLE == 0 {
        return None;
    }
    let x2 = base & APIC_BASE_X2APIC != 0;
    let mmio = (base & 0xFFFF_F000) as usize;
    Some((mmio, x2))
}

/// Инициализирует LAPIC на ТЕКУЩЕМ ядре: детект, включение (глобальный
/// бит MSR + программное разрешение через spurious), глушение LVT.
/// Вызывается на BSP из init (см. irq::init_from_madt); AP-ядра в v2
/// остаются с IF=0 — их LAPIC не настраивается (не мешает: маскирован-
/// ные линии им ничего не доставляют).
pub fn init() -> bool {
    let Some((mmio, x2)) = detect() else {
        return false;
    };
    LAPIC_MMIO_BASE.store(mmio, Ordering::Relaxed);
    X2APIC.store(x2, Ordering::Relaxed);

    if !x2 {
        // Глушим LVT ДО включения: ни один локальный источник не должен
        // прийти на непредназначенный для него вектор.
        for reg in [
            REG_LVT_CMCI,
            REG_LVT_TIMER,
            REG_LVT_THERMAL,
            REG_LVT_PERF,
            REG_LVT_LINT0,
            REG_LVT_LINT1,
        ] {
            mmio_write(reg, LVT_MASK);
        }
        // Программное включение + спурьё-вектор 255.
        mmio_write(REG_SPURIOUS, SPURIOUS_VECTOR as u32 | APIC_SW_ENABLE);
    } else {
        // SAFETY: x2APIC MSR-группа существует при бите 10 APIC_BASE.
        unsafe {
            Msr::new(MSR_X2APIC_SPURIOUS).write(SPURIOUS_VECTOR as u64 | APIC_SW_ENABLE as u64);
        }
        // LVT в x2APIC остаются доступными через MMIO-нумерацию MSR
        // (0x82F..) — глушим их тоже: LVT_LINT0 (0x835).
        for msr in [0x82Fu32, 0x832, 0x833, 0x834, 0x835, 0x836] {
            // SAFETY: см. выше.
            unsafe { Msr::new(msr).write(LVT_MASK as u64) };
        }
    }

    BSP_LAPIC_ID.store(lapic_id_inner(x2, mmio), Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
    true
}

/// Активен ли LAPIC (EOI обязаны идти).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Идентификатор локального APIC (физический дестинейшен). До init() — 0.
pub fn lapic_id() -> u32 {
    if !ACTIVE.load(Ordering::Relaxed) {
        return 0;
    }
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: x2APIC id — MSR 0x802.
        (unsafe { Msr::new(MSR_X2APIC_ID).read() }) as u32
    } else {
        mmio_read(REG_ID) >> 24
    }
}

/// Внутреннее чтение ID во время init() (до установки ACTIVE).
fn lapic_id_inner(x2: bool, mmio: usize) -> u32 {
    if x2 {
        // SAFETY: x2APIC id — MSR 0x802 (бит 10 APIC_BASE проверен).
        (unsafe { Msr::new(MSR_X2APIC_ID).read() }) as u32
    } else {
        // SAFETY: MMIO-окно LAPIC замаплено HHDM (reserved-регион).
        (unsafe { core::ptr::read_volatile((mmio + REG_ID) as *const u32) }) >> 24
    }
}

/// End-of-Interrupt: подтверждает обработку прерывания текущему ядру.
/// Вызывается диспетчером irq.rs ПОСЛЕ хука (контракт «ack после
/// обработки»); для спурья (255) EOI не требуется и не вызывается.
/// До init() — безопасный no-op (база окна ещё не известна).
pub fn eoi() {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: EOI — запись нуля в MSR 0x80B.
        unsafe { Msr::new(MSR_X2APIC_EOI).write(0) };
    } else {
        mmio_write(REG_EOI, 0);
    }
}

/// Идентификатор BSP (для RTE-дестинейшенов: все линии в v2 доставляются
/// на bootstrap-ядро, где крутится планировщик и ждут серверы).
pub fn bsp_lapic_id() -> u32 {
    BSP_LAPIC_ID.load(Ordering::Relaxed)
}

// ─── Тесты (хост: арифметика форматов, без MMIO) ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spurious_vector_outside_dispatch_space() {
        // Спурьё 255 не попадает в диапазон линий диспетчера (32..255):
        // стаб 255 обязан молчать, MSI-пул обязан заканчиваться раньше.
        assert_eq!(SPURIOUS_VECTOR, u8::MAX);
    }

    #[test]
    fn inactive_eoi_is_safe_noop_path() {
        // До init() active()==false; eoi() без init обязан быть безопасен
        // (mmio_read с base=0 не вызывается — x2APIC=false и запись в
        // окно base=0 была бы записью по нулю... поэтому eoi гейтится
        // active() на стороне диспетчера).
        assert!(!active());
    }
}
