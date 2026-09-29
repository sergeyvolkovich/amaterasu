//! IO-APIC: маршрутизация проводных линий (GSI) на векторы LAPIC.
//!
//! РЕГИСТРЫ: два 32-битных окна MMIO — IOREGSEL (0x00) и IOWIN (0x10);
//! доступ к произвольному регистру — запись его индекса в IOREGSEL,
//! чтение/запись IOWIN. RTE (перенаправление) — 64-битные, по два
//! 32-битных доступа; кодируются структурой RedirectionEntry (биты
//! ниже — по спецификации Intel 82093AA).
//!
//! ЛИНИИ → ВЕКТОРЫ: у IO-APIC нет своей жёсткой карты — каждая RTE
//! несёт вектор доставки. Порт закрепляет: GSI g → вектор 32+g
//! (исключения CPU занимают 0..31). Число линий контроллера берётся
//! из регистра VER (max_redirection_entry + 1), НЕ константой.
//!
//! МУЛЬТИ-КОНТРОЛЛЕРНОСТЬ: MADT может перечислить до MAX_IOAPICS
//! контроллеров с непересекающимися gsi_base; разрешение GSI→контроллер
//! — линейный скан по ([gsi_base, gsi_base + entries)).
//!
//! ПАРНОСТЬ EOI: IO-APIC не имеет собственного EOI — уровень сбрасывается
//! записью LAPIC EOI (для level-линий это снимает remote IRR в RTE).

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kernel_base::traits::irq::TriggerMode;

/// Максимум контроллеров (совпадает с boot::madt::MAX_IOAPICS).
pub const MAX_IOAPICS: usize = 4;

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;

/// Регистр идентификации/версии (0x01): [7:0] version, [23:16] max RTE.
const REG_VER: u32 = 0x01;
/// Регистр арбитража (0x02) — не используется (boot priority).
const REG_IOAPICID: u32 = 0x00;

/// Один IO-APIC-контроллер.
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    /// Физический адрес MMIO-окна (замаплен HHDM — reserved-регион).
    phys: usize,
    /// Первая GSI контроллера.
    gsi_base: u32,
    /// Число линий (из VER-регистра).
    pub entries: u32,
}

struct RedirectionEntry {
    vector: u8,
    delivery_mode: u8, // 0 = fixed
    dest_mode_logical: bool,
    active_low: bool,
    level_triggered: bool,
    masked: bool,
    destination: u8,
}

impl RedirectionEntry {
    fn to_bits(self) -> u64 {
        let mut lo = self.vector as u64;
        lo |= (self.delivery_mode as u64) << 8;
        if self.dest_mode_logical {
            lo |= 1 << 11;
        }
        if self.active_low {
            lo |= 1 << 13;
        }
        if self.level_triggered {
            lo |= 1 << 15;
        }
        if self.masked {
            lo |= 1 << 16;
        }
        lo | ((self.destination as u64) << 56)
    }
}

impl IoApic {
    /// Создаёт контроллер из MADT-дескриптора: читает VER (число линий).
    ///
    /// # Safety
    /// `phys` обязан указывать на MMIO-окно IO-APIC (замаплено HHDM,
    /// reserved-регион карты памяти).
    pub unsafe fn new(phys: usize, gsi_base: u32) -> Self {
        // SAFETY: контракт функции.
        let ver = unsafe { read_reg(phys, REG_VER) };
        let entries = ((ver >> 16) & 0xFF) + 1;
        Self {
            phys,
            gsi_base,
            entries,
        }
    }

    #[inline]
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: phys — валидное MMIO-окно из MADT (см. new).
        unsafe { read_reg(self.phys, reg) }
    }

    #[inline]
    fn write(&self, reg: u32, value: u32) {
        // SAFETY: см. read.
        unsafe { write_reg(self.phys, reg, value) }
    }

    fn rte_index(&self, gsi: u32) -> Option<u32> {
        if gsi < self.gsi_base || gsi >= self.gsi_base + self.entries {
            return None;
        }
        Some(0x10 + (gsi - self.gsi_base) * 2)
    }

    /// Программирует RTE линии (вектор/полярность/триггер/маска).
    pub fn program(&self, gsi: u32, entry: RedirectionEntry) {
        let Some(idx) = self.rte_index(gsi) else {
            return;
        };
        let bits = entry.to_bits();
        self.write(idx, bits as u32);
        self.write(idx + 1, (bits >> 32) as u32);
    }

    /// Читает текущий RTE (диагностика/инварианты).
    pub fn rte_bits(&self, gsi: u32) -> Option<u64> {
        let idx = self.rte_index(gsi)?;
        let lo = self.read(idx) as u64;
        let hi = self.read(idx + 1) as u64;
        Some(lo | (hi << 32))
    }

    pub fn mask(&self, gsi: u32) {
        let Some(idx) = self.rte_index(gsi) else {
            return;
        };
        let lo = self.read(idx);
        self.write(idx, lo | (1 << 16));
    }

    pub fn unmask(&self, gsi: u32) {
        let Some(idx) = self.rte_index(gsi) else {
            return;
        };
        let lo = self.read(idx);
        self.write(idx, lo & !(1 << 16));
    }

    pub fn gsi_range(&self) -> (u32, u32) {
        (self.gsi_base, self.gsi_base + self.entries)
    }
}

#[inline]
/// # Safety
/// `phys` — замапленное HHDM MMIO-окно IO-APIC.
unsafe fn read_reg(phys: usize, reg: u32) -> u32 {
    // SAFETY: контракт функции; селектор+окно — два volatile-доступа.
    unsafe {
        core::ptr::write_volatile((phys + IOREGSEL) as *mut u32, reg);
        core::ptr::read_volatile((phys + IOWIN) as *const u32)
    }
}

#[inline]
/// # Safety
/// `phys` — замапленное HHDM MMIO-окно IO-APIC.
unsafe fn write_reg(phys: usize, reg: u32, value: u32) {
    // SAFETY: контракт функции.
    unsafe {
        core::ptr::write_volatile((phys + IOREGSEL) as *mut u32, reg);
        core::ptr::write_volatile((phys + IOWIN) as *mut u32, value);
    }
}

// ─── Пул контроллеров платформы ──────────────────────────────────────────────

static IOAPICS: spin::Once<[Option<IoApic>; MAX_IOAPICS]> = spin::Once::new();
static IOAPIC_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Суммарное число проводных линий (Σ entries).
static WIRED_LINES: AtomicU32 = AtomicU32::new(0);

/// Инициализирует пул из MADT-дескрипторов. Все RTE маскируются сразу:
/// «всё молчит, пока владелец не попросил WAIT» — платформенный инвариант.
///
/// # Safety
/// `phys` каждого дескриптора — валидное MMIO-окно IO-APIC.
pub unsafe fn init_from_madt(
    descs: impl Iterator<Item = (usize, u32)>,
) -> Option<&'static [Option<IoApic>; MAX_IOAPICS]> {
    IOAPICS.call_once(|| {
        let mut arr: [Option<IoApic>; MAX_IOAPICS] = [None; MAX_IOAPICS];
        let mut count = 0usize;
        let mut wired = 0u32;
        for (phys, gsi_base) in descs {
            if count >= MAX_IOAPICS {
                break;
            }
            // SAFETY: контракт функции (phys из MADT, валидные окна).
            let apic = unsafe { IoApic::new(phys, gsi_base) };
            // Маскируем ВСЕ линии контроллера (индексы RTE 0x10..0x10+2N).
            for i in 0..apic.entries {
                let idx = 0x10 + i * 2;
                apic.write(idx, apic.read(idx) | (1 << 16));
            }
            wired += apic.entries;
            arr[count] = Some(apic);
            count += 1;
        }
        IOAPIC_COUNT.store(count, Ordering::Relaxed);
        WIRED_LINES.store(wired, Ordering::Relaxed);
        arr
    })
    .into()
}

/// Пул контроллеров (None — не инициализирован).
pub fn ioapics() -> Option<&'static [Option<IoApic>; MAX_IOAPICS]> {
    IOAPICS.get()
}

/// Число проводных линий платформы (0 — IO-APIC нет).
pub fn wired_line_count() -> u32 {
    WIRED_LINES.load(Ordering::Relaxed)
}

/// Контроллер, обслуживающий GSI.
pub fn controller_of(gsi: u32) -> Option<&'static IoApic> {
    let arr = IOAPICS.get()?;
    for slot in arr.iter().flatten() {
        let (lo, hi) = slot.gsi_range();
        if gsi >= lo && gsi < hi {
            return Some(slot);
        }
    }
    None
}

/// Программирует маршрут GSI: вектор = 32 + gsi, дестинейшен — BSP.
pub fn program_route(gsi: u32, active_low: bool, level: bool, masked: bool) {
    let Some(apic) = controller_of(gsi) else {
        return;
    };
    let dest = crate::apic::bsp_lapic_id() as u8;
    apic.program(
        gsi,
        RedirectionEntry {
            vector: 32u8.wrapping_add(gsi as u8),
            delivery_mode: 0,
            dest_mode_logical: false,
            active_low,
            level_triggered: level,
            masked,
            destination: dest,
        },
    );
}

pub fn mask_gsi(gsi: u32) {
    if let Some(apic) = controller_of(gsi) {
        apic.mask(gsi);
    }
}

pub fn unmask_gsi(gsi: u32) {
    if let Some(apic) = controller_of(gsi) {
        apic.unmask(gsi);
    }
}

/// TriggerMode → (polarity, level) для program_route (высокая полярность).
pub fn trigger_bits(mode: TriggerMode) -> bool {
    matches!(mode, TriggerMode::Level)
}

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// RTE-кодирование без железа: битовая раскладка входа.
    #[test]
    fn rte_bit_layout() {
        let e = RedirectionEntry {
            vector: 34,
            delivery_mode: 0,
            dest_mode_logical: false,
            active_low: false,
            level_triggered: true,
            masked: true,
            destination: 0,
        };
        let bits = e.to_bits();
        assert_eq!(bits & 0xFF, 34, "вектор в [7:0]");
        assert_eq!(bits >> 8 & 0x7, 0, "delivery fixed");
        assert_eq!(bits >> 11 & 1, 0, "physical dest mode");
        assert_eq!(bits >> 13 & 1, 0, "active high");
        assert_eq!(bits >> 15 & 1, 1, "level triggered");
        assert_eq!(bits >> 16 & 1, 1, "masked");
        assert_eq!(bits >> 56, 0, "dest = BSP lapic 0");
    }

    #[test]
    fn vector_math_gsi_to_vector() {
        // GSI g → вектор 32+g; вектор обязан остаться в u8 при легитимных
        // GSI (контроллер же ограничен числом RTE).
        assert_eq!(32u8.wrapping_add(2), 34, "PIT GSI 2");
        assert_eq!(32u8.wrapping_add(31), 63);
    }
}
