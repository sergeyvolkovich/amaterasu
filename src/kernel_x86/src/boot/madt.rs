//! Разбор MADT (APIC-таблицы ACPI): источникиIRQ-топологии платформы.
//!
//! Что вынимаем (только то, что нужно контроллерам прерываний):
//!   - IO-APIC-узлы (type 1): MMIO-адрес + gsi_base → проводное
//!     пространство линий 0..Σcount;
//!   - Interrupt Source Overrides (type 2): ISA-линия → GSI с
//!     полярностью/триггером (PIT: ISA 0 → GSI 2 edge/high на PC-платформе);
//!   - Local APIC-узлы игнорируются: ядро знает BSP id через
//!     LAPIC-регистр (apic::lapic_id), а не через MADT.
//!
//! Все поля читаются из уже дочемапленной таблицы (boot/acpi std_slice).
//! Границы записей проверяются по полю Length каждой — битый MADT
//! (QEMU такого не делает, но контракт fail-closed) даёт None/усечение.

/// Максимум IO-APIC-контроллеров (реальные платы ≤4; QEMU — 1).
pub const MAX_IOAPICS: usize = 4;
/// Максимум override-записей (ISA-линий всего 16).
pub const MAX_ISO: usize = 16;

/// Описание IO-APIC из MADT (type 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicDesc {
    /// Физический адрес MMIO-окна (IOREGSEL).
    pub phys: usize,
    /// Первая GSI этого контроллера.
    pub gsi_base: u32,
}

/// Override ISA→GSI (MADT type 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoEntry {
    /// Исходная ISA-линия (0..16).
    pub isa_source: u8,
    /// Целевая GSI.
    pub gsi: u32,
    /// Полярность: true = active-low (MADT flags bits [0:2] == 3).
    pub active_low: bool,
    /// Триггер: true = level (MADT flags bits [2:4] == 3).
    pub level_triggered: bool,
}

/// Разобранная IRQ-топология MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtIrq {
    pub ioapics: [Option<IoApicDesc>; MAX_IOAPICS],
    pub ioapic_count: usize,
    pub iso: [Option<IsoEntry>; MAX_ISO],
    pub iso_count: usize,
}

impl MadtIrq {
    pub const fn empty() -> Self {
        Self {
            ioapics: [None; MAX_IOAPICS],
            ioapic_count: 0,
            iso: [None; MAX_ISO],
            iso_count: 0,
        }
    }

    /// Override для ISA-линии (None — конформинг: GSI = линия, edge/high).
    pub fn isa_override(&self, isa: u8) -> Option<IsoEntry> {
        self.iso
            .iter()
            .flatten()
            .find(|e| e.isa_source == isa)
            .copied()
    }
}

/// Разбирает MADT (таблица "APIC") из сырых байтов. Возвращает None,
/// если таблица обрезана/нет ни одного IO-APIC (fallback-платформа).
pub fn parse(table: &[u8]) -> Option<MadtIrq> {
    if table.len() < 44 {
        return None;
    }
    let mut out = MadtIrq::empty();
    // Локальный APIC-адрес (u32 @36) и flags (@40) не нужны — см. шапку.
    let mut off = 44usize;
    while off + 2 <= table.len() {
        let etype = table[off];
        let elen = table[off + 1] as usize;
        if elen < 2 || off + elen > table.len() {
            break; // битая запись — stop fail-closed
        }
        let e = &table[off..off + elen];
        match etype {
            1 if elen >= 12 => {
                // IO-APIC: [2] id, [4..8] MMIO addr, [8..12] gsi_base.
                let phys = u32::from_le_bytes([e[4], e[5], e[6], e[7]]) as usize;
                let gsi_base = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
                if phys != 0 && out.ioapic_count < MAX_IOAPICS {
                    out.ioapics[out.ioapic_count] = Some(IoApicDesc { phys, gsi_base });
                    out.ioapic_count += 1;
                }
            }
            2 if elen >= 10 => {
                // ISO: [2] bus, [3] source, [4..8] gsi, [8..10] flags.
                let isa = e[3];
                let gsi = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
                let flags = u16::from_le_bytes([e[8], e[9]]);
                let pol = flags & 0b11; // 0=conforming, 1=high, 3=low
                let trg = (flags >> 2) & 0b11; // 0=conforming, 1=edge, 3=level
                if out.iso_count < MAX_ISO {
                    out.iso[out.iso_count] = Some(IsoEntry {
                        isa_source: isa,
                        gsi,
                        active_low: pol == 3,
                        level_triggered: trg == 3,
                    });
                    out.iso_count += 1;
                }
            }
            _ => {} // Local APIC (0), NMI (4), x2APIC (5) — не нужны
        }
        off += elen;
    }
    if out.ioapic_count == 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сборщик MADT из записей (тип, payload — байты после [type, len]).
    fn build_madt(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut t = vec![0u8; 44]; // заголовок + local apic addr + flags
        for (etype, payload) in entries {
            let mut entry = vec![*etype, (payload.len() + 2) as u8];
            entry.extend_from_slice(payload);
            t.extend_from_slice(&entry);
        }
        t
    }

    #[test]
    fn qemu_like_topology() {
        // QEMU i440fx: один IO-APIC (0xFEC00000, gsi 0), override PIT
        // (ISA 0 → GSI 2), RTC (ISA 8 → GSI 8).
        // Payload IO-APIC (после [type,len]): [id, rsvd, addr LE, gsi LE].
        let ioapic: Vec<u8> = vec![0, 0, 0x00, 0x00, 0xC0, 0xFE, 0x00, 0x00, 0x00, 0x00];
        // Payload ISO: [bus, source, gsi LE, flags LE].
        let iso_pit = [0u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]; // gsi=2, flags=0
        let iso_rtc = [0u8, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let madt = build_madt(&[(1, &ioapic), (2, &iso_pit), (2, &iso_rtc)]);

        let m = parse(&madt).expect("madt");
        assert_eq!(m.ioapic_count, 1);
        assert_eq!(m.ioapics[0], Some(IoApicDesc { phys: 0xFEC0_0000, gsi_base: 0 }));
        assert_eq!(m.iso_count, 2);

        let pit = m.isa_override(0).expect("pit override");
        assert_eq!(pit.gsi, 2);
        assert!(!pit.active_low);
        assert!(!pit.level_triggered);
        let rtc = m.isa_override(8).expect("rtc override");
        assert_eq!(rtc.gsi, 8);
        assert!(m.isa_override(5).is_none());
    }

    #[test]
    fn level_low_flags_decoded() {
        // flags: polarity low (0b11), trigger level (0b11<<2) = 0x0F.
        let ioapic: Vec<u8> = vec![0, 0, 0x00, 0x00, 0xC0, 0xFE, 0x00, 0x00, 0x00, 0x00];
        let iso = [0u8, 0x04, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x00];
        let madt = build_madt(&[(1, &ioapic), (2, &iso)]);
        let m = parse(&madt).expect("madt");
        let e = m.isa_override(4).expect("override");
        assert_eq!(e.gsi, 0x10);
        assert!(e.active_low && e.level_triggered);
    }

    #[test]
    fn truncated_and_empty_rejected() {
        assert!(parse(&[0u8; 43]).is_none(), "короче шапки");
        // Таблица с одним Local APIC (type 0) — IO-APIC нет → None.
        let lapic = [0u8, 0x00, 0x00, 0x01];
        let madt = build_madt(&[(0, &lapic)]);
        assert!(parse(&madt).is_none());
    }

    #[test]
    fn entry_len_overflow_fails_closed() {
        // Запись с len=0xFF при короткой таблице — разбор останавливается,
        // IO-APIC до места обрыва уже собран.
        let ioapic: Vec<u8> = vec![0, 0, 0x00, 0x00, 0xC0, 0xFE, 0x00, 0x00, 0x00, 0x00];
        let mut madt = build_madt(&[(1, &ioapic)]);
        madt.push(0x03); // тип 3 (unknown)
        madt.push(0xFF); // len 255 > остаток
        let m = parse(&madt).expect("ioapic собран до обрыва");
        assert_eq!(m.ioapic_count, 1);
    }
}
