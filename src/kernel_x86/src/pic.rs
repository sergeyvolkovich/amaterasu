//! Legacy PIC (Intel 8259A): ремап, маскирование, EOI.
//!
//! Ремап ОБЯЗАН предшествовать первому STI: без него линии IRQ 0..15
//! приходят на векторы 8..15/0x70..0x77 — поверх исключений CPU
//! (IRQ0 → вектор 8 = #DF — мгновенный triple fault).
//!
//! Тихий контракт для QEMU/BIOS: PIC остаётся в legacy-режиме (не IMCR),
//! внешние устройства сидят на нём до подъёма IOAPIC-драйвера юзерспейсом.
//!
//! Линия IRQ n → вектор 32+n (мастер 0..7 → 32..39, слейв 8..15 →
//! 40..47) — ровно то пространство, на которое собраны IDT-стабы
//! cswitch (32..95 → irq::irq_vector_dispatch, линия = вектор − 32).

use x86_64::instructions::port::{Port, PortWriteOnly};

/// Порт команд мастера (ICW/OCW) и его маска данных.
const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
/// Порт команд слейва и его маска данных.
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

/// База векторов мастера (IRQ 0..7 → 32..39).
pub const MASTER_VECTOR_BASE: u8 = 0x20;
/// База векторов слейва (IRQ 8..15 → 40..47).
pub const SLAVE_VECTOR_BASE: u8 = 0x28;

/// ICW1: инициализация (каскад, edge-triggered, нужен ICW4).
const ICW1_INIT: u8 = 0b0001_0001;
/// ICW4: 8086-режим, обычный EOI, не special fully nested.
const ICW4_8086: u8 = 0b0000_0001;

/// Перепрограммирует оба PIC: векторы 0x20/0x28, каскад на IRQ2,
/// 8086-режим, ВСЕ линии замаскированы (размаскирует точечно владелец
/// устройства — например, [`crate::timer`] линию 0).
///
/// Порядок байтов ICW фиксирован спецификацией 8259A; пауза не нужна —
/// QEMU/железо принимают последовательный поток портов.
pub fn remap_and_mask_all() {
    let mut master_cmd = PortWriteOnly::new(MASTER_CMD);
    let mut master_data = Port::new(MASTER_DATA);
    let mut slave_cmd = PortWriteOnly::new(SLAVE_CMD);
    let mut slave_data = Port::new(SLAVE_DATA);

    unsafe {
        // ICW1: старт инициализации обоих контроллеров.
        master_cmd.write(ICW1_INIT);
        slave_cmd.write(ICW1_INIT);
        // ICW2: базы векторов.
        master_data.write(MASTER_VECTOR_BASE);
        slave_data.write(SLAVE_VECTOR_BASE);
        // ICW3: мастер — слейв на линии 2 (битовая маска);
        //        слейв  — идентификатор каскада (2).
        master_data.write(0b0000_0100);
        slave_data.write(2);
        // ICW4: 8086-режим.
        master_data.write(ICW4_8086);
        slave_data.write(ICW4_8086);
        // OCW1: маскируем всё — размаскирует только владелец линии.
        master_data.write(0xFF);
        slave_data.write(0xFF);
    }
}

/// Размаскировать линию (0..15) — разрешить её доставку на CPU.
pub fn unmask(line: u8) {
    if line >= 16 {
        return;
    }
    let mut port: Port<u8> = Port::new(if line < 8 { MASTER_DATA } else { SLAVE_DATA });
    let bit = if line < 8 { line } else { line - 8 };
    unsafe {
        let mask = port.read();
        port.write(mask & !(1 << bit));
    }
}

/// Замаскировать линию (0..15).
pub fn mask(line: u8) {
    if line >= 16 {
        return;
    }
    let mut port: Port<u8> = Port::new(if line < 8 { MASTER_DATA } else { SLAVE_DATA });
    let bit = if line < 8 { line } else { line - 8 };
    unsafe {
        let mask = port.read();
        port.write(mask | (1 << bit));
    }
}

/// Specific EOI линии (0..15). Для слейва (8..15) — EOI ОБАМУ
/// контроллерам: слейву (своя линия) и мастеру (каскадная линия 2),
/// иначе мастер держит линию слейва замороженной.
pub fn send_eoi(line: u8) {
    if line >= 16 {
        return;
    }
    let mut master_cmd = PortWriteOnly::new(MASTER_CMD);
    let mut slave_cmd = PortWriteOnly::new(SLAVE_CMD);
    unsafe {
        if line >= 8 {
            slave_cmd.write(0x60 | (line - 8)); // specific EOI слейву
        }
        master_cmd.write(0x60 | if line >= 8 { 2 } else { line }); // specific EOI мастеру
    }
}
