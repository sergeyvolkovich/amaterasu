//! Драйвер последовательного порта COM1 (16550 UART) для отладочного
//! вывода ядра.
//!
//! QEMU пробрасывает COM1 (0x3F8) в `-serial stdio`: единственный канал,
//! по которому видно происходящее в ядре до подъёма init-сервера.
//! Инициализация порта НЕ требуется для вывода — QEMU работает и без
//! программирования baud/divisor (UART эмулируется всегда готовым);
//! init всё же выполняем для честного железа.

use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

const COM1: u16 = 0x3F8;

/// Регистр Line Status (offset 5): бит 5 = THR пуст, можно писать.
const LSR: u16 = COM1 + 5;
/// Регистр данных (offset 0).
const DATA: u16 = COM1;

/// Программирует COM1: 115200 8N1, FIFO включён. Вызывается один раз
/// на старте (до первого вывода — иначе QEMU всё равно выведет).
pub fn init() {
    unsafe {
        // DLAB=1, divisor=1 (115200), 8 бит, FIFO.
        PortWriteOnly::<u8>::new(COM1 + 1).write(0x00); // IER: без IRQ
        PortWriteOnly::<u8>::new(COM1 + 3).write(0x80); // DLAB
        PortWriteOnly::<u8>::new(DATA).write(0x01); // divisor low: 1
        PortWriteOnly::<u8>::new(COM1 + 1).write(0x00); // divisor high
        PortWriteOnly::<u8>::new(COM1 + 3).write(0x03); // 8N1, DLAB=0
        PortWriteOnly::<u8>::new(COM1 + 2).write(0xC7); // FIFO, очистка
        PortWriteOnly::<u8>::new(COM1 + 4).write(0x0B); // RTS/DSR/OUT2
    }
}

/// Пишет один байт, дожидаясь готовности THR (ограниченное число
/// попыток — зависший порт не должен вешать ядро).
pub fn putc(byte: u8) {
    let mut tries = 100_000u32;
    unsafe {
        let mut lsr = PortReadOnly::<u8>::new(LSR);
        loop {
            if lsr.read() & 0x20 != 0 {
                break;
            }
            tries -= 1;
            if tries == 0 {
                return; // порт молчит — теряем байт, но не зависаем
            }
            core::hint::spin_loop();
        }
        PortWriteOnly::<u8>::new(DATA).write(byte);
    }
}

/// Пишет срез байтов.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        putc(b);
    }
}

/// `\n` -> `\r\n` (терминалы ждут CR+LF).
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// fmt::Write-адаптер (для `write!(serial, ...)`).
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Экспорт для kernel_base::log::set_console_hook.
pub fn console_hook(bytes: &[u8]) {
    // hook получает сырые байты лога; перевод строки дублируем CR.
    for &b in bytes {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// Печатает строку в serial (без крючка лога — для паники/раннего бута).
#[macro_export]
macro_rules! serial_log {
    ($($arg:tt)*) => {
        $crate::serial::write_str(concat!($($arg)*))
    };
}
