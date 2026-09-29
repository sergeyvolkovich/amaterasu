//! dlog — минимальное логирование юзерспейс-бинарников в журнал ядра
//! (DBG_LOG_WRITE → serial + кольцо, видимое init-консолью).
//!
//! Десятичные u64 без fmt-механизмов Rust (профиль panic=abort, размер
//! образа важнее удобства). [`Line`] — растущая в фиксированном буфере
//! строка: str/ch/u64/nl + as_bytes.

use crate::abi;
use crate::syscall;

/// Пишет байты в журнал ядра (serial + кольцо лога).
pub fn log(msg: &[u8]) {
    unsafe {
        syscall::syscall2(abi::nr::DBG_LOG_WRITE, msg.as_ptr() as u64, msg.len() as u64)
    };
}

/// Строка лога в фиксированном буфере (без аллокаций).
pub struct Line {
    buf: [u8; 192],
    len: usize,
}

impl Line {
    pub fn new() -> Self {
        Line { buf: [0; 192], len: 0 }
    }

    /// Литеральный фрагмент (обрезается по остатку буфера).
    pub fn str(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }

    /// Один байт.
    pub fn ch(&mut self, c: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    /// Перевод строки.
    pub fn nl(&mut self) {
        self.ch(b'\n');
    }

    /// Десятичная запись u64.
    pub fn u64(&mut self, mut v: u64) {
        if v == 0 {
            self.ch(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.ch(digits[n]);
        }
    }

    /// Шестнадцатеричная запись u64 (0x-префикс).
    pub fn hex(&mut self, v: u64) {
        self.str(b"0x");
        let mut digits = [0u8; 16];
        let mut n = 0;
        let mut v = v;
        if v == 0 {
            self.ch(b'0');
            return;
        }
        while v > 0 {
            let d = (v % 16) as u8;
            digits[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
            v /= 16;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.ch(digits[n]);
        }
    }

    /// Готовые байты строки.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}
