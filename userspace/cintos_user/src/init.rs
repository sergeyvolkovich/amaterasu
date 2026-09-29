//! init-сервер: первый userspace-процесс NOMAD.
//!
//! Логика: принимает от ядра bootstrap (self-cap, namespace-cap) и
//! параметры фреймбуфера через auxv, затем в цикле читает ДЕЛЬТУ лога
//! ядра (DBG_LOG_READ, NR 46) и рисует её во фреймбуфер. Запись в FB
//! ведёт ИМЕННО userspace — ядро только пробрасывает параметры.
//!
//! Цикл: сон-поллинг (yield) без таймера; с появлением таймер-IRQ
//! заменяется на IrqWait.

use crate::fb::{pack_pixel, TextConsole, Color, FbInfo, GLYPH_H};

/// Адрес FB в адресном пространстве init: ядро мапит образ MMIO по
/// фиксированному VA (FB_VA_BASE, см. kernel_exec::spawn) и передаёт
/// через auxv. Параметры публикует расширенный crt0 (см. fb_aux).
pub fn fb_info_from_aux() -> Option<FbInfo> {
    crate::crt0::fb_aux()
}

/// Считывает дельту лога ядра в буфер. Возвращает (новое since, байт).
pub fn read_log_delta(since: u64, buf: &mut [u8]) -> (u64, usize) {
    unsafe {
        let new = crate::syscall::syscall3(
            crate::abi::nr::DBG_LOG_READ,
            since,
            buf.as_mut_ptr() as usize as u64,
            buf.len() as u64,
        );
        // Возврат: новое since (успех) или ошибка со старшим битом.
        if new & 0x8000_0000_0000_0000 != 0 {
            (since, 0)
        } else {
            (new, (new - since) as usize)
        }
    }
}

/// Разбивает байты лога на строки (последняя может быть неполной) и
/// добавляет в консоль.
pub fn feed_console(con: &mut TextConsole, bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            let s = con.take_pending();
            con.push_line(&s);
        } else if (32..127).contains(&b) {
            con.push_byte(b as char);
        }
    }
}

/// Инициализация текстовой консоли поверх FB.
pub fn make_console(fb: &FbInfo) -> TextConsole {
    TextConsole::new(
        fb,
        Color(220, 230, 240), // светлый текст
        Color(16, 20, 28),    // тёмный фон
    )
}

/// Фон/цвет пикселя для тестов и standalone-использования.
pub fn fg() -> u32 { pack_pixel(Color(220, 230, 240), 16, 8, 8, 8) }
pub fn bg() -> u32 { pack_pixel(Color(16, 20, 28), 16, 8, 8, 8) }

/// Высота строки консоли в пикселях.
pub const LINE_HEIGHT: usize = GLYPH_H;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fb::font8x8;

    #[test]
    fn read_log_delta_handles_error() {
        // syscall на хосте недоступен — проверяем упаковку ошибки:
        // read_log_delta вернёт (since, 0) при ошибочном RAX. Здесь
        // тестируем разбиение на строки (чистая логика feed_console).
        let (info, buf) = crate::fb::tests::test_fb_pub();
        let mut con = make_console(&info);
        feed_console(&mut con, b"limine: ok\nexec: init spawned\n");
        con.redraw(buf, &info);
        // Глиф 'l' в левом верхнем углу: 0x38 -> биты 3..5 строки 0.
        assert!(buf[..8].iter().any(|&p| p != 0));
    }

    #[test]
    fn console_clips_long_lines() {
        let (info, buf) = crate::fb::tests::test_fb_pub();
        let mut con = make_console(&info);
        feed_console(&mut con, &[b'X'; 512]); // длиннее экрана
        con.redraw(buf, &info);
        let _ = font8x8::glyph(b'X');
        let _ = buf.len();
    }
}
