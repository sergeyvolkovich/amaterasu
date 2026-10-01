//! Текстовый рендерер во фреймбуфер (userspace init-сервер).
//!
//! Ядро НЕ пишет в фреймбуфер: Limine отдаёт FB, ядро пробрасывает его
//! параметры init-серверу через auxv (AT_NOMAD_FB_*), и init сам рисует
//! дамп лога ядра. Рендерер — чистые функции над пиксельным буфером:
//! тестируются на хосте без железа.
//!
//! Формат пикселя собирается по маскам из Framebuffer (red/green/blue
//! mask_size/shift) — поддержан любой 32bpp порядок (BGRA/RGBA).

/// Ширина/высота глифа (встроенный шрифт 8x8, ASCII 32..127).
pub const GLYPH_W: usize = 8;
pub const GLYPH_H: usize = 8;

/// Параметры фреймбуфера (из auxv init-сервера).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FbInfo {
    /// Виртуальный адрес FB (ядро смапило в адресное пространство init).
    pub addr: usize,
    /// Байт на строку.
    pub pitch: usize,
    /// Пикселей в ширину.
    pub width: u32,
    /// Пикселей в высоту.
    pub height: u32,
    /// Бит на пиксель (32 ожидается).
    pub bpp: u8,
}

/// RGB-цвет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color(pub u8, pub u8, pub u8);

/// Простой встроенный шрифт 8x8 (ASCII 32..126, бит 0 = левый столбец).
/// Сокращённая таблица: печатаемые символы; 0x7F+ -> пустой глиф.
pub mod font8x8 {
    /// Возвращает 8 байт глифа (по одному на строку) для ASCII-кода.
    pub const fn glyph(ch: u8) -> [u8; 8] {
        if ch < 32 || ch >= 127 {
            return [0; 8];
        }
        FONT[(ch - 32) as usize]
    }

    // Базовые 5x7-подобные глифы, растянутые до 8x8 (левое выравнивание).
    // Собраны вручную для ASCII 32..126.
    pub static FONT: [[u8; 8]; 95] = [
        [0x00; 8],                       // space
        [0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18], // !
        [0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00], // "
        [0x66, 0xFF, 0x66, 0x66, 0xFF, 0x66, 0x66, 0x00], // #
        [0x18, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x18, 0x00], // $
        [0x66, 0x6C, 0x18, 0x30, 0x66, 0x46, 0x66, 0x00], // %
        [0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00], // &
        [0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00], // '
        [0x0E, 0x1C, 0x18, 0x18, 0x1C, 0x0E, 0x00, 0x00], // (
        [0x70, 0x38, 0x18, 0x18, 0x38, 0x70, 0x00, 0x00], // )
        [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00], // *
        [0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00], // +
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30], // ,
        [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00], // -
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00], // .
        [0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00], // /
        [0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00], // 0
        [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00], // 1
        [0x3C, 0x66, 0x06, 0x0C, 0x30, 0x60, 0x7E, 0x00], // 2
        [0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00], // 3
        [0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x00], // 4
        [0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00], // 5
        [0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00], // 6
        [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00], // 7
        [0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00], // 8
        [0x3C, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00], // 9
        [0x00, 0x18, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00], // :
        [0x00, 0x00, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30], // ;
        [0x0E, 0x1C, 0x38, 0x70, 0x38, 0x1C, 0x0E, 0x00], // <
        [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00], // =
        [0x70, 0x38, 0x1C, 0x0E, 0x1C, 0x38, 0x70, 0x00], // >
        [0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00], // ?
        [0x3C, 0x66, 0x6E, 0x6A, 0x6E, 0x60, 0x3E, 0x00], // @
        [0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00], // A
        [0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00], // B
        [0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00], // C
        [0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00], // D
        [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00], // E
        [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00], // F
        [0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00], // G
        [0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00], // H
        [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00], // I
        [0x06, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00], // J
        [0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00], // K
        [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00], // L
        [0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00], // M
        [0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00], // N
        [0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00], // O
        [0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00], // P
        [0x3C, 0x66, 0x66, 0x66, 0x66, 0x6C, 0x36, 0x00], // Q
        [0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00], // R
        [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00], // S
        [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00], // T
        [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00], // U
        [0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00], // V
        [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00], // W
        [0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00], // X
        [0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00], // Y
        [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00], // Z
        [0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00], // [
        [0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00], // backslash
        [0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00], // ]
        [0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00], // ^
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF], // _
        [0x0C, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00], // `
        [0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00], // a
        [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00], // b
        [0x00, 0x00, 0x3C, 0x60, 0x60, 0x60, 0x3C, 0x00], // c
        [0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00], // d
        [0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00], // e
        [0x0E, 0x18, 0x3E, 0x18, 0x18, 0x18, 0x18, 0x00], // f
        [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x7C], // g
        [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00], // h
        [0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00], // i
        [0x06, 0x00, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00], // j
        [0x60, 0x60, 0x6C, 0x78, 0x6C, 0x66, 0x66, 0x00], // k
        [0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00], // l
        [0x00, 0x00, 0x66, 0x7F, 0x7F, 0x6B, 0x63, 0x00], // m
        [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00], // n
        [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00], // o
        [0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60], // p
        [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06], // q
        [0x00, 0x00, 0x3E, 0x60, 0x60, 0x60, 0x60, 0x00], // r
        [0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00], // s
        [0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x0E, 0x00], // t
        [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00], // u
        [0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00], // v
        [0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00], // w
        [0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00], // x
        [0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x7C], // y
        [0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00], // z
        [0x1C, 0x30, 0x30, 0xE0, 0x30, 0x30, 0x1C, 0x00], // {
        [0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18], // |
        [0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00], // }
        [0x00, 0x30, 0x3C, 0x0E, 0x00, 0x00, 0x00, 0x00], // ~
    ];
}

/// Рисует один глиф в буфер FB. `stride` в пикселях.
pub fn draw_char(buf: &mut [u32], info: &FbInfo, x: usize, y: usize, ch: u8, fg: u32) {
    let glyph = font8x8::glyph(ch);
    for (row, bits) in glyph.iter().enumerate() {
        let py = y + row;
        if py as u32 >= info.height {
            continue;
        }
        let row_bits = *bits;
        for col in 0..GLYPH_W {
            let px = x + col;
            if px as u32 >= info.width {
                continue;
            }
            // бит col установлен -> рисуем (бит 0 — левый столбец глифа).
            if row_bits & (1 << col) != 0 {
                let idx = py * (info.pitch / 4) + px;
                if idx < buf.len() {
                    buf[idx] = fg;
                }
            }
        }
    }
}

/// Рисует строку; возвращает следующую координату X.
pub fn draw_str(buf: &mut [u32], info: &FbInfo, x: usize, y: usize, text: &str, fg: u32) -> usize {
    let mut cx = x;
    for b in text.bytes() {
        draw_char(buf, info, cx, y, b, fg);
        cx += GLYPH_W;
    }
    cx
}

/// Очистка экрана цветом.
pub fn clear(buf: &mut [u32], info: &FbInfo, bg: u32) {
    let pixels = (info.pitch / 4) * info.height as usize;
    let pixels = pixels.min(buf.len());
    for p in buf.iter_mut().take(pixels) {
        *p = bg;
    }
}

/// Консоль: окно текста поверх FB (кол-во колонок/строк по размеру глифа).
pub struct TextConsole {
    pub cols: usize,
    pub rows: usize,
    cursor_row: usize,
    cursor_col: usize,
    lines: heapless::String<{ 8 * 512 }>,
    /// Накопитель неполной строки (до \n).
    pending: heapless::String<256>,
    /// Сколько ПОЛНЫХ строк уже отрисовано (дельта-перерисовка).
    drawn_upto: usize,
    /// skip (первая видимая строка) на момент прошлой отрисовки;
    /// usize::MAX — «ещё не рисовали / буфер сжимался» → полная.
    skip_last: usize,
    fg: u32,
    bg: u32,
}

impl TextConsole {
    /// Новая консоль под размер FB.
    pub fn new(info: &FbInfo, fg: Color, bg: Color) -> Self {
        let fg32 = pack_pixel(fg, 16, 8, 8, 8);
        let bg32 = pack_pixel(bg, 16, 8, 8, 8);
        Self {
            cols: info.width as usize / GLYPH_W,
            rows: info.height as usize / GLYPH_H,
            cursor_row: 0,
            cursor_col: 0,
            lines: heapless::String::new(),
            pending: heapless::String::new(),
            drawn_upto: 0,
            skip_last: usize::MAX,
            fg: fg32,
            bg: bg32,
        }
    }

    /// Добавляет строку в буфер (кольцевой: старые вытесняются).
    pub fn push_line(&mut self, line: &str) {
        // Перенос длинных строк по колонкам.
        for chunk in line.as_bytes().chunks(self.cols.max(1)) {
            let s = core::str::from_utf8(chunk).unwrap_or("");
            if self.lines.len() + s.len() + 1 > self.lines.capacity() {
                // Вытесняем первую половину: пересобираем строку вручную.
                let bytes = self.lines.as_bytes();
                let keep_from = bytes.len() / 2;
                // до границы строки
                let mut start = keep_from;
                while start < bytes.len() && bytes[start] != b'\n' {
                    start += 1;
                }
                if start < bytes.len() {
                    start += 1;
                }
                let mut new_lines = heapless::String::new();
                for &b in &bytes[start..] {
                    let _ = new_lines.push(b as char);
                }
                self.lines = new_lines;
            }
            let _ = self.lines.push_str(s);
            let _ = self.lines.push('\n');
        }
    }

    /// Байт текущей неполной строки (до \n).
    pub fn push_byte(&mut self, ch: char) {
        let _ = self.pending.push(ch);
        if self.pending.len() >= self.cols {
            let s = self.take_pending();
            self.push_line(&s);
        }
    }

    /// Забирает накопленную неполную строку.
    pub fn take_pending(&mut self) -> heapless::String<256> {
        core::mem::take(&mut self.pending)
    }

    /// Перерисовывает консоль. ДЕЛЬТА-РЕЖИМ (полная заливка + все глифы
    /// на каждую строку лога стоили ~50 мс — на это время консоль-сервер
    /// держал готовые-но-незапланированные задачи, и таймер-сервер терял
    /// больше половины тиков):
    ///   - скролла нет (skip не изменился) — рисуются ТОЛЬКО новые строки;
    ///   - скролл на d строк — пиксельные строки уезжают вверх одним
    ///     memmove (copy_within), заново рисуется только хвост;
    ///   - полная перерисовка — первый показ, вытеснение кольцевого
    ///     буфера (индексы сдвинулись) или дамп длиннее экрана.
    pub fn redraw(&mut self, buf: &mut [u32], info: &FbInfo) {
        let max_lines = self.rows;
        let total_lines = self.lines.matches('\n').count();
        let skip = total_lines.saturating_sub(max_lines - 1);
        let pitch_words = info.pitch / 4;

        // Вытеснение буфера: количество строк УПАЛО — индексы недействительны.
        let full = self.skip_last == usize::MAX
            || total_lines < self.drawn_upto
            || skip < self.skip_last
            || skip - self.skip_last >= max_lines;

        if full {
            clear(buf, info, self.bg);
            self.draw_lines(buf, info, skip, skip, total_lines);
            self.skip_last = skip;
            self.drawn_upto = total_lines;
        } else {
            let d = skip - self.skip_last;
            if d > 0 {
                // Сдвиг пикселей вверх на d глиф-строк: один memmove
                // вместо полной перерисовки.
                let text_px = max_lines * GLYPH_H; // пиксельных строк текста
                let shift_px = d * GLYPH_H;
                let top_words = (text_px - shift_px) * pitch_words;
                if top_words > 0 && text_px * pitch_words <= buf.len() {
                    buf.copy_within(shift_px * pitch_words..text_px * pitch_words, 0);
                }
                // Очистка освободившихся нижних глиф-строк.
                for w in buf
                    .iter_mut()
                    .take(text_px * pitch_words)
                    .skip(top_words)
                {
                    *w = self.bg;
                }
            }
            // Хвост: строки, не рисованные прошлым вызовом.
            let from = self.drawn_upto.max(skip);
            self.draw_lines(buf, info, from, skip, total_lines);
            self.skip_last = skip;
            self.drawn_upto = total_lines;
        }

        // Позиция курсора — конец последней строки (дёшево, без пикселей).
        let tail = self
            .lines
            .rfind('\n')
            .map(|p| self.lines.len() - p - 1)
            .unwrap_or(self.lines.len());
        self.cursor_row = total_lines.saturating_sub(skip).min(max_lines.saturating_sub(1));
        self.cursor_col = tail.min(self.cols.saturating_sub(1));
    }

    /// Рисует строки [from..total) по их местам: строка i — на экранном
    /// ряду (i - skip). (Прежний код рисовал по АБСОЛЮТНОМУ индексу —
    /// после первого экрана текст уходил за низ и не рисовался вовсе.)
    fn draw_lines(
        &self,
        buf: &mut [u32],
        info: &FbInfo,
        from: usize,
        skip: usize,
        total: usize,
    ) {
        let mut cur_line = 0usize;
        let mut col = 0usize;
        for &b in self.lines.as_bytes() {
            if b == b'\n' {
                cur_line += 1;
                col = 0;
                continue;
            }
            if cur_line >= from && cur_line < total {
                let row = cur_line - skip;
                if row < self.rows {
                    draw_char(buf, info, col * GLYPH_W, row * GLYPH_H, b, self.fg);
                }
            }
            col += 1;
            if col >= self.cols {
                col = 0; // перенос внутри строки (страховка: строки уже
                         // нарезаны по cols при push_line)
            }
        }
    }
}

#[inline]
pub fn pack_pixel(color: Color, r_shift: u8, r_size: u8, g_shift: u8, b_shift: u8) -> u32 {
    let mask = |size: u8| -> u32 { if size == 0 || size >= 32 { 0xFF } else { (1u32 << size) - 1 } };
    let r = (color.0 as u32) & mask(r_size);
    let g = (color.1 as u32) & mask(r_size);
    let b = (color.2 as u32) & mask(r_size);
    (r << r_shift) | (g << g_shift) | (b << b_shift)
}
#[cfg(test)]
pub mod tests {
    use super::*;
    extern crate std;
    use std::{boxed::Box, vec};

    pub fn test_fb() -> (FbInfo, &'static mut [u32]) {
        let info = FbInfo {
            addr: 0x1000,
            pitch: 32 * 4,
            width: 32,
            height: 32,
            bpp: 32,
        };
        let buf = Box::leak(vec![0u32; 32 * 32].into_boxed_slice());
        (info, buf)
    }

    pub fn test_fb_pub() -> (FbInfo, &'static mut [u32]) {
        test_fb()
    }

    #[test]
    fn glyph_pixel_is_set() {
        let (info, buf) = test_fb();
        draw_char(buf, &info, 0, 0, b'A', 0xFFFFFFFF);
        let row0 = &buf[0..8];
        assert_eq!(row0[3], 0xFFFFFFFF);
        assert_eq!(row0[4], 0xFFFFFFFF);
        assert_eq!(row0[0], 0);
    }

    #[test]
    fn draw_str_advances_and_clips() {
        let (info, buf) = test_fb();
        draw_str(buf, &info, 28, 0, "ABC", 0xFFFFFFFF);
        assert_eq!(draw_str(buf, &info, 0, 8, "AB", 0xFFFFFFFF), 2 * GLYPH_W);
    }

    #[test]
    fn console_pushes_and_redraws() {
        let (info, buf) = test_fb();
        let mut con = TextConsole::new(&info, Color(255, 255, 255), Color(0, 0, 0));
        con.push_line("BOOT OK");
        con.redraw(buf, &info);
        assert!(buf[..8].iter().any(|&p| p != 0), "глиф отрисован");
        for i in 0..40 {
            let mut s = heapless::String::<32>::new();
            use core::fmt::Write;
            let _ = write!(s, "line {}", i);
            con.push_line(s.as_str());
        }
        con.redraw(buf, &info);
    }
}
