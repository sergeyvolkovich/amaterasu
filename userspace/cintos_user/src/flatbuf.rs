//! flatbuf — минимальный no_std FlatBuffers-рантайм для IPC-сообщений
//! NOMAD (СЕРИАЛИЗАЦИЯ В ЮЗЕРСПЕЙСЕ; ядро — чистый L4-транспорт и
//! payload НЕ разбирает — см. ipc-сисколлы).
//!
//! Полный crates.io-крейт `flatbuffers` тянет std и аллокатор — для
//! freestanding-бинарников NOMAD это неприемлемо. Здесь реализовано
//! ТОЛЬКО то, что нужно IPC:
//!
//!   - [`Builder`] — кодировщик табличного типа `IpcMessage`;
//!   - [`MessageRef`] — верификатор/ридер того же типа (zero-copy, без
//!     аллокаций, ВСЕ границы проверяются: буфер может прийти от
//!     чужой задачи).
//!
//! Схема (эквивалент .fbs):
//!
//! ```fbs
//! table IpcMessage {
//!   label:   u64;      // тег типа сообщения (MR0 у Лидтке)
//!   payload: [ubyte];  // непрозрачные байты (двоичные структуры юзерспейса)
//! }
//! ```
//!
//! ПЕРЕСЫЛКА CAPABILITY — НЕ здесь: дескрипторы едут отдельным
//! kernel-side массивом сисколла IPC_SEND (аналог L4 map items),
//! доставляет их ядро (access::cap_transfer). Проволочный формат
//! сообщения содержит только данные.
//!
//! ПРОВОЛОЧНЫЙ ФОРМАТ — канонический FlatBuffers (little-endian):
//!   - `[u32 root_uoffset]` в начале буфера: target = 0 + uoffset;
//!   - таблица `[i32 soffset][данные полей...]`, vtable = table - soffset;
//!   - vtable `[u16 vt_size][u16 table_size][u16 off_поля...]`, смещения
//!     полей — от НАЧАЛА таблицы, 0 = поле отсутствует (значение по
//!     умолчанию);
//!   - вектор `[u32 count][элементы...]`.
//!
//! КОДИРОВАНИЕ (back-to-front): байты пишутся с КОНЦА буфера к началу,
//! ссылки всегда вперёд (на уже записанное — по более высоким адресам).
//! Все смещения считаются в «дистанциях от конца» (см. [`Builder`]).
//!
//! БЕЗОПАСНОСТЬ (сторонний буфер!): [`MessageRef::parse`] не паникует и
//! не читает вне переданного среза — любая ошибка структуры даёт `None`.
//! Арифметика checked, длины векторов сверяются с размером буфера ДО
//! первого чтения элементов.

#![forbid(unsafe_code)]

/// Максимум FlatBuffers-части IPC-сообщения (байт). Совпадает с лимитом
/// почтового ящика транспорта ядра (kernel_base::ipc::endpoint::MAX_MSG).
pub const MAX_MSG: usize = 512;

// ─── Чтение/запись скаляров (unaligned, little-endian) ──────────────────────

#[inline]
fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    let e = at.checked_add(2)?;
    if e > b.len() {
        return None;
    }
    Some(u16::from_le_bytes([b[at], b[at + 1]]))
}

#[inline]
fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    let e = at.checked_add(4)?;
    if e > b.len() {
        return None;
    }
    Some(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

#[inline]
fn rd_u64(b: &[u8], at: usize) -> Option<u64> {
    let e = at.checked_add(8)?;
    if e > b.len() {
        return None;
    }
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..e]);
    Some(u64::from_le_bytes(w))
}

// ─── Верификатор/ридер ──────────────────────────────────────────────────────

/// Проверенное представление `IpcMessage` поверх чужого буфера (zero-copy).
#[derive(Debug, Clone, Copy)]
pub struct MessageRef<'a> {
    buf: &'a [u8],
    /// Позиция (в байтах от начала buf) таблицы IpcMessage.
    table: usize,
    /// Позиция вектора payload ([u32 len][bytes]) или None.
    payload_vec: Option<usize>,
}

impl<'a> MessageRef<'a> {
    /// Полная проверка проволочного формата. `None` — буфер не является
    /// валидным IpcMessage (любое нарушение границ/структуры).
    ///
    /// Проверяются: корневое смещение, soffset/vtable таблицы, размеры
    /// vtable/таблицы, границы каждого поля, длина вектора payload.
    /// Отсутствующие поля легальны (значения по умолчанию).
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() > MAX_MSG || buf.len() < 4 {
            return None;
        }
        let root = rd_u32(buf, 0)? as usize;
        let table = root.checked_add(0)?; // uoffset от позиции 0
        if table < 4 || table >= buf.len() {
            return None;
        }
        let (vtable, vt_size, _table_size) = vtable_of(buf, table)?;

        // Поле 0: label (u64) — только границы.
        let label_off = field_off_in(buf, vtable, vt_size, 0)?;
        if label_off != 0 {
            let at = table.checked_add(label_off as usize)?;
            rd_u64(buf, at)?; // проверка границ
        }

        // Поле 1: payload ([u32 len][bytes]).
        let payload_off = field_off_in(buf, vtable, vt_size, 1)?;
        let payload_vec = if payload_off != 0 {
            let at = table.checked_add(payload_off as usize)?;
            let u = rd_u32(buf, at)? as usize;
            let vec = at.checked_add(u)?; // uoffset от адреса поля
            if vec <= at {
                return None; // ссылка назад невозможна в каноническом FB
            }
            let len = rd_u32(buf, vec)? as usize;
            if vec.checked_add(4)?.checked_add(len)? > buf.len() {
                return None;
            }
            Some(vec)
        } else {
            None
        };

        Some(Self {
            buf,
            table,
            payload_vec,
        })
    }

    /// Тег типа сообщения (0 — поле отсутствует).
    pub fn label(&self) -> u64 {
        read_field_u64(self.buf, self.table, 0).unwrap_or(0)
    }

    /// Payload сообщения (пустой срез — если поля нет или оно пустое).
    pub fn payload(&self) -> &'a [u8] {
        match self.payload_vec {
            Some(v) => {
                let len = rd_u32(self.buf, v).unwrap_or(0) as usize;
                let start = v + 4;
                &self.buf[start..start + len]
            }
            None => &[],
        }
    }
}

/// vtable таблицы по позиции таблицы: (vtable_pos, vt_size, table_size).
fn vtable_of(buf: &[u8], table: usize) -> Option<(usize, usize, usize)> {
    let so = rd_u32(buf, table)? as i64;
    let vtable = (table as i64).checked_sub(so)? as usize;
    let vt_size = rd_u16(buf, vtable)? as usize;
    if vt_size < 4 || vtable.checked_add(vt_size)? > buf.len() {
        return None;
    }
    let table_size = rd_u16(buf, vtable.checked_add(2)?)? as usize;
    // Таблица целиком обязана быть в буфере (table_size — консервативная
    // верхняя граница полей; реальные границы проверяются по полям).
    if table.checked_add(table_size)? > buf.len() {
        return None;
    }
    Some((vtable, vt_size, table_size))
}

/// Реальное чтение офсета поля f (0-based) из vtable (0 = отсутствует).
fn field_off_in(buf: &[u8], vtable: usize, vt_size: usize, f: usize) -> Option<u16> {
    let at = vtable.checked_add(4)?.checked_add(f.checked_mul(2)?)?;
    if at.checked_add(2)? > vtable + vt_size {
        // Поле за пределами vtable — отсутствует (по умолчанию).
        return Some(0);
    }
    rd_u16(buf, at)
}

fn read_field_u64(buf: &[u8], table: usize, f: usize) -> Option<u64> {
    let (vtable, vt_size, _) = vtable_of(buf, table)?;
    let off = field_off_in(buf, vtable, vt_size, f)?;
    if off == 0 {
        return None;
    }
    rd_u64(buf, table.checked_add(off as usize)?)
}

// ─── Кодировщик ─────────────────────────────────────────────────────────────

/// Кодировщик `IpcMessage` в фиксированном буфере (без аллокаций).
///
/// Пишет back-to-front: `d` — сколько байт уже занято ОТ КОНЦА буфера
/// (`buf[MAX_MSG - d .. MAX_MSG]` — готовое сообщение). Ссылка (u32
/// вперёд) из позиции с дистанцией `dA` на цель с дистанцией `dT` равна
/// `dA - dT` (цель записана раньше — лежит выше). soffset таблицы на
/// vtable, лежащую сразу под таблицей размером S, равен S.
///
/// Порядок сборки (сверху вниз): payload-вектор → таблица IpcMessage →
/// vtable → корневой uoffset.
#[derive(Debug, Clone)]
pub struct Builder {
    buf: [u8; MAX_MSG],
    /// Занято байт от конца.
    d: usize,
    label: u64,
    /// Буфер payload уже записан вектором ([len][bytes]) на верху.
    payload_present: bool,
    overflow: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        Self {
            buf: [0; MAX_MSG],
            d: 0,
            label: 0,
            payload_present: false,
            overflow: false,
        }
    }

    /// Тег типа сообщения (поле label).
    pub fn label(&mut self, label: u64) -> &mut Self {
        self.label = label;
        self
    }

    /// Непрозрачные байты payload (поле payload). Повторный вызов
    /// перезаписывает предыдущий (старый блок затирается записью нового
    /// с чистого d — консистентность сохранена, мусор ниже d невидим).
    pub fn payload(&mut self, bytes: &[u8]) -> &mut Self {
        // Сброс к состоянию «payload нет» и запись заново: блок payload
        // обязан быть САМЫМ ВЕРХНИМ (выше таблиц), поэтому проще
        // перезаписать с нуля, чем патчить.
        self.d = 0;
        self.payload_present = false;
        if bytes.len() + 4 > MAX_MSG {
            self.overflow = true;
            return self;
        }
        // [u32 len][bytes] одним блоком от конца.
        self.d = 4 + bytes.len();
        let start = MAX_MSG - self.d;
        self.buf[start..start + 4]
            .copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf[start + 4..MAX_MSG].copy_from_slice(bytes);
        self.payload_present = true;
        self
    }

    /// Дописывает таблицу/vtable/корень и возвращает готовое сообщение
    /// (срез внутри билдера). `None` — не влезло в MAX_MSG.
    ///
    /// АРИФМЕТИКА ДИСТАНЦИЙ (от конца буфера): позиция p ↔ дистанция
    /// d(p) = MAX_MSG − p; ссылка u32 из поля F на цель T равна
    /// d(F) − d(T) (цель записана раньше — лежит выше, дистанция
    /// меньше). Блок, записанный при переходе self.d → self.d + size,
    /// начинается на дистанции self.d + size (= self.d ПОСЛЕ записи).
    pub fn finish(&mut self) -> Option<&[u8]> {
        if self.overflow {
            return None;
        }

        // ── Таблица IpcMessage: [i32 soffset][pad4][label u64][payload u32].
        const MSG_TABLE: usize = 20;
        const MSG_VT: usize = 8; // size, table_size, label, payload
        if self.d.checked_add(MSG_TABLE + MSG_VT + 4)? > MAX_MSG {
            return None;
        }
        let d_payload_block = self.d; // дистанция начала [len][bytes]

        let base = MAX_MSG - self.d - MSG_TABLE;
        let t = &mut self.buf[base..base + MSG_TABLE];
        // soffset: vtable лежит СРАЗУ под таблицей (меньший адрес) —
        // table_pos − vtable_pos = MSG_VT.
        t[..4].copy_from_slice(&(MSG_VT as i32).to_le_bytes());
        t[8..16].copy_from_slice(&self.label.to_le_bytes());
        // payload-поле — офсет 16 от НАЧАЛА таблицы: его позиция на
        // 16 байт выше начала таблицы → дистанция D_table − 16.
        let d_table = self.d + MSG_TABLE;
        let payload_field_dist = d_table - 16;
        let payload_u = if self.payload_present {
            let u = payload_field_dist - d_payload_block;
            if u == 0 {
                return None; // дистанция совпала — невозможна
            }
            u
        } else {
            0 // 0 — недопустимый uoffset; поле отсутствует в vtable
        };
        t[16..20].copy_from_slice(&(payload_u as u32).to_le_bytes());
        self.d = d_table;

        // ── VTable IpcMessage: [vt_size][table_size][label@8][payload@16].
        let base = MAX_MSG - self.d - MSG_VT;
        let v = &mut self.buf[base..base + MSG_VT];
        v[0..2].copy_from_slice(&(MSG_VT as u16).to_le_bytes());
        v[2..4].copy_from_slice(&(MSG_TABLE as u16).to_le_bytes());
        v[4..6].copy_from_slice(&8u16.to_le_bytes()); // label @ 8
        let payload_off: u16 = if self.payload_present { 16 } else { 0 };
        v[6..8].copy_from_slice(&payload_off.to_le_bytes());
        self.d += MSG_VT;

        // ── Корневой uoffset: [u32 root -> таблица]. Поле корня — на
        // дистанции self.d + 4 (D_root), цель — D_table.
        let d_root = self.d + 4;
        let u = d_root - d_table;
        let base = MAX_MSG - self.d - 4;
        self.buf[base..base + 4].copy_from_slice(&(u as u32).to_le_bytes());
        self.d = d_root;

        Some(&self.buf[MAX_MSG - self.d..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_full() {
        let mut b = Builder::new();
        b.label(0xC1A0_BEEF).payload(b"ping-42");
        let msg = b.finish().expect("build");
        let m = MessageRef::parse(msg).expect("parse");
        assert_eq!(m.label(), 0xC1A0_BEEF);
        assert_eq!(m.payload(), b"ping-42");
    }

    #[test]
    fn roundtrip_minimal() {
        let mut b = Builder::new();
        b.label(7);
        let msg = b.finish().expect("build");
        let m = MessageRef::parse(msg).expect("parse");
        assert_eq!(m.label(), 7);
        assert_eq!(m.payload(), b"");
    }

    #[test]
    fn empty_payload_is_present() {
        let mut b = Builder::new();
        b.label(1).payload(b"");
        let msg = b.finish().expect("build");
        let m = MessageRef::parse(msg).expect("parse");
        assert_eq!(m.payload(), b"");
    }

    #[test]
    fn payload_rewritten() {
        let mut b = Builder::new();
        b.label(1).payload(b"first-longer-bytes").payload(b"ok");
        let msg = b.finish().expect("build");
        let m = MessageRef::parse(msg).expect("parse");
        assert_eq!(m.payload(), b"ok");
    }

    #[test]
    fn too_big_payload_overflows() {
        let mut b = Builder::new();
        b.payload(&[0xAB; 600]);
        assert!(b.finish().is_none());
    }

    #[test]
    fn corrupt_buffers_rejected() {
        let mut b = Builder::new();
        b.label(9).payload(b"abcdef");
        let msg = b.finish().expect("build").to_vec();

        // Усечение с каждой позиции: любая префикс-часть — невалидна.
        for cut in 1..msg.len() {
            assert!(
                MessageRef::parse(&msg[..cut]).is_none(),
                "усечение {} байт обязано ломать парс",
                cut
            );
        }
        assert!(MessageRef::parse(&msg).is_some());

        // Порча корневого смещения.
        let mut bad = msg.clone();
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MessageRef::parse(&bad).is_none());

        // Порча soffset таблицы: vtable уходит за буфер.
        let mut bad = msg.clone();
        bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MessageRef::parse(&bad).is_none());

        // Порча длин: хоть одна позиция обязана ловиться.
        let mut any_rejected = false;
        for at in 0..bad.len().saturating_sub(4) {
            let mut probe = msg.clone();
            probe[at..at + 4].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
            if MessageRef::parse(&probe).is_none() {
                any_rejected = true;
            }
        }
        assert!(any_rejected, "хоть одна порча длины обязана ловиться");
    }

    #[test]
    fn big_message_roundtrip() {
        // payload почти на весь лимит.
        let mut b = Builder::new();
        b.label(u64::MAX).payload(&[0x5A; 460]);
        let msg = b.finish().expect("build");
        assert!(msg.len() <= MAX_MSG);
        let m = MessageRef::parse(msg).unwrap();
        assert_eq!(m.payload().len(), 460);
        assert!(m.payload().iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn empty_buffer_rejected() {
        assert!(MessageRef::parse(&[]).is_none());
        assert!(MessageRef::parse(&[0, 0, 0, 0]).is_none()); // root -> сам корень
    }
}
