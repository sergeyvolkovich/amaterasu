//! flatbuf — минимальный no_std FlatBuffers-рантайм для IPC-сообщений
//! NOMAD (СЕРИАЛИЗАЦИЯ В ЮЗЕРСПЕЙСЕ; ядро — чистый L4-транспорт и
//! payload НЕ разбирает — см. ipc-сисколлы).
//!
//! Полный crates.io-крейт `flatbuffers` тянет std и аллокатор — для
//! freestanding-бинарников NOMAD это неприемлемо (дискуссия
//! google/flatbuffers#7089 про no_std висит без ответа с 2022 — no_std
//! не на дорожной карте официального биндинга; сам проволочный ФОРМАТ
//! при этом std-free). Здесь реализовано два слоя:
//!
//!   - generic-слой [`TableBuilder`]/[`TableRef`]/[`Val`] — кодирование
//!     и верифицирующее чтение ПРОИЗВОЛЬНЫХ таблиц (скаляры/Bytes/Str,
//!     дефолты, разреженные id, эволюция схем); типизированные
//!     протоколы поверх него — в [`crate::proto`];
//!   - [`Builder`] — кодировщик табличного типа `IpcMessage`;
//!   - [`MessageRef`] — верификатор/ридер того же типа (zero-copy, без
//!     аллокаций, ВСЕ границы проверяются: буфер может прийти от
//!     чужой задачи).
//!
//! `IpcMessage` — частный случай таблицы {0: label u64,
//! 1: payload [ubyte]}. Legacy-пара Builder/MessageRef сохранена как
//! есть: она самодостаточна (Builder без заимствований — обязателен
//! для C-ABI, где контекст кладётся по сырому указателю) и
//! проволочно совместима с generic-слоем В ОБЕ стороны (проверено
//! тестами compat_* ниже).
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
//! КОДИРОВАНИЕ. [`Builder`] (IpcMessage) строит back-to-front: байты
//! пишутся с КОНЦА буфера к началу, ссылки всегда вперёд (на уже
//! записанное — по более высоким адресам); смещения — в «дистанциях от
//! конца» (см. [`Builder`]). [`TableBuilder`] (generic-слой) строит
//! вперёд — раскладка `[root][vtable][таблица][векторы…]` с каноническим
//! выравниванием. Оба дают валидный канонический FlatBuffers-буфер.
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

/// i32 по границам (LE) — soffset vtable подписан.
#[inline]
fn rd_i32(b: &[u8], at: usize) -> Option<i32> {
    rd_u32(b, at).map(|v| v as i32)
}

/// Выравнивание вверх с проверкой переполнения.
#[inline]
fn align_up(v: usize, a: usize) -> Option<usize> {
    let s = v.checked_add(a - 1)?;
    Some(s - s % a)
}

// ─── Generic-слой: произвольные таблицы ───────────────────────────────

/// Максимальный id поля: vt_size = 4 + 2·(id+1) обязан влезать в u16
/// с запасом; практического IPC хватает с огромным избытком.
pub const MAX_FIELD_ID: u16 = 8191;

/// Ошибка кодирования generic-таблицы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// Слотов `MAXF` меньше, чем полей.
    TooManyFields,
    /// Поле с таким id уже установлено.
    DuplicateField,
    /// id > [`MAX_FIELD_ID`] (vtable не влезает в u16-размеры).
    FieldIdTooBig,
    /// Результат не влезает в выходной срез.
    Overflow,
    /// Переполнение/выход за u16 при расчёте раскладки.
    Layout,
}

/// Значение поля (заимствования живут до конца `encode`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Val<'a> {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    /// `[ubyte]`-вектор: проволочно `[u32 len][bytes]`.
    Bytes(&'a [u8]),
    /// Строка: проволочно `[u32 len][utf8][0]` (канонический FB).
    Str(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    B8,
    B16,
    B32,
    B64,
    Vec,
}

impl Kind {
    #[inline]
    fn size(self) -> usize {
        match self {
            Kind::B8 => 1,
            Kind::B16 => 2,
            Kind::B32 => 4,
            Kind::B64 => 8,
            Kind::Vec => 4, // в таблице — u32-ссылка
        }
    }
    #[inline]
    fn align(self) -> usize {
        self.size()
    }
}

impl Val<'_> {
    fn kind(self) -> Kind {
        match self {
            Val::Bool(_) | Val::U8(_) | Val::I8(_) => Kind::B8,
            Val::U16(_) | Val::I16(_) => Kind::B16,
            Val::U32(_) | Val::I32(_) | Val::F32(_) => Kind::B32,
            Val::U64(_) | Val::I64(_) | Val::F64(_) => Kind::B64,
            Val::Bytes(_) | Val::Str(_) => Kind::Vec,
        }
    }
}

// Сахар: b.set(3, 42u32.into()) вместо b.set(3, Val::U32(42)).
impl From<bool> for Val<'_> {
    fn from(v: bool) -> Self { Val::Bool(v) }
}
impl From<u8> for Val<'_> {
    fn from(v: u8) -> Self { Val::U8(v) }
}
impl From<u16> for Val<'_> {
    fn from(v: u16) -> Self { Val::U16(v) }
}
impl From<u32> for Val<'_> {
    fn from(v: u32) -> Self { Val::U32(v) }
}
impl From<u64> for Val<'_> {
    fn from(v: u64) -> Self { Val::U64(v) }
}
impl From<i8> for Val<'_> {
    fn from(v: i8) -> Self { Val::I8(v) }
}
impl From<i16> for Val<'_> {
    fn from(v: i16) -> Self { Val::I16(v) }
}
impl From<i32> for Val<'_> {
    fn from(v: i32) -> Self { Val::I32(v) }
}
impl From<i64> for Val<'_> {
    fn from(v: i64) -> Self { Val::I64(v) }
}
impl From<f32> for Val<'_> {
    fn from(v: f32) -> Self { Val::F32(v) }
}
impl From<f64> for Val<'_> {
    fn from(v: f64) -> Self { Val::F64(v) }
}
impl<'a> From<&'a [u8]> for Val<'a> {
    fn from(v: &'a [u8]) -> Self { Val::Bytes(v) }
}
impl<'a> From<&'a str> for Val<'a> {
    fn from(v: &'a str) -> Self { Val::Str(v) }
}

/// Кодировщик одной таблицы в фиксированный выходной срез (без heap).
///
/// Поля хранятся в массиве фиксированного размера `MAXF`, вставка —
/// по возрастанию id. Дубликат id отвергается: в FlatBuffers поле
/// идентифицируется номером.
///
/// Раскладка (вперёд, каноническая):
/// `[root u32][vtable][pad][таблица][pad][векторы…]` — таблица
/// выровнена по самому строгому полю (u64/f64 → 8), векторы — на 4.
#[derive(Debug, Clone)]
pub struct TableBuilder<'a, const MAXF: usize> {
    fields: [Option<(u16, Val<'a>)>; MAXF],
    n: usize,
}

impl<'a, const MAXF: usize> TableBuilder<'a, MAXF> {
    pub const fn new() -> Self {
        Self {
            fields: [None; MAXF],
            n: 0,
        }
    }

    /// Слот по индексу (i < n всегда занят; None-слот — Layout).
    fn get(&self, i: usize) -> Result<(u16, Val<'a>), EncodeError> {
        match self.fields.get(i) {
            Some(Some(pair)) => Ok(*pair),
            _ => Err(EncodeError::Layout),
        }
    }

    /// Устанавливает поле (id по возрастанию; дубликат — ошибка).
    pub fn set(&mut self, id: u16, v: Val<'a>) -> Result<(), EncodeError> {
        if id > MAX_FIELD_ID {
            return Err(EncodeError::FieldIdTooBig);
        }
        let mut i = 0;
        while i < self.n {
            let (fid, _) = self.get(i)?;
            if fid == id {
                return Err(EncodeError::DuplicateField);
            }
            if fid > id {
                break;
            }
            i += 1;
        }
        if self.n >= MAXF {
            return Err(EncodeError::TooManyFields);
        }
        let mut j = self.n;
        while j > i {
            self.fields[j] = self.fields[j - 1];
            j -= 1;
        }
        self.fields[i] = Some((id, v));
        self.n += 1;
        Ok(())
    }

    /// Сахар для `[ubyte]`-вектора.
    pub fn set_bytes(&mut self, id: u16, v: &'a [u8]) -> Result<(), EncodeError> {
        self.set(id, Val::Bytes(v))
    }

    /// Сахар для строки.
    pub fn set_str(&mut self, id: u16, v: &'a str) -> Result<(), EncodeError> {
        self.set(id, Val::Str(v))
    }

    /// Кодирует таблицу в `out`, возвращает длину сообщения.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let n = self.n;

        // ── 1. VTable: записи 0..=max_id (разреженные поля → 0).
        let vt_entries = match n {
            0 => 0,
            _ => self.get(n - 1)?.0 as usize + 1, // отсортирован → последний max
        };
        let vt_size: u16 =
            u16::try_from(4 + vt_entries * 2).map_err(|_| EncodeError::Layout)?;

        // ── 2. Таблица: [i32 soffset][поля по возрастанию id].
        let mut field_off = [0u16; MAXF];
        let mut cur = 4usize; // после soffset
        let mut max_align = 4usize; // soffset требует 4
        for i in 0..n {
            let (_, v) = self.get(i)?;
            let k = v.kind();
            cur = align_up(cur, k.align()).ok_or(EncodeError::Layout)?;
            field_off[i] = u16::try_from(cur).map_err(|_| EncodeError::Layout)?;
            cur = cur.checked_add(k.size()).ok_or(EncodeError::Layout)?;
            max_align = max_align.max(k.align());
        }
        let table_size: u16 = u16::try_from(cur).map_err(|_| EncodeError::Layout)?;

        // ── 3. Позиции блоков: root | vtable | таблица | векторы.
        let vtable_pos = 4usize;
        let table_pos =
            align_up(vtable_pos + vt_size as usize, max_align).ok_or(EncodeError::Layout)?;
        let table_pos =
            u32::try_from(table_pos).map_err(|_| EncodeError::Layout)? as usize;

        // ── 4. Векторы после таблицы, каждый блок выровнен на 4.
        let mut vec_pos = [0usize; MAXF];
        let mut vp =
            align_up(table_pos + table_size as usize, 4).ok_or(EncodeError::Layout)?;
        for i in 0..n {
            let (_, v) = self.get(i)?;
            let data_len = match v {
                Val::Bytes(b) => b.len(),
                Val::Str(s) => s.len() + 1, // + терминатор
                _ => continue,
            };
            vp = align_up(vp, 4).ok_or(EncodeError::Layout)?;
            vec_pos[i] = vp;
            vp = vp.checked_add(4 + data_len).ok_or(EncodeError::Layout)?;
        }
        let total = vp;
        if out.len() < total {
            return Err(EncodeError::Overflow);
        }

        // ── 5. Пишем байты (нулями закрыты паддинги и пустые записи).
        out[..total].fill(0);
        out[0..4].copy_from_slice(&(table_pos as u32).to_le_bytes());

        out[vtable_pos..vtable_pos + 2].copy_from_slice(&vt_size.to_le_bytes());
        out[vtable_pos + 2..vtable_pos + 4].copy_from_slice(&table_size.to_le_bytes());
        for i in 0..n {
            let (id, _) = self.get(i)?;
            let at = vtable_pos + 4 + 2 * id as usize;
            out[at..at + 2].copy_from_slice(&field_off[i].to_le_bytes());
        }

        // soffset = table − vtable (vtable раньше → положительный).
        let so = i32::try_from(table_pos - vtable_pos).map_err(|_| EncodeError::Layout)?;
        out[table_pos..table_pos + 4].copy_from_slice(&so.to_le_bytes());
        for i in 0..n {
            let (_, v) = self.get(i)?;
            let at = table_pos + field_off[i] as usize;
            match v {
                Val::Bool(x) => out[at] = x as u8,
                Val::U8(x) => out[at] = x,
                Val::I8(x) => out[at] = x as u8,
                Val::U16(x) => out[at..at + 2].copy_from_slice(&x.to_le_bytes()),
                Val::I16(x) => out[at..at + 2].copy_from_slice(&x.to_le_bytes()),
                Val::U32(x) => out[at..at + 4].copy_from_slice(&x.to_le_bytes()),
                Val::I32(x) => out[at..at + 4].copy_from_slice(&x.to_le_bytes()),
                Val::F32(x) => out[at..at + 4].copy_from_slice(&x.to_le_bytes()),
                Val::U64(x) => out[at..at + 8].copy_from_slice(&x.to_le_bytes()),
                Val::I64(x) => out[at..at + 8].copy_from_slice(&x.to_le_bytes()),
                Val::F64(x) => out[at..at + 8].copy_from_slice(&x.to_le_bytes()),
                Val::Bytes(b) => emit_vec(out, at, vec_pos[i], b, false)?,
                Val::Str(s) => emit_vec(out, at, vec_pos[i], s.as_bytes(), true)?,
            }
        }
        Ok(total)
    }
}

impl<'a, const MAXF: usize> Default for TableBuilder<'a, MAXF> {
    fn default() -> Self {
        Self::new()
    }
}

/// Пишет ссылку u32 из поля `at` на блок вектора `target` и сам блок
/// `[u32 len][данные][0?]`. Цель записывается позже → лежит выше →
/// uoffset строго положительный (0 зарезервирован под «отсутствует»).
fn emit_vec(
    out: &mut [u8],
    at: usize,
    target: usize,
    data: &[u8],
    terminate: bool,
) -> Result<(), EncodeError> {
    let u = target
        .checked_sub(at)
        .filter(|&u| u > 0)
        .and_then(|u| u32::try_from(u).ok())
        .ok_or(EncodeError::Layout)?;
    let len = u32::try_from(data.len()).map_err(|_| EncodeError::Layout)?;
    out[at..at + 4].copy_from_slice(&u.to_le_bytes());
    out[target..target + 4].copy_from_slice(&len.to_le_bytes());
    out[target + 4..target + 4 + data.len()].copy_from_slice(data);
    if terminate {
        out[target + 4 + data.len()] = 0;
    }
    Ok(())
}

/// Проверенное zero-copy представление произвольной таблицы поверх
/// чужого буфера.
///
/// `parse` проверяет структуру (root/vtable/таблица в границах буфера);
/// доступ к полям — через типизированные геттеры, каждый со своей
/// проверкой границ. Любое нарушение → `None`, паники исключены.
///
/// Ридер намеренно толерантнее писателя: границы/структура проверяются,
/// но НЕ абсолютное выравнивание — буферы [`Builder`] (таблица может
/// быть невыровнена абсолютно) остаются читаемыми; чтение побайтовое,
/// поэтому толерантность не ослабляет memory-safety.
///
/// ВАЖНО (каноника FlatBuffers): геттеры НЕ знают схему — тип геттера
/// обязан совпадать с типом поля в схеме протокола; несовпадение даёт
/// мусор или `None` (memory-safe в любом случае). Несоответствия ловит
/// типизированный слой — [`crate::proto`].
#[derive(Debug, Clone, Copy)]
pub struct TableRef<'a> {
    buf: &'a [u8],
    table: usize,
    vtable: usize,
    vt_size: usize,
}

impl<'a> TableRef<'a> {
    /// Полная структурная проверка буфера. `None` — не валидная таблица.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let root = rd_u32(buf, 0)? as usize;
        // Таблица не может совпадать с корнем (uoffset обязан быть > 0).
        if root < 4 || root >= buf.len() {
            return None;
        }
        let table = root;
        let so = rd_i32(buf, table)? as i64; // подписанный soffset
        let vt = (table as i64).checked_sub(so)?;
        if vt < 0 {
            return None;
        }
        let vtable = vt as usize;
        if vtable.checked_add(4)? > buf.len() {
            return None;
        }
        let vt_size = rd_u16(buf, vtable)? as usize;
        if vt_size < 4 || vtable.checked_add(vt_size)? > buf.len() {
            return None;
        }
        let table_size = rd_u16(buf, vtable + 2)? as usize;
        if table_size < 4 || table.checked_add(table_size)? > buf.len() {
            return None;
        }
        Some(Self {
            buf,
            table,
            vtable,
            vt_size,
        })
    }

    /// Позиция таблицы в буфере (диагностика/тесты).
    pub fn table_pos(&self) -> usize {
        self.table
    }

    /// Смещение поля относительно начала таблицы (0 = отсутствует).
    fn offset_of(&self, id: u16) -> Option<u16> {
        let at = self
            .vtable
            .checked_add(4)?
            .checked_add((id as usize).checked_mul(2)?)?;
        if at.checked_add(2)? > self.vtable + self.vt_size {
            // Поле за пределами vtable — отсутствует (дефолт).
            return Some(0);
        }
        rd_u16(self.buf, at)
    }

    /// Абсолютная позиция поля размера `size`; `Ok(None)` — отсутствует,
    /// `Err(())` — буфер испорчен (ссылка невалидна).
    fn field_abs(&self, id: u16, size: usize) -> Result<Option<usize>, ()> {
        let off = self.offset_of(id).ok_or(())?;
        if off == 0 {
            return Ok(None);
        }
        let at = self
            .table
            .checked_add(off as usize)
            .filter(|&a| a.checked_add(size).is_some_and(|e| e <= self.buf.len()))
            .ok_or(())?;
        Ok(Some(at))
    }

    /// Скаляр u64: `None` — буфер испорчен; отсутствующее поле — дефолт.
    pub fn get_u64(&self, id: u16, default: u64) -> Option<u64> {
        match self.field_abs(id, 8) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u64(self.buf, at),
        }
    }

    /// Скаляр u32.
    pub fn get_u32(&self, id: u16, default: u32) -> Option<u32> {
        match self.field_abs(id, 4) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u32(self.buf, at),
        }
    }

    /// Скаляр u16.
    pub fn get_u16(&self, id: u16, default: u16) -> Option<u16> {
        match self.field_abs(id, 2) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u16(self.buf, at),
        }
    }

    /// Скаляр u8.
    pub fn get_u8(&self, id: u16, default: u8) -> Option<u8> {
        match self.field_abs(id, 1) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => self.buf.get(at).copied(),
        }
    }

    /// Логическое значение: байт обязан быть 0 или 1.
    pub fn get_bool(&self, id: u16, default: bool) -> Option<bool> {
        match self.get_u8(id, default as u8)? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// Скаляр i8.
    pub fn get_i8(&self, id: u16, default: i8) -> Option<i8> {
        self.get_u8(id, default as u8).map(|v| v as i8)
    }

    /// Скаляр i16.
    pub fn get_i16(&self, id: u16, default: i16) -> Option<i16> {
        match self.field_abs(id, 2) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u16(self.buf, at).map(|v| v as i16),
        }
    }

    /// Скаляр i32.
    pub fn get_i32(&self, id: u16, default: i32) -> Option<i32> {
        self.get_u32(id, default as u32).map(|v| v as i32)
    }

    /// Скаляр i64 (LE-байты те же, что у u64).
    pub fn get_i64(&self, id: u16, default: i64) -> Option<i64> {
        self.get_u64(id, default as u64).map(|v| v as i64)
    }

    /// Скаляр f32.
    pub fn get_f32(&self, id: u16, default: f32) -> Option<f32> {
        match self.field_abs(id, 4) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u32(self.buf, at).map(f32::from_bits),
        }
    }

    /// Скаляр f64.
    pub fn get_f64(&self, id: u16, default: f64) -> Option<f64> {
        match self.field_abs(id, 8) {
            Err(()) => None,
            Ok(None) => Some(default),
            Ok(Some(at)) => rd_u64(self.buf, at).map(f64::from_bits),
        }
    }

    /// `[ubyte]`-вектор: отсутствующее поле → пустой срез; испорчено →
    /// `None`.
    pub fn get_bytes(&self, id: u16) -> Option<&'a [u8]> {
        let off = self.offset_of(id)?;
        if off == 0 {
            return Some(&[]);
        }
        let at = self.table.checked_add(off as usize)?;
        let u = rd_u32(self.buf, at)? as usize;
        let vec = at.checked_add(u)?;
        if vec <= at {
            return None; // ссылка назад/в себя невозможна в каноническом FB
        }
        let len = rd_u32(self.buf, vec)? as usize;
        let start = vec.checked_add(4)?;
        let end = start.checked_add(len)?;
        if end > self.buf.len() {
            return None;
        }
        Some(&self.buf[start..end])
    }

    /// Строка: отсутствующее поле → `""`; испорчено/не-UTF8 → `None`.
    /// Терминатор `[0]` не включается.
    pub fn get_str(&self, id: u16) -> Option<&'a str> {
        let b = self.get_bytes(id)?;
        core::str::from_utf8(b).ok()
    }
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

    // ─── Generic-слой: проволочная совместимость с IpcMessage ───────────

    /// Детерминированный LCG вместо rand-зависимости.
    struct Lcg(u32);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
            self.0
        }
    }

    /// IpcMessage через generic-слой (форма {0: label u64, 1: payload}).
    fn encode_ipc_generic(msg: &mut [u8], label: u64, payload: &[u8]) -> usize {
        let mut b = TableBuilder::<4>::new();
        b.set(0, label.into()).expect("label");
        b.set_bytes(1, payload).expect("payload");
        b.encode(msg).expect("encode")
    }

    #[test]
    fn compat_generic_writer_legacy_reader() {
        let mut out = [0u8; MAX_MSG];
        let n = encode_ipc_generic(&mut out, 0xC1A0_BEEF, b"ping-42");
        let m = MessageRef::parse(&out[..n]).expect("legacy reader обязан принять");
        assert_eq!(m.label(), 0xC1A0_BEEF);
        assert_eq!(m.payload(), b"ping-42");

        // Только label (payload отсутствует) и только payload.
        let mut out = [0u8; MAX_MSG];
        let n = encode_ipc_generic(&mut out, 7, &[]);
        let m = MessageRef::parse(&out[..n]).unwrap();
        assert_eq!(m.label(), 7);
        assert_eq!(m.payload(), b"");

        let mut b = TableBuilder::<4>::new();
        b.set_bytes(1, b"nolabel").expect("payload");
        let n = b.encode(&mut out).expect("encode");
        let m = MessageRef::parse(&out[..n]).unwrap();
        assert_eq!(m.label(), 0);
        assert_eq!(m.payload(), b"nolabel");
    }

    #[test]
    fn compat_legacy_writer_generic_reader() {
        let mut lb = Builder::new();
        lb.label(0xDEAD_BEEF).payload(b"legacy-bytes");
        let msg = lb.finish().expect("build");

        let t = TableRef::parse(msg).expect("generic reader обязан принять legacy");
        assert_eq!(t.get_u64(0, 0), Some(0xDEAD_BEEF));
        assert_eq!(t.get_bytes(1), Some(&b"legacy-bytes"[..]));
        assert_eq!(t.get_str(2), Some("")); // поля нет в legacy-буфере

        // Legacy без payload.
        let mut lb = Builder::new();
        lb.label(3);
        let msg = lb.finish().unwrap();
        let t = TableRef::parse(msg).unwrap();
        assert_eq!(t.get_u64(0, 0), Some(3));
        assert_eq!(t.get_bytes(1), Some(&[][..]));
    }

    #[test]
    fn generic_scalars_bytes_str_roundtrip() {
        let data = [1u8, 0, 2, 0, 3]; // внутренние NUL сохраняются
        let mut b = TableBuilder::<8>::new();
        b.set(0, 70_000u32.into()).unwrap();
        b.set(1, u64::MAX.into()).unwrap();
        b.set(2, (-2.25f64).into()).unwrap();
        b.set_bytes(3, &data).unwrap();
        b.set_str(4, "привет").unwrap();

        let mut out = [0u8; 128];
        let n = b.encode(&mut out).expect("encode");
        let t = TableRef::parse(&out[..n]).expect("parse");

        assert_eq!(t.get_u32(0, 0), Some(70_000));
        assert_eq!(t.get_u64(1, 0), Some(u64::MAX));
        assert_eq!(t.get_f64(2, 0.0), Some(-2.25));
        assert_eq!(t.get_bytes(3), Some(&data[..]));
        assert_eq!(t.get_str(4), Some("привет"));
        assert_eq!(t.get_u8(5, 9), Some(9)); // отсутствует → дефолт
        assert_eq!(out[n - 1], 0); // канонический терминатор строки
        assert_eq!(t.table_pos() % 8, 0); // u64 в таблице → выравнивание 8
    }

    #[test]
    fn generic_schema_evolution() {
        // v1: {0: req_id u32, 1: version str}; v2: добавил 2: uptime u64.
        let mut v1 = TableBuilder::<4>::new();
        v1.set(0, 111u32.into()).unwrap();
        v1.set_str(1, "0.9.1").unwrap();
        let mut out = [0u8; 64];
        let n = v1.encode(&mut out).expect("encode");
        let t = TableRef::parse(&out[..n]).expect("parse");

        // Читатель v2: старые поля на месте, новое — дефолт.
        assert_eq!(t.get_u32(0, 0), Some(111));
        assert_eq!(t.get_str(1), Some("0.9.1"));
        assert_eq!(t.get_u64(2, 3600), Some(3600));

        // Писатель v2, читатель v1: новые поля игнорируются безвредно.
        let mut v2 = TableBuilder::<4>::new();
        v2.set(0, 222u32.into()).unwrap();
        v2.set_str(1, "1.0.0").unwrap();
        v2.set(2, 7200u64.into()).unwrap();
        let n = v2.encode(&mut out).expect("encode");
        let t = TableRef::parse(&out[..n]).expect("parse");
        assert_eq!(t.get_u32(0, 0), Some(222));
        assert_eq!(t.get_str(1), Some("1.0.0"));
    }

    #[test]
    fn generic_builder_errors_and_overflow() {
        let mut b = TableBuilder::<2>::new();
        b.set(0, 1u32.into()).unwrap();
        assert_eq!(b.set(0, 2u32.into()), Err(EncodeError::DuplicateField));
        assert_eq!(b.set(1, 3u32.into()), Ok(()));
        assert_eq!(b.set(2, 4u32.into()), Err(EncodeError::TooManyFields));
        assert_eq!(
            b.set(MAX_FIELD_ID + 1, 5u32.into()),
            Err(EncodeError::FieldIdTooBig)
        );

        let data = [7u8; 64];
        let mut big = TableBuilder::<2>::new();
        big.set_bytes(0, &data).unwrap();
        let mut tiny = [0u8; 16];
        assert_eq!(big.encode(&mut tiny), Err(EncodeError::Overflow));
    }

    #[test]
    fn generic_no_panic_on_truncation_and_mutation() {
        let payload = b"payload-0123456789";
        let mut out = [0u8; MAX_MSG];
        let n = encode_ipc_generic(&mut out, 0x1234_5678_9ABC_DEF0, payload);

        // Читает всё, что можно, у грязного буфера — только Option'ы.
        fn read_everything(t: &TableRef<'_>) {
            let _ = t.get_bool(0, false);
            let _ = t.get_u8(0, 0);
            let _ = t.get_u16(0, 0);
            let _ = t.get_u32(0, 0);
            let _ = t.get_u64(0, 0);
            let _ = t.get_i64(0, 0);
            let _ = t.get_f64(0, 0.0);
            let _ = t.get_bytes(0);
            let _ = t.get_bytes(1);
            let _ = t.get_str(0);
            let _ = t.get_str(999);
        }

        // Усечение с каждой позиции.
        for cut in 0..n {
            if let Some(t) = TableRef::parse(&out[..cut]) {
                read_everything(&t);
            }
        }
        // Порча каждого байта (детерминированный LCG).
        let mut rng = Lcg(0xC1A0);
        let mut dirty = out;
        for i in 0..n {
            dirty[i] ^= (rng.next() >> 24) as u8;
            if let Some(t) = TableRef::parse(&dirty[..n]) {
                read_everything(&t);
            }
            dirty[i] = out[i];
        }
        // Полное сообщение валидно.
        assert!(TableRef::parse(&out[..n]).is_some());
    }
}
