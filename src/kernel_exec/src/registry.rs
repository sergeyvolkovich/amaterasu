//! Форматы исполняемых файлов: подключаемый слой (arch-независимый).
//!
//! Архитектурная цель (требование NOMAD): ЗАМЕНА формата исполняемых
//! файлов не должна быть проблемой. Поэтому:
//!
//!   - формат = трейт [`ExecFormat`]: `probe()` по магии выбирает формат,
//!     `parse()` заполняет [`ImageInfo`] (entry, OSABI, сегменты) — никакой
//!     код ядра не знает про ELF напрямую;
//!   - [`FormatRegistry`] — фиксированная таблица форматов (без alloc):
//!     порт регистрирует сколько нужно (ELF-NOMAD сегодня, завтра любой
//!     контейнер/упакованный формат — добавлением одного регистра);
//!   - [`ImageInfo`] — нейтральное представление: сегменты
//!     (vaddr/file-offset/размеры/права), по которым загрузчик arch-слоя
//!     строит маппинги.
//!
//! Кастомный OS ABI: ELF-реализация требует `EI_OSABI == CINTOS_OSABI`
//! (0xC1) — обычные системные ELF'ы ядро не загружает (см. exec::elf).

use heapless::Vec as HVec;

/// Максимум загружаемых сегментов в образе.
pub const MAX_SEGMENTS: usize = 16;

/// Максимум зарегистрированных форматов.
pub const MAX_FORMATS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// Пустой/обрезанный образ.
    Truncated,
    /// Магия не совпала ни с одним зарегистрированным форматом.
    UnknownFormat,
    /// Формат узнали, но заголовок битый (класс/endianness/версия).
    BadHeader(&'static str),
    /// Чужой OS ABI (например, обычный Linux-ELF).
    UnsupportedOsAbi(u8),
    /// Чужая целевая архитектура (e_machine).
    UnsupportedMachine(u16),
    /// Программные заголовки обрезаны/за пределами образа.
    BadProgramHeaders,
    /// Нет ни одного PT_LOAD-сегмента.
    NoLoadSegments,
    /// Сегментов больше MAX_SEGMENTS.
    TooManySegments,
    /// Сегмент указывает за пределы образа.
    SegmentOutOfRange,
}

/// Дескриптор одного загружаемого сегмента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentDesc {
    /// Смещение данных в образе (файл-офсет).
    pub file_offset: usize,
    /// Размер данных в образе (файл-часть; остаток mem_size — BSS).
    pub file_size: usize,
    /// Виртуальный адрес загрузки.
    pub vaddr: usize,
    /// Полный размер в памяти (file_size + bss).
    pub mem_size: usize,
    /// Запись разрешена (PF_W).
    pub writable: bool,
    /// Исполнение разрешено (PF_X).
    pub executable: bool,
}

/// Нейтральное представление разобранного образа (heapless::Vec не Copy).
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Адрес входа (виртуальный).
    pub entry: usize,
    /// OS ABI образа (для ELF — EI_OSABI).
    pub os_abi: u8,
    /// Загружаемые сегменты.
    pub segments: HVec<SegmentDesc, MAX_SEGMENTS>,
}

/// Трейт формата исполняемого файла. Реализации — статические объекты
/// (`&'static dyn`), регистрируются в [`FormatRegistry`].
pub trait ExecFormat: Sync {
    /// Имя формата (для диагностики).
    fn name(&self) -> &'static str;

    /// Быстрая проверка: этот ли формат у образа (по магии). Вызывается
    /// на первом заголовке образа — не обязана валидировать целиком.
    fn probe(&self, image: &[u8]) -> bool;

    /// Разобрать образ в `out`. Вызывается после успешного `probe`.
    fn parse(&self, image: &[u8], out: &mut ImageInfo) -> Result<(), ExecError>;
}

/// Реестр форматов: probe -> parse. Замена формата = регистрация другого
/// `&'static dyn ExecFormat` (первыми опрашиваются ранее зарегистрированные).
pub struct FormatRegistry {
    formats: [Option<&'static dyn ExecFormat>; MAX_FORMATS],
    count: usize,
}

impl FormatRegistry {
    /// Пустой реестр.
    pub const fn new() -> Self {
        Self {
            formats: [None; MAX_FORMATS],
            count: 0,
        }
    }

    /// Регистрирует формат. Переполнение — паника на этапе старта
    /// (конфигурация ядра статична).
    pub fn register(&mut self, format: &'static dyn ExecFormat) {
        assert!(self.count < MAX_FORMATS, "format registry full");
        self.formats[self.count] = Some(format);
        self.count += 1;
    }

    /// Число зарегистрированных форматов.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Выбирает формат по probe и разбирает образ.
    pub fn parse(&self, image: &[u8]) -> Result<ImageInfo, ExecError> {
        let mut out = ImageInfo {
            entry: 0,
            os_abi: 0,
            segments: HVec::new(),
        };
        for format in self.formats.iter().take(self.count).flatten() {
            if format.probe(image) {
                format.parse(image, &mut out)?;
                return Ok(out);
            }
        }
        Err(ExecError::UnknownFormat)
    }
}

impl Default for FormatRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Фейковый формат: магия b"FAKE", один сегмент.
    struct FakeFormat;

    impl ExecFormat for FakeFormat {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn probe(&self, image: &[u8]) -> bool {
            image.len() >= 4 && &image[0..4] == b"FAKE"
        }

        fn parse(&self, image: &[u8], out: &mut ImageInfo) -> Result<(), ExecError> {
            if image.len() < 24 {
                return Err(ExecError::Truncated);
            }
            out.entry = 0x1000;
            out.os_abi = 0xC1;
            out.segments
                .push(SegmentDesc {
                    file_offset: 24,
                    file_size: image.len() - 24,
                    vaddr: 0x1000,
                    mem_size: image.len() - 24,
                    writable: false,
                    executable: true,
                })
                .map_err(|_| ExecError::TooManySegments)?;
            Ok(())
        }
    }

    #[test]
    fn registry_probes_and_parses() {
        let mut registry = FormatRegistry::new();
        registry.register(&FakeFormat);

        // Чужой формат.
        assert_eq!(
            registry.parse(b"NOPE_NOPE_NOPE").unwrap_err(),
            ExecError::UnknownFormat
        );
        // Свой: разобран.
        let mut image = Vec::new();
        image.extend_from_slice(b"FAKE");
        image.extend_from_slice(&[0u8; 24]);
        let info = registry.parse(&image).expect("parsed");
        assert_eq!(info.entry, 0x1000);
        assert_eq!(info.os_abi, 0xC1);
        assert_eq!(info.segments.len(), 1);
        assert_eq!(info.segments[0].vaddr, 0x1000);
        // Обрезанный образ — ошибка формата.
        assert_eq!(registry.parse(b"FAKE").unwrap_err(), ExecError::Truncated);
    }
}
