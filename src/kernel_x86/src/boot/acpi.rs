//! Разбор ACPI-таблиц: RSDP -> XSDT/RSDT -> таблицы (DMAR, IVRS, ...).
//!
//! Только то, что нужно ядру на этапе загрузки: валидация RSDP по
//! сигнатуре/чек-суммам, обход корневой таблицы (XSDT у ACPI 2.0+ с
//! 64-битными указателями, RSDT у 1.0 с 32-битными), поиск таблиц по
//! сигнатуре с проверкой контрольной суммы самой таблицы.
//!
//! Все указатели в ACPI — ФИЗИЧЕСКИЕ; чтение идёт через HHDM
//! (`phys_to_virt`). НО: Limine (протокол rev.3) не отражает в HHDM
//! ни reserved-регионы (RSDP в низу BIOS), ни области ACPI-таблиц —
//! поэтому каждое чтение сначала ДОЧЕРЧИВАЕТ нужные страницы в текущую
//! таблицу (см. [`std_slice`] и `paging::hhdm_ensure_mapped`).
//!
//! DTB здесь НЕТ сознательно: на x86_64 DT-бут не существует в железе;
//! переносимость достижится отдельным arch-крейтом (aarch64), а не
//! подмешиванием DTB в x86-бэкенд.

use kernel_base::traits::memory::phys_to_virt;
use spin::Once;

/// Кадро-аллокатор для дочемапливания страниц ACPI на лету.
/// Устанавливается портом ДО `BootBackend::detect` (контракт).
static ACPI_FRAMES: Once<&'static (dyn kernel_base::traits::memory::FrameAllocator + Sync)> =
    Once::new();

/// Регистрирует аллокатор кадров, которым дочемапливаются страницы ACPI
/// в таблицы текущего CR3. Вызывается один раз из бут-пути порта
/// ДО `BootBackend::detect` / `init_iommu_from_boot`.
pub fn set_frame_allocator(
    frames: &'static (dyn kernel_base::traits::memory::FrameAllocator + Sync),
) {
    ACPI_FRAMES.call_once(|| frames);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// Сигнатура RSDP не "RSD PTR " или ревизия неизвестна.
    BadRsdpSignature,
    /// Контрольная сумма RSDP/таблицы не сходится.
    BadChecksum,
    /// Корневая таблица (XSDT/RSDT) отсутствует или обрезана.
    TruncatedRoot,
    /// Таблица короче заголовка или обрезана.
    TruncatedTable,
    /// Адрес вне зоны, пригодной для чтения (0 / переполнение).
    BadAddress,
}

/// Заголовок любой ACPI-таблицы (System Description Table Header).
///
/// | offset | поле          | размер |
/// |--------|---------------|--------|
/// | 0      | Signature     | 4      |
/// | 4      | Length        | 4      |
/// | 8      | Revision      | 1      |
/// | 9      | Checksum      | 1      |
/// | 10     | OEMID         | 6      |
/// | 16     | OEM Table ID  | 8      |
/// | 24     | OEM Revision  | 4      |
/// | 28     | Creator ID    | 4      |
/// | 32     | Creator Rev   | 4      |
const HEADER_LEN: usize = 36;

#[inline]
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// Сумма байтов `bytes` по модулю 256 равна нулю (ACPI-чек-сумма).
fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// Валидированный RSDP (Root System Description Pointer).
///
/// | offset | поле           | размер | с версии |
/// |--------|----------------|--------|----------|
/// | 0      | Signature      | 8      | 1.0      |
/// | 8      | Checksum       | 1      | 1.0      |
/// | 9      | OEMID          | 6      | 1.0      |
/// | 15     | Revision       | 1      | 1.0      |
/// | 16     | RSDT Address   | 4      | 1.0      |
/// | 20     | Length         | 4      | 2.0      |
/// | 24     | XSDT Address   | 8      | 2.0      |
/// | 32     | Ext. Checksum  | 1      | 2.0      |
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    revision: u8,
    rsdt_phys: usize,
    xsdt_phys: Option<usize>,
}

impl Rsdp {
    /// Разбирает и валидирует RSDP по ФИЗИЧЕСКОМУ адресу.
    ///
    /// # Safety
    /// `rsdp_phys` обязан указывать на замапленную HHDM память с RSDP
    /// (поиск по EBDA/0xE0000-0xFFFFF или указатель загрузчика).
    pub unsafe fn from_physical(rsdp_phys: usize) -> Result<Self, AcpiError> {
        if rsdp_phys == 0 {
            return Err(AcpiError::BadAddress);
        }
        // SAFETY: 36 байт RSDP 2.0 — максимум, что читаем; область замаплена.
        let raw = unsafe { std_slice(rsdp_phys, 36) }.ok_or(AcpiError::BadAddress)?;

        if raw[0..8] != *b"RSD PTR " {
            return Err(AcpiError::BadRsdpSignature);
        }
        let revision = raw[15];
        // Обязательная часть 1.0 — первые 20 байт.
        if !checksum_ok(&raw[0..20]) {
            return Err(AcpiError::BadChecksum);
        }
        let rsdt_phys = le32(raw, 16) as usize;

        let xsdt_phys = if revision >= 2 {
            let length = le32(raw, 20) as usize;
            if length < 32 || !checksum_ok(&raw[0..length.min(36)]) {
                return Err(AcpiError::BadChecksum);
            }
            let xsdt = le64(raw, 24) as usize;
            Some(xsdt)
        } else {
            None
        };

        Ok(Self {
            revision,
            rsdt_phys,
            xsdt_phys,
        })
    }

    /// Версия RSDP.
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Физический адрес корневой таблицы: XSDT (ACPI 2.0+), иначе RSDT.
    pub fn root_table_phys(&self) -> Result<usize, AcpiError> {
        if self.revision >= 2 {
            self.xsdt_phys.ok_or(AcpiError::TruncatedRoot)
        } else {
            Ok(self.rsdt_phys)
        }
    }
}

/// Корневая таблица (XSDT/RSDT): обход дочерних таблиц по 64/32-битным
/// указателям с проверкой чек-суммы каждой.
#[derive(Debug, Clone, Copy)]
pub struct AcpiTables {
    root_phys: usize,
    /// 64-битные указатели (XSDT) или 32-битные (RSDT).
    extended: bool,
    /// Число записей-указателей в корневой таблице: (Length - 36) / размер
    /// записи. Итерация ОБЯЗАНА ограничиваться этим числом: чтение за
    /// пределами таблицы даёт мусорные "указатели".
    entry_count: usize,
}

impl AcpiTables {
    /// Разбирает корневую таблицу по её физическому адресу (XSDT либо
    /// RSDT — определяется по сигнатуре).
    ///
    /// # Safety
    /// `root_phys` — замапленная HHDM память с валидной XSDT/RSDT.
    pub unsafe fn from_physical(root_phys: usize) -> Result<Self, AcpiError> {
        if root_phys == 0 {
            return Err(AcpiError::BadAddress);
        }
        // SAFETY: заголовок 36 байт; область замаплена.
        let header = unsafe { std_slice(root_phys, HEADER_LEN) }.ok_or(AcpiError::BadAddress)?;
        let extended = match &header[0..4] {
            b"XSDT" => true,
            b"RSDT" => false,
            _ => return Err(AcpiError::TruncatedRoot),
        };
        // Чек-сумма ACPI покрывает ВСЮ таблицу (по полю Length), не только
        // заголовок.
        let length = le32(header, 4) as usize;
        if length < HEADER_LEN {
            return Err(AcpiError::TruncatedRoot);
        }
        // SAFETY: длина из заголовка той же области.
        let full = unsafe { std_slice(root_phys, length) }.ok_or(AcpiError::TruncatedRoot)?;
        if !checksum_ok(full) {
            return Err(AcpiError::BadChecksum);
        }
        let entry_size = if extended { 8 } else { 4 };
        Ok(Self {
            root_phys,
            extended,
            entry_count: (length - HEADER_LEN) / entry_size,
        })
    }

    /// Обёртка над RSDP: берёт XSDT (ACPI 2.0+) или RSDT.
    pub fn from_rsdp(rsdp: &Rsdp) -> Result<Self, AcpiError> {
        // SAFETY: адрес уже валидирован в Rsdp::from_physical.
        unsafe { Self::from_physical(rsdp.root_table_phys()?) }
    }

    /// Итератор по дочерним таблицам (сырые байты, длина из заголовка).
    ///
    /// Возвращает только таблицы с корректной чек-суммой: битые записи
    /// пропускаются (в boot-данных бывают пустые слоты с нулевыми
    /// указателями).
    pub fn tables(&self) -> impl Iterator<Item = &[u8]> {
        let (root_phys, extended, entry_count) = (self.root_phys, self.extended, self.entry_count);
        (0..entry_count as u32).filter_map(move |i| {
            let ptr_off = HEADER_LEN + i as usize * if extended { 8 } else { 4 };
            // Читаем указатель и заголовок (длину) по физике.
            // SAFETY: записи корневой таблицы — замапленная HHDM память;
            // нулевые/битые указатели отфильтрованы проверками ниже.
            unsafe {
                let raw = std_slice(root_phys, ptr_off + if extended { 8 } else { 4 })?;
                let ptr = if extended {
                    le64(raw, ptr_off) as usize
                } else {
                    le32(raw, ptr_off) as usize
                };
                if ptr == 0 {
                    return None;
                }
                // Длина таблицы — u32 по смещению 4 её заголовка.
                let len_raw = std_slice(ptr, 8)?;
                let len = le32(len_raw, 4) as usize;
                if len < HEADER_LEN {
                    return None;
                }
                let table = std_slice(ptr, len)?;
                if !checksum_ok(table) {
                    return None; // битая таблица — пропускаем
                }
                Some(table)
            }
        })
    }

    /// Поиск таблицы по сигнатуре ("DMAR", "IVRS", "APIC", ...).
    pub fn find_table(&self, signature: &[u8; 4]) -> Option<&[u8]> {
        self.tables().find(|t| &t[0..4] == signature)
    }
}

/// # Safety
/// `phys..phys+len` — читаемая память (страницы дочемапливаются в HHDM
/// текущей таблицы автоматически, если аллокатор зарегистрирован).
unsafe fn std_slice(phys: usize, len: usize) -> Option<&'static [u8]> {
    let end = phys.checked_add(len)?;
    if end == 0 || len == 0 {
        return None;
    }
    // Limine rev.3 не мапит reserved/ACPI-регионы в HHDM — дочерчиваем
    // страницы ДО первого deref (поймано в QEMU: RSDP 0xF52C0 и
    // XSDT/MADT 0x1FFE2xxx давали page fault). Без аллокатора (тесты
    // хоста) — старое поведение: читаем как есть.
    if let Some(frames) = ACPI_FRAMES.get() {
        let _ = crate::paging::hhdm_ensure_mapped(*frames, phys, len);
    }
    let virt = phys_to_virt(phys);
    Some(unsafe { core::slice::from_raw_parts(virt as *const u8, len) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_base::traits::memory::set_hhdm_offset;

    /// Сборщик синтетической ACPI-структуры в тестовый буфер.
    struct TableBuilder {
        buf: &'static mut [u8],
        cursor: usize,
    }

    impl TableBuilder {
        fn new(total: usize) -> Self {
            // Странично выровненный буфер: HHDM-офсет обязан быть кратен
            // странице (инвариант set_hhdm_offset).
            let buf = crate::test_support::page_aligned_leak(total.div_ceil(4096));
            // Курсор НЕ с нуля: нулевой указатель в ACPI = пустой слот,
            // реальная таблица по адресу 0 отфильтровалась бы.
            Self { buf, cursor: 64 }
        }

        /// Добавляет таблицу с заголовком; чек-сумма проставляется автоматически.
        fn add_table(&mut self, signature: &[u8; 4], payload: &[u8]) -> usize {
            let start = self.cursor;
            let len = HEADER_LEN + payload.len();
            self.buf[start..start + 4].copy_from_slice(signature);
            self.buf[start + 4..start + 8].copy_from_slice(&(len as u32).to_le_bytes());
            self.buf[start + 8] = 2; // revision
            self.buf[start + 10..start + 16].copy_from_slice(b"CINTOS");
            self.buf[start + 36..start + len].copy_from_slice(payload);
            // Checksum: все байты таблицы (включая поле Checksum) дают 0 mod 256.
            let sum: u8 = self.buf[start..start + len]
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_add(b));
            self.buf[start + 9] = sum.wrapping_neg();
            self.cursor += len;
            start
        }

        /// "Портит" байт таблицы — чек-сумма перестаёт сходиться.
        fn corrupt(&mut self, at: usize) {
            self.buf[at] ^= 0xff;
        }
    }

    #[test]
    fn rsdp_xsdt_dmar_discovery() {
        let _guard = crate::test_support::GLOBAL.lock();
        // "Физическая память": буфер; физический 0 = начало.
        let mut tb = TableBuilder::new(4096);
        set_hhdm_offset(tb.buf.as_ptr() as usize);

        // DMAR-таблица (payload — любые байты, проверяем только поиск).
        let dmar_phys = tb.add_table(b"DMAR", &[0x33, 0x00, 0x11]);
        // APIC-таблица — для проверки фильтра по сигнатуре.
        let _apic_phys = tb.add_table(b"APIC", &[0xaa; 8]);

        // XSDT с указателями на обе таблицы.
        let mut entries = Vec::new();
        entries.extend_from_slice(&(dmar_phys as u64).to_le_bytes());
        entries.extend_from_slice(&((dmar_phys + 39) as u64).to_le_bytes());
        let xsdt_phys = tb.add_table(b"XSDT", &entries);
        // Вторая запись (APIC) затирается в нулевой указатель: пустые
        // слоты должны пропускаться итератором.
        let zero_ptr_off = 36 + 8;
        tb.buf[zero_ptr_off..zero_ptr_off + 8].copy_from_slice(&0u64.to_le_bytes());

        // RSDP 2.0.
        let rsdp_start = tb.cursor;
        tb.buf[rsdp_start..rsdp_start + 8].copy_from_slice(b"RSD PTR ");
        tb.buf[rsdp_start + 15] = 2; // revision 2
        tb.buf[rsdp_start + 16..rsdp_start + 20].copy_from_slice(&(0u32).to_le_bytes());
        tb.buf[rsdp_start + 20..rsdp_start + 24].copy_from_slice(&(36u32).to_le_bytes());
        tb.buf[rsdp_start + 24..rsdp_start + 32].copy_from_slice(&(xsdt_phys as u64).to_le_bytes());
        // Main checksum (байт 8) — по байтам 0..20; extended (байт 32) —
        // по 0..36 (length). Сначала main, потом extended.
        let main_sum: u8 = tb.buf[rsdp_start..rsdp_start + 20]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        tb.buf[rsdp_start + 8] = main_sum.wrapping_neg();
        let ext_sum: u8 = tb.buf[rsdp_start..rsdp_start + 36]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        tb.buf[rsdp_start + 32] = ext_sum.wrapping_neg();

        // ── Разбор ──
        let rsdp = unsafe { Rsdp::from_physical(rsdp_start) }.expect("rsdp");
        assert_eq!(rsdp.revision(), 2);
        let tables = AcpiTables::from_rsdp(&rsdp).expect("root");
        let dmar = tables.find_table(b"DMAR").expect("DMAR найдена");
        assert_eq!(&dmar[0..4], b"DMAR");
        assert_eq!(&dmar[36..39], &[0x33, 0x00, 0x11]);
        assert!(tables.find_table(b"HPET").is_none(), "нет такой таблицы");
    }

    #[test]
    fn bad_checksums_are_rejected() {
        let _guard = crate::test_support::GLOBAL.lock();
        let mut tb = TableBuilder::new(4096);
        set_hhdm_offset(tb.buf.as_ptr() as usize);

        let good_phys = tb.add_table(b"DMAR", &[1]);
        let bad_phys = tb.add_table(b"IVRS", &[2]);
        tb.corrupt(bad_phys + 10); // ломаем байт вне поля checksum

        // RSDP 1.0 с неверной чек-суммой — отказ.
        let rsdp_start = tb.cursor;
        tb.buf[rsdp_start..rsdp_start + 8].copy_from_slice(b"RSD PTR ");
        tb.buf[rsdp_start + 15] = 1;
        // чек-сумма не проставлена -> байты не дают 0 -> BadChecksum
        assert_eq!(
            unsafe { Rsdp::from_physical(rsdp_start) }.unwrap_err(),
            AcpiError::BadChecksum
        );

        // Корректный RSDP 1.0 + RSDT, где битая таблица отфильтрована.
        let entries = (good_phys as u32).to_le_bytes();
        let e = entries;
        let mut entries_buf = Vec::new();
        entries_buf.extend_from_slice(&e);
        entries_buf.extend_from_slice(&(bad_phys as u32).to_le_bytes());
        let rsdt_phys = tb.add_table(b"RSDT", &entries_buf);
        let rsdp_ok = tb.cursor;
        tb.buf[rsdp_ok..rsdp_ok + 8].copy_from_slice(b"RSD PTR ");
        tb.buf[rsdp_ok + 15] = 1;
        tb.buf[rsdp_ok + 16..rsdp_ok + 20].copy_from_slice(&(rsdt_phys as u32).to_le_bytes());
        let main_sum: u8 = tb.buf[rsdp_ok..rsdp_ok + 20]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        tb.buf[rsdp_ok + 8] = main_sum.wrapping_neg();

        let rsdp = unsafe { Rsdp::from_physical(rsdp_ok) }.expect("rsdp 1.0");
        let tables = AcpiTables::from_rsdp(&rsdp).expect("rsdt");
        assert!(tables.find_table(b"DMAR").is_some(), "хорошая таблица видна");
        assert!(
            tables.find_table(b"IVRS").is_none(),
            "битая чек-сумма -> таблица отфильтрована"
        );

        // Неверная сигнатура RSDP.
        assert_eq!(
            unsafe { Rsdp::from_physical(good_phys) }.unwrap_err(),
            AcpiError::BadRsdpSignature
        );
    }
}
