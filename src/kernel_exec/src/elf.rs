//! ELF64-реализация [`ExecFormat`] с КАСТОМНЫМ OS ABI.
//!
//! NOMAD использует обычный ELF64-контейнер, но с собственным индексом
//! OS ABI: `EI_OSABI == CINTOS_OSABI (0xC1)`. Обычные системные ELF'ы
//! (Linux-сборки, EI_OSABI = 0/3) ядро ОТКЛОНЯЕТ — это сознательная
//! граница: образы под NOMAD собираются целевым тулингом, и чужой
//! бинарник не может быть случайно запущен.
//!
//! Разбор delegируется крейту `xmas-elf` (no_std, zero-copy) — здесь
//! только гейты (OS ABI, machine, ET_EXEC) и сведение PT_LOAD в
//! нейтральный [`ImageInfo`]. Машинный тип передаётся при регистрации
//! (`ElfFormat::new(EM_X86_64)`) — сам формат arch-независим.

use crate::registry::{ExecError, ExecFormat, ImageInfo, SegmentDesc};
use xmas_elf::ElfFile;

/// OS ABI NOMAD в EI_OSABI (свободный индекс).
pub const CINTOS_OSABI: u8 = 0xC1;
/// EM_X86_64 (e_machine).
pub const EM_X86_64: u16 = 62;
/// ELF64-формат. Один инстанс на целевую архитектуру.
#[derive(Debug, Clone, Copy)]
pub struct ElfFormat {
    /// Ожидаемый e_machine.
    machine: u16,
}

impl ElfFormat {
    /// Формат для машины `machine` (например, [`EM_X86_64`]).
    pub const fn new(machine: u16) -> Self {
        Self { machine }
    }
}

impl ExecFormat for ElfFormat {
    fn name(&self) -> &'static str {
        "elf64-cintos"
    }

    fn probe(&self, image: &[u8]) -> bool {
        // Быстрая проверка по сырым байтам заголовка (без полного парса):
        // магия, ELFCLASS64, LSB, наш OS ABI, наша машина.
        image.len() >= 20
            && image[0] == 0x7f
            && &image[1..4] == b"ELF"
            && image[4] == 2
            && image[5] == 1
            && image[7] == CINTOS_OSABI
            && u16::from_le_bytes([image[18], image[19]]) == self.machine
    }

    fn parse(&self, image: &[u8], out: &mut ImageInfo) -> Result<(), ExecError> {
        // Полная валидация заголовков — xmas-elf.
        let file = ElfFile::new(image).map_err(|_| ExecError::BadHeader("invalid elf"))?;

        // Raw EI_OSABI/e_machine: обёртки крейта не отдают сырые значения.
        let os_abi = *image.get(7).ok_or(ExecError::Truncated)?;
        if os_abi != CINTOS_OSABI {
            return Err(ExecError::UnsupportedOsAbi(os_abi));
        }
        let machine = u16::from_le_bytes(
            image
                .get(18..20)
                .ok_or(ExecError::Truncated)?
                .try_into()
                .expect("2 bytes"),
        );
        if machine != self.machine {
            return Err(ExecError::UnsupportedMachine(machine));
        }
        if file.header.pt2.type_().as_type() != xmas_elf::header::Type::Executable {
            return Err(ExecError::BadHeader("only ET_EXEC supported"));
        }

        out.entry = file.header.pt2.entry_point() as usize;
        out.os_abi = os_abi;

        let mut loads = 0usize;
        for ph in file.program_iter() {
            if ph.get_type() != Ok(xmas_elf::program::Type::Load) {
                continue;
            }
            let file_offset = ph.offset() as usize;
            let vaddr = ph.virtual_addr() as usize;
            let file_size = ph.file_size() as usize;
            let mem_size = ph.mem_size() as usize;
            let flags = ph.flags();

            // Сегмент обязан лежать внутри образа.
            let file_end = file_offset
                .checked_add(file_size)
                .ok_or(ExecError::SegmentOutOfRange)?;
            if file_end > image.len() {
                return Err(ExecError::SegmentOutOfRange);
            }
            if mem_size < file_size {
                return Err(ExecError::BadHeader("memsz < filesz"));
            }
            let entry = SegmentDesc {
                file_offset,
                file_size,
                vaddr,
                mem_size,
                writable: flags.is_write(),
                executable: flags.is_execute(),
            };
            if out.segments.push(entry).is_err() {
                return Err(ExecError::TooManySegments);
            }
            loads += 1;
        }
        if loads == 0 {
            return Err(ExecError::NoLoadSegments);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::{boxed::Box, vec::Vec};
    use crate::registry::FormatRegistry;

    const PT_LOAD: u32 = 1;

    /// Сборщик синтетического NOMAD-ELF64 с PT_LOAD-сегментами.
    struct ElfBuilder {
        buf: Vec<u8>,
    }

    impl ElfBuilder {
        fn new(entry: u64) -> Self {
            // Резервируем phdr-область на 8 записей: данные add_load
            // дописываются в конец и не должны пересекаться с phdr-слотами
            // следующих сегментов (иначе phdr #2 затирает данные #1).
            let mut buf = std::vec![0u8; 64 + 8 * 56];
            buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            buf[4] = 2; // ELFCLASS64
            buf[5] = 1; // ELFDATA2LSB
            buf[6] = 1; // EV_CURRENT
            buf[7] = CINTOS_OSABI;
            buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
            buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
            buf[24..32].copy_from_slice(&entry.to_le_bytes());
            buf[32..40].copy_from_slice(&(64u64).to_le_bytes()); // e_phoff
            buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
            buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
            Self { buf }
        }

        fn add_load(&mut self, vaddr: u64, data: &[u8], memsz: u64, flags: u32) {
            let phnum = u16::from_le_bytes([self.buf[56], self.buf[57]]) + 1;
            self.buf[56..58].copy_from_slice(&phnum.to_le_bytes());
            let off = 64 + (phnum as usize - 1) * 56;
            self.buf[off..off + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            self.buf[off + 4..off + 8].copy_from_slice(&flags.to_le_bytes());
            let file_offset = self.buf.len() as u64;
            self.buf[off + 8..off + 16].copy_from_slice(&file_offset.to_le_bytes());
            self.buf[off + 16..off + 24].copy_from_slice(&vaddr.to_le_bytes());
            self.buf[off + 32..off + 40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            self.buf[off + 40..off + 48].copy_from_slice(&memsz.to_le_bytes());
            self.buf.extend_from_slice(data);
        }
    }

    fn registry() -> &'static FormatRegistry {
        // parse() возвращает ImageInfo с borrow-free данными, но сам
        // ElfFile внутри xmas-elf связан с image — реестр статический,
        // чтобы удержать &'static dyn ExecFormat без lifetime-танцев.
        Box::leak(Box::new({
            let mut r = FormatRegistry::new();
            let elf_format: &'static ElfFormat = Box::leak(Box::new(ElfFormat::new(EM_X86_64)));
            r.register(elf_format);
            r
        }))
    }

    #[test]
    fn parses_cintos_elf() {
        let mut elf = ElfBuilder::new(0x401_000);
        elf.add_load(0x401_000, &[0x90, 0x90, 0xC3], 3, 5); // R+X
        elf.add_load(0x402_000, &[0xAA; 4], 0x2000, 6); // R+W, с BSS

        let info = registry().parse(&elf.buf).expect("parsed");
        assert_eq!(info.os_abi, CINTOS_OSABI);
        assert_eq!(info.entry, 0x401_000);
        assert_eq!(info.segments.len(), 2);
        assert_eq!(info.segments[0].vaddr, 0x401_000);
        assert_eq!(info.segments[0].file_size, 3);
        assert!(info.segments[0].executable && !info.segments[0].writable);
        assert_eq!(info.segments[1].mem_size, 0x2000, "BSS в mem_size");
        assert_eq!(info.segments[1].file_size, 4);
        assert!(info.segments[1].writable && !info.segments[1].executable);
    }

    #[test]
    fn rejects_foreign_osabi_and_machine() {
        let mut out = crate::registry::ImageInfo {
            entry: 0,
            os_abi: 0,
            segments: heapless::Vec::new(),
        };

        // Linux-ELF (OSABI = 0) — probe не узнаёт, parse отклоняет.
        let mut linux = ElfBuilder::new(0x1000);
        linux.buf[7] = 0;
        linux.add_load(0x1000, &[1], 1, 5);
        assert!(!ElfFormat::new(EM_X86_64).probe(&linux.buf));
        assert_eq!(
            ElfFormat::new(EM_X86_64).parse(&linux.buf, &mut out),
            Err(ExecError::UnsupportedOsAbi(0))
        );

        // Наш OSABI, но чужая машина (aarch64 = 183).
        let mut aarch = ElfBuilder::new(0x1000);
        aarch.buf[18..20].copy_from_slice(&183u16.to_le_bytes());
        aarch.add_load(0x1000, &[1], 1, 5);
        assert_eq!(
            ElfFormat::new(EM_X86_64).parse(&aarch.buf, &mut out),
            Err(ExecError::UnsupportedMachine(183))
        );

        // PT_LOAD нет вообще.
        let empty = ElfBuilder::new(0x1000);
        assert_eq!(
            ElfFormat::new(EM_X86_64).parse(&empty.buf, &mut out),
            Err(ExecError::NoLoadSegments)
        );

        // Обрезанный образ.
        assert_eq!(
            ElfFormat::new(EM_X86_64).parse(&[0x7f, b'E', b'L', b'F'], &mut out),
            Err(ExecError::BadHeader("invalid elf"))
        );
    }
}
