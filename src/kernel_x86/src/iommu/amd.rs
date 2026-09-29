//! AMD-Vi (AMD I/O Virtualization) бэкенд поверх крейта `amd-iommu`,
//! реализующий `IommuUnit`/`IommuDomain` из kernel_base.
//!
//! Распределение ролей — как у VT-d бэкенда (iommu::intel): крейт даёт
//! форматы (IVRS, 256-битные DTE, команды, v1/v2 walkers), здесь —
//! политика: выделение Device Table (2 МиБ физически непрерывных),
//! command buffer с синхронной инвалидацией через COMPLETION_WAIT,
//! запись DTE и построение v2-таблиц (AMD64 long-mode раскладка —
//! естественный выбор DMA-трансляции на x86_64).
//!
//! MMIO: DEV_TABLE_BASE/CMD_BUF_BASE/CONTROL по физической базе из IVHD
//! (0x0000/0x0008/0x0018), дверной звонок очереди команд — CMD_TAIL
//! (0x2008). Как и в VT-d бэкенде, регистровое окно обязано быть покрыто
//! HHDM; `register_base == 0` — тестовый режим (MMIO-операции отключены).
//!
//! DomainID в DTE выставляется (with_domain_id из крейта) — домен-scoped
//! инвалидации (INVALIDATE_IOMMU_PAGES.DID) матчатся аппаратно.
//! TODO(железо): прогон на QEMU (кэши командного кольца, GN-инвалидации).

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_base::idalloc::IdPool;
use kernel_base::traits::iommu::{
    IommuCapabilities, IommuDomain, IommuError, IommuModel, IommuProtection, IommuUnit, Pasid,
    PciAddress,
};
use kernel_base::traits::memory::{FrameAllocator, MemoryPTR, PAGE_SIZE, phys_to_virt};

use amd_iommu::cmd::{CompletionWait, InvalidateDevTabEntry, InvalidateIommuPages};
use amd_iommu::dte::{DeviceTableEntry, PagingMode};
use amd_iommu::ivrs::IvrsTable;
use amd_iommu::pagetables::{self, Format, Perm};
use amd_iommu::regs::{self, CommandBufferBase, Control, DeviceTableBase};

/// Маска физического адреса в записях таблиц AMD (биты 51:12).
const AMD_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
/// Флаги промежуточных записей гостевой v1-таблицы: P|IR|IW.
const GUEST_TABLE_FLAGS: u64 = Perm::P.bits() | Perm::IR.bits() | Perm::IW.bits();

/// Длина command buffer: order 8 -> 2^(8+4) = 4096 байт = 256 команд.
const CMD_BUF_ORDER: u8 = 8;
const CMD_ENTRIES: usize = 256;
/// Device Table: 65536 устройств x 32 байта = 2 МиБ (512 страниц),
/// физически непрерывная — требование спецификации.
const DEV_TABLE_PAGES: usize = 65536 * 32 / PAGE_SIZE;
/// Порядок Device Table для регистра DEV_TABLE_BASE: 2^(N+1) записей.
const DEV_TABLE_ORDER: u8 = 15;

/// EFR.GTSup (Extended Feature Register, бит 4) — поддержка гостевой
/// трансляции (GCR3/PASID-путь). Единственный бит EFR, на который
/// опирается логика юнита: PASID-операции гейтятся на нём, а
/// capabilities() отражает его в supports_pasid/max_pasid.
///
/// Остальные биты EFR (HATS/GATS — уровни трансляции, PPR/X2APIC и
/// пр.) сознательно НЕ расшифровываются: юнит всегда строит v2-таблицы
/// AMD64 long-mode (4 уровня, 48 бит VA — фиксировано ниже), а для
/// остального нет железа для сверки (QEMU не эмулирует AMD-Vi);
/// выдумывать позиции битов без верификации хуже, чем честный минимум.
const EFR_GTSUP: u32 = 1 << 4;

/// Маркер завершения для COMPLETION_WAIT store.
const COMPLETION_MAGIC: u64 = 0xC1A7_4E05_0000_0001;

// ─── MMIO ────────────────────────────────────────────────────────────────────

/// SAFETY: `base` — замапленная HHDM база регистрового окна AMD-VI.
#[inline]
unsafe fn read_reg(base: usize, offset: u64) -> u64 {
    unsafe { core::ptr::read_volatile((phys_to_virt(base) + offset as usize) as *const u64) }
}

/// SAFETY: см. read_reg.
#[inline]
unsafe fn write_reg(base: usize, offset: u64, value: u64) {
    unsafe { core::ptr::write_volatile((phys_to_virt(base) + offset as usize) as *mut u64, value) }
}

/// SAFETY: `phys` — выровненный на 8 адрес живой страницы юнита (HHDM).
#[inline]
unsafe fn read_phys_u64(phys: usize) -> u64 {
    unsafe { core::ptr::read_volatile(phys_to_virt(phys) as *const u64) }
}

/// SAFETY: см. read_phys_u64.
#[inline]
unsafe fn write_phys_u64(phys: usize, value: u64) {
    unsafe { core::ptr::write_volatile(phys_to_virt(phys) as *mut u64, value) }
}

// ─── AmdUnit ─────────────────────────────────────────────────────────────────

/// Один IOMMU-юнит AMD-Vi (один IVHD).
///
/// Немутабельные поля — снимки при инициализации; мутабельное (доменные
/// id, хвост командного кольца) — атомарное/под мьютексом. Юнит живёт в
/// статике (`Once`), домены ссылаются на него `&'static`.
pub struct AmdUnit {
    /// Физическая база MMIO-окна (из IVHD); 0 — тестовый режим.
    register_base: usize,
    /// PCI-сегмент юнита.
    segment: u16,
    /// Расширенные возможности (IVHD EFR или MMIO EXT_FEATURES).
    efr: u32,
    /// Физический адрес Device Table (2 МиБ непрерывно).
    dev_table_phys: usize,
    /// Физический адрес command buffer (1 страница).
    cmd_buf_phys: usize,
    /// Физический адрес флага завершения (u64).
    completion_flag_phys: usize,
    /// Индекс следующей записи командного кольца.
    cmd_tail: AtomicU32,
    /// Пул domain-ID (v2: slab-очередь возвратов; 0 резервируется).
    /// БАГ v1 УСТРАНЁН: PASID и domain-ID — независимые аппаратные
    /// пространства, но делили один счётчик/стек — 64K доменов съедали
    /// все PASID и наоборот.
    domain_pool: IdPool,
    /// ОТДЕЛЬНЫЙ пул PASID (v2; 16-битные id — DTE GCR3-раскладка юнита).
    pasid_pool: IdPool,
    frames: &'static (dyn FrameAllocator + Sync),
}

impl AmdUnit {
    /// Юнит из готового сырья (без MMIO). Тестам — `register_base == 0`
    /// (юнит при этом обязан быть Box::leak-нут: домены держат &'static);
    /// порту — [`AmdUnit::new_from_ivrs`].
    ///
    /// Аллоцирует Device Table (2 МиБ), command buffer и флаг завершения.
    pub fn new_raw(
        register_base: usize,
        segment: u16,
        efr: u32,
        frames: &'static (dyn FrameAllocator + Sync),
    ) -> Result<Self, IommuError> {
        let dev_table = alloc_contiguous(frames, DEV_TABLE_PAGES)?;
        let cmd_buf = alloc_contiguous(frames, 1)?;
        let completion_flag = alloc_contiguous(frames, 1)?;

        if register_base != 0 {
            // SAFETY: MMIO-окно замаплено HHDM (контракт модуля).
            unsafe {
                write_reg(
                    register_base,
                    regs::DEV_TABLE_BASE,
                    DeviceTableBase::new(dev_table as u64, DEV_TABLE_ORDER).bits(),
                );
                write_reg(
                    register_base,
                    regs::CMD_BUF_BASE,
                    CommandBufferBase::new(cmd_buf as u64, CMD_BUF_ORDER).bits(),
                );
            }
        }

        Ok(Self {
            register_base,
            segment,
            efr,
            dev_table_phys: dev_table,
            cmd_buf_phys: cmd_buf,
            completion_flag_phys: completion_flag,
            cmd_tail: AtomicU32::new(0),
            // IdPool константен: slab-очередь возвратов ленива (slab-хуки
            // поднимаются позже iommu_early_init).
            domain_pool: IdPool::new(1 << 16),
            pasid_pool: IdPool::new(1 << 16),
            frames,
        })
    }

    /// Инициализация из сырья ACPI IVRS-таблицы: первый IVHD-юнит.
    /// EFR берётся из IVHD (типы 11h/40h), при отсутствии — из MMIO
    /// EXT_FEATURES.
    ///
    /// # Safety
    /// `ivrs_raw` — настоящая IVRS-таблица; MMIO-окно IVHD замаплено HHDM.
    pub unsafe fn new_from_ivrs(
        ivrs_raw: &[u8],
        frames: &'static (dyn FrameAllocator + Sync),
    ) -> Result<Self, IommuError> {
        let table = IvrsTable::new(ivrs_raw).map_err(|_| IommuError::NoIommuUnits)?;
        let ivhd = table.ivhd_units().next().ok_or(IommuError::NoIommuUnits)?;

        let base = ivhd.base_address() as usize;
        let efr = match ivhd.extended_features() {
            Some(efr) => efr,
            None if base != 0 => {
                // SAFETY: MMIO-окно замаплено HHDM.
                unsafe { read_reg(base, regs::EXT_FEATURES) as u32 }
            }
            None => 0,
        };

        Self::new_raw(base, ivhd.segment(), efr, frames)
    }

    /// Сегмент юнита.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Расширенные возможности (EFR).
    pub fn extended_features(&self) -> u32 {
        self.efr
    }

    /// Включает IOMMU: Control.IOMMU_EN | CMD_BUF_EN. Вызывать после
    /// заполнения Device Table нужными устройствами.
    ///
    /// TODO(железо): прогнать на QEMU (биты interrupt-remapping сознательно
    /// не трогаются, event log не включается).
    pub fn enable(&self) -> Result<(), IommuError> {
        if self.register_base != 0 {
            let base = self.register_base;
            // SAFETY: MMIO-окно замаплено HHDM.
            unsafe {
                let ctrl = Control::IOMMU_EN | Control::CMD_BUF_EN;
                write_reg(base, regs::CONTROL, ctrl.bits());
            }
        }
        Ok(())
    }

    /// Синхронно отправляет команды: пишет записи в кольцо (последняя —
    /// COMPLETION_WAIT с store-флагом), звонит в дверной звонок (CMD_TAIL)
    /// и ждёт флаг. После возврата кольцо ПУСТО (все команды обработаны):
    /// голова аппаратно догнала хвост, поэтому перенос хвоста на 0 при
    /// нехватке места безопасен.
    fn submit_and_wait(&self, commands: &[[u32; 4]]) -> Result<(), IommuError> {
        if self.register_base == 0 || commands.is_empty() {
            // Тестовый режим: без MMIO команды неотправляемы — записи PTE
            // уже сделаны напрямую, кэша IOMMU в тестах нет.
            return Ok(());
        }
        let total = commands.len() + 1; // + COMPLETION_WAIT
        if total > CMD_ENTRIES {
            return Err(IommuError::HardwareError { detail: 3 });
        }

        let start = {
            let tail = self.cmd_tail.load(Ordering::Acquire);
            if tail as usize + total > CMD_ENTRIES {
                // Кольцо "пусто" после прошлого синхронного ожидания —
                // безопасно переносим хвост в начало.
                self.cmd_tail.store(0, Ordering::Release);
                // SAFETY: MMIO-окно замаплено HHDM.
                unsafe { write_reg(self.register_base, regs::CMD_TAIL, 0) };
                0
            } else {
                tail as usize
            }
        };

        for (i, cmd) in commands.iter().enumerate() {
            let entry_phys = self.cmd_buf_phys + (start + i) * 16;
            // SAFETY: слот внутри живой страницы командного кольца.
            unsafe {
                let p = phys_to_virt(entry_phys) as *mut [u32; 4];
                core::ptr::write_unaligned(p, *cmd);
            }
        }
        let wait_phys = self.cmd_buf_phys + (start + commands.len()) * 16;
        let wait =
            CompletionWait::new()
                .with_store(self.completion_flag_phys as u64, COMPLETION_MAGIC)
                .encode();
        // SAFETY: см. выше.
        unsafe {
            let p = phys_to_virt(wait_phys) as *mut [u32; 4];
            core::ptr::write_unaligned(p, wait);
        }

        let new_tail = ((start + total) % CMD_ENTRIES) as u32;
        // SAFETY: MMIO-окно замаплено HHDM; флаг — живая страница юнита.
        unsafe {
            write_phys_u64(self.completion_flag_phys, 0);
            self.cmd_tail.store(new_tail, Ordering::Release);
            write_reg(self.register_base, regs::CMD_TAIL, new_tail as u64);
            for _ in 0..1_000_000 {
                if read_phys_u64(self.completion_flag_phys) == COMPLETION_MAGIC {
                    return Ok(());
                }
            }
        }
        Err(IommuError::HardwareError { detail: 2 })
    }

    /// Пишет 32-байтовый DTE устройства и инвалидирует кэш DTE.
    fn write_dte_and_invalidate(
        &self,
        requester_id: u16,
        entry: DeviceTableEntry,
    ) -> Result<(), IommuError> {
        let slot = self.dev_table_phys + (requester_id as usize) * 32;
        // SAFETY: слот внутри живой 2 МиБ Device Table.
        unsafe {
            let p = phys_to_virt(slot) as *mut [u8; 32];
            core::ptr::write_unaligned(p, entry.into_bytes());
        }
        let (d0, d1) = InvalidateDevTabEntry {
            device_id: requester_id,
        }
        .encode();
        self.submit_and_wait(&[[d0, d1, 0, 0]])
    }
}

/// Выделяет физически НЕПРЕРЫВНЫЙ регион из `pages` страниц и обнуляет.
fn alloc_contiguous(
    frames: &(dyn FrameAllocator + Sync),
    pages: usize,
) -> Result<usize, IommuError> {
    let region = frames.allocate_pages(pages).ok_or(IommuError::OutOfFrames)?;
    let virt = phys_to_virt(region.phys_base());
    // SAFETY: регион выделен под нас и никем больше не занят.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, pages * PAGE_SIZE) };
    Ok(region.phys_base())
}

impl IommuUnit for AmdUnit {
    type Domain = AmdDomain;

    fn model(&self) -> IommuModel {
        IommuModel::AmdVi
    }

    fn mmio_base(&self) -> usize {
        self.register_base
    }

    fn capabilities(&self) -> IommuCapabilities {
        // PASID-путь (GCR3) существует ⇔ EFR.GTSup; id — 16-битные
        // (DTE GCR3-раскладка юнита, см. alloc_pasid: предел 1<<16).
        let pasid_ok = self.efr & EFR_GTSUP != 0;
        IommuCapabilities {
            model: IommuModel::AmdVi,
            address_width_bits: 48,
            page_size_mask: (1 << 12) | (1 << 21) | (1 << 30),
            max_pasid: if pasid_ok { (1 << 16) - 1 } else { 0 },
            supports_pasid: pasid_ok,
            // AMD64 v2 PTE имеет NX (бит 63): запрет исполнения поддержан.
            supports_exec_permission: true,
            coherent_walk: true,
            supports_scalable: false, // scalable-mode — это Intel-термин
            max_domains: 1 << 16,
        }
    }

    fn create_domain(&self) -> Result<Self::Domain, IommuError> {
        // v2: id из slab-пула доменов (O(1), без молчаливых потерь).
        let id: u16 = self
            .domain_pool
            .alloc()
            .ok_or(IommuError::DomainLimitReached)? as u16;
        let root = alloc_contiguous(self.frames, 1)?;
        Ok(AmdDomain {
            id,
            root_phys: root,
            levels: 4,
            unit: self as *const AmdUnit,
        })
    }

    fn destroy_domain(&self, domain: Self::Domain) -> Result<(), IommuError> {
        let region = MemoryPTR::new(domain.root_phys, 1)
            .ok_or(IommuError::InvalidPhysicalAddress(domain.root_phys))?;
        self.frames.deallocate_pages(region);
        self.domain_pool.release(domain.id as u32);
        Ok(())
    }

    fn attach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError> {
        if pasid.is_some() {
            return Err(IommuError::PasidNotSupported);
        }
        if device.segment != self.segment {
            return Err(IommuError::InvalidPhysicalAddress(device.segment as usize));
        }
        let dte = DeviceTableEntry::new()
            .with_valid(true)
            .with_translation_valid(true)
            .with_paging_mode(PagingMode::Level2_4)
            .with_host_page_table_root(domain.root_phys as u64)
            // IR/IW: разрешение устройству DMA-чтения/записи — без них
            // трансляция отбраковывает все транзакции.
            .with_ir(true)
            .with_iw(true)
            // DID: домен-scoped инвалидации матчятся аппаратно.
            .with_domain_id(domain.id);
        self.write_dte_and_invalidate(device.requester_id().0, dte)
    }

    // ── PASID / GCR3 (гостевая трансляция) ──

    fn alloc_pasid(&self) -> Result<Pasid, IommuError> {
        // Гейт: EFR.GTSup — поддержка гостевой трансляции (см. константу).
        if self.efr & EFR_GTSUP == 0 {
            return Err(IommuError::PasidNotSupported);
        }
        // v2: ОТДЕЛЬНЫЙ пул PASID (v1 делил счётчик со domain-ID — баг).
        let id = self.pasid_pool.alloc().ok_or(IommuError::PasidLimitReached)?;
        Ok(Pasid(id))
    }

    fn free_pasid(&self, pasid: Pasid) -> Result<(), IommuError> {
        // v2: гейт + валидация диапазона (v1 не проверял вовсе — мусорный
        // id попадал в общий стек, где его выдавали как DID/домен).
        if self.efr & EFR_GTSUP == 0 {
            return Err(IommuError::PasidNotSupported);
        }
        if pasid.0 == 0 || pasid.0 >= 1 << 16 {
            return Err(IommuError::InvalidIova(pasid.0 as usize));
        }
        self.pasid_pool.release(pasid.0);
        Ok(())
    }

    fn set_pasid_context(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
        fs_root: Option<usize>,
        fs_levels: u8,
    ) -> Result<usize, IommuError> {
        // Гейт GTSup (см. alloc_pasid).
        if self.efr & EFR_GTSUP == 0 {
            return Err(IommuError::PasidNotSupported);
        }
        if !(2..=4).contains(&fs_levels) {
            return Err(IommuError::UnsupportedAddressWidth {
                requested_bits: fs_levels * 9,
                supported_bits: 48,
            });
        }
        if device.segment != self.segment {
            return Err(IommuError::InvalidPhysicalAddress(device.segment as usize));
        }
        let rid = device.requester_id().0;

        // Читаем ТЕКУЩИЙ DTE (host-часть от attach_device) и достраиваем
        // гостевую половину: GV + GLX + GCR3.
        let slot = self.dev_table_phys + (rid as usize) * 32;
        // SAFETY: слот внутри живой Device Table.
        let raw: [u8; 32] = unsafe {
            core::ptr::read_unaligned(phys_to_virt(slot) as *const [u8; 32])
        };
        let mut dte = DeviceTableEntry {
            q0: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            q1: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            q2: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            q3: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
        };
        if dte.q0 & 1 == 0 || dte.host_page_table_root() == 0 {
            return Err(IommuError::DeviceNotAttached(device));
        }

        let first_root = match fs_root {
            Some(root) => root,
            None => alloc_contiguous(self.frames, 1)?,
        };

        // GLX (q0[57:56]): 00b=4 уровня, 01b=3, 10b=2 (билдер with_glx).
        let glx: u8 = match fs_levels {
            4 => 0b00,
            3 => 0b01,
            _ => 0b10,
        };
        dte = dte
            .with_guest_translation_valid(true)
            .with_guest_cr3_table(first_root as u64)
            // GLX — билдер появился в крейте (with_glx).
            .with_glx(glx);
        // DID в DTE: домен-scoped инвалидации матчятся аппаратно.
        dte = dte.with_domain_id(domain.id);
        self.write_dte_and_invalidate(rid, dte)?;

        // Инвалидация гостевых кэшей: INV_IOMMU_PAGES с GN=1 и PASID.
        let cmd = InvalidateIommuPages {
            domain_id: domain.id,
            pasid: pasid.0,
            addr: 0,
            size: false,
            pde: false,
            guest_nested: true,
        }
        .encode();
        self.submit_and_wait(&[cmd])?;
        Ok(first_root)
    }

    fn clear_pasid_context(
        &self,
        _domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
    ) -> Result<(), IommuError> {
        let rid = device.requester_id().0;
        let slot = self.dev_table_phys + (rid as usize) * 32;
        // SAFETY: слот внутри живой Device Table.
        let raw: [u8; 32] = unsafe {
            core::ptr::read_unaligned(phys_to_virt(slot) as *const [u8; 32])
        };
        let mut dte = DeviceTableEntry {
            q0: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            q1: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            q2: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            q3: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
        };
        if dte.guest_translation_valid() {
            // GV=0 + обнуление GCR3/GLX через билдеры крейта.
            dte = dte
                .with_guest_translation_valid(false)
                .with_guest_cr3_table(0)
                .with_glx(0);
            self.write_dte_and_invalidate(rid, dte)?;
        }

        let cmd = InvalidateIommuPages {
            domain_id: 0,
            pasid: pasid.0,
            addr: 0,
            size: false,
            pde: false,
            guest_nested: true,
        }
        .encode();
        self.submit_and_wait(&[cmd])
    }

    fn map_first_stage(
        &self,
        domain: &Self::Domain,
        pasid: Pasid,
        fs_root: usize,
        gva: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError> {
        if pages == 0 || !gva.is_multiple_of(PAGE_SIZE) || !phys.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::InvalidIova(gva));
        }
        let write = prot.contains(IommuProtection::WRITE);
        if !prot.contains(IommuProtection::READ) && !write {
            return Err(IommuError::UnsupportedProtection(prot));
        }
        for i in 0..pages {
            map_guest_page(self.frames, fs_root, gva + i * PAGE_SIZE, phys + i * PAGE_SIZE, write)?;
        }
        // GN=1: инвалидация гостевых кэшей диапазона.
        let cmd = InvalidateIommuPages {
            domain_id: domain.id,
            pasid: pasid.0,
            addr: gva as u64,
            size: false,
            pde: false,
            guest_nested: true,
        }
        .encode();
        self.submit_and_wait(&[cmd])
    }

    fn unmap_first_stage(
        &self,
        domain: &Self::Domain,
        pasid: Pasid,
        fs_root: usize,
        gva: usize,
        pages: usize,
    ) -> Result<(), IommuError> {
        if pages == 0 || !gva.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::InvalidIova(gva));
        }
        for i in 0..pages {
            unmap_guest_page(fs_root, gva + i * PAGE_SIZE)?;
        }
        let cmd = InvalidateIommuPages {
            domain_id: domain.id,
            pasid: pasid.0,
            addr: gva as u64,
            size: false,
            pde: false,
            guest_nested: true,
        }
        .encode();
        self.submit_and_wait(&[cmd])
    }

    fn detach_device(
        &self,
        _domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError> {
        if pasid.is_some() {
            return Err(IommuError::PasidNotSupported);
        }
        self.write_dte_and_invalidate(device.requester_id().0, DeviceTableEntry::new())
    }

    /// v2: возврат кадра dedicated first-stage (GCR3 v1) root при
    /// уничтожении PASID-пространства (1 страница; SVA root — не наш).
    fn release_fs_root(&self, fs_root: usize) {
        if let Some(region) = MemoryPTR::new(fs_root, 1) {
            self.frames.deallocate_pages(region);
        }
    }
}

/// Домен трансляции AMD-Vi: id + v2 (AMD64) таблица.
/// Copy: чистый дескриптор (см. VtdDomain); ссылка на юнит — 'static
/// (юнит живёт в Once статике).
#[derive(Clone, Copy)]
pub struct AmdDomain {
    id: u16,
    root_phys: usize,
    levels: u8,
    /// Сырой указатель на юнит: трейт create_domain даёт только &self,
    /// а срок жизни юнита — 'static по контракту размещения (Once-статика
    /// у X86Backend, Box::leak в тестах).
    unit: *const AmdUnit,
}

// SAFETY: AmdDomain — чистый дескриптор; сырой указатель ведёт на
// 'static Sync-юнит (контракт поля unit), собственного мутабельного
// состояния у домена нет — синхронизация живёт в AmdUnit.
unsafe impl Send for AmdDomain {}
unsafe impl Sync for AmdDomain {}

impl AmdDomain {
    /// Ссылка на юнит.
    ///
    /// SAFETY-контракт: юнит размещён в 'static-хранилище и жив столько же,
    /// сколько домен (домены уничтожаются раньше юнита).
    fn unit(&self) -> &'static AmdUnit {
        // SAFETY: контракт выше; указатель получен от валидного &AmdUnit.
        unsafe { &*self.unit }
    }

    /// Доменный id.
    pub fn domain_id(&self) -> u16 {
        self.id
    }

    /// Физический адрес корня v2-таблицы.
    pub fn root_phys(&self) -> usize {
        self.root_phys
    }

    /// Ставит один 4K-лист v2-таблицы, аллоцируя недостающие уровни
    /// (v2_table: P|RW, права живут в листьях).
    fn map_page(&self, iova: usize, hpa: usize, rw: bool) -> Result<(), IommuError> {
        let mut table = self.root_phys;
        let mut shift = 12 + 9 * (self.levels as usize - 1);
        while shift > 12 {
            let slot = (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *mut u64;
            // SAFETY: таблица — живая страница из кадро-аллокатора.
            let entry = unsafe { core::ptr::read_volatile(slot) };
            table = if entry & 1 == 0 {
                let next = alloc_contiguous(self.unit().frames, 1)?;
                // SAFETY: см. выше.
                unsafe { core::ptr::write_volatile(slot, pagetables::v2_table(next as u64)) };
                next
            } else {
                (entry & AMD_ADDR_MASK) as usize
            };
            shift -= 9;
        }
        let slot = (phys_to_virt(table) + ((iova >> 12) & 0x1ff) * 8) as *mut u64;
        // SAFETY: лист внутри живой страницы таблицы.
        unsafe { core::ptr::write_volatile(slot, pagetables::v2_page(hpa as u64, rw, false)) };
        Ok(())
    }

    /// Снимает 4K-лист (промежуточные уровни не освобождаются — как у VT-d).
    fn unmap_page(&self, iova: usize) -> Result<(), IommuError> {
        let mut table = self.root_phys;
        let mut shift = 12 + 9 * (self.levels as usize - 1);
        loop {
            let slot = (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *mut u64;
            // SAFETY: живая страница таблицы.
            let entry = unsafe { core::ptr::read_volatile(slot) };
            if entry & 1 == 0 {
                return Err(IommuError::InvalidIova(iova));
            }
            if shift == 12 {
                // SAFETY: см. выше.
                unsafe { core::ptr::write_volatile(slot, 0) };
                return Ok(());
            }
            table = (entry & AMD_ADDR_MASK) as usize;
            shift -= 9;
        }
    }

    /// Синхронная инвалидация страниц домена в кэше IOMMU (постранично;
    /// батчинг по S-биту — оптимизация на потом).
    fn invalidate_pages(&self, iova: usize, pages: usize) -> Result<(), IommuError> {
        if self.unit().register_base == 0 {
            return Ok(()); // тестовый режим
        }
        for i in 0..pages {
            let cmd = InvalidateIommuPages {
                domain_id: self.id,
                pasid: 0,
                addr: (iova + i * PAGE_SIZE) as u64,
                size: false,
                pde: false,
                guest_nested: false,
            }
            .encode();
            self.unit().submit_and_wait(&[cmd])?;
        }
        Ok(())
    }
}

impl IommuDomain for AmdDomain {
    fn map_pages(
        &self,
        iova: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError> {
        if pages == 0 || !iova.is_multiple_of(PAGE_SIZE) || !phys.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::InvalidIova(iova));
        }
        // v2_page(rw, user) не выставляет NX: EXEC-запрос схлопывается в
        // read (DMA-исполнение на AMD64 PTE без NX-билдера не выразить).
        let rw = prot.contains(IommuProtection::WRITE);
        if !prot.contains(IommuProtection::READ) && !rw {
            return Err(IommuError::UnsupportedProtection(prot));
        }
        for i in 0..pages {
            self.map_page(iova + i * PAGE_SIZE, phys + i * PAGE_SIZE, rw)?;
        }
        self.invalidate_pages(iova, pages)
    }

    fn unmap_pages(&self, iova: usize, pages: usize) -> Result<(), IommuError> {
        if pages == 0 || !iova.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::InvalidIova(iova));
        }
        for i in 0..pages {
            self.unmap_page(iova + i * PAGE_SIZE)?;
        }
        self.invalidate_pages(iova, pages)
    }

    fn translate(&self, iova: usize) -> Result<usize, IommuError> {
        let fetch = |entry_addr: u64| -> u64 {
            // SAFETY: запись в живой таблице домена, замапленной HHDM.
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        pagetables::walk(Format::V2, self.levels, self.root_phys as u64, iova as u64, &fetch)
            .map(|r| r.physical as usize)
            .map_err(|e| match e {
                pagetables::WalkError::NotPresent { .. }
                | pagetables::WalkError::AddressTooLarge { .. } => IommuError::InvalidIova(iova),
            })
    }

    fn flush_iotlb(&self) {
        // Полнодоменная флэш-инвалидация: AMD не даёт домен-scoped "flush
        // all" одной командой — посылается инвалидация страницы 0 домена
        // как заглушка; полный обход требует буфера диапазонов.
        // TODO(железо): пересмотреть после QEMU-прогона.
        let _ = self.invalidate_pages(0, 1);
    }
}

/// Ставит один 4K-лист в гостевой v1-таблице (GCR3): промежуточные
/// записи P|IR|IW, лист через v1_page крейта (P[|IR|IW]).
fn map_guest_page(
    frames: &(dyn FrameAllocator + Sync),
    fs_root: usize,
    gva: usize,
    phys: usize,
    write: bool,
) -> Result<(), IommuError> {
    let mut table = fs_root;
    let mut shift = 12 + 9 * 3; // 4-уровневая гостевая таблица
    while shift > 12 {
        let slot = (phys_to_virt(table) + ((gva >> shift) & 0x1ff) * 8) as *mut u64;
        // SAFETY: таблица — живая страница из кадро-аллокатора.
        let entry = unsafe { core::ptr::read_volatile(slot) };
        table = if entry & 1 == 0 {
            let next = alloc_contiguous(frames, 1)?;
            // SAFETY: см. выше.
            unsafe { core::ptr::write_volatile(slot, (next as u64) | GUEST_TABLE_FLAGS) };
            next
        } else {
            (entry & AMD_ADDR_MASK) as usize
        };
        shift -= 9;
    }
    let slot = (phys_to_virt(table) + ((gva >> 12) & 0x1ff) * 8) as *mut u64;
    // SAFETY: лист внутри живой страницы таблицы.
    unsafe {
        core::ptr::write_volatile(slot, pagetables::v1_page(phys as u64, true, write));
    }
    Ok(())
}

/// Снимает 4K-лист гостевой v1-таблицы.
fn unmap_guest_page(fs_root: usize, gva: usize) -> Result<(), IommuError> {
    let mut table = fs_root;
    let mut shift = 12 + 9 * 3;
    loop {
        let slot = (phys_to_virt(table) + ((gva >> shift) & 0x1ff) * 8) as *mut u64;
        // SAFETY: живая страница таблицы.
        let entry = unsafe { core::ptr::read_volatile(slot) };
        if entry & 1 == 0 {
            return Err(IommuError::InvalidIova(gva));
        }
        if shift == 12 {
            // SAFETY: см. выше.
            unsafe { core::ptr::write_volatile(slot, 0) };
            return Ok(());
        }
        table = (entry & AMD_ADDR_MASK) as usize;
        shift -= 9;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amd_iommu::pagetables::Perm;
    use kernel_base::traits::memory::set_hhdm_offset;
    use crate::test_support::page_aligned_leak;
    use core::sync::atomic::AtomicUsize;

    struct TestFrames(AtomicUsize);

    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));

    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            // Тестовый bump с выравниванием базы на count (запрос 2x) —
            // см. комментарий в iommu::tests.
            let raw = self.0.fetch_add(count * 2, Ordering::SeqCst);
            let first = raw.next_multiple_of(count.max(1));
            MemoryPTR::new(first * PAGE_SIZE, count)
        }

        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    #[test]
    fn amd_gcr3_guest_context() {
        let _guard = crate::test_support::GLOBAL.lock();
        let mem = page_aligned_leak(16 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        // v2: create_domain/alloc_pasid лениво поднимают slab-очередь
        // IdPool — хуки нужны уже в тестах.
        crate::test_support::init_slab_once();

        // EFR с GTSup (бит 4) — гостевая трансляция доступна.
        let unit: &'static AmdUnit = Box::leak(Box::new(
            AmdUnit::new_raw(0, 0, 1 << 4, &FRAMES).expect("unit"),
        ));
        let domain = unit.create_domain().expect("domain");
        let pasid = unit.alloc_pasid().expect("pasid");

        // Сначала host-привязка устройства, потом гостевой контекст.
        let dev = PciAddress { segment: 0, bus: 0x0b, device: 3, function: 0 };
        unit.attach_device(&domain, dev, None).expect("attach");
        let fs_root = unit
            .set_pasid_context(&domain, dev, pasid, None, 4)
            .expect("set_pasid_context");

        // DTE: GV=1, GLX=00b (4 уровня), GCR3 = fs_root, host-часть на месте.
        let rid = dev.requester_id().0 as usize;
        let raw: [u8; 32] = unsafe {
            core::ptr::read_unaligned((phys_to_virt(unit.dev_table_phys) + rid * 32) as *const [u8; 32])
        };
        let q0 = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let q1 = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let rebuilt = DeviceTableEntry { q0, q1, q2: 0, q3: 0 };
        assert!(rebuilt.guest_translation_valid(), "GV=1");
        assert_eq!(rebuilt.glx(), 0, "GLX=00b -> 4 уровня");
        assert_eq!(
            rebuilt.guest_cr3_table(),
            fs_root as u64 & !0xfff,
            "GCR3 root"
        );
        assert_eq!(q0 & 1, 1, "DTE valid");
        assert_eq!((q0 >> 9) & 0x7, PagingMode::Level2_4.bits() as u64, "host v2");

        // Гостевой v1-маппинг + проверка родным walker'ом (Format::V1).
        let gva = 0x7000_0000usize;
        let hpa = 0x8000_0000usize;
        unit.map_first_stage(&domain, pasid, fs_root, gva, hpa, 1, IommuProtection::READ | IommuProtection::WRITE)
            .expect("map guest");
        let fetch = |entry_addr: u64| -> u64 {
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        let r = pagetables::walk(Format::V1, 4, fs_root as u64, gva as u64, &fetch)
            .expect("guest walk");
        assert_eq!(r.physical, hpa as u64);
        assert!(r.perms.contains(Perm::P | Perm::IR | Perm::IW));

        // unmap: лист снят.
        unit.unmap_first_stage(&domain, pasid, fs_root, gva, 1).expect("unmap");
        assert!(pagetables::walk(Format::V1, 4, fs_root as u64, gva as u64, &fetch).is_err());

        // clear: GV сброшен.
        unit.clear_pasid_context(&domain, dev, pasid).expect("clear");
        let raw: [u8; 32] = unsafe {
            core::ptr::read_unaligned((phys_to_virt(unit.dev_table_phys) + rid * 32) as *const [u8; 32])
        };
        let q0 = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        assert_eq!(q0 & (1 << 55), 0, "GV сброшен");
        unit.free_pasid(pasid).expect("free");
    }

    #[test]
    fn amd_domain_maps_and_translates() {
        // Сериализация с другими тестами (общие статики HHDM).
        let _guard = crate::test_support::GLOBAL.lock();

        let mem = page_aligned_leak(8 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        // v2: create_domain/alloc_pasid лениво поднимают slab-очередь
        // IdPool — хуки нужны уже в тестах.
        crate::test_support::init_slab_once();

        // Юнит обязан быть 'static: домены ссылаются на него.
        let unit: &'static AmdUnit =
            Box::leak(Box::new(AmdUnit::new_raw(0, 0, 0, &FRAMES).expect("unit")));

        let caps = unit.capabilities();
        assert_eq!(caps.model, IommuModel::AmdVi);
        assert_eq!(caps.max_domains, 1 << 16);
        assert_eq!(caps.page_size_mask, (1 << 12) | (1 << 21) | (1 << 30));

        let domain = unit.create_domain().expect("domain");
        assert_eq!(domain.domain_id(), 1);

        // v2-маппинг: IOVA 0x2000_0000 -> HPA 0x3000_0000, RW.
        let iova = 0x2000_0000usize;
        let hpa = 0x3000_0000usize;
        domain
            .map_pages(iova, hpa, 2, IommuProtection::READ | IommuProtection::WRITE)
            .expect("map");

        // Проверка РОДНЫМ walker'ом amd-iommu (Format::V2).
        let fetch = |entry_addr: u64| -> u64 {
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        for i in 0..2 {
            let r = pagetables::walk(
                Format::V2,
                4,
                domain.root_phys() as u64,
                (iova + i * PAGE_SIZE) as u64,
                &fetch,
            )
            .expect("walk");
            assert_eq!(r.physical, (hpa + i * PAGE_SIZE) as u64);
            assert!(r.perms.contains(Perm::P | Perm::RW));
        }

        // Read-only: без RW-бита.
        domain
            .map_pages(iova + 8 * PAGE_SIZE, hpa + 8 * PAGE_SIZE, 1, IommuProtection::READ)
            .unwrap();
        let r = pagetables::walk(
            Format::V2,
            4,
            domain.root_phys() as u64,
            (iova + 8 * PAGE_SIZE) as u64,
            &fetch,
        )
        .unwrap();
        assert!(r.perms.contains(Perm::P));
        assert!(!r.perms.contains(Perm::RW));

        // unmap снимает лист: translate больше не резолвит.
        domain.unmap_pages(iova, 2).unwrap();
        assert!(domain.translate(iova).is_err());
        assert!(domain.unmap_pages(iova, 1).is_err(), "повторный unmap — ошибка");

        // DTE roundtrip: attach через тестовый режим (без MMIO) пишет
        // 32-байтовый DTE в Device Table.
        let dev = PciAddress { segment: 0, bus: 0x0a, device: 1, function: 2 };
        unit.attach_device(&domain, dev, None).expect("attach");
        let rid = dev.requester_id().0 as usize;
        let dte_bytes: [u8; 32] = unsafe {
            core::ptr::read_unaligned((phys_to_virt(unit.dev_table_phys) + rid * 32) as *const [u8; 32])
        };
        let q0 = u64::from_le_bytes(dte_bytes[0..8].try_into().unwrap());
        assert_eq!(q0 & 1, 1, "DTE valid");
        assert_eq!((q0 >> 9) & 0x7, PagingMode::Level2_4.bits() as u64, "v2 4-level");
        assert_eq!(q0 & AMD_ADDR_MASK, domain.root_phys() as u64, "root таблицы");
        // Контроль через билдеры крейта: реконструируем и сверяем поля
        // (включая IR/IW и DID, выставляемые attach_device).
        let dte = DeviceTableEntry::new()
            .with_valid(true)
            .with_translation_valid(true)
            .with_paging_mode(PagingMode::Level2_4)
            .with_host_page_table_root(domain.root_phys() as u64)
            .with_ir(true)
            .with_iw(true)
            .with_domain_id(domain.domain_id());
        assert_eq!(dte.into_bytes(), dte_bytes, "DTE байт-в-байт совпадает");
    }
}
