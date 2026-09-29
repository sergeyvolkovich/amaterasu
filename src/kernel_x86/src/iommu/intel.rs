//! Драйвер Intel VT-d поверх крейта `intel-iommu` (форматы, регистры и
//! walkers), реализующий архитектурно-независимые трейты
//! `kernel_base::traits::iommu::{IommuUnit, IommuDomain}`.
//!
//! Распределение ролей:
//!   - `intel-iommu` — ЧИСТЫЕ форматы (zerocopy-оверлеи), регистровая карта,
//!     closure-driven walkers; сам не трогает ни память, ни MMIO;
//!   - здесь — политика: аллокация таблиц и доменных id, запись
//!     root/context-записей, построение second-stage маппингов через
//!     `SecondStagePte`, инвалидации регистрами CCMD/IOTLB, включение
//!     трансляции (GCMD.SRTP/TE).
//!
//! MMIO: регистры читаются/пишутся как volatile u32/u64 по адресу
//! `phys_to_virt(register_base) + offset`. Предположение: MMIO-окно VT-d
//! покрыто HHDM-маппингом — в NOMAD это так, потому что
//! `build_identity_hhdm` мапит ВСЕ регионы карты памяти (включая Reserved,
//! где живёт MMIO) до `compute_mapped_limit`.
//!
//! ТЕСТИРУЕМОСТЬ: построение таблиц проверяется на хосте — тест мапит
//! страницы через `VtdDomain` и сверяет трансляцию РОДНЫМ
//! `intel_iommu::pagetables::walk()` (fetch через HHDM). Регистровые
//! инвалидации в тестах отключены (`mmio_base: Option<usize> == None`).
//! Порядок включения на живом железе (SRTP -> TE) на QEMU ещё не
//! прогонялся — перед реальным запуском см. TODO у `enable_translation`.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_base::idalloc::IdPool;
use kernel_base::traits::iommu::{
    IommuCapabilities, IommuDomain, IommuError, IommuModel, IommuProtection, IommuUnit, Pasid,
    PciAddress,
};
use kernel_base::traits::memory::{
    FrameAllocator, MemoryPTR, PAGE_SIZE, phys_to_virt,
};

use intel_iommu::context::{
    AddrWidth, ContextEntry, Flpm, PasidTableEntry, Pgtt, ScalableContextEntry, TransType,
};
use intel_iommu::dmar::DmarTable;
use intel_iommu::pagetables::{self, Perm, SecondStagePte, Stage};
use intel_iommu::qi::{Granularity, QiIotlb, QiPc, QiWait};
use intel_iommu::regs::{self, Cap, Ecap};

// ─── Регистровый доступ ──────────────────────────────────────────────────────

/// SAFETY: `base` — физическая база MMIO-блока VT-d, замапленная HHDM;
/// размер окна >= 0x100 (все используемые регистры).
#[inline]
unsafe fn read_reg64(base: usize, offset: u64) -> u64 {
    unsafe { core::ptr::read_volatile((phys_to_virt(base) + offset as usize) as *const u64) }
}

/// SAFETY: см. read_reg64.
#[inline]
unsafe fn read_reg32(base: usize, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((phys_to_virt(base) + offset as usize) as *const u32) }
}

/// SAFETY: см. read_reg64.
#[inline]
unsafe fn write_reg32(base: usize, offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile((phys_to_virt(base) + offset as usize) as *mut u32, value) }
}

/// SAFETY: см. read_reg64.
#[inline]
unsafe fn write_reg64(base: usize, offset: u64, value: u64) {
    unsafe { core::ptr::write_volatile((phys_to_virt(base) + offset as usize) as *mut u64, value) }
}

// ─── Конверсии типов трейта <-> intel-iommu ─────────────────────────────────

/// Семантические права трейта -> биты second-stage PTE (spec 9.8: R=0, W=1, X=2).
fn protection_to_perm(prot: IommuProtection) -> Perm {
    let mut perm = Perm::empty();
    if prot.contains(IommuProtection::READ) {
        perm |= Perm::R;
    }
    if prot.contains(IommuProtection::WRITE) {
        perm |= Perm::W;
    }
    if prot.contains(IommuProtection::EXEC) {
        perm |= Perm::X;
    }
    perm
}

// ─── VtdUnit ─────────────────────────────────────────────────────────────────

/// Один IOMMU-юнит VT-d (один DRHD). Реализация `IommuUnit`.
///
/// Устойчивость: все поля — снимки, сделанные при инициализации; MMIO
/// доступ — только volatile-чтения/записи, а мутабельное состояние
/// (доменные id) — атомарное/под мьютексом, поэтому `Sync` корректен
/// (трейт требует `&self` на create_domain: домены создаются из разных
/// ядер).
pub struct VtdUnit {
    /// Физическая база MMIO-регистров (из DRHD); 0 — тестовый режим
    /// (регистровые инвалидации отключены).
    register_base: usize,
    /// PCI-сегмент, обслуживаемый юнитом.
    segment: u16,
    /// Декодированный CAP_REG.
    cap: Cap,
    /// Декодированный ECAP_REG.
    ecap: Ecap,
    /// Физический адрес root-таблицы (1 страница, 256 записей по шинам).
    root_table_phys: usize,
    /// Кадро-аллокатор для таблиц (root/context/страницы трансляции).
    frames: &'static (dyn FrameAllocator + Sync),
    /// Число доменных id, выражаемое CAP.ND.
    max_domain_ids: u32,
    /// AGAW: 4-уровневая (48 бит) или 3-уровневая (39 бит) трансляция.
    levels: u8,
    agaw: AddrWidth,
    /// Scalable-mode: ECAP.SRS && ECAP.PASIDE.
    scalable: bool,
    /// QI-кольцо (1 страница, 256 дескрипторов по 16 байт).
    qi_ring_phys: usize,
    /// Страница статус-флагов QI (u32, 8-байт выровнен).
    qi_status_phys: usize,
    /// Хвост QI-кольца (индекс дескриптора).
    qi_tail: AtomicU32,
    /// PASID-директория (1 страница, PDTS=0: 2^7 = 128 записей по 16 байт;
    /// индекс PASID[19:9]).
    pasid_dir_phys: usize,
    /// Пул domain-ID (v2: slab-очередь возвратов вместо фиксированного
    /// стека на 16 слотов — без молчаливой потери id; 0 резервируется).
    domain_pool: IdPool,
    /// Пул PASID (v2: ОТДЕЛЬНЫЙ от domain-ID; потолок — размер
    /// PASID-таблицы юнита).
    pasid_pool: IdPool,
}


/// ECAP.PASIDE (бит 40) — поддержка PASID; ECAP.SRS (бит 41) — scalable
/// root/context. Оба нужны для scalable-режима.
const ECAP_PASIDE: u64 = 1 << 40;
const ECAP_SRS: u64 = 1 << 41;
/// RTADDR.RTT (бит 12): 1 = scalable root/context-таблицы.
const RTADDR_RTT: u64 = 1 << 12;
/// GCMD/GSTS: включение Queued Invalidation (бит 26).
const GCMD_QIE: u32 = 1 << 26;
const GSTS_QIES: u32 = 1 << 26;
/// IQA.QS = 4: кольцо 2^(4+8) = 4096 байт = 256 дескрипторов по 16 байт.
const QI_RING_ORDER: u64 = 4;
const QI_ENTRIES: usize = 256;
/// Магазин-флаг завершения QI (u32, пишется дескриптором Wait).
const QI_MAGIC: u32 = 0xC17_0505;
/// PASID-таблица: 8 страниц (32 КиБ, 32 КиБ выровнены): 512 записей по
/// 64 байта, индекс PASID[8:0]. PASID юнита ограничен 0..512.
const PASID_TABLE_PAGES: usize = 8;
const MAX_PASID: u32 = 512;
/// Флаги промежуточных first-stage записей (Intel-64: P|RW|US|A; бит 2 —
/// US, не X).
impl VtdUnit {
    /// Собирает юнит из готового сырья (без MMIO). Используется тестами;
    /// порту — [`VtdUnit::new_from_dmar`].
    ///
    /// Аллоцирует root-таблицу и вычисляет AGAW из `cap_raw`.
    /// `register_base == 0` — тестовый режим: регистровые операции
    /// (RTADDR/инвалидации/enable_translation) отключены.
    pub fn new_raw(
        register_base: usize,
        segment: u16,
        cap_raw: u64,
        ecap_raw: u64,
        frames: &'static (dyn FrameAllocator + Sync),
    ) -> Result<Self, IommuError> {
        let cap = Cap::new(cap_raw);
        let ecap = Ecap::new(ecap_raw);

        // AGAW: предпочитаем 48-бит (4 уровня), откатываемся на 39 (3
        // уровня), если SAGAW не поддерживает 4-уровневые таблицы.
        let sagaw = cap.sagaw();
        let (levels, agaw) = if sagaw & 0b100 != 0 {
            (4u8, AddrWidth::Agaw48)
        } else if sagaw & 0b010 != 0 {
            (3u8, AddrWidth::Agaw39)
        } else {
            return Err(IommuError::UnsupportedAddressWidth {
                requested_bits: 48,
                supported_bits: cap.mgaw() as u8,
            });
        };

        // Scalable-mode: нужны ОБА бита — PASIDE (принимать PASID-запросы)
        // и SRS (scalable root/context).
        let scalable = ecap.0 & (ECAP_PASIDE | ECAP_SRS) == (ECAP_PASIDE | ECAP_SRS);

        let root_page = alloc_table_page(frames)?;
        let qi_ring = alloc_table_page(frames)?;
        let qi_status = alloc_table_page(frames)?;
        let pasid_dir = alloc_table_page(frames)?;

        if register_base != 0 {
            let rtt = if scalable { RTADDR_RTT } else { 0 };
            // SAFETY: MMIO-окно замаплено HHDM (контракт модуля).
            unsafe {
                // RTADDR: root-таблица + RTT (1 = scalable root/context).
                write_reg64(register_base, regs::RTADDR, root_page as u64 | rtt);
                // IQA: кольцо + QS. QIE включится в enable_translation
                // (до SRTP — дескрипторы недействительны без QI в scalable).
                write_reg64(register_base, regs::IQA, qi_ring as u64 | QI_RING_ORDER);
            }
        }

        Ok(Self {
            register_base,
            segment,
            cap,
            ecap,
            root_table_phys: root_page,
            frames,
            max_domain_ids: cap.domain_ids(),
            // IdPool константен: slab-очередь возвратов создаётся лениво
            // при первом free (slab-хуки поднимаются позже iommu_early_init).
            domain_pool: IdPool::new(cap.domain_ids()),
            pasid_pool: IdPool::new(MAX_PASID),
            levels,
            agaw,
            scalable,
            qi_ring_phys: qi_ring,
            qi_status_phys: qi_status,
            qi_tail: AtomicU32::new(0),
            pasid_dir_phys: pasid_dir,
        })
    }

    /// Инициализация из сырья ACPI DMAR-таблицы: берёт ПЕРВЫЙ DRHD-юнит,
    /// читает CAP/ECAP из MMIO. `dmar_raw` — полные байты таблицы
    /// (порт достаёт их из RSDP/XSDT; энумерация PCI — userspace).
    ///
    /// # Safety
    /// `dmar_raw` обязан указывать на настоящую DMAR-таблицу; MMIO-окно
    /// первого DRHD обязано быть доступно через HHDM.
    pub unsafe fn new_from_dmar(
        dmar_raw: &[u8],
        frames: &'static (dyn FrameAllocator + Sync),
    ) -> Result<Self, IommuError> {
        let table = DmarTable::new(dmar_raw).map_err(|_| IommuError::NoIommuUnits)?;
        let drhd = table.drhd_units().next().ok_or(IommuError::NoIommuUnits)?;

        let base = drhd.register_base() as usize;
        if !base.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::HardwareError { detail: base as u64 });
        }
        // SAFETY: окно заявлено DRHD; читаем CAP/ECAP (offsets 0x08/0x10).
        let cap_raw = unsafe { read_reg64(base, regs::CAP) };
        let ecap_raw = unsafe { read_reg64(base, regs::ECAP) };

        Self::new_raw(base, drhd.segment(), cap_raw, ecap_raw, frames)
    }

    /// Сегмент юнита.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Включает трансляцию: SRTP (загрузка root-указателя) -> TE.
    /// Ждёт подтверждения в GSTS. Вызывать один раз при старте, ПОСЛЕ
    /// того как в root-таблицу записаны все нужные устройства.
    ///
    /// TODO(железо): последовательность не прогонялась на QEMU — проверить
    /// поведение RWBF (CAP.RWBF требует flush write-буферов перед TE).
    pub fn enable_translation(&mut self) -> Result<(), IommuError> {
        const GCMD_SRTP: u32 = 1 << 30;
        const GCMD_TE: u32 = 1 << 31;
        const GSTS_RTPS: u32 = 1 << 30;
        const GSTS_TES: u32 = 1 << 31;
        let base = self.register_base;
        // SAFETY: MMIO-окно замаплено HHDM (контракт модуля).
        unsafe {
            if self.scalable {
                // QI обязателен для scalable: включаем ДО загрузки root.
                write_reg32(base, regs::GCMD, GCMD_QIE);
                wait_gsts(base, GSTS_QIES)?;
            }
            write_reg32(base, regs::GCMD, GCMD_SRTP);
            wait_gsts(base, GSTS_RTPS)?;
            write_reg32(base, regs::GCMD, GCMD_SRTP | GCMD_TE);
            wait_gsts(base, GSTS_TES)?;
        }
        Ok(())
    }

    /// Scalable-mode юнита (ECAP.SRS && PASIDE).
    pub fn scalable(&self) -> bool {
        self.scalable
    }

    /// Физический адрес PASID-директории (диагностика/тесты).
    pub fn pasid_dir_phys_for_test(&self) -> usize {
        self.pasid_dir_phys
    }

    /// Физический адрес root-таблицы (диагностика/тесты).
    pub fn root_table_phys(&self) -> usize {
        self.root_table_phys
    }

    /// Синхронная отправка QI-дескрипторов: записи в кольцо, последним —
    /// Wait-дескриптор со status-write, дверной звонок IQT, ожидание флага.
    /// После возврата кольцо пусто (все дескрипторы обработаны) — перенос
    /// хвоста на 0 безопасен.
    fn qi_submit_and_wait(&self, descs: &[[u64; 2]]) -> Result<(), IommuError> {
        if self.register_base == 0 || descs.is_empty() {
            return Ok(()); // тестовый режим: кэшей IOMMU нет
        }
        let total = descs.len() + 1; // + Wait
        if total > QI_ENTRIES {
            return Err(IommuError::HardwareError { detail: 3 });
        }
        let start = {
            let tail = self.qi_tail.load(Ordering::Acquire);
            if tail as usize + total > QI_ENTRIES {
                self.qi_tail.store(0, Ordering::Release);
                // SAFETY: MMIO-окно замаплено HHDM.
                unsafe { write_reg64(self.register_base, regs::IQT, 0) };
                0
            } else {
                tail as usize
            }
        };
        for (i, d) in descs.iter().enumerate() {
            let p = (phys_to_virt(self.qi_ring_phys) + (start + i) * 16) as *mut [u64; 2];
            // SAFETY: слот внутри живой страницы кольца.
            unsafe { core::ptr::write_unaligned(p, *d) };
        }
        let wait = QiWait::status_write(self.qi_status_phys as u64, QI_MAGIC).to_words();
        let wp = (phys_to_virt(self.qi_ring_phys) + (start + descs.len()) * 16) as *mut [u64; 2];
        // SAFETY: см. выше.
        unsafe { core::ptr::write_unaligned(wp, wait) };

        let new_tail = ((start + total) % QI_ENTRIES) as u32;
        // SAFETY: MMIO/статус-страница замаплены HHDM.
        unsafe {
            core::ptr::write_volatile(phys_to_virt(self.qi_status_phys) as *mut u32, 0);
            self.qi_tail.store(new_tail, Ordering::Release);
            write_reg64(self.register_base, regs::IQT, new_tail as u64);
            for _ in 0..1_000_000 {
                if core::ptr::read_volatile(phys_to_virt(self.qi_status_phys) as *const u32)
                    == QI_MAGIC
                {
                    return Ok(());
                }
            }
        }
        Err(IommuError::HardwareError { detail: 2 })
    }

    /// Записывает 32-байтовый scalable context entry устройства
    /// (PASIDE-включён, директория PASID подключена).
    fn write_scalable_context_entry(
        &self,
        bus: usize,
        devfn: u8,
    ) -> Result<(), IommuError> {
        let (table, entry_size) = self.context_table_for_bus(bus)?;
        debug_assert_eq!(entry_size, 32);
        let entry = {
            let mut e = ScalableContextEntry::new()
                .with_present(true)
                .with_pasid_dir_size(0) // 2^7 = 128 записей директории
                .with_pasid_dir_ptr(self.pasid_dir_phys as u64);
            // PASIDE (бит 3) — билдера в крейте нет, поле публичное.
            e.q0 |= 8;
            e
        };
        // Сериализация вручную: у ScalableContextEntry в крейте нет
        // into_bytes (фидбек крейту); раскладка = q0, q1, reserved[2].
        let slot = (phys_to_virt(table) + (devfn as usize) * 32) as *mut [u64; 4];
        // SAFETY: слот внутри живой context-таблицы.
        unsafe {
            core::ptr::write_unaligned(
                slot,
                [entry.q0, entry.q1, entry.reserved[0], entry.reserved[1]],
            );
        }
        Ok(())
    }

    /// Физический адрес PASID-таблицы устройства из его директории
    /// (аллоцируя при первом обращении).
    fn pasid_table_for_device(&self, rid: u16) -> Result<usize, IommuError> {
        let dir_index = ((rid >> 9) & 0x7f) as usize;
        let dir_slot = (phys_to_virt(self.pasid_dir_phys) + dir_index * 16) as *mut u64;
        // SAFETY: слот внутри живой страницы PASID-директории.
        let entry = unsafe { core::ptr::read_volatile(dir_slot) };
        if entry & 1 != 0 {
            return Ok((entry & !0xfff) as usize);
        }
        let table = alloc_aligned_contiguous(self.frames, PASID_TABLE_PAGES)?;
        // SAFETY: см. выше.
        unsafe { core::ptr::write_volatile(dir_slot, (table as u64) | 1) };
        Ok(table)
    }

    /// Записывает context-запись устройства в таблицы юнита.
    ///
    /// `devfn` — младшие 8 бит requester id (device[7:3] | function[2:0]);
    /// bus выбирает root-запись, devfn — слот в context-таблице шины.
    fn write_context_entry(
        &self,
        bus: usize,
        devfn: u8,
        entry: ContextEntry,
    ) -> Result<(), IommuError> {
        let (context_table, entry_size) = self.context_table_for_bus(bus)?;
        debug_assert_eq!(entry_size, 16);
        let bytes = entry.into_bytes();
        // Указатель на слот context-таблицы (живая страница из
        // кадро-аллокатора). Контракт видимости: запись выполняется до
        // enable_translation либо пока трансляция устройства запрещена;
        // после включения TE любое изменение записи сопровождается
        // invalidate_context_cache (вызывается наверху).
        let slot = (phys_to_virt(context_table) + (devfn as usize) * 16) as *mut [u8; 16];
        // SAFETY: слот внутри живой страницы context-таблицы.
        unsafe { core::ptr::write_unaligned(slot, bytes) };
        Ok(())
    }

    /// Возвращает (аллоцируя при первом обращении) context-таблицу шины:
    /// (физика, размер записи). Legacy — 1 страница / 16 байт; scalable —
    /// 2 страницы (8 КиБ, выровнены) / 32 байта.
    fn context_table_for_bus(&self, bus: usize) -> Result<(usize, usize), IommuError> {
        if bus >= 256 {
            return Err(IommuError::InvalidIova(bus));
        }
        let entry_size = if self.scalable { 32 } else { 16 };
        let root = unsafe { root_table_slice(self.root_table_phys) };
        let entry = root[bus];
        if entry & 1 != 0 {
            return Ok(((entry & !0xfff) as usize, entry_size));
        }
        let table = if self.scalable {
            alloc_aligned_contiguous(self.frames, 2)?
        } else {
            alloc_table_page(self.frames)?
        };
        root[bus] = (table as u64) | 1;
        Ok((table, entry_size))
    }

    /// Инвалидация context-кэша (глобальная) регистром CCMD.
    ///
    /// Кодировка: ICC=1 (бит 31), CAIG=01b (глобальная, бит 32) — как в
    /// Linux (DMA_CCMD_GLOBAL_INCL). В тестовом режиме (base == 0) — no-op.
    fn invalidate_context_cache(&self, _domain_id: u16) {
        if self.register_base != 0 {
            const CCMD_ICC: u64 = 1 << 31;
            const CCMD_CAIG_GLOBAL: u64 = 1 << 32;
            let base = self.register_base;
            // SAFETY: MMIO-окно замаплено HHDM.
            unsafe {
                write_reg64(base, regs::CCMD, CCMD_ICC | CCMD_CAIG_GLOBAL);
                // ICC аппаратно сбрасывается по завершении.
                loop {
                    if read_reg64(base, regs::CCMD) & CCMD_ICC == 0 {
                        break;
                    }
                }
            }
        }
    }

    /// Инвалидация IOTLB (глобальная) через регистры IVA/IOTLB по ECAP.IRO.
    ///
    /// Кодировка IOTLB_IVT (бит 63, «invalidate») — по spec 6.5.2; для
    /// глобальной инвалидации адресная часть IVA не используется.
    /// TODO(железо): прогнать на QEMU перед реальным запуском.
    pub fn invalidate_iotlb_registers(base: usize, ecap: Ecap) {
        if base != 0 {
            let (iva, iotlb) = regs::iotlb_offset(ecap);
            const IOTLB_IVT: u64 = 1 << 63;
            // SAFETY: MMIO-окно замаплено HHDM.
            unsafe {
                write_reg64(base, iva, 0); // адресная часть не нужна для глобальной
                write_reg64(base, iotlb, IOTLB_IVT);
                loop {
                    if read_reg64(base, iotlb) & IOTLB_IVT == 0 {
                        break;
                    }
                }
            }
        }
    }

    /// v2: возвращает PASID-таблицу устройства, если все 512 PASIDTE
    /// пусты (и обнуляет запись директории). Вызывается после снятия
    /// последнего контекста устройства.
    fn reclaim_pasid_table_if_empty(&self, table: usize, dir_slot: *mut u64) {
        let entries = unsafe {
            core::slice::from_raw_parts(phys_to_virt(table) as *const u64, 512 * 8)
        };
        if entries.iter().any(|&q| q != 0) {
            return; // живые контексты — таблица остаётся
        }
        // SAFETY: слот директории жив (проверен при чтении выше по цепи).
        unsafe { core::ptr::write_volatile(dir_slot, 0) };
        if let Some(region) = MemoryPTR::new(table, PASID_TABLE_PAGES) {
            self.frames.deallocate_pages(region);
        }
    }
}

/// Ждёт установку битов в GSTS (с защитой от зависания).
///
/// # Safety
/// MMIO-окно замаплено HHDM.
unsafe fn wait_gsts(base: usize, mask: u32) -> Result<(), IommuError> {
    for _ in 0..1_000_000 {
        // SAFETY: см. контракт функции.
        if unsafe { read_reg32(base, regs::GSTS) } & mask == mask {
            return Ok(());
        }
    }
    Err(IommuError::HardwareError { detail: mask as u64 })
}

/// Выделяет `pages` НЕПРЕРЫВНЫХ страниц, выровненных на `pages * PAGE_SIZE`
/// (нужно для scalable context-таблиц 8 КиБ и PASID-таблиц 32 КиБ).
/// Bump-аллокатор может выдать невыровненную базу — повторяем несколько раз
/// (выдача только вперёд, так что прогресс гарантирован).
fn alloc_aligned_contiguous(
    frames: &(dyn FrameAllocator + Sync),
    pages: usize,
) -> Result<usize, IommuError> {
    let align = pages * PAGE_SIZE;
    for _ in 0..8 {
        let region = frames.allocate_pages(pages).ok_or(IommuError::OutOfFrames)?;
        if region.phys_base().is_multiple_of(align) {
            // SAFETY: регион выделен под нас и никем больше не занят.
            unsafe {
                core::ptr::write_bytes(phys_to_virt(region.phys_base()) as *mut u8, 0, align)
            };
            return Ok(region.phys_base());
        }
        frames.deallocate_pages(region);
    }
    Err(IommuError::OutOfFrames)
}

/// Аллоцирует и обнуляет страницу под таблицу IOMMU.
fn alloc_table_page(frames: &(dyn FrameAllocator + Sync)) -> Result<usize, IommuError> {
    let page = frames.allocate_pages(1).ok_or(IommuError::OutOfFrames)?;
    let virt = phys_to_virt(page.phys_base());
    // SAFETY: страница выделена под нас и никем больше не занята.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE) };
    Ok(page.phys_base())
}

/// SAFETY: root-таблица — живая выровненная страница.
unsafe fn root_table_slice(root_phys: usize) -> &'static mut [u64; 256] {
    unsafe { &mut *(phys_to_virt(root_phys) as *mut [u64; 256]) }
}

impl IommuUnit for VtdUnit {
    type Domain = VtdDomain;

    fn model(&self) -> IommuModel {
        IommuModel::IntelVtd
    }

    fn mmio_base(&self) -> usize {
        self.register_base
    }

    fn capabilities(&self) -> IommuCapabilities {
        let sslps = self.cap.sslps(); // bit0 = 2 MiB, bit1 = 1 GiB (second-stage)
        let mut page_size_mask = 1u64 << 12;
        if sslps & 0b01 != 0 {
            page_size_mask |= 1 << 21;
        }
        if sslps & 0b10 != 0 {
            page_size_mask |= 1 << 30;
        }

        // ECAP: PASIDE (бит 40) — поддержка PASID; PPS (биты 44:40) —
        // максимальный PASID. intel-iommu не декодирует их методами, поэтому
        // читаем сырое слово. v2: объявляем МИНИМУМ из ECAP.PPS и размера
        // PASID-таблицы юнита — раньше капабилити обещала больше,
        // чем выдавал alloc_pasid (потолок 512).
        const ECAP_PASIDE: u64 = 1 << 40;
        let supports_pasid = self.scalable && self.ecap.0 & ECAP_PASIDE != 0;
        let max_pasid = if supports_pasid {
            let pps = (intel_iommu::extract_bits(self.ecap.0, 44, 40) as u32) + 1;
            pps.min(MAX_PASID)
        } else {
            0
        };

        IommuCapabilities {
            model: IommuModel::IntelVtd,
            address_width_bits: self.cap.mgaw() as u8,
            page_size_mask,
            max_pasid,
            supports_pasid,
            // Second-stage PTE имеют аппаратный X-бит (spec 9.8).
            supports_exec_permission: true,
            coherent_walk: self.ecap.coherent(),
            supports_scalable: self.scalable,
            max_domains: self.max_domain_ids,
        }
    }

    fn create_domain(&self) -> Result<Self::Domain, IommuError> {
        // v2: id из slab-пула (bump + очередь возвратов, O(1), без потерь).
        let id: u16 = self
            .domain_pool
            .alloc()
            .ok_or(IommuError::DomainLimitReached)? as u16;

        // Root второй-stage таблицы (SS-PML4): 1 страница.
        let root = alloc_table_page(self.frames)?;

        Ok(VtdDomain {
            id,
            root_phys: root,
            levels: self.levels,
            // Инвалидации через регистры юнита (base == 0 -> no-op, тесты).
            unit_base: self.register_base,
            ecap: self.ecap,
            frames: self.frames,
        })
    }

    fn destroy_domain(&self, domain: Self::Domain) -> Result<(), IommuError> {
        // Возвращаем только страницу root; страницы нижних уровней
        // (аллоцированные map_pages) освобождает владелец, пройдясь по
        // своим маппингам, — у трейта нет обхода дерева. id возвращается
        // в slab-пул (без молчаливых потерь — v2).
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
            // PASID-путь — через set_pasid_context (PASID-капабилити v2).
            return Err(IommuError::PasidNotSupported);
        }
        if self.scalable {
            // v2 fail-closed: legacy 16-байтный ContextEntry в 32-байтном
            // scalable-слоте портил бы таблицу (SSPTPTR/DID/AW лежат в
            // других позициях). Крейт не даёт билдеров scalable-CE без
            // PASID — v3. Используй PASID-капабилити (set_pasid_context
            // пишет корректный nested PASIDTE).
            return Err(IommuError::LegacyContextRequired);
        }
        if device.segment != self.segment {
            return Err(IommuError::InvalidPhysicalAddress(device.segment as usize));
        }

        let rid = device.requester_id().0;
        let bus = (rid >> 8) as usize;
        let devfn = (rid & 0xff) as u8;

        let entry = ContextEntry::new()
            .with_present(true)
            .with_translation_type(TransType::SecondStage)
            .with_address_width(self.agaw)
            .with_domain_id(domain.id)
            .with_second_stage_ptr(domain.root_phys as u64);

        self.write_context_entry(bus, devfn, entry)?;
        self.invalidate_context_cache(domain.id);
        Ok(())
    }

    fn detach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError> {
        if pasid.is_some() {
            return Err(IommuError::PasidNotSupported);
        }
        if self.scalable {
            // v2 fail-closed: см. attach_device (обнуление 16 из 32 байт
            // слота оставило бы мусор в scalable-раскладке).
            return Err(IommuError::LegacyContextRequired);
        }
        let rid = device.requester_id().0;
        let bus = (rid >> 8) as usize;
        let devfn = (rid & 0xff) as u8;

        let (context_table, entry_size) = self.context_table_for_bus(bus)?;
        debug_assert_eq!(entry_size, 16);
        // SAFETY: живая страница context-таблицы.
        let slot = (phys_to_virt(context_table) + (devfn as usize) * 16) as *mut [u8; 16];
        unsafe { core::ptr::write_unaligned(slot, [0u8; 16]) };
        self.invalidate_context_cache(domain.id);
        Ok(())
    }

    // ── PASID / scalable-mode ──

    fn alloc_pasid(&self) -> Result<Pasid, IommuError> {
        if !self.scalable {
            return Err(IommuError::PasidNotSupported);
        }
        // v2: отдельный пул (у AMD v1 PASID делил счётчик с domain-ID —
        // два независимых аппаратных пространства истощали друг друга);
        // исчерпание — PasidLimitReached (раньше шло под видом
        // DomainLimitReached).
        let id = self
            .pasid_pool
            .alloc()
            .ok_or(IommuError::PasidLimitReached)?;
        Ok(Pasid(id))
    }

    fn free_pasid(&self, pasid: Pasid) -> Result<(), IommuError> {
        if !self.scalable {
            return Err(IommuError::PasidNotSupported);
        }
        if pasid.0 == 0 || pasid.0 >= MAX_PASID {
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
        if !self.scalable {
            return Err(IommuError::PasidNotSupported);
        }
        if fs_levels != 4 {
            // first-stage сейчас только 4-уровневый (Flpm::FourLevel).
            return Err(IommuError::UnsupportedAddressWidth {
                requested_bits: fs_levels * 9,
                supported_bits: 48,
            });
        }
        if device.segment != self.segment {
            return Err(IommuError::InvalidPhysicalAddress(device.segment as usize));
        }
        let rid = device.requester_id().0;

        // 1. Scalable context entry устройства: PASIDE + PASID-директория.
        self.write_scalable_context_entry((rid >> 8) as usize, (rid & 0xff) as u8)?;

        // 2. PASID-таблица устройства (по директории, аллокация по требованию).
        let table = self.pasid_table_for_device(rid)?;

        // 3. First-stage root: SVA (передан) или dedicated (аллоцируем).
        let first_root = match fs_root {
            Some(root) => root,
            None => alloc_table_page(self.frames)?,
        };

        // 4. PASIDTE: SLPTPTR = second-stage домена, DID, PGTT=Nested,
        //    FLPM=4-уровневый; FLRTP (q2[63:12]) — first-stage root
        //    (билдера в крейте нет, поле публичное).
        // FLRTP (first-stage root) — через билдер крейта (with_first_level_ptr).
        let pte = PasidTableEntry::new()
            .with_present(true)
            .with_pgtt(Pgtt::Nested)
            .with_page_table_ptr(domain.root_phys as u64)
            .with_domain_id(domain.id)
            .with_flpm(Flpm::FourLevel)
            .with_first_level_ptr(first_root as u64);

        let slot = (phys_to_virt(table) + (pasid.0 as usize & 0x1ff) * 64) as *mut [u8; 64];
        // SAFETY: слот внутри живой PASID-таблицы (32 КиБ).
        unsafe { core::ptr::write_unaligned(slot, pte.into_bytes()) };

        // 5. Инвалидации через QI: PASID-кэш (глобально) + IOTLB домена.
        self.qi_submit_and_wait(&[
            QiPc::new(Granularity::Global, domain.id, pasid.0).to_words(),
            QiIotlb::new(Granularity::Domain, domain.id, 0, 0).to_words(),
        ])?;
        Ok(first_root)
    }

    fn clear_pasid_context(
        &self,
        _domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
    ) -> Result<(), IommuError> {
        if !self.scalable {
            return Err(IommuError::PasidNotSupported);
        }
        let rid = device.requester_id().0;
        let dir_index = ((rid >> 9) & 0x7f) as usize;
        let dir_slot = (phys_to_virt(self.pasid_dir_phys) + dir_index * 16) as *mut u64;
        // SAFETY: слот PASID-директории жив.
        let entry = unsafe { core::ptr::read_volatile(dir_slot) };
        if entry & 1 == 0 {
            return Err(IommuError::DeviceNotAttached(device));
        }
        let table = (entry & !0xfff) as usize;

        // Снимаем PASIDTE и инвалидацируем кэши.
        let pte_slot = (phys_to_virt(table) + (pasid.0 as usize & 0x1ff) * 64) as *mut [u8; 64];
        // SAFETY: слот внутри живой PASID-таблицы.
        unsafe { core::ptr::write_unaligned(pte_slot, [0u8; 64]) };
        self.qi_submit_and_wait(&[
            QiPc::new(Granularity::Domain, 0, pasid.0).to_words(),
            QiIotlb::new(Granularity::Global, 0, 0, 0).to_words(),
        ])?;

        // v2: если PASID-таблица устройства опустела — возвращаем её
        // страницы юниту (32 КиБ за устройство в v1 текли навсегда).
        self.reclaim_pasid_table_if_empty(table, dir_slot);
        Ok(())
    }

    /// v2: возврат кадра dedicated first-stage root при уничтожении
    /// PASID-пространства (1 страница, см. set_pasid_context).
    fn release_fs_root(&self, fs_root: usize) {
        if let Some(region) = MemoryPTR::new(fs_root, 1) {
            self.frames.deallocate_pages(region);
        }
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
        let writable = prot.contains(IommuProtection::WRITE);
        for i in 0..pages {
            map_first_stage_page(
                self.frames,
                fs_root,
                gva + i * PAGE_SIZE,
                phys + i * PAGE_SIZE,
                writable,
            )?;
        }
        // Инвалидация first-stage кэшей: PASID-кэш + IOTLB домена.
        self.qi_submit_and_wait(&[
            QiPc::new(Granularity::Domain, domain.id, pasid.0).to_words(),
            QiIotlb::new(Granularity::Domain, domain.id, 0, 0).to_words(),
        ])
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
            unmap_first_stage_page(fs_root, gva + i * PAGE_SIZE)?;
        }
        self.qi_submit_and_wait(&[
            QiPc::new(Granularity::Domain, domain.id, pasid.0).to_words(),
            QiIotlb::new(Granularity::Domain, domain.id, 0, 0).to_words(),
        ])
    }
}

// ─── First-stage (Intel-64) таблицы PASID-контекстов ─────────────────────────

/// Флаги промежуточных first-stage записей: P|RW|US|A (бит 2 в Intel-64
/// раскладке — US, не X).
const FS_TABLE_FLAGS: u64 = Perm::R.bits() | Perm::W.bits() | Perm::X.bits() | Perm::ACCESSED.bits();
/// Маска физического адреса в first-stage записях.
const FS_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Ставит один 4K-лист в first-stage таблице: промежуточные записи —
/// FS_TABLE_FLAGS, лист через first_stage_leaf крейта (P|A|D[|W|US]).
fn map_first_stage_page(
    frames: &(dyn FrameAllocator + Sync),
    fs_root: usize,
    gva: usize,
    phys: usize,
    writable: bool,
) -> Result<(), IommuError> {
    let mut table = fs_root;
    let mut shift = 39usize;
    while shift > 12 {
        let slot = (phys_to_virt(table) + ((gva >> shift) & 0x1ff) * 8) as *mut u64;
        // SAFETY: таблица — живая страница из кадро-аллокатора.
        let entry = unsafe { core::ptr::read_volatile(slot) };
        table = if entry & 1 == 0 {
            let next = alloc_table_page(frames)?;
            // SAFETY: см. выше.
            unsafe { core::ptr::write_volatile(slot, (next as u64) | FS_TABLE_FLAGS) };
            next
        } else {
            (entry & FS_ADDR_MASK) as usize
        };
        shift -= 9;
    }
    let slot = (phys_to_virt(table) + ((gva >> 12) & 0x1ff) * 8) as *mut u64;
    // SAFETY: лист внутри живой страницы таблицы.
    unsafe {
        core::ptr::write_volatile(
            slot,
            intel_iommu::pagetables::first_stage_leaf(phys as u64, true, writable),
        );
    }
    Ok(())
}

/// Снимает 4K-лист first-stage таблицы (промежуточные уровни не
/// освобождаются — как у second-stage).
fn unmap_first_stage_page(fs_root: usize, gva: usize) -> Result<(), IommuError> {
    let mut table = fs_root;
    let mut shift = 39usize;
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
        table = (entry & FS_ADDR_MASK) as usize;
        shift -= 9;
    }
}

// ─── VtdDomain: second-stage таблицы ─────────────────────────────────────────

/// Домен трансляции: идентификатор + second-stage таблица (SS-PML4).
/// Все устройства домена видят одно адресное пространство.
/// Copy: чистый дескриптор (id/адреса/аллокатор-ссылка) — таблицы доменов
/// arch-слоя хранят его по значению. Debug не выводится: `&dyn FrameAllocator`
/// не Debug; диагностика через методы домена.
#[derive(Clone, Copy)]
pub struct VtdDomain {
    /// Доменный id (записывается в ContextEntry.DID).
    id: u16,
    /// Физический адрес SS-PML4.
    root_phys: usize,
    /// Уровней в таблице (3 или 4 — от CAP.SAGAW).
    levels: u8,
    /// MMIO-база юнита для инвалидаций; `None` (base == 0) — тесты.
    unit_base: usize,
    ecap: Ecap,
    /// Кадро-аллокатор промежуточных таблиц.
    frames: &'static (dyn FrameAllocator + Sync),
}

impl VtdDomain {
    /// Доменный id.
    pub fn domain_id(&self) -> u16 {
        self.id
    }

    /// Физический адрес SS-PML4.
    pub fn root_phys(&self) -> usize {
        self.root_phys
    }

    /// Читает SS-PTE по иерархии (без аллокаций) — диагностика домена
    /// (аудит маппингов из отладчика ядра).
    pub fn lookup_pte(&self, iova: usize) -> Option<SecondStagePte> {
        let mut table = self.root_phys;
        let mut shift = 12 + 9 * (self.levels as usize - 1);
        loop {
            let entry = unsafe {
                // SAFETY: таблица — живая страница из кадро-аллокатора.
                core::ptr::read_volatile(
                    (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *const u64,
                )
            };
            let pte = SecondStagePte(entry);
            if shift == 12 || pte.perms().contains(Perm::PAGE_SIZE) {
                return Some(pte);
            }
            if !pte.present() {
                return None;
            }
            table = pte.frame() as usize;
            shift -= 9;
        }
    }

    /// Ставит один 4K-лист, аллоцируя недостающие промежуточные таблицы
    /// (Present|RWX — промежуточные, права живут в листьях).
    fn map_page(&self, iova: usize, hpa: usize, perm: Perm) -> Result<(), IommuError> {
        let mut table = self.root_phys;
        let mut shift = 12 + 9 * (self.levels as usize - 1);
        while shift > 12 {
            let slot = (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *mut u64;
            // SAFETY: таблица — живая страница из кадро-аллокатора.
            let entry = unsafe { core::ptr::read_volatile(slot) };
            table = if entry & 1 == 0 {
                let next = alloc_table_page(self.frames)?;
                // Промежуточная запись: present + RWX (по шаблону
                // SecondStagePte::table).
                unsafe { core::ptr::write_volatile(slot, SecondStagePte::table(next as u64).bits()) };
                next
            } else {
                (SecondStagePte(entry).frame()) as usize
            };
            shift -= 9;
        }
        let slot = (phys_to_virt(table) + ((iova >> 12) & 0x1ff) * 8) as *mut u64;
        unsafe { core::ptr::write_volatile(slot, SecondStagePte::page(hpa as u64, perm).bits()) };
        Ok(())
    }

    /// Снимает 4K-лист. Промежуточные таблицы НЕ освобождаются (см.
    /// комментарий в IommuDomain::unmap_pages).
    fn unmap_page(&self, iova: usize) -> Result<u64, IommuError> {
        let mut table = self.root_phys;
        let mut shift = 12 + 9 * (self.levels as usize - 1);
        loop {
            let slot = (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *mut u64;
            let entry = unsafe { core::ptr::read_volatile(slot) };
            if entry & 1 == 0 {
                return Err(IommuError::InvalidIova(iova));
            }
            if shift == 12 {
                unsafe { core::ptr::write_volatile(slot, 0) };
                return Ok(entry & !0xfff);
            }
            table = (SecondStagePte(entry).frame()) as usize;
            shift -= 9;
        }
    }
}

impl IommuDomain for VtdDomain {
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
        let perm = protection_to_perm(prot);
        if perm.is_empty() {
            return Err(IommuError::UnsupportedProtection(prot));
        }
        for i in 0..pages {
            self.map_page(iova + i * PAGE_SIZE, phys + i * PAGE_SIZE, perm)?;
        }
        self.flush_iotlb();
        Ok(())
    }

    fn unmap_pages(&self, iova: usize, pages: usize) -> Result<(), IommuError> {
        if pages == 0 || !iova.is_multiple_of(PAGE_SIZE) {
            return Err(IommuError::InvalidIova(iova));
        }
        for i in 0..pages {
            self.unmap_page(iova + i * PAGE_SIZE)?;
        }
        // Промежуточные таблицы не освобождаются сознательно: у трейта нет
        // безопасного способа узнать, что уровень опустел (и refcount их
        // между доменами нет). Переиспользование домена при переаллокации
        // в тех же диапазонах амортизирует расход; полный возврат страниц —
        // вместе с destroy_domain расширенным учётом.
        self.flush_iotlb();
        Ok(())
    }

    fn translate(&self, iova: usize) -> Result<usize, IommuError> {
        let fetch = |entry_addr: u64| -> u64 {
            // SAFETY: entry_addr — адрес записи в таблице домена (живая
            // страница), замапленной HHDM.
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        pagetables::walk(Stage::Second, self.levels, self.root_phys as u64, iova as u64, &fetch)
            .map(|r| r.physical as usize)
            .map_err(|e| match e {
                pagetables::WalkError::NotPresent { .. } => IommuError::InvalidIova(iova),
                pagetables::WalkError::AddressTooLarge { .. } => IommuError::InvalidIova(iova),
            })
    }

    fn flush_iotlb(&self) {
        // Тестовый режим (unit_base == 0): регистровый хелпер сам это
        // понимает и ничего не делает.
        VtdUnit::invalidate_iotlb_registers(self.unit_base, self.ecap);
    }
}

// ─── Тесты (хост): таблицы проверяются родным walk() intel-iommu ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use intel_iommu::context::RootEntry;
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
    fn intel_scalable_pasid_context() {
        let _guard = crate::test_support::GLOBAL.lock();
        let mem = page_aligned_leak(16 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        // v2: create_domain/alloc_pasid лениво поднимают slab-очередь
        // IdPool — хуки нужны уже в тестах.
        crate::test_support::init_slab_once();

        // CAP: SAGAW 48-бит (4 << 8). ECAP: PASIDE (40) | SRS (41).
        let ecap = (1u64 << 40) | (1u64 << 41);
        let unit: &'static VtdUnit = Box::leak(Box::new(
            VtdUnit::new_raw(0, 0, 4 << 8, ecap, &FRAMES).expect("unit"),
        ));
        assert!(unit.scalable());
        assert!(unit.capabilities().supports_scalable);

        let domain = unit.create_domain().expect("domain");
        let pasid = unit.alloc_pasid().expect("pasid");
        assert_eq!(pasid.0, 1);

        // Dedicated-контекст: бэкенд аллоцирует first-stage root.
        let dev = PciAddress { segment: 0, bus: 0x10, device: 2, function: 1 };
        let fs_root = unit
            .set_pasid_context(&domain, dev, pasid, None, 4)
            .expect("set_pasid_context");

        // ── ScalableContextEntry: q0 = present | PASIDE, PASIDDIRPTR ──
        let rid = dev.requester_id().0 as usize;
        // root[bus] указывает на 8КиБ context-таблицу; читаем её через root.
        let root_entry = unsafe {
            core::ptr::read_volatile(
                (phys_to_virt(unit.root_table_phys()) + (dev.bus as usize) * 8) as *const u64,
            )
        };

        assert_ne!(root_entry & 1, 0, "root entry present");
        let ctx_table = (root_entry & !0xfff) as usize;
        let se_q0 = unsafe {
            core::ptr::read_volatile((phys_to_virt(ctx_table) + (rid & 0xff) * 32) as *const u64)
        };
        assert_ne!(se_q0 & 1, 0, "scalable context entry present");
        assert_ne!(se_q0 & 8, 0, "PASIDE включён");
        assert_eq!(
            se_q0 & !0xfff,
            unit.pasid_dir_phys_for_test() as u64,
            "PASIDDIRPTR"
        );

        // ── PASIDTE: present, SLPTPTR = домен, DID, PGTT=Nested, FLPM, FLRTP ──
        let dir_index = (rid >> 9) & 0x7f;
        let dir_entry = unsafe {
            core::ptr::read_volatile(
                (phys_to_virt(unit.pasid_dir_phys_for_test()) + dir_index * 16) as *const u64,
            )
        };
        assert_ne!(dir_entry & 1, 0, "PASID dir entry present");
        let pasid_table = (dir_entry & !0xfff) as usize;
        let pte = unsafe {
            let base = (phys_to_virt(pasid_table) + (pasid.0 as usize & 0x1ff) * 64) as *const u64;
            [
                core::ptr::read_volatile(base),
                core::ptr::read_volatile(base.add(1)),
                core::ptr::read_volatile(base.add(2)),
            ]
        };
        assert_ne!(pte[0] & 1, 0, "PASIDTE present");
        assert_eq!(pte[0] & !0xfff, domain.root_phys() as u64, "SLPTPTR");
        assert_eq!((pte[1] & 0xffff), domain.domain_id() as u64, "DID");
        assert_eq!(((pte[2] >> 2) & 0x3), 0, "FLPM = FourLevel");
        // FLRTP через геттер крейта (реконструкция записи из проводных байт).
        let rebuilt = PasidTableEntry {
            q0: pte[0],
            q1: pte[1],
            q2: pte[2],
            q3: 0,
            hpt: [0; 4],
        };
        assert_eq!(
            rebuilt.first_level_ptr(),
            fs_root as u64 & FS_ADDR_MASK,
            "FLRTP"
        );

        // ── first-stage маппинг + проверка родным walker'ом ──
        let gva = 0x4000_0000usize;
        let hpa = 0x6000_0000usize;
        unit.map_first_stage(&domain, pasid, fs_root, gva, hpa, 2, IommuProtection::READ | IommuProtection::WRITE)
            .expect("map_first_stage");
        let fetch = |entry_addr: u64| -> u64 {
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        for i in 0..2 {
            let r = pagetables::walk(
                Stage::First,
                4,
                fs_root as u64,
                (gva + i * PAGE_SIZE) as u64,
                &fetch,
            )
            .expect("first-stage walk");
            assert_eq!(r.physical, (hpa + i * PAGE_SIZE) as u64);
            assert!(r.perms.contains(Perm::R | Perm::W));
        }

        // ── unmap + clear ──
        unit.unmap_first_stage(&domain, pasid, fs_root, gva, 2).expect("unmap");
        assert!(pagetables::walk(Stage::First, 4, fs_root as u64, gva as u64, &fetch).is_err());
        unit.clear_pasid_context(&domain, dev, pasid).expect("clear");
        // PASIDTE после clear — нулевой.
        let cleared = unsafe {
            core::ptr::read_volatile(
                (phys_to_virt(pasid_table) + (pasid.0 as usize & 0x1ff) * 64) as *const u64,
            )
        };
        assert_eq!(cleared, 0, "PASIDTE снят");
        unit.free_pasid(pasid).expect("free pasid");
        // Свободный PASID выдаётся заново.
        let reused = unit.alloc_pasid().expect("pasid reuse");
        assert_eq!(reused.0, pasid.0);
    }

    #[test]
    fn vtd_domain_maps_and_translates() {
        // Глобальный лок против paging-теста (общие статики HHDM-offset).
        let _guard = crate::test_support::GLOBAL.lock();
        // "Физическая память": физический 0 = начало leaks-нутого буфера.
        let mem = page_aligned_leak(8 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        // v2: create_domain/alloc_pasid лениво поднимают slab-очередь
        // IdPool — хуки нужны уже в тестах.
        crate::test_support::init_slab_once();

        // CAP: SAGAW в битах 12:8, код 4 (0b100) = 48-бит (4 уровня)
        // -> 4 << 8; ND (биты 2:0) = 0 -> 2^4 = 16 доменов. ECAP пустой.
        // base == 0 -> MMIO-инвалидации отключены (тестовый режим).
        let unit = VtdUnit::new_raw(0, 0, 4 << 8, 0, &FRAMES).expect("unit");
        assert_eq!(unit.capabilities().max_domains, 16);

        let caps = unit.capabilities();
        assert_eq!(caps.model, IommuModel::IntelVtd);
        assert_eq!(caps.max_domains, 16);
        assert_eq!(caps.page_size_mask, 1 << 12); // SSLPS пуст -> только 4K

        let domain = unit.create_domain().expect("domain");
        assert_eq!(domain.domain_id(), 1);

        // Мапим 4 страницы: IOVA 0x1000_0000 -> HPA 0x5000_0000, RW.
        let iova = 0x1000_0000usize;
        let hpa = 0x5000_0000usize;
        domain
            .map_pages(iova, hpa, 4, IommuProtection::READ | IommuProtection::WRITE)
            .expect("map");

        // Трансляция через РОДНОЙ walker intel-iommu: fetch читает записи
        // через HHDM из нашей (построенной нами) таблицы.
        let root = domain.root_phys();
        let fetch = |entry_addr: u64| -> u64 {
            unsafe { core::ptr::read_volatile(phys_to_virt(entry_addr as usize) as *const u64) }
        };
        for i in 0..4 {
            let va = (iova + i * PAGE_SIZE) as u64;
            let r = pagetables::walk(Stage::Second, 4, root as u64, va, &fetch)
                .expect("walk должен найти лист");
            assert_eq!(r.physical, (hpa + i * PAGE_SIZE) as u64);
            assert!(r.perms.contains(Perm::R | Perm::W));
            assert!(!r.perms.contains(Perm::X), "X не запрошен и не должен стоять");
        }

        // translate() трейта даёт тот же результат.
        assert_eq!(domain.translate(iova + 2 * PAGE_SIZE).unwrap(), hpa + 2 * PAGE_SIZE);

        // Часть прав: только READ — запись в PTE не содержит W.
        domain
            .map_pages(iova + 16 * PAGE_SIZE, hpa + 16 * PAGE_SIZE, 1, IommuProtection::READ)
            .unwrap();
        let pte = SecondStagePte(
            unsafe { core::ptr::read_volatile(lookup_leaf(&domain, iova + 16 * PAGE_SIZE)) },
        );
        assert!(pte.perms().contains(Perm::R));
        assert!(!pte.perms().contains(Perm::W));

        // unmap_pages снимает лист: translate больше не резолвит.
        domain.unmap_pages(iova, 4).unwrap();
        assert!(domain.translate(iova).is_err());

        // Хвост: идемпотентность unmap — повторный unmap того же диапазона
        // возвращает InvalidIova (лист пуст), это ошибка вызывающего.
        assert!(domain.unmap_pages(iova, 1).is_err());
    }

    /// Адрес листовой записи 4K-уровня (для прямых проверок PTE в тестах).
    fn lookup_leaf(domain: &VtdDomain, iova: usize) -> *const u64 {
        let mut table = domain.root_phys;
        let mut shift = 12 + 9 * (domain.levels as usize - 1);
        while shift > 12 {
            let entry = unsafe {
                core::ptr::read_volatile(
                    (phys_to_virt(table) + ((iova >> shift) & 0x1ff) * 8) as *const u64,
                )
            };
            table = (entry & !0xfff) as usize;
            shift -= 9;
        }
        (phys_to_virt(table) + ((iova >> 12) & 0x1ff) * 8) as *const u64
    }

    #[test]
    fn context_entry_layout_roundtrip() {
        // RootEntry/ContextEntry из intel-iommu сериализуются в правильный
        // аппаратный формат — проверяем побайтово.
        let entry = ContextEntry::new()
            .with_present(true)
            .with_translation_type(TransType::SecondStage)
            .with_address_width(AddrWidth::Agaw48)
            .with_domain_id(7)
            .with_second_stage_ptr(0x1234_5000);
        let bytes = entry.into_bytes();
        let q0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let q1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(q0 & 1, 1); // present
        assert_eq!(q0 & !0xfff, 0x1234_5000); // SSPTPTR
        assert_eq!(q1 & 0x7, AddrWidth::Agaw48.bits() as u64);
        assert_eq!((q1 >> 8) & 0xffff, 7); // DID

        let root = RootEntry::new(0xabc_000);
        assert_eq!(root.low, 0xabc_000 | 1);
        assert!(root.present());

        // RequesterId из PciAddress: шина [15:8], устройство [7:3], функция [2:0].
        let dev = PciAddress { segment: 0, bus: 0x2a, device: 5, function: 3 };
        assert_eq!(dev.requester_id().0, (0x2a << 8) | (5 << 3) | 3);
    }
}
