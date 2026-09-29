//! seL4-стиль сисколлы IOMMU — архитектурно-НЕЗАВИСИМЫЙ слой (v2).
//!
//! Все операции над DMA-доменами, PASID-пространствами и PASID-капабилити —
//! инвокации capability, работающие через трейт [`IommuTokenLayer`]: сисколлы
//! не знают про VT-d/AMD-Vi и slab-реестры — это забота порта.
//!
//! РАСКЛАД v2 (NR 32..44; userspace-кода под старые номера нет — перенумерация
//! свободна):
//!   32 CreateDomain      — домен second-stage + корневая capability.
//!   33 AttachDevice      — устройство в домен (без PASID).
//!   34 MapDma            — IOVA -> физика в домене (сырая физика).
//!   35 UnmapDma          — снятие IOVA-маппинга (+ pin-учёт MapDmaVa).
//!   50 MapDmaVa          — DMA-buf: маппинг ИЗ ПАМЯТИ ВЫЗЫВАЮЩЕГО
//!                          (VA -> физика резолвит ядро, регион пинится,
//!                          FREE_PAGES под пином — E_BUSY).
//!   36 CreatePasidSpace  — пространство first-stage (SVA: root = CR3 владельца).
//!   37 AllocPasid        — PASID-капабилити с потолком пользователей (v2).
//!   38 FreePasid         — уничтожение PASID (снятие всех привязок).
//!   39 BindPasidDevice   — устройство-пользователь в PASID (квота: E_QUOTA).
//!   40 UnbindPasidDevice — отвязка устройства.
//!   41 MapVa             — first-stage маппинг через PASID-капабилити.
//!   42 UnmapVa           — снятие first-stage маппинга.
//!   43 DestroyPasidSpace — уничтожение пространства (без живых PASID).
//!   44 DestroyDomain     — уничтожение домена (закрывает утечку: раньше
//!                          домены userspace-ом не уничтожались вовсе).
//!
//! МОДЕЛЬ АДМИССИИ PASID (v2): PASID несёт max_users — потолок одновременных
//! пользователей (привязанных устройств). Bind сверх потолка — E_QUOTA
//! (deny-семантика; блокировка внутри сисколла в микроядре — приоритетная
//! инверсия и тривиальный DoS). Владелец узнаёт об отказе немедленно и
//! волен ретраить/перепланировать.
//!
//! АВТОРИТЕТ (закрытие ambient authority — как в v1): владелец capability —
//! либо САМА текущая задача, либо задача, на которую у вызывающего есть
//! живая TaskTCB-капабилити (AccessManager::controls_task); запись обязана
//! резолвиться и нести право Send.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    access::{
        AccessManager,
        capability::{CapabilityObject, DirectCapabilityRights},
        capspace, capspace::CapspaceError,
        namespace::NamespaceRights,
    },
    traits::{
        iommu::{IommuError, IommuProtection, IommuTokenLayer, PciAddress, TokenError},
        memory::MemoryInterfaceUserspace,
        syscall::{SyscallDomain, syscall_result as res},
    },
    KernelCTL,
};

fn domain_table_error_code(e: TokenError) -> u64 {
    match e {
        TokenError::Full => res::E_SLAB,
        TokenError::BadToken => res::E_NOT_FOUND,
        // Объект занят живыми ссылками (домен — устройствами/PASID,
        // пространство — PASID): семантика занятого слота.
        TokenError::Occupied => res::E_SLOT_OCCUPIED,
    }
}

fn iommu_error_code(e: IommuError) -> u64 {
    match e {
        IommuError::NoIommuUnits => res::E_NOT_FOUND,
        // Исчерпание ДОМЕНОВ/PASID и пользователей — квоты ресурса, не slab.
        IommuError::DomainLimitReached
        | IommuError::PasidLimitReached
        | IommuError::QuotaExceeded => res::E_QUOTA,
        IommuError::OutOfFrames => res::E_SLAB,
        IommuError::UnsupportedAddressWidth { .. }
        | IommuError::UnsupportedPageSize(_)
        | IommuError::UnsupportedProtection(_)
        | IommuError::PasidNotSupported
        | IommuError::LegacyContextRequired => res::E_INVALID_ARG,
        IommuError::DeviceNotAttached(_) | IommuError::SpaceHasPasids => res::E_NOT_FOUND,
        IommuError::DeviceAlreadyAttached(_) => res::E_SLOT_OCCUPIED,
        IommuError::InvalidIova(_) | IommuError::InvalidPhysicalAddress(_) => res::E_INVALID_ARG,
        // Токен умер между резолвом и операцией (гонка с destroy) — объект не найден.
        IommuError::StaleToken => res::E_NOT_FOUND,
        IommuError::HardwareError { .. } => res::E_INTERNAL,
    }
}

fn capspace_code(e: CapspaceError) -> u64 {
    match e {
        CapspaceError::SlotOccupied => res::E_SLOT_OCCUPIED,
        CapspaceError::SlotEmpty => res::E_INTERNAL,
        CapspaceError::Slab(_) => res::E_SLAB,
        CapspaceError::Quota => res::E_QUOTA,
    }
}

/// Проверка авторитета на ВЛАДЕЛЬЦА записи: текущая задача либо задача
/// под TaskTCB-контролем (controls_task). Иначе — E_RIGHTS_DENIED.
fn check_cap_authority<A: IommuTokenLayer>(
    access: &AccessManager<A::Umap>,
    current: u64,
    task_cap: u64,
) -> Result<(), u64> {
    if task_cap == current {
        return Ok(());
    }
    let controlled = caller_of::<A>(access, current)
        .map(|g| access.controls_task(g, task_cap))
        .unwrap_or(false);
    if controlled {
        Ok(())
    } else {
        Err(res::E_RIGHTS_DENIED)
    }
}

/// Резолв capability домена: (current, task_cap, slot) -> токен.
fn resolve_domain_cap<A: IommuTokenLayer>(
    access: &AccessManager<A::Umap>,
    current: u64,
    task_cap: u64,
    slot: u64,
) -> Result<u64, u64> {
    let gtcb_ptr = access.get_task_tcb(task_cap).ok_or(res::E_NOT_FOUND)?;
    // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
    let gtcb = unsafe { gtcb_ptr.as_ref() };
    let caps = gtcb.capspace().lock();
    let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
    let (object, rights) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
    if !rights.contains(DirectCapabilityRights::Send) {
        return Err(res::E_RIGHTS_DENIED);
    }
    match &object {
        CapabilityObject::IommuDomain { domain_token, .. } => {
            check_cap_authority::<A>(access, current, task_cap)?;
            Ok(*domain_token)
        }
        _ => Err(res::E_NOT_FOUND),
    }
}

/// Резолв PASID-пространства.
fn resolve_space_cap<A: IommuTokenLayer>(
    access: &AccessManager<A::Umap>,
    current: u64,
    task_cap: u64,
    slot: u64,
) -> Result<u64, u64> {
    let gtcb_ptr = access.get_task_tcb(task_cap).ok_or(res::E_NOT_FOUND)?;
    // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
    let gtcb = unsafe { gtcb_ptr.as_ref() };
    let caps = gtcb.capspace().lock();
    let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
    let (object, rights) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
    if !rights.contains(DirectCapabilityRights::Send) {
        return Err(res::E_RIGHTS_DENIED);
    }
    match &object {
        CapabilityObject::PasidSpace { space_token, .. } => {
            check_cap_authority::<A>(access, current, task_cap)?;
            Ok(*space_token)
        }
        _ => Err(res::E_NOT_FOUND),
    }
}

/// Резолв PASID-капабилити (v2).
fn resolve_pasid_cap<A: IommuTokenLayer>(
    access: &AccessManager<A::Umap>,
    current: u64,
    task_cap: u64,
    slot: u64,
) -> Result<u64, u64> {
    let gtcb_ptr = access.get_task_tcb(task_cap).ok_or(res::E_NOT_FOUND)?;
    // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
    let gtcb = unsafe { gtcb_ptr.as_ref() };
    let caps = gtcb.capspace().lock();
    let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
    let (object, rights) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
    if !rights.contains(DirectCapabilityRights::Send) {
        return Err(res::E_RIGHTS_DENIED);
    }
    match &object {
        CapabilityObject::Pasid { pasid_token, .. } => {
            check_cap_authority::<A>(access, current, task_cap)?;
            Ok(*pasid_token)
        }
        _ => Err(res::E_NOT_FOUND),
    }
}

/// GTcb текущей задачи для controls_task (None — авторитета нет).
fn caller_of<'a, A: IommuTokenLayer>(
    access: &'a AccessManager<A::Umap>,
    current: u64,
) -> Option<&'a crate::task::tcb::GTcb<A::Umap>> {
    let ptr = access.get_task_tcb(current)?;
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    Some(unsafe { ptr.as_ref() })
}

/// PHYS-ВАЛИДАЦИЯ DMA (см. phys_guard): диапазон обязан целиком лежать
/// в одном регионе RAM и не задевать запреты (образ ядра/модулей,
/// метаданные аллокатора). Иначе устройство читает/пишет память ядра
/// по произвольной физике из ring3 — IOMMU-домен защищает ТОЛЬКО от
/// чужих устройств, а не от владельца домена, задавшего phys руками.
pub(crate) fn phys_range_ok(phys: u64, pages: u64) -> bool {
    if pages == 0 {
        return false;
    }
    let begin = phys as usize;
    let end = match (pages
        .checked_mul(crate::traits::memory::PAGE_SIZE as u64))
    .and_then(|bytes| begin.checked_add(bytes as usize))
    {
        Some(e) => e,
        None => return false,
    };
    crate::phys_guard::dma_allowed(begin, end)
}

fn check_dma_rights<A: IommuTokenLayer>(
    access: &AccessManager<A::Umap>,
    current: u64,
) -> Result<(), u64> {
    access
        .check_task_rights(current, NamespaceRights::DMA_ATTACH)
        .map_err(|_| res::E_RIGHTS_DENIED)
}

fn install_root<A: IommuTokenLayer>(
    access: &mut AccessManager<A::Umap>,
    owner: u64,
    dst_slot: u64,
    object: CapabilityObject<A::Umap>,
) -> u64 {
    let cap_id = match access.create_new_object(object) {
        Ok(id) => id,
        Err(_) => return res::E_SLAB,
    };
    let Some(zygote) = access.get_zygote(cap_id) else {
        let _ = access.destroy_object(cap_id);
        return res::E_INTERNAL;
    };
    let Some(owner_ptr) = access.get_task_tcb(owner) else {
        let _ = access.destroy_object(cap_id);
        return res::E_NOT_FOUND;
    };
    // SAFETY: под permission_backend-локом задача не уничтожается.
    let owner_gtcb = unsafe { owner_ptr.as_ref() };
    match capspace::install_root_capability(
        owner_gtcb,
        dst_slot,
        zygote,
        DirectCapabilityRights::all(),
        access.task_namespace(owner),
    ) {
        Ok(()) => cap_id,
        Err(e) => {
            let _ = access.destroy_object(cap_id);
            capspace_code(e)
        }
    }
}

// ─── DMA-домены (NR 32..35, 44) ─────────────────────────────────────────────

/// Создание DMA-домена.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuCreateDomain {
    pub dst_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuCreateDomain> {
    const SYSCALL_ID: usize = 32;
    type Args = SyscallCapIommuCreateDomain;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let mut access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match self.0.arch_backend().create_domain(current) {
            Ok(token) => token,
            Err(e) => return domain_table_error_code(e),
        };
        let cap = install_root::<A>(
            &mut access,
            current,
            args.dst_slot,
            CapabilityObject::IommuDomain { unit: 0, domain_token: token },
        );
        if cap & res::E_NO_CURRENT_TASK & 0x8000_0000_0000_0000 != 0 {
            // Откат домена при неудаче установки capability.
            let _ = self.0.arch_backend().destroy_domain(token);
        }
        cap
    }
}

/// Присоединение устройства PCIe к DMA-домену.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuAttachDevice {
    pub task_cap: u64,
    pub cap_slot: u64,
    pub bus: u64,
    pub device: u64,
    pub function: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuAttachDevice> {
    const SYSCALL_ID: usize = 33;
    type Args = SyscallCapIommuAttachDevice;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.bus > u8::MAX as u64 || args.device > 0x1f || args.function > 0x7 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().attach_device(
            token,
            PciAddress {
                segment: 0,
                bus: args.bus as u8,
                device: args.device as u8,
                function: args.function as u8,
            },
        )
        .map(|()| res::OK)
        .unwrap_or_else(iommu_error_code)
    }
}

/// Отсоединение устройства от DMA-домена (v2 — учёт attached для destroy).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuDetachDevice {
    pub task_cap: u64,
    pub cap_slot: u64,
    pub bus: u64,
    pub device: u64,
    pub function: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuDetachDevice> {
    const SYSCALL_ID: usize = 45;
    type Args = SyscallCapIommuDetachDevice;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.bus > u8::MAX as u64 || args.device > 0x1f || args.function > 0x7 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().detach_device(
            token,
            PciAddress {
                segment: 0,
                bus: args.bus as u8,
                device: args.device as u8,
                function: args.function as u8,
            },
        )
        .map(|()| res::OK)
        .unwrap_or_else(iommu_error_code)
    }
}

/// DMA-маппинг в домен.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuMapDma {
    pub task_cap: u64,
    pub cap_slot: u64,
    pub iova: u64,
    pub phys: u64,
    pub pages: u64,
    pub prot_mask: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuMapDma> {
    const SYSCALL_ID: usize = 34;
    type Args = SyscallCapIommuMapDma;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let prot = IommuProtection::from_bits_truncate(args.prot_mask as u8);
        if prot.is_empty() || args.pages == 0 {
            return res::E_INVALID_ARG;
        }
        if !phys_range_ok(args.phys, args.pages) {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().map_dma(token, args.iova as usize, args.phys as usize, args.pages as usize, prot)
            .map(|()| res::OK)
            .unwrap_or_else(iommu_error_code)
    }
}

/// Снятие DMA-маппинга.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuUnmapDma {
    pub task_cap: u64,
    pub cap_slot: u64,
    pub iova: u64,
    pub pages: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuUnmapDma> {
    const SYSCALL_ID: usize = 35;
    type Args = SyscallCapIommuUnmapDma;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.pages == 0 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().unmap_dma(token, args.iova as usize, args.pages as usize)
            .map(|()| {
                // Pin-учёт (MapDmaVa): маппинг снят — снимаем привязку
                // источника, FREE_PAGES снова разрешён. Владелец мог
                // умереть (umap удалён вместе с задачей) — пинить
                // нечего; запись в домене снята в любом случае.
                if let Some((owner, virt_base)) =
                    self.0.arch_backend().take_dma_pin(token, args.iova as usize)
                {
                    if let Some(owner_ptr) = access.get_task_tcb(owner) {
                        // SAFETY: под permission_backend-локом.
                        let owner_gtcb = unsafe { owner_ptr.as_ref() };
                        let _ = owner_gtcb.vmap().unpin_dma(virt_base);
                    }
                }
                res::OK
            })
            .unwrap_or_else(iommu_error_code)
    }
}

/// DMA-маппинг ИЗ ПАМЯТИ ВЫЗЫВАЮЩЕГО (NR 50; DMA-buf примитив).
///
/// Ключевое отличие от MapDma (34): источник физики — не сырой phys от
/// ring3, а регион В АДРЕСНОМ ПРОСТРАНСТВЕ ВЫЗЫВАЮЩЕГО: ядро резолвит
/// VA -> физика через VmapRegion (find_containing), пинит регион
/// (FREE_PAGES на пиннутый — E_BUSY) и записывает привязку в домен
/// (UnmapDma снимет pin). Драйвер легально получает DMA на СВОИ буферы
/// и буферы, полученные по IPC, не зная физику и не имея шанса
/// смаппить чужую/системную память.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuMapDmaVa {
    pub task_cap: u64,
    pub cap_slot: u64,
    pub iova: u64,
    /// VA источника в пространстве ВЫЗЫВАЮЩЕГО (page-aligned); диапазон
    /// обязан целиком лежать в ОДНОЙ аллокации (физика непрерывна).
    pub va: u64,
    pub pages: u64,
    pub prot_mask: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuMapDmaVa> {
    const SYSCALL_ID: usize = 50;
    type Args = SyscallCapIommuMapDmaVa;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let prot = IommuProtection::from_bits_truncate(args.prot_mask as u8);
        if prot.is_empty() || args.pages == 0 {
            return res::E_INVALID_ARG;
        }
        if args.iova % crate::traits::memory::PAGE_SIZE as u64 != 0
            || args.va % crate::traits::memory::PAGE_SIZE as u64 != 0
        {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        // Источник — только СВОЯ память: VA резолвится в umap ВЫЗЫВАЮЩЕГО.
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };
        let Some((virt_base, entry)) =
            gtcb.vmap().find_containing(args.va as usize, args.pages as usize)
        else {
            return res::E_INVALID_ARG;
        };
        if entry.external {
            // MMIO-монты (окна устройств) DMA не отдаём — dma_allowed-
            // политика сырого MapDma: двигатель ходит только по RAM.
            return res::E_INVALID_ARG;
        }
        let page = crate::traits::memory::PAGE_SIZE as u64;
        let phys = entry.phys_base as u64 + ((args.va - virt_base as u64) / page) * page;
        // Pin ДО маппинга; при срыве map — откат.
        if gtcb.vmap().pin_dma(virt_base).is_err() {
            return res::E_INTERNAL;
        }
        if let Err(e) = self.0.arch_backend().map_dma(
            token,
            args.iova as usize,
            phys as usize,
            args.pages as usize,
            prot,
        ) {
            let _ = gtcb.vmap().unpin_dma(virt_base);
            return iommu_error_code(e);
        }
        // Привязка в домене: UnmapDma найдёт, чей pin снимать. Срыв —
        // полный откат (маппинг + pin), привязка не остаётся "наполовину".
        if self.0.arch_backend().record_dma_pin(token, args.iova as usize, current, virt_base).is_err() {
            let _ = self.0.arch_backend().unmap_dma(token, args.iova as usize, args.pages as usize);
            let _ = gtcb.vmap().unpin_dma(virt_base);
            return res::E_SLAB;
        }
        res::OK
    }
}

// ─── PASID-пространства и PASID-капабилити (NR 36..43) ──────────────────────

/// Создание PASID-пространства.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuCreatePasidSpace {
    pub domain_task: u64,
    pub domain_slot: u64,
    /// 0 = Dedicated, 1 = OwnAddressSpace (SVA).
    pub mode: u64,
    pub dst_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuCreatePasidSpace> {
    const SYSCALL_ID: usize = 36;
    type Args = SyscallCapIommuCreatePasidSpace;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.mode > 1 {
            return res::E_INVALID_ARG;
        }
        let mut access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let domain_token = match resolve_domain_cap::<A>(&access, current, args.domain_task, args.domain_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        // SVA: root = CR3 ВЛАДЕЛЬЦА (создателя) пространства — фиксируется
        // в момент create, а не при позднем bind (v1 брал root при attach —
        // окно рассогласования с жизнью процесса). Dedicated: root None —
        // бэкенд выделит при первом bind.
        let sva_root = if args.mode == 1 {
            access
                .get_task_tcb(current)
                .and_then(|ptr| {
                    // SAFETY: под permission_backend-локом задача жива.
                    unsafe { ptr.as_ref() }.userspace_map().root_table()
                })
        } else {
            None
        };
        let space_token = match self.0.arch_backend().create_pasid_space(domain_token, args.mode == 1, sva_root, current) {
            Ok(token) => token,
            Err(e) => return domain_table_error_code(e),
        };
        let cap = install_root::<A>(
            &mut access,
            current,
            args.dst_slot,
            CapabilityObject::PasidSpace { unit: 0, space_token },
        );
        if cap & 0x8000_0000_0000_0000 != 0 {
            let _ = self.0.arch_backend().destroy_pasid_space(space_token);
        }
        cap
    }
}

/// Выделение PASID-капабилити (v2): PASID + потолок пользователей.
#[derive(SyscallArguments)]
pub struct SyscallCapIommuAllocPasid {
    pub space_task: u64,
    pub space_slot: u64,
    /// Потолок одновременных пользователей (привязанных устройств);
    /// 0 — без лимита (только явные free/bind-отказы по slab).
    pub max_users: u64,
    pub dst_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuAllocPasid> {
    const SYSCALL_ID: usize = 37;
    type Args = SyscallCapIommuAllocPasid;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let mut access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let space_token = match resolve_space_cap::<A>(&access, current, args.space_task, args.space_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        let pasid_token = match self.0.arch_backend().alloc_pasid_cap(space_token, args.max_users as u32, current) {
            Ok(token) => token,
            Err(e) => return domain_table_error_code(e),
        };
        let cap = install_root::<A>(
            &mut access,
            current,
            args.dst_slot,
            CapabilityObject::Pasid { unit: 0, pasid_token },
        );
        if cap & 0x8000_0000_0000_0000 != 0 {
            // Откат: снимаем аппаратный контекст и возвращаем id в пул.
            let _ = self.0.arch_backend().free_pasid_cap(pasid_token);
        }
        cap
    }
}

/// Уничтожение PASID-капабилити (v2).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuFreePasid {
    pub pasid_task: u64,
    pub pasid_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuFreePasid> {
    const SYSCALL_ID: usize = 38;
    type Args = SyscallCapIommuFreePasid;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let pasid_token = match resolve_pasid_cap::<A>(&access, current, args.pasid_task, args.pasid_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        // Сама capability со слота НЕ снимается (cap_id записи недоступен
        // из (task_cap, slot) без обратного индекса) — она естественно
        // протухает: токен после free мёртв, resolve жив, но все инвокации
        // вернут E_NOT_FOUND (BadToken). Семантика seL4-удаления объекта.
        self.0.arch_backend().free_pasid_cap(pasid_token)
            .map(|()| res::OK)
            .unwrap_or_else(|e| domain_table_error_code(e))
    }
}

/// Привязка устройства-пользователя к PASID (v2; квота — E_QUOTA).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuBindPasidDevice {
    pub pasid_task: u64,
    pub pasid_slot: u64,
    pub bus: u64,
    pub device: u64,
    pub function: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuBindPasidDevice> {
    const SYSCALL_ID: usize = 39;
    type Args = SyscallCapIommuBindPasidDevice;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.bus > u8::MAX as u64 || args.device > 0x1f || args.function > 0x7 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let pasid_token = match resolve_pasid_cap::<A>(&access, current, args.pasid_task, args.pasid_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0
            .arch_backend()
            .bind_pasid_device(
                pasid_token,
                PciAddress {
                    segment: 0,
                    bus: args.bus as u8,
                    device: args.device as u8,
                    function: args.function as u8,
                },
            )
            .map(|()| res::OK)
            .unwrap_or_else(iommu_error_code)
    }
}

/// Отвязка устройства-пользователя от PASID (v2).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuUnbindPasidDevice {
    pub pasid_task: u64,
    pub pasid_slot: u64,
    pub bus: u64,
    pub device: u64,
    pub function: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuUnbindPasidDevice> {
    const SYSCALL_ID: usize = 40;
    type Args = SyscallCapIommuUnbindPasidDevice;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.bus > u8::MAX as u64 || args.device > 0x1f || args.function > 0x7 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let pasid_token = match resolve_pasid_cap::<A>(&access, current, args.pasid_task, args.pasid_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0
            .arch_backend()
            .unbind_pasid_device(
                pasid_token,
                PciAddress {
                    segment: 0,
                    bus: args.bus as u8,
                    device: args.device as u8,
                    function: args.function as u8,
                },
            )
            .map(|()| res::OK)
            .unwrap_or_else(iommu_error_code)
    }
}

/// Маппинг first-stage через PASID-капабилити (v2).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuMapVa {
    pub pasid_task: u64,
    pub pasid_slot: u64,
    pub gva: u64,
    pub phys: u64,
    pub pages: u64,
    pub prot_mask: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuMapVa> {
    const SYSCALL_ID: usize = 41;
    type Args = SyscallCapIommuMapVa;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let prot = IommuProtection::from_bits_truncate(args.prot_mask as u8);
        if prot.is_empty() || args.pages == 0 {
            return res::E_INVALID_ARG;
        }
        if !phys_range_ok(args.phys, args.pages) {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let pasid_token = match resolve_pasid_cap::<A>(&access, current, args.pasid_task, args.pasid_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().map_va(pasid_token, args.gva as usize, args.phys as usize, args.pages as usize, prot)
            .map(|()| res::OK)
            .unwrap_or_else(iommu_error_code)
    }
}

/// Снятие first-stage маппинга (v2).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuUnmapVa {
    pub pasid_task: u64,
    pub pasid_slot: u64,
    pub gva: u64,
    pub pages: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuUnmapVa> {
    const SYSCALL_ID: usize = 42;
    type Args = SyscallCapIommuUnmapVa;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.pages == 0 {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let pasid_token = match resolve_pasid_cap::<A>(&access, current, args.pasid_task, args.pasid_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().unmap_va(pasid_token, args.gva as usize, args.pages as usize)
            .map(|()| res::OK)
            .unwrap_or_else(iommu_error_code)
    }
}

/// Уничтожение PASID-пространства (v2; только без живых PASID).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuDestroyPasidSpace {
    pub space_task: u64,
    pub space_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuDestroyPasidSpace> {
    const SYSCALL_ID: usize = 43;
    type Args = SyscallCapIommuDestroyPasidSpace;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let space_token = match resolve_space_cap::<A>(&access, current, args.space_task, args.space_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().destroy_pasid_space(space_token)
            .map(|()| res::OK)
            .unwrap_or_else(domain_table_error_code)
    }
}

/// Уничтожение DMA-домена (v2 — закрывает утечку: раньше домены не
/// уничтожались userspace-ом вовсе).
#[derive(SyscallArguments)]
pub struct SyscallCapIommuDestroyDomain {
    pub task_cap: u64,
    pub cap_slot: u64,
}

impl<A: IommuTokenLayer> SyscallDomain for DomainIommu<A, SyscallCapIommuDestroyDomain> {
    const SYSCALL_ID: usize = 44;
    type Args = SyscallCapIommuDestroyDomain;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let access = self.0.permission_backend().lock();
        if check_dma_rights::<A>(&access, current).is_err() {
            return res::E_RIGHTS_DENIED;
        }
        let token = match resolve_domain_cap::<A>(&access, current, args.task_cap, args.cap_slot) {
            Ok(token) => token,
            Err(code) => return code,
        };
        self.0.arch_backend().destroy_domain(token)
            .map(|()| res::OK)
            .unwrap_or_else(domain_table_error_code)
    }
}

/// Публичный домен-обёртка (сисколлы регистрирует порт).
pub struct DomainIommu<A: IommuTokenLayer, Handler>(&'static KernelCTL<A>, PhantomData<Handler>);

impl<A: IommuTokenLayer, Handler> DomainIommu<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

/// Регистрация домена IOMMU (вызывает порт ПОСЛЕ init_syscalls).
pub fn init_iommu_syscalls<A: IommuTokenLayer>(kctl: &'static KernelCTL<A>) {
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuCreateDomain>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuAttachDevice>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuDetachDevice>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuMapDma>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuUnmapDma>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuMapDmaVa>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuCreatePasidSpace>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuAllocPasid>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuFreePasid>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuBindPasidDevice>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuUnbindPasidDevice>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuMapVa>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuUnmapVa>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuDestroyPasidSpace>::new(kctl));
    A::register_syscalls(DomainIommu::<A, SyscallCapIommuDestroyDomain>::new(kctl));
}
