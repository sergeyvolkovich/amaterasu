//! Архитектурно-независимые трейты IOMMU (Intel VT-d / AMD-Vi).
//!
//! ГРАНИЦЫ МОДУЛЯ (важно):
//!   - здесь ТОЛЬКО контракты и переносимые типы данных; никакой логики —
//!     ни парсинга ACPI (DRHD-записи у VT-d / IVHD у AMD-Vi), ни работы с
//!     регистрами, ни построения таблиц трансляции. Всё это — забота
//!     реализации трейтов в порту (`ArchImplementation::Iommu`);
//!   - перечисление PCIe (enumiration) выполняет USERSPACE. Ядро получает
//!     готовый `PciAddress` из запроса userspace и только конвертирует его
//!     в аппаратный формат идентификатора запросчика (`RequesterId`);
//!   - типы намеренно не привязаны к x86_64: VT-d и AMD-Vi различаются
//!     только в реализациях, а контракт (домен, маппинг IOVA->физика,
//!     присоединение устройств) одинаков для любой платформы с IOMMU.
//!
//! СВЯЗЬ С КАПАБИЛИТАМИ: доступ к операциям присоединения устройств
//! должен открываться только носителям DMA-права группы
//! (NamespaceRights::DMA_ATTACH) — это проверяет слой сисколлов, трейтам
//! здесь про права знать нечего.

use bitflags::bitflags;

/// Адрес устройства PCI, как его сообщает userspace (сегмент:шина:устройство:
/// функция). Энумерация PCIe — задача userspace; ядро ничего не сканирует
/// само и доверяет этому адресу настолько, насколько доверяет вызывающему
/// (проверка права — на слое капабилити).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    /// Канонический 16-битный идентификатор запросчика (BDF без сегмента):
    /// шина [15:8], устройство [7:3], функция [2:0]. Именно в таком виде
    /// устройство подписывает свои DMA-транзакции и его видят оба IOMMU
    /// (VT-d: source-id в контексте; AMD-Vi: device id в device table).
    pub fn requester_id(self) -> RequesterId {
        RequesterId(
            ((self.bus as u16) << 8)
                | ((self.device as u16 & 0x1F) << 3)
                | (self.function as u16 & 0x7),
        )
    }
}

/// Идентификатор запросчика DMA (source-id), под которым устройство видно
/// IOMMU в транзакции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequesterId(pub u16);

/// Процесс-контекст DMA (PASID): разделяемый несколькими потоками
/// адресный пространство одного устройства. У VT-d — PASID-записи в
/// контексте (scalable mode), у AMD-Vi — PASID через GCR3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pasid(pub u32);

/// Семейство IOMMU. Реализация трейтов обязана честно сообщить, что под
/// капотом, чтобы верхние слои могли настраивать специфичные вещи (например,
/// прерывания-фолты: VT-d — через FRR/IRR, AMD-Vi — через event log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuModel {
    /// Intel Virtualization Technology for Directed I/O.
    IntelVtd,
    /// AMD I/O Virtualization Technology (AMD-Vi).
    AmdVi,
}

bitflags! {
    /// Права доступа к DMA-странице. Биты семантические: реализация мапит их
    /// на аппаратные (VT-d: R/W/S/X в PTE; AMD-Vi: IR/IW в PTE, исполнительного
    /// бита нет — см. IommuCapabilities::supports_exec_permission).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IommuProtection: u8 {
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

/// Статический снимок возможностей конкретного IOMMU-юнита. Заполняется
/// реализацией один раз при инициализации из аппаратных capability-
/// регистров (VT-d: CAP/ECAP; AMD-Vi: IVHD-флаги + Extended Feature Reg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuCapabilities {
    /// Семейство (дублируется из IommuUnit::model для удобства переносов
    /// через границы слоёв).
    pub model: IommuModel,
    /// Максимальная ширина входного адреса (IA) в битах: 39/48 у VT-d,
    /// 40/48/64 у AMD-Vi — в зависимости от поколения.
    pub address_width_bits: u8,
    /// Бит N == 1: поддерживается страница размера 2^N (у VT-d — 4K/2M/1G,
    /// у AMD-Vi — 4K/2M/1G/... в зависимости от уровня таблиц).
    pub page_size_mask: u64,
    /// Максимальный поддерживаемый PASID (0 — PASID нет вовсе).
    pub max_pasid: u32,
    /// Есть ли вообще процесс-контексты (PASID/GCR3).
    pub supports_pasid: bool,
    /// Есть ли аппаратный запрет исполнения DMA-страниц (у AMD-Vi — нет).
    pub supports_exec_permission: bool,
    /// Когерентный обход таблиц трансляции (snoop); на некогерентных
    /// реализациях драйвер обязан инвалилидировать кэши CPU после
    /// изменения таблиц.
    pub coherent_walk: bool,
    /// Scalable-mode поддержка (Intel ECAP.SRS: scalable root/context +
    /// PASID-таблицы). Для AMD аналогом служит GTSup (см. supports_pasid).
    pub supports_scalable: bool,
    /// Максимум доменов трансляции, выражаемых аппаратурой (у VT-d —
    /// размер контекстной таблицы, у AMD-Vi — домены device table).
    pub max_domains: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU-юнитов в системе нет (или ещё не инициализированы портом).
    NoIommuUnits,
    /// Аппаратный лимит доменов исчерпан.
    DomainLimitReached,
    /// Кадро-аллокатор не дал страницу под таблицу трансляции.
    OutOfFrames,
    /// Запрошенная ширина адреса превышает capability юнита.
    UnsupportedAddressWidth { requested_bits: u8, supported_bits: u8 },
    /// Размер страницы не поддерживается этим юнитом (см. page_size_mask).
    UnsupportedPageSize(usize),
    /// Комбинация прав не выражается аппаратурой (например, EXEC у AMD-Vi).
    UnsupportedProtection(IommuProtection),
    /// PASID-контексты юнитом не поддерживаются / пока не реализованы.
    PasidNotSupported,
    /// Устройство не присоединено к этому домену.
    DeviceNotAttached(PciAddress),
    /// Устройство уже присоединено (к этому или другому домену).
    DeviceAlreadyAttached(PciAddress),
    /// IOVA вне диапазона, которым владеет домен.
    InvalidIova(usize),
    /// Физический адрес вне зоны, которую юнит способен транслировать.
    InvalidPhysicalAddress(usize),
    /// Аппаратная ошибка: реализации передают свой код/статус.
    HardwareError { detail: u64 },
    /// Пул PASID юнита исчерпан (v2: отдельная от доменов ошибка —
    /// раньше оба случая шли через DomainLimitReached и мапились в E_SLAB,
    /// хотя семантика — исчерпание КВОТЫ ресурса).
    PasidLimitReached,
    /// Превышен лимит одновременных пользователей PASID-капабилити
    /// (admission control v2: bind сверх max_users отклоняется —
    /// deny-семантика; уведомление держателя — через fault-endpoint).
    QuotaExceeded,
    /// PASID-пространство нельзя уничтожить: в нём живы PASID-капабилити
    /// (инвариант времени жизни: пространство умирает последним).
    SpaceHasPasids,
    /// Токен умер между резолвом и операцией (гонка с destroy — v2:
    /// операции по копиям полей проверяют живость под локом записи).
    StaleToken,
    /// Операция требует legacy-юнита: на scalable-юните legacy 16-байтный
    /// context entry писал бы в 32-байтный слот (порча таблицы). Крейт
    /// intel-iommu пока не даёт билдеров SSPTPTR/DID/AW для scalable-CE —
    /// честный fail-closed вместо выдуманной раскладки (v3: scalable
    /// second-stage-only attach).
    LegacyContextRequired,
}

/// Ошибки реестров IOMMU (capability-фасад).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Нет памяти (slab OOM) или ресурс юнита исчерпан.
    Full,
    /// Токен не резолвится (умер/чужое поколение).
    BadToken,
    /// Объект занят живыми ссылками (домен — устройствами, пространство —
    /// PASID): уничтожение отложено до обнуления счётчика.
    Occupied,
}

/// Capability-фасад IOMMU над таблицами токенов arch-слоя.
///
/// Сисколлы инвокаций (syscall::iommu) работают ТОЛЬКО через этот трейт —
/// они архитектурно-независимы и не знают про VT-d/AMD-Vi; порт реализует
/// фасад поверх своих конкретных бэкендов (у x86 — enum-диспетчер
/// VtdUnit/AmdUnit + таблицы доменов/пространств с поколениями).
/// МОДЕЛЬ PASID v2 (PASID-как-капабилити):
///
///   PasidSpace — АДРЕСНОЕ пространство (домен second-stage + first-stage
///   root: SVA — CR3 владельца при создании; Dedicated — выделяется
///   бэкендом при первом bind). Многопользовательское: на одно пространство
///   может ссылаться произвольное число PASID-капабилити.
///
///   Pasid — КАПАБИЛИТИЯ на аппаратный PASID юнита, привязанный к
///   пространству. Несёт учёт пользователей: max_users (потолок,
///   задан при создании) и список привязанных устройств. Каждая
///   привязка (device) — пользователь; bind сверх max_users —
///   QuotaExceeded (deny-семантика, не блокировка в сисколле).
///   Invокации bind/unbind/map_va/unmap_va идут через PASID-капабилити.
///
/// ПОРЯДОК ЖИЗНИ: space жив, пока есть хотя бы один его PASID
/// (destroy_space при живых pasid — SpaceHasPasids); PASID жив, пока
/// есть пользователи или пока владелец не вызвал free.
pub trait IommuTokenLayer: crate::traits::ArchImplementation {
    /// Активный IOMMU-юнит (None — не инициализирован/нет в системе).
    fn iommu_unit(&self) -> Option<&'static <Self as ArchIommuBase>::Iommu>;

    // ── DMA-домены (second-stage) ──

    /// `owner` — task_cap создателя (для teardown погибших задач).
    fn create_domain(&self, owner: u64) -> Result<u64, TokenError>;
    fn destroy_domain(&self, token: u64) -> Result<(), TokenError>;
    fn attach_device(&self, token: u64, device: PciAddress) -> Result<(), IommuError>;
    fn detach_device(&self, token: u64, device: PciAddress) -> Result<(), IommuError>;
    fn map_dma(&self, token: u64, iova: usize, phys: usize, pages: usize, prot: IommuProtection) -> Result<(), IommuError>;
    fn unmap_dma(&self, token: u64, iova: usize, pages: usize) -> Result<(), IommuError>;

    // ── PASID v2 (см. документацию трейта) ──

    /// Создаёт PASID-пространство над доменом. `sva_root` — готовый
    /// first-stage root (CR3 владельца; для SVA). Для Dedicated —
    /// `None`: бэкенд выделит root при первом bind. `owner` — создатель.
    fn create_pasid_space(
        &self,
        domain_token: u64,
        sva: bool,
        sva_root: Option<usize>,
        owner: u64,
    ) -> Result<u64, TokenError>;
    /// Уничтожает пространство (только без живых PASID — Occupied).
    fn destroy_pasid_space(&self, space_token: u64) -> Result<(), TokenError>;

    fn alloc_pasid_cap(&self, space_token: u64, max_users: u32, owner: u64) -> Result<u64, TokenError>;
    /// Уничтожает PASID-капабилити: все привязки снимаются аппаратно,
    /// id возвращается пулу.
    fn free_pasid_cap(&self, pasid_token: u64) -> Result<(), TokenError>;

    /// Привязывает устройство-пользователя к PASID (set_pasid_context +
    /// учёт). Сверх max_users — QuotaExceeded; повторная привязка того
    /// же устройства — DeviceAlreadyAttached.
    fn bind_pasid_device(&self, pasid_token: u64, device: PciAddress) -> Result<(), IommuError>;
    /// Отвязывает устройство-пользователя.
    fn unbind_pasid_device(&self, pasid_token: u64, device: PciAddress) -> Result<(), IommuError>;

    /// Маппит first-stage страницы через PASID-капабилити (GVA -> физика);
    /// инвалидации — доменно-scoped по (DID, PASID).
    fn map_va(&self, pasid_token: u64, gva: usize, phys: usize, pages: usize, prot: IommuProtection) -> Result<(), IommuError>;
    /// Снимает first-stage страницы.
    fn unmap_va(&self, pasid_token: u64, gva: usize, pages: usize) -> Result<(), IommuError>;
}

/// Подставка-трейт для ассоциированных типов (Umap нужен сисколлам для
/// AccessManager, Iommu — для юнита; структурно = ArchImplementation).
pub trait ArchIommuBase {
    type Umap: crate::traits::memory::MemoryInterfaceUserspace;
    type Iommu: IommuUnit;
}

impl<T: crate::traits::ArchImplementation> ArchIommuBase for T {
    type Umap = T::Umap;
    type Iommu = T::Iommu;
}

/// Домен трансляции IOMMU: набор маппингов IOVA -> физика + множество
/// присоединённых устройств. Все устройства одного домена видят одно
/// адресное пространство — это и есть "песочница" для драйверов
/// userspace: домен на задачу/драйвер, устройства внутрь, маппинги
/// строго через права.
///
/// Реализация обязана быть потокобезопасной (Sync): домены могут
/// разделяться планировщиком между ядрами.
pub trait IommuDomain: Sync {
    /// Отображает `pages` последовательных страниц: IOVA `iova` -> физика
    /// `phys` (оба адреса обязаны быть выровнены на размер страницы).
    fn map_pages(
        &self,
        iova: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError>;

    /// Снимает `pages` страниц, начиная с `iova`.
    fn unmap_pages(&self, iova: usize, pages: usize) -> Result<(), IommuError>;

    /// Проверочная трансляция IOVA -> физика (для отладки и аудита
    /// маппингов; DMA-путь её не использует).
    fn translate(&self, iova: usize) -> Result<usize, IommuError>;

    /// Полная инвалидация IOTLB домена. Реализация сама обязана
    /// инвалилидировать на лету где нужно; этот метод — "протолкнуть
    /// всё" (например, после массового размапинга перед передачей
    /// устройства другому домену).
    fn flush_iotlb(&self);
}

/// Один IOMMU-юнит платформы: у VT-d — один DRHD-блок, у AMD-Vi — один
/// IVHD-дескриптор. Ядро может иметь несколько юнитов; порт отдаёт их
/// через ArchImplementation::Iommu / ArchImplementation::iommu().
pub trait IommuUnit: Sync {
    /// Тип домена, создаваемого этим юнитом (аппаратный хэндл реализации).
    type Domain: IommuDomain;

    /// Семейство контроллера.
    fn model(&self) -> IommuModel;

    /// База MMIO-регистров юнита (для диагностики/дампов из отладчика ядра).
    fn mmio_base(&self) -> usize;

    /// Снимок capability-регистров юнита.
    fn capabilities(&self) -> IommuCapabilities;

    /// Создаёт пустой домен трансляции.
    fn create_domain(&self) -> Result<Self::Domain, IommuError>;

    /// Уничтожает домен. Реализация обязана гарантировать, что после
    /// возврата Ok ни одна DMA-транзакция не обслуживается маппингами
    /// этого домена (внутрь входит инвалидация).
    fn destroy_domain(&self, domain: Self::Domain) -> Result<(), IommuError>;

    /// Присоединяет устройство (опционально — с PASID-контекстом) к домену.
    /// Переданный PciAddress приходит из userspace-запроса; право на
    /// операцию проверяется слоем капабилити ДО вызова.
    fn attach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError>;

    /// Отсоединяет устройство от домена.
    fn detach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError>;

    // ── PASID / SVA (scalable-mode у Intel, GCR3 у AMD) ──
    // Дефолты возвращают PasidNotSupported: бэкенды без PASID-поддержки
    // не обязаны ничего переопределять (см. PasidSpace-инвокации).

    /// Выделяет PASID на юните.
    fn alloc_pasid(&self) -> Result<Pasid, IommuError> {
        Err(IommuError::PasidNotSupported)
    }

    /// Возвращает PASID юниту.
    fn free_pasid(&self, pasid: Pasid) -> Result<(), IommuError> {
        let _ = pasid;
        Err(IommuError::PasidNotSupported)
    }

    /// Привязывает PASID-контекст (device, PASID) -> first-stage
    /// адресное пространство. Возвращает физический адрес first-stage root,
    /// использованный бэкендом.
    ///
    /// `fs_root`: `Some(root)` — SVA (root указывает на готовые
    /// Intel-64/v1 таблицы, например CR3 процесса); `None` — бэкенд
    /// аллоцирует отдельный (dedicated) root. `fs_levels` — уровней в
    /// first-stage таблицах.
    fn set_pasid_context(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
        fs_root: Option<usize>,
        fs_levels: u8,
    ) -> Result<usize, IommuError> {
        let _ = (domain, device, pasid, fs_root, fs_levels);
        Err(IommuError::PasidNotSupported)
    }

    /// Отвязывает PASID-контекст устройства (и освобождает dedicated-root,
    /// если контекст создавался бэкендом).
    fn clear_pasid_context(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
    ) -> Result<(), IommuError> {
        let _ = (domain, device, pasid);
        Err(IommuError::PasidNotSupported)
    }

    /// Маппит страницы в first-stage адресное пространство PASID-контекста
    /// (GVA -> физика). Для SVA-контекстов, привязанных к CR3 процесса,
    /// маппинг ведёт сам процесс через обычные пути — вызов нужен только
    /// dedicated-контекстам.
    // Аргументов 8 — сознательно: инвокация транслирует (домен, pasid,
    // root, диапазон) одним вызовом, чтобы портам не нужен промежуточный
    // тип-пачка. У clippy отключение локально.
    #[allow(clippy::too_many_arguments)]
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
        let _ = (domain, pasid, fs_root, gva, phys, pages, prot);
        Err(IommuError::PasidNotSupported)
    }

    /// Снимает страницы first-stage адресного пространства.
    fn unmap_first_stage(
        &self,
        domain: &Self::Domain,
        pasid: Pasid,
        fs_root: usize,
        gva: usize,
        pages: usize,
    ) -> Result<(), IommuError> {
        let _ = (domain, pasid, fs_root, gva, pages);
        Err(IommuError::PasidNotSupported)
    }

    /// Возвращает кадр dedicated first-stage root (аллоцированный
    /// бэкендом в set_pasid_context) при уничтожении PASID-пространства.
    /// Для SVA-пространств НЕ вызывается (root принадлежит процессу).
    /// Дефолт — no-op (утечка кадра, но не безопасности).
    fn release_fs_root(&self, fs_root: usize) {
        let _ = fs_root;
    }
}
