//! IOMMU-слой x86_64: два бэкенда (Intel VT-d / AMD-Vi) за одним
//! архитектурно-независимым контрактом kernel_base — РЕЕСТРЫ v2.
//!
//!   iommu::intel — VtdUnit/VtdDomain (крейт intel-iommu)
//!   iommu::amd   — AmdUnit/AmdDomain  (крейт amd-iommu)
//!   iommu::mod   — slab-реестры объектов (домены / PASID-пространства /
//!                  PASID-капабилити) + enum-диспетчер юнитов
//!
//! Выбор бэкенда — по boot-таблице (DMAR -> Intel, IVRS -> AMD).
//!
//! ─── ЧТО ИЗМЕНИЛО v2 (устранение бутылочных горлышек) ───────────────────────
//!
//! v1 держал домены и PASID-пространства в статических массивах
//! `[Option<Slot>; 64]` под ОДНИМ глобальным SpinMutex, который удерживался
//! на ВСЁ аппаратное подтверждение (QI/COMPLETION_WAIT — до 10^6 спиннов):
//! все ядра сериализовались на каждом bind/unmap, заклинившее железо
//! останавливало систему. Лимиты 64/64 были ниже аппаратных (CAP.ND до 64K,
//! PASID 512+) — горлышко было в ядровом букйкинге, не в железе.
//!
//! v2 переводит реестры на slab-аллокатор (идиома ядра — RBSlabIO, как
//! capspace/AccessManager) и разносит блокировки:
//!
//!   1. РЕЕСТРЫ БЕЗ ПРЕДЕЛОВ: RBSlabIO<u64, Entry, false> — деревья под
//!      коротким SpinMutex (только вставка/поиск/тумбстоун, O(log n),
//!      НИКАКОГО MMIO под деревом). Память растёт динамически (slab-страницы
//!      по 4 КиБ), потолок — кадровый аллокатор, а не константа.
//!   2. ТОКЕНЫ МОНОТОННЫ: token = глобальный AtomicU64, никогда не
//!      переиспользуется. Поколения v1 не нужны — тумбстоуненный ключ
//!      физически не может совпасть с живым (ABA закрыт конструктивно).
//!      ПАМЯТЬ ЗАПИСЕЙ БЕССМЕРТНА (tombstone-на-месте, remove запрещён —
//!      тот же контракт, что у capspace): NonNull, снятый под деревом,
//!      валиден и после снятия лока.
//!   3. ПЕР-ОБЪЕКТНЫЕ ЛОКИ: у домена — hw-мьютекс (сериализация мутаций
//!      таблиц), у PASID — users-мьютекс (учёт пользователей + аппаратные
//!      операции над ЕГО контекстами). MMIO держит только лок СВОЕГО
//!      объекта — bind разных PASID/доменов идёт параллельно.
//!   4. ПОРЯДОК ЛОКОВ (защита от дедлока): pasid.users -> space.tree ->
//!      space.fs_root; domain.hw -> unit-пулы. Дерево никогда не берётся
//!      под деревом: resolve_* ВСЕГДА снимают лок до возврата (снятие
//!      NonNull под деревом законно — записи бессмертны).
//!
//! ─── PASID-КАПАБИЛИТИ (v2) ──────────────────────────────────────────────────
//!
//!   PasidSpace — first-stage АДРЕСНОЕ пространство: домен second-stage +
//!   root (SVA: CR3 владельца, фиксируется при create; Dedicated: выделяется
//!   бэкендом при первом bind и разделяется всеми устройствами). На одно
//!   пространство — произвольное число PASID-капабилити.
//!
//!   Pasid — КАПАБИЛИТИЯ: аппаратный PASID юнита + привязка к пространству
//!   + учёт пользователей (max_users задан при создании; список привязанных
//!   устройств — slab-дерево по requester id). bind сверх потолка —
//!   QuotaExceeded (deny-семантика адмиссии). Пользователь = устройство.
//!
//!   ЦЕПЬ ВРЕМЁН ЖИЗНИ: domain <- space <- pasid <- users. Каждый
//!   нижележащий объект держит счётчик на вышележащем (live_pasids,
//!   DomainEntry.attached — он же учёт и устройств, и PASID-контекстов);
//!   уничтожение верхнего — только при нуле. Teardown погибшей задачи
//!   (on_task_destroy) рвёт цепь сверху вниз: pasid -> space -> domain.

pub mod amd;
pub mod intel;

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernel_base::collection::RBSlabIO;
use kernel_base::traits::iommu::{
    IommuCapabilities, IommuDomain, IommuError, IommuModel, IommuProtection, IommuTokenLayer,
    IommuUnit, Pasid, PciAddress, TokenError,
};
use kernel_base::traits::memory::PAGE_SIZE;
use spin::mutex::SpinMutex;
use spin::Once;

// ─── Диспетчер юнитов ────────────────────────────────────────────────────────

/// Объединённый IOMMU-юнит платформы (один из двух бэкендов).
/// `ArchImplementation::Iommu` = этот тип.
pub enum IommuUnitHandle {
    Intel(intel::VtdUnit),
    Amd(amd::AmdUnit),
}

impl IommuUnit for IommuUnitHandle {
    type Domain = IommuDomainHandle;

    fn model(&self) -> IommuModel {
        match self {
            IommuUnitHandle::Intel(u) => u.model(),
            IommuUnitHandle::Amd(u) => u.model(),
        }
    }

    fn mmio_base(&self) -> usize {
        match self {
            IommuUnitHandle::Intel(u) => u.mmio_base(),
            IommuUnitHandle::Amd(u) => u.mmio_base(),
        }
    }

    fn capabilities(&self) -> IommuCapabilities {
        match self {
            IommuUnitHandle::Intel(u) => u.capabilities(),
            IommuUnitHandle::Amd(u) => u.capabilities(),
        }
    }

    fn create_domain(&self) -> Result<Self::Domain, IommuError> {
        match self {
            IommuUnitHandle::Intel(u) => u.create_domain().map(IommuDomainHandle::Intel),
            IommuUnitHandle::Amd(u) => u.create_domain().map(IommuDomainHandle::Amd),
        }
    }

    fn destroy_domain(&self, domain: Self::Domain) -> Result<(), IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => u.destroy_domain(d),
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => u.destroy_domain(d),
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn attach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.attach_device(d, device, pasid)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => u.attach_device(d, device, pasid),
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn detach_device(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Option<Pasid>,
    ) -> Result<(), IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.detach_device(d, device, pasid)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => {
                u.detach_device(d, device, pasid)
            }
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn alloc_pasid(&self) -> Result<Pasid, IommuError> {
        match self {
            IommuUnitHandle::Intel(u) => u.alloc_pasid(),
            IommuUnitHandle::Amd(u) => u.alloc_pasid(),
        }
    }

    fn free_pasid(&self, pasid: Pasid) -> Result<(), IommuError> {
        match self {
            IommuUnitHandle::Intel(u) => u.free_pasid(pasid),
            IommuUnitHandle::Amd(u) => u.free_pasid(pasid),
        }
    }

    fn set_pasid_context(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
        fs_root: Option<usize>,
        fs_levels: u8,
    ) -> Result<usize, IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.set_pasid_context(d, device, pasid, fs_root, fs_levels)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => {
                u.set_pasid_context(d, device, pasid, fs_root, fs_levels)
            }
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn clear_pasid_context(
        &self,
        domain: &Self::Domain,
        device: PciAddress,
        pasid: Pasid,
    ) -> Result<(), IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.clear_pasid_context(d, device, pasid)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => {
                u.clear_pasid_context(d, device, pasid)
            }
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
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
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.map_first_stage(d, pasid, fs_root, gva, phys, pages, prot)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => {
                u.map_first_stage(d, pasid, fs_root, gva, phys, pages, prot)
            }
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn unmap_first_stage(
        &self,
        domain: &Self::Domain,
        pasid: Pasid,
        fs_root: usize,
        gva: usize,
        pages: usize,
    ) -> Result<(), IommuError> {
        match (self, domain) {
            (IommuUnitHandle::Intel(u), IommuDomainHandle::Intel(d)) => {
                u.unmap_first_stage(d, pasid, fs_root, gva, pages)
            }
            (IommuUnitHandle::Amd(u), IommuDomainHandle::Amd(d)) => {
                u.unmap_first_stage(d, pasid, fs_root, gva, pages)
            }
            _ => Err(IommuError::HardwareError { detail: 0xBAD }),
        }
    }

    fn release_fs_root(&self, fs_root: usize) {
        match self {
            IommuUnitHandle::Intel(u) => u.release_fs_root(fs_root),
            IommuUnitHandle::Amd(u) => u.release_fs_root(fs_root),
        }
    }
}

// ─── Диспетчер доменов ───────────────────────────────────────────────────────

/// Домен одного из бэкендов. Copy: VtdDomain/AmdDomain — чистые
/// дескрипторы; таблицы (память) живут в ядре, мутации через &self.
#[derive(Clone, Copy)]
pub enum IommuDomainHandle {
    Intel(intel::VtdDomain),
    Amd(amd::AmdDomain),
}

impl IommuDomain for IommuDomainHandle {
    fn map_pages(
        &self,
        iova: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError> {
        match self {
            IommuDomainHandle::Intel(d) => d.map_pages(iova, phys, pages, prot),
            IommuDomainHandle::Amd(d) => d.map_pages(iova, phys, pages, prot),
        }
    }

    fn unmap_pages(&self, iova: usize, pages: usize) -> Result<(), IommuError> {
        match self {
            IommuDomainHandle::Intel(d) => d.unmap_pages(iova, pages),
            IommuDomainHandle::Amd(d) => d.unmap_pages(iova, pages),
        }
    }

    fn translate(&self, iova: usize) -> Result<usize, IommuError> {
        match self {
            IommuDomainHandle::Intel(d) => d.translate(iova),
            IommuDomainHandle::Amd(d) => d.translate(iova),
        }
    }

    fn flush_iotlb(&self) {
        match self {
            IommuDomainHandle::Intel(d) => d.flush_iotlb(),
            IommuDomainHandle::Amd(d) => d.flush_iotlb(),
        }
    }
}

// ─── Slab-реестры (v2): деревья токенов, tombstone-на-месте ──────────────────

/// Ключ реестров — монотонный токен (0 не выдаётся: 0 = невалиден).
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

fn fresh_token() -> u64 {
    NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
}

/// Реестр DMA-доменов: токен -> домен + учёт аппаратных пользователей.
pub struct DomainEntry {
    /// Сам токен (дублируется в значении: for_each-сканы teardown идут
    /// по &V без ключей).
    pub token: u64,
    /// Иммутабельный дескриптор домена (таблицы — в кадрах юнита).
    pub domain: IommuDomainHandle,
    /// Создатель (task_cap) — для teardown. 0 — ядро.
    pub owner_task: u64,
    /// Аппаратные пользователи second-stage домена: привязанные устройства
    /// (AttachDevice/DetachDevice) + живые PASID-контексты пространств над
    /// доменом (SLPTPTR/DID в PASIDTE). Destroy — только при нуле: иначе
    /// DID вернулся бы в пул при живой аппаратной ссылке — aliasing DMA.
    pub attached: AtomicU32,
    /// Жив (не тумбстоунен). Тумбстоун — навсегда: ключ не переиспользуется.
    pub live: AtomicBool,
    /// Сериализация аппаратных мутаций домена (attach/detach/map/unmap):
    /// один домен — друг за другом, разные домены — параллельно.
    pub hw: SpinMutex<()>,
}

/// Реестр PASID-пространств: токен -> пространство first-stage.
pub struct PasidSpaceEntry {
    /// Сам токен (для for_each-сканов).
    pub token: u64,
    /// Домен second-stage (иммутабелен после создания).
    pub domain: IommuDomainHandle,
    /// Токен домена — для учёта attached на домене.
    pub domain_token: u64,
    /// Dedicated (root выделяет бэкенд) или SVA (root = CR3 владельца).
    pub dedicated: bool,
    /// First-stage root. SVA: Some(CR3) при create. Dedicated: None до
    /// первого bind — бэкенд выделит, адрес сохранится здесь и будет
    /// разделён всеми устройствами пространства.
    pub fs_root: SpinMutex<Option<usize>>,
    /// Создатель (task_cap) — для teardown.
    pub owner_task: u64,
    /// Живых PASID-капабилити пространства. Destroy — только при нуле
    /// (пространство умирает последним: PASIDTE ссылается на fs_root).
    pub live_pasids: AtomicU32,
    /// Жив (не тумбстоунен).
    pub live: AtomicBool,
}

/// Реестр PASID-капабилити (v2): токен -> PASID с учётом пользователей.
pub struct PasidEntry {
    /// Сам токен (для for_each-сканов).
    pub token: u64,
    /// Токен PASID-пространства (резолвится на каждой операции — без
    /// удержания двух деревьев одновременно).
    pub space_token: u64,
    /// Домен пространства (копия дескриптора — для аппаратных вызовов).
    pub domain: IommuDomainHandle,
    /// Аппаратный PASID юнита.
    pub pasid: Pasid,
    /// Потолок одновременных пользователей (0 — без лимита).
    pub max_users: u32,
    /// Текущее число пользователей (консистентно под `users`-локом).
    pub user_count: AtomicU32,
    /// Пользователи (привязанные устройства): slab-дерево по requester id.
    /// Ключ и значение — requester id (значение нужно дренажу teardown:
    /// for_each даёт только &V).
    pub users: SpinMutex<RBSlabIO<u64, u64, false>>,
    /// Создатель (task_cap) — для teardown.
    pub owner_task: u64,
    /// Жив (не тумбстоунен).
    pub live: AtomicBool,
}

type DomainTree = SendTree<RBSlabIO<u64, DomainEntry, false>>;
type SpaceTree = SendTree<RBSlabIO<u64, PasidSpaceEntry, false>>;
type PasidTree = SendTree<RBSlabIO<u64, PasidEntry, false>>;

/// Обёртка Send для slab-деревьев (NoLock-контракт).
///
/// RBSlabIO с NoLock-кэшем формально !Send: контракт NoLock требует, чтобы
/// весь доступ к slab-кэшу дерева (insert = alloc узла, remove = free узла)
/// шёл под внешним локом. Обёртка его обеспечивает: ВСЕ структурные операции
/// идут под SpinMutex внутри (tree.lock()). Чтение полей записей ПОСЛЕ
/// снятия лока (NonNull-кэширование) синхронизировано тем же локом: запись
/// видна любому, кто позже взял лок (happens-before), а дальнейшие чтения
/// — иммутабельные поля и атомарные флаги.
struct SendTree<T>(SpinMutex<T>);
// SAFETY: см. выше — NoLock-контракт закрыт SpinMutex обёртки (структурные
// операции дерева); пер-записные slab-кэши (users у PasidEntry) закрыты
// собственными лками записей. Все методы (&self) блокируют мьютекс —
// конкурентный &-доступ сериализован.
unsafe impl<T> Send for SendTree<T> {}
unsafe impl<T> Sync for SendTree<T> {}

impl<T> SendTree<T> {
    fn new(value: T) -> Option<Self> {
        Some(Self(SpinMutex::new(value)))
    }

    fn lock(&self) -> spin::mutex::SpinMutexGuard<'_, T> {
        self.0.lock()
    }
}

/// Деревья ленивы: slab-хуки ядра поднимаются ПОЗЖЕ iommu_early_init
/// (boot-путь kernel_limine), поэтому RBSlabIO::new() нельзя звать в
/// статическом инициализаторе. Первый доступ — из сисколлов/тестов, когда
/// init_allocator уже отработал. `None` внутри Once — slab OOM при
/// инициализации (навсегда; операции возвращают TokenError::Full).
static DOMAIN_TREE: Once<Option<DomainTree>> = Once::new();
static SPACE_TREE: Once<Option<SpaceTree>> = Once::new();
static PASID_TREE: Once<Option<PasidTree>> = Once::new();

macro_rules! tree_of {
    ($static:expr) => {
        // spin 0.12: call_once возвращает &Option<T>; as_ref() — внешний
        // Option (None => slab OOM при инициализации дерева).
        ($static.call_once(|| RBSlabIO::new().ok().and_then(SendTree::new))).as_ref()
    };
}

fn domain_tree() -> Option<&'static DomainTree> {
    tree_of!(DOMAIN_TREE)
}

fn space_tree() -> Option<&'static SpaceTree> {
    tree_of!(SPACE_TREE)
}

fn pasid_tree() -> Option<&'static PasidTree> {
    tree_of!(PASID_TREE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Slab OOM при инициализации дерева/вставке или исчерпание пула юнита.
    Full,
    /// Токен не резолвится или запись тумбстоунена.
    BadToken,
    /// Объект занят живыми ссылками (DomainEntry.attached /
    /// PasidSpaceEntry.live_pasids).
    Occupied,
}

impl From<RegistryError> for TokenError {
    fn from(e: RegistryError) -> TokenError {
        match e {
            RegistryError::Full => TokenError::Full,
            RegistryError::BadToken => TokenError::BadToken,
            RegistryError::Occupied => TokenError::Occupied,
        }
    }
}

// ─── Домены ──────────────────────────────────────────────────────────────────

/// Создаёт домен на юните и регистрирует под свежим токеном.
pub fn create_domain_token(unit: &IommuUnitHandle, owner_task: u64) -> Result<u64, RegistryError> {
    let domain = unit.create_domain().map_err(|_| RegistryError::Full)?;
    let tree = domain_tree().ok_or(RegistryError::Full)?;
    let token = fresh_token();
    let entry = DomainEntry {
        token,
        domain,
        owner_task,
        attached: AtomicU32::new(0),
        live: AtomicBool::new(true),
        hw: SpinMutex::new(()),
    };
    if tree.lock().insert(token, entry).is_err() {
        // Slab OOM при вставке — домен не регистрируется, ресурс назад.
        let _ = unit.destroy_domain(domain);
        return Err(RegistryError::Full);
    }
    Ok(token)
}

/// Резолвит токен -> (копия дескриптора, NonNull живой записи).
///
/// NonNull законен ПОСЛЕ снятия лока дерева: записи реестров бессмертны
/// (tombstone-на-месте, remove запрещён — контракт capspace), дроп дерева
/// происходит только при выключении ядра.
fn resolve_domain(
    token: u64,
) -> Result<(IommuDomainHandle, NonNull<DomainEntry>), RegistryError> {
    let tree = domain_tree().ok_or(RegistryError::Full)?;
    let tree = tree.lock();
    let entry = tree.get(&token).ok_or(RegistryError::BadToken)?;
    if !entry.live.load(Ordering::Acquire) {
        return Err(RegistryError::BadToken);
    }
    Ok((entry.domain, NonNull::from(entry)))
}

fn domain_entry(token: u64) -> Result<NonNull<DomainEntry>, RegistryError> {
    let tree = domain_tree().ok_or(RegistryError::Full)?;
    let tree = tree.lock();
    let entry = tree.get(&token).ok_or(RegistryError::BadToken)?;
    if !entry.live.load(Ordering::Acquire) {
        return Err(RegistryError::BadToken);
    }
    Ok(NonNull::from(entry))
}

/// Уничтожает домен по токену. Без `force` требует нуля аппаратных
/// пользователей (Occupied). Тумбстоун — ДО аппаратной части; ошибка
/// аппаратного уничтожения не воскрешает токен (безопасное направление:
/// ресурс теряется, но не переиспользуется).
pub fn destroy_domain_token(
    unit: &IommuUnitHandle,
    token: u64,
    force: bool,
) -> Result<(), RegistryError> {
    let (handle, entry) = resolve_domain(token)?;
    let entry_ref = entry as NonNull<DomainEntry>;
    // SAFETY: запись бессмертна (slab); мутации — атомарные/под hw-локом.
    let entry = unsafe { entry_ref.as_ref() };
    let attached = entry.attached.load(Ordering::Acquire);
    if attached != 0 && !force {
        return Err(RegistryError::Occupied);
    }
    entry.live.store(false, Ordering::Release);
    let _guard = entry.hw.lock();
    if attached == 0 {
        // Ноль пользователей — таблицы/DID можно вернуть юниту. С force
        // при живых ссылках уничтожение НЕ делаем: DID вернулся бы в пул
        // при живом context entry/PASIDTE — aliasing. Зомби-домен
        // (тумбстоунен, аппаратура доигрывает) — осознанная утечка
        // teardown'а (устройствам некому сделать detach после смерти
        // владельца; v3 — реестр устройств и их ревок).
        let _ = unit.destroy_domain(handle);
    }
    Ok(())
}

// ─── PASID-пространства ──────────────────────────────────────────────────────

/// Создаёт PASID-пространство над живым доменом.
pub fn create_space_token(
    domain_token: u64,
    dedicated: bool,
    sva_root: Option<usize>,
    owner_task: u64,
) -> Result<u64, RegistryError> {
    let (domain, _) = resolve_domain(domain_token)?;
    let tree = space_tree().ok_or(RegistryError::Full)?;
    let token = fresh_token();
    let entry = PasidSpaceEntry {
        token,
        domain,
        domain_token,
        dedicated,
        // SVA: root владельца фиксируется в момент create; Dedicated:
        // None — бэкенд выделит при первом bind (v1 брал/создавал root
        // при attach — окно рассогласования и по времени жизни, и по
        // разделению между устройствами одного пространства).
        fs_root: SpinMutex::new(if dedicated { None } else { sva_root }),
        owner_task,
        live_pasids: AtomicU32::new(0),
        live: AtomicBool::new(true),
    };
    if tree.lock().insert(token, entry).is_err() {
        return Err(RegistryError::Full);
    }
    Ok(token)
}

fn resolve_space(token: u64) -> Result<NonNull<PasidSpaceEntry>, RegistryError> {
    let tree = space_tree().ok_or(RegistryError::Full)?;
    let tree = tree.lock();
    let entry = tree.get(&token).ok_or(RegistryError::BadToken)?;
    if !entry.live.load(Ordering::Acquire) {
        return Err(RegistryError::BadToken);
    }
    Ok(NonNull::from(entry))
}

fn space_is_live(token: u64) -> bool {
    resolve_space(token).is_ok()
}

/// Уничтожает пространство: только без живых PASID. Возвращает
/// dedicated-root юниту (SVA root принадлежит процессу — не наш).
pub fn destroy_space_token(unit: &IommuUnitHandle, token: u64) -> Result<(), RegistryError> {
    let space = resolve_space(token)?;
    // SAFETY: запись бессмертна (slab, tombstone-на-месте); live —
    // атомарное, fs_root — под собственным локом.
    let space_ref = unsafe { space.as_ref() };
    if space_ref.live_pasids.load(Ordering::Acquire) != 0 {
        return Err(RegistryError::Occupied);
    }
    space_ref.live.store(false, Ordering::Release);
    let root = space_ref.fs_root.lock().take();
    if space_ref.dedicated {
        if let Some(root) = root {
            unit.release_fs_root(root);
        }
    }
    Ok(())
}

// ─── PASID-капабилити (v2) ───────────────────────────────────────────────────

/// Выделяет PASID юнита и регистрирует PASID-капабилити с потолком
/// пользователей. Держит счётчики цепи: space.live_pasids и
/// domain.attached (PASID-контекст — аппаратный пользователь домена).
pub fn alloc_pasid_token(
    unit: &IommuUnitHandle,
    space_token: u64,
    max_users: u32,
    owner_task: u64,
) -> Result<u64, RegistryError> {
    let space = resolve_space(space_token)?;
    // SAFETY: запись бессмертна; ниже — только чтение иммутабельных полей
    // и атомарный инкремент счётчика.
    let space_ref = unsafe { space.as_ref() };
    let domain = space_ref.domain;

    let pasid = unit.alloc_pasid().map_err(|_| RegistryError::Full)?;

    let users_tree = match RBSlabIO::new() {
        Ok(t) => t,
        Err(_) => {
            let _ = unit.free_pasid(pasid);
            return Err(RegistryError::Full);
        }
    };

    let tree = pasid_tree().ok_or(RegistryError::Full)?;
    let token = fresh_token();
    let entry = PasidEntry {
        token,
        space_token,
        domain,
        pasid,
        max_users,
        user_count: AtomicU32::new(0),
        users: SpinMutex::new(users_tree),
        owner_task,
        live: AtomicBool::new(true),
    };
    if tree.lock().insert(token, entry).is_err() {
        let _ = unit.free_pasid(pasid);
        return Err(RegistryError::Full);
    }
    // Учёт цепи: PASID — пользователь пространства И домена. Порядок
    // не имеет значения: оба инкремента — атомарные.
    space_ref.live_pasids.fetch_add(1, Ordering::AcqRel);
    if let Ok(d) = domain_entry(space_ref.domain_token) {
        unsafe { d.as_ref() }.attached.fetch_add(1, Ordering::AcqRel);
    }
    Ok(token)
}

fn resolve_pasid(token: u64) -> Result<NonNull<PasidEntry>, RegistryError> {
    let tree = pasid_tree().ok_or(RegistryError::Full)?;
    let tree = tree.lock();
    let entry = tree.get(&token).ok_or(RegistryError::BadToken)?;
    if !entry.live.load(Ordering::Acquire) {
        return Err(RegistryError::BadToken);
    }
    Ok(NonNull::from(entry))
}

/// Привязывает устройство-пользователя к PASID.
///
/// Секция под `users`-локом записи: сериализует bind/unbind/map/free
/// ОДНОГО PASID (в т.ч. аппаратные операции) и делает учёт пользователей
/// консистентным. Квота: bind сверх max_users — QuotaExceeded (deny).
pub fn bind_pasid_device(
    unit: &IommuUnitHandle,
    token: u64,
    device: PciAddress,
) -> Result<(), IommuError> {
    let entry = resolve_pasid(token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна (slab, tombstone-на-месте — контракт
    // capspace); мутации ниже — под users-локом.
    let entry = unsafe { entry.as_ref() };
    let mut users = entry.users.lock();
    if !entry.live.load(Ordering::Acquire) {
        return Err(IommuError::StaleToken);
    }
    let rid = device.requester_id().0 as u64;

    // Повторная привязка того же устройства — занятый слот (проверяем
    // ДО квоты: существующий пользователь — точный диагноз, а не «квота»).
    if users.contains_key(&rid) {
        return Err(IommuError::DeviceAlreadyAttached(device));
    }
    // Квота одновременных пользователей (deny-семантика адмиссии).
    if entry.max_users > 0 && entry.user_count.load(Ordering::Acquire) >= entry.max_users {
        return Err(IommuError::QuotaExceeded);
    }

    // Пространство живо; root — под его локом (для Dedicated первый bind
    // аллоцирует root и сохраняет его ДЛЯ ВСЕХ устройств пространства).
    let space = resolve_space(entry.space_token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; fs_root — под своим локом.
    let space_ref = unsafe { space.as_ref() };
    if !space_ref.live.load(Ordering::Acquire) {
        return Err(IommuError::StaleToken);
    }
    let mut fs_root = space_ref.fs_root.lock();
    let requested = if space_ref.dedicated {
        *fs_root // None -> бэкенд аллоцирует и вернёт
    } else {
        match *fs_root {
            Some(root) => Some(root),
            // SVA без root (владелец не дал CR3 при create) — first-stage
            // не существует, привязывать не к чему.
            None => return Err(IommuError::PasidNotSupported),
        }
    };
    let allocated = unit.set_pasid_context(&entry.domain, device, entry.pasid, requested, 4);
    if space_ref.dedicated && requested.is_none() {
        if let Ok(root) = allocated {
            *fs_root = Some(root);
        }
    }
    drop(fs_root);
    let Ok(_) = allocated else {
        return Err(allocated.unwrap_err());
    };

    // Учёт пользователя; slab OOM при вставке — откат аппаратной привязки.
    if users.insert(rid, rid).is_err() {
        let _ = unit.clear_pasid_context(&entry.domain, device, entry.pasid);
        return Err(IommuError::OutOfFrames);
    }
    entry.user_count.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// Отвязывает устройство-пользователя от PASID.
pub fn unbind_pasid_device(
    unit: &IommuUnitHandle,
    token: u64,
    device: PciAddress,
) -> Result<(), IommuError> {
    let entry = resolve_pasid(token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; мутации — под users-локом.
    let entry = unsafe { entry.as_ref() };
    let mut users = entry.users.lock();
    if !entry.live.load(Ordering::Acquire) {
        return Err(IommuError::StaleToken);
    }
    let rid = device.requester_id().0 as u64;
    if !users.contains_key(&rid) {
        return Err(IommuError::DeviceNotAttached(device));
    }

    // Аппаратная отвязка ДО удаления из учёта: неудача — пользователь
    // остаётся (устройство всё ещё привязано аппаратно).
    unit.clear_pasid_context(&entry.domain, device, entry.pasid)?;
    let _ = users.remove(&rid);
    entry.user_count.fetch_sub(1, Ordering::AcqRel);
    Ok(())
}

/// Уничтожает PASID-капабилити: все привязки снимаются аппаратно,
/// id возвращается пулу юнита, счётчики цепи декрементируются.
pub fn free_pasid_token(unit: &IommuUnitHandle, token: u64) -> Result<(), RegistryError> {
    let entry = resolve_pasid(token)?;
    // SAFETY: запись бессмертна; полный дренаж — под users-локом.
    let entry = unsafe { entry.as_ref() };
    let mut users = entry.users.lock();
    if !entry.live.load(Ordering::Acquire) {
        return Err(RegistryError::BadToken);
    }
    // Токен домена кэшируется ДО тумбстоуна: пространство ещё живо
    // (умирает после декремента live_pasids ниже — у нас последний
    // учётный доступ к нему).
    let domain_token = match resolve_space(entry.space_token) {
        Ok(space) => unsafe { space.as_ref() }.domain_token,
        Err(_) => 0,
    };

    // Дренаж пользователей: ключи собираются чанками (for_each не
    // прерывается), удаление — по ключу. Аппаратная отвязка каждого
    // устройства — перед удалением из учёта.
    let mut keys = [0u64; 16];
    loop {
        let mut n = 0usize;
        users.for_each(|rid| {
            if n < keys.len() {
                keys[n] = *rid;
                n += 1;
            }
        });
        if n == 0 {
            break;
        }
        for key in &keys[..n] {
            let _ = users.remove(key);
            entry.user_count.fetch_sub(1, Ordering::AcqRel);
            let device = PciAddress {
                segment: 0,
                bus: (key >> 8) as u8,
                device: ((key & 0xff) >> 3) as u8,
                function: (key & 0x7) as u8,
            };
            // Ошибки аппаратной отвязки при дренаже не останавливают:
            // PASID уничтожается (безопасное направление).
            let _ = unit.clear_pasid_context(&entry.domain, device, entry.pasid);
        }
    }

    entry.live.store(false, Ordering::Release);
    drop(users);
    let _ = unit.free_pasid(entry.pasid);
    // Учёт цепи (записи бессмертны — декременты безопасны всегда).
    if let Ok(space) = resolve_space(entry.space_token) {
        unsafe { space.as_ref() }.live_pasids.fetch_sub(1, Ordering::AcqRel);
    }
    if domain_token != 0 {
        if let Ok(d) = domain_entry(domain_token) {
            unsafe { d.as_ref() }.attached.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

/// Маппит first-stage страницы через PASID-капабилити.
pub fn map_va_token(
    unit: &IommuUnitHandle,
    token: u64,
    gva: usize,
    phys: usize,
    pages: usize,
    prot: IommuProtection,
) -> Result<(), IommuError> {
    let entry = resolve_pasid(token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; консистентность — под users-локом
    // (free/bind/unbind того же PASID сериализованы).
    let entry = unsafe { entry.as_ref() };
    let users = entry.users.lock();
    if !entry.live.load(Ordering::Acquire) {
        return Err(IommuError::StaleToken);
    }
    if pages == 0 || gva % PAGE_SIZE != 0 || phys % PAGE_SIZE != 0 {
        return Err(IommuError::InvalidIova(gva));
    }
    let space = resolve_space(entry.space_token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; fs_root держим на время аппаратной части:
    // destroy_space не освободит root, пока мы мапим (take под локом).
    let space_ref = unsafe { space.as_ref() };
    let root_guard = space_ref.fs_root.lock();
    let Some(root) = *root_guard else {
        return Err(IommuError::DeviceNotAttached(PciAddress {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        }));
    };
    let result = unit.map_first_stage(&entry.domain, entry.pasid, root, gva, phys, pages, prot);
    drop(root_guard);
    drop(users);
    result
}

/// Снимает first-stage страницы через PASID-капабилити.
pub fn unmap_va_token(
    unit: &IommuUnitHandle,
    token: u64,
    gva: usize,
    pages: usize,
) -> Result<(), IommuError> {
    let entry = resolve_pasid(token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; консистентность — под users-локом.
    let entry = unsafe { entry.as_ref() };
    let users = entry.users.lock();
    if !entry.live.load(Ordering::Acquire) {
        return Err(IommuError::StaleToken);
    }
    if pages == 0 || gva % PAGE_SIZE != 0 {
        return Err(IommuError::InvalidIova(gva));
    }
    let space = resolve_space(entry.space_token).map_err(|_| IommuError::StaleToken)?;
    // SAFETY: запись бессмертна; fs_root — под своим локом.
    let space_ref = unsafe { space.as_ref() };
    let root_guard = space_ref.fs_root.lock();
    let Some(root) = *root_guard else {
        return Err(IommuError::DeviceNotAttached(PciAddress {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        }));
    };
    let result = unit.unmap_first_stage(&entry.domain, entry.pasid, root, gva, pages);
    drop(root_guard);
    drop(users);
    result
}

// ─── Teardown задачи (хук из syscall_task::destroy_task_full) ────────────────

/// Отзывает IOMMU-объекты погибшей задачи — сверху вниз по цепи времён
/// жизни (pasid -> space -> domain):
///
///   1. PASID-капабилити ВЛАДЕЛЬЦА: аппаратный дренаж привязок + free.
///   2. PASID-капабилити ЧУЖИХ задач, чьи пространства создавал погибший
///      (капабилити передаваемы): пространство умирает — его контексты
///      обязаны умереть первыми, иначе PASIDTE указывает на освобождаемый
///      CR3/Dedicated-root.
///   3. Пространства владельца: тумбстоун + возврат dedicated-root юниту
///      (destroy_space сам откажется при живых pasid — пп. 1-2 их дренируют).
///   4. Домены владельца: с нулём пользователей — destroy; с живыми —
///      зомби (тумбстоун без уничтожения аппаратуры; безопасно, утечно).
pub fn on_task_destroy(unit: &IommuUnitHandle, task_cap: u64) {
    // 1+2. PASID-капабилити. Сканы — чанками: под деревом только снимок
    // полей (&V, записи бессмертны), free — вне дерева.
    let mut tokens = [0u64; 16];
    loop {
        let mut n = 0usize;
        if let Some(tree) = pasid_tree() {
            let tree = tree.lock();
            tree.for_each(|entry| {
                if n >= tokens.len() {
                    return;
                }
                if !entry.live.load(Ordering::Acquire) {
                    return;
                }
                let mine = entry.owner_task == task_cap;
                // Чужой PASID — кандидат, только если его пространство
                // уже мертво (tombstone teardown'ом этой же задачи).
                if mine {
                    tokens[n] = entry.token;
                    n += 1;
                } else if !space_is_live(entry.space_token) {
                    tokens[n] = entry.token;
                    n += 1;
                }
            });
        }
        if n == 0 {
            break;
        }
        for &token in &tokens[..n] {
            let _ = free_pasid_token(unit, token);
        }
    }

    // 3. Пространства владельца.
    let mut tokens = [0u64; 16];
    loop {
        let mut n = 0usize;
        if let Some(tree) = space_tree() {
            let tree = tree.lock();
            tree.for_each(|entry| {
                if n >= tokens.len() {
                    return;
                }
                if entry.live.load(Ordering::Acquire) && entry.owner_task == task_cap {
                    tokens[n] = entry.token;
                    n += 1;
                }
            });
        }
        if n == 0 {
            break;
        }
        for &token in &tokens[..n] {
            let _ = destroy_space_token(unit, token);
        }
    }

    // 4. Домены владельца (force: тумбстоун всегда; destroy — при нуле
    // пользователей; зомби с живыми устройствами — осознанная утечка).
    let mut tokens = [0u64; 16];
    loop {
        let mut n = 0usize;
        if let Some(tree) = domain_tree() {
            let tree = tree.lock();
            tree.for_each(|entry| {
                if n >= tokens.len() {
                    return;
                }
                if entry.live.load(Ordering::Acquire) && entry.owner_task == task_cap {
                    tokens[n] = entry.token;
                    n += 1;
                }
            });
        }
        if n == 0 {
            break;
        }
        for &token in &tokens[..n] {
            let _ = destroy_domain_token(unit, token, true);
        }
    }
}

/// Удобная обёртка для хука порта: берёт юнит из X86Backend.
pub fn on_task_destroy_current(task_cap: u64) {
    if let Some(unit) =
        <crate::X86Backend as kernel_base::traits::ArchImplementation>::iommu()
    {
        on_task_destroy(unit, task_cap);
    }
}

// ─── IommuTokenLayer: capability-фасад x86 ───────────────────────────────────

impl IommuTokenLayer for crate::X86Backend {
    fn iommu_unit(
        &self,
    ) -> Option<&'static <Self as kernel_base::traits::ArchImplementation>::Iommu> {
        <crate::X86Backend as kernel_base::traits::ArchImplementation>::iommu()
    }

    fn create_domain(&self, owner: u64) -> Result<u64, TokenError> {
        let unit = self.iommu_unit().ok_or(TokenError::BadToken)?;
        create_domain_token(unit, owner).map_err(TokenError::from)
    }

    fn destroy_domain(&self, token: u64) -> Result<(), TokenError> {
        let unit = self.iommu_unit().ok_or(TokenError::BadToken)?;
        destroy_domain_token(unit, token, false).map_err(TokenError::from)
    }

    fn attach_device(&self, token: u64, device: PciAddress) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        let (domain, entry) = resolve_domain(token).map_err(|_| IommuError::StaleToken)?;
        // SAFETY: запись бессмертна; учёт+аппаратура — под hw-локом домена
        // (параллельные attach к одному домену не рвут context-записи).
        let entry_ref = unsafe { entry.as_ref() };
        let _guard = entry_ref.hw.lock();
        let result = unit.attach_device(&domain, device, None);
        if result.is_ok() {
            entry_ref.attached.fetch_add(1, Ordering::AcqRel);
        }
        result
    }

    fn detach_device(&self, token: u64, device: PciAddress) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        let (domain, entry) = resolve_domain(token).map_err(|_| IommuError::StaleToken)?;
        // SAFETY: запись бессмертна; учёт+аппаратура — под hw-локом.
        let entry_ref = unsafe { entry.as_ref() };
        if entry_ref.attached.load(Ordering::Acquire) == 0 {
            return Err(IommuError::DeviceNotAttached(device));
        }
        let _guard = entry_ref.hw.lock();
        let result = unit.detach_device(&domain, device, None);
        if result.is_ok() {
            entry_ref.attached.fetch_sub(1, Ordering::AcqRel);
        }
        result
    }

    fn map_dma(
        &self,
        token: u64,
        iova: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError> {
        let (domain, entry) = resolve_domain(token).map_err(|_| IommuError::StaleToken)?;
        // SAFETY: запись бессмертна; hw-лок сериализует мутации таблиц.
        let _guard = unsafe { entry.as_ref() }.hw.lock();
        domain.map_pages(iova, phys, pages, prot)
    }

    fn unmap_dma(&self, token: u64, iova: usize, pages: usize) -> Result<(), IommuError> {
        let (domain, entry) = resolve_domain(token).map_err(|_| IommuError::StaleToken)?;
        // SAFETY: запись бессмертна; hw-лок сериализует мутации таблиц.
        let _guard = unsafe { entry.as_ref() }.hw.lock();
        domain.unmap_pages(iova, pages)
    }

    fn create_pasid_space(
        &self,
        domain_token: u64,
        sva: bool,
        sva_root: Option<usize>,
        owner: u64,
    ) -> Result<u64, TokenError> {
        create_space_token(domain_token, !sva, sva_root, owner).map_err(TokenError::from)
    }

    fn destroy_pasid_space(&self, space_token: u64) -> Result<(), TokenError> {
        let unit = self.iommu_unit().ok_or(TokenError::BadToken)?;
        destroy_space_token(unit, space_token).map_err(TokenError::from)
    }

    fn alloc_pasid_cap(
        &self,
        space_token: u64,
        max_users: u32,
        owner: u64,
    ) -> Result<u64, TokenError> {
        let unit = self.iommu_unit().ok_or(TokenError::BadToken)?;
        alloc_pasid_token(unit, space_token, max_users, owner).map_err(TokenError::from)
    }

    fn free_pasid_cap(&self, pasid_token: u64) -> Result<(), TokenError> {
        let unit = self.iommu_unit().ok_or(TokenError::BadToken)?;
        free_pasid_token(unit, pasid_token).map_err(TokenError::from)
    }

    fn bind_pasid_device(&self, pasid_token: u64, device: PciAddress) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        bind_pasid_device(unit, pasid_token, device)
    }

    fn unbind_pasid_device(&self, pasid_token: u64, device: PciAddress) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        unbind_pasid_device(unit, pasid_token, device)
    }

    fn map_va(
        &self,
        pasid_token: u64,
        gva: usize,
        phys: usize,
        pages: usize,
        prot: IommuProtection,
    ) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        map_va_token(unit, pasid_token, gva, phys, pages, prot)
    }

    fn unmap_va(&self, pasid_token: u64, gva: usize, pages: usize) -> Result<(), IommuError> {
        let unit = self.iommu_unit().ok_or(IommuError::NoIommuUnits)?;
        unmap_va_token(unit, pasid_token, gva, pages)
    }
}

// ─── Тесты (хост): slab-реестры + токены + PASID-жизненный цикл v2 ──────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iommu::intel::VtdUnit;
    use crate::test_support::{init_slab_once, page_aligned_leak, GLOBAL};
    use core::sync::atomic::AtomicUsize;
    use kernel_base::traits::memory::{set_hhdm_offset, FrameAllocator, MemoryPTR, PAGE_SIZE};

    struct TestFrames(AtomicUsize);
    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1000));

    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            // Тестовый bump с выравниванием базы на count страниц (запрос
            // 2x): alloc_aligned_contiguous для PASID-таблиц (8 страниц,
            // выровненных на 32 КиБ) получает выровненную базу с первой
            // попытки — без лотереи no-op deallocate.
            let raw = self.0.fetch_add(count * 2, core::sync::atomic::Ordering::SeqCst);
            let first = raw.next_multiple_of(count.max(1));
            MemoryPTR::new(first * PAGE_SIZE, count)
        }
        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    /// Тестовая задача-владелец: уникальные id на тест (реестры —
    /// статические, живут между тестами; тумбстоуненные записи из
    /// прежних тестов не мешают — токены монотонны, сканы идут по owner).
    const OWNER_A: u64 = 0xA00_0001;
    const OWNER_B: u64 = 0xB00_0002;

    fn test_unit() -> IommuUnitHandle {
        // Intel-юнит в тестовом режиме, LEGACY (ecap=0): доменный путь
        // attach_device с 16-байтными context entries. Scalable-юнит
        // (PASIDE|SRS) — test_unit_scalable (PASID-путь).
        let vtd = VtdUnit::new_raw(0, 0, 4 << 8, 0, &FRAMES).expect("unit");
        IommuUnitHandle::Intel(vtd)
    }

    fn test_unit_scalable() -> IommuUnitHandle {
        // ECAP: PASIDE (бит 40) | SRS (бит 41) — scalable-mode юнит.
        let ecap = (1u64 << 40) | (1u64 << 41);
        let vtd = VtdUnit::new_raw(0, 0, 4 << 8, ecap, &FRAMES).expect("unit");
        IommuUnitHandle::Intel(vtd)
    }

    fn setup() -> spin::mutex::SpinMutexGuard<'static, ()> {
        // ГАРД ДЕРЖИТСЯ ДО КОНЦА ТЕСТА (возвращаем guard): реестры/пулы —
        // статики, параллельный запуск тестов их перемешивает.
        let guard = GLOBAL.lock();
        let mem = page_aligned_leak(32 * 1024 * 1024 / 4096);
        set_hhdm_offset(mem.as_ptr() as usize);
        init_slab_once();
        guard
    }

    #[test]
    fn domain_tokens_survive_dispatch() {
        let _g = setup();
        let unit = test_unit();

        // Create -> токен; lookup резолвит; маппинг через дескриптор.
        let token = create_domain_token(&unit, OWNER_A).expect("token");
        let (domain, entry) = resolve_domain(token).expect("resolve");
        assert!(unsafe { entry.as_ref() }.live.load(Ordering::Acquire));
        domain
            .map_pages(0x1000_0000, 0x5000_0000, 1, IommuProtection::READ)
            .expect("map через handle");
        assert_eq!(domain.translate(0x1000_0000).expect("translate"), 0x5000_0000);

        // Мусорный токен не резолвится.
        assert!(matches!(resolve_domain(token ^ 0x5555), Err(RegistryError::BadToken)));

        // Destroy с живой привязкой — Occupied (v2 учёт attached).
        {
            let _guard = unsafe { entry.as_ref() }.hw.lock();
            unit.attach_device(&domain, PciAddress { segment: 0, bus: 5, device: 1, function: 0 }, None)
                .expect("attach");
            // Учёт, который в ядре делает IommuTokenLayer::attach_device
            // (тест зовёт юнит напрямую — фасад не задействован).
            unsafe { entry.as_ref() }.attached.fetch_add(1, Ordering::AcqRel);
        }
        assert_eq!(
            destroy_domain_token(&unit, token, false),
            Err(RegistryError::Occupied)
        );
        // Detach обнуляет учёт — destroy проходит.
        {
            let (d, e) = resolve_domain(token).expect("resolve 2");
            let _g = unsafe { e.as_ref() }.hw.lock();
            unit.detach_device(&d, PciAddress { segment: 0, bus: 5, device: 1, function: 0 }, None)
                .expect("detach");
            unsafe { e.as_ref() }.attached.fetch_sub(1, Ordering::AcqRel);
        }
        destroy_domain_token(&unit, token, false).expect("destroy");
        assert!(matches!(resolve_domain(token), Err(RegistryError::BadToken)));

        // Токены монотонны: следующий — не равен и не «реанимирует» старый.
        let token2 = create_domain_token(&unit, OWNER_A).expect("token 2");
        assert_ne!(token2, token);
        assert!(matches!(resolve_domain(token), Err(RegistryError::BadToken)));
        destroy_domain_token(&unit, token2, false).expect("destroy 2");
    }

    #[test]
    fn pasid_capability_lifecycle_and_quota() {
        let _g = setup();
        let unit = test_unit_scalable();

        // Домен -> пространство (SVA: root — «CR3 владельца», фиктивная
        // страница) -> PASID-капабилити с потолком 2 пользователей.
        let dtok = create_domain_token(&unit, OWNER_A).expect("domain");
        let fake_cr3 = 0x7_0000usize;
        let stok = create_space_token(dtok, false, Some(fake_cr3), OWNER_A).expect("space");
        assert!(!create_space_token(dtok ^ 0x9999, false, None, OWNER_A).is_ok());

        let ptok = alloc_pasid_token(&unit, stok, 2, OWNER_A).expect("pasid");

        let dev1 = PciAddress { segment: 0, bus: 1, device: 2, function: 0 };
        let dev2 = PciAddress { segment: 0, bus: 1, device: 3, function: 0 };
        let dev3 = PciAddress { segment: 0, bus: 1, device: 4, function: 0 };

        // Первые два пользователя проходят, третий — квота (deny, E_QUOTA).
        bind_pasid_device(&unit, ptok, dev1).expect("bind 1");
        bind_pasid_device(&unit, ptok, dev2).expect("bind 2");
        assert_eq!(
            bind_pasid_device(&unit, ptok, dev3),
            Err(IommuError::QuotaExceeded)
        );
        // Повторная привязка — занятый слот.
        assert_eq!(
            bind_pasid_device(&unit, ptok, dev1),
            Err(IommuError::DeviceAlreadyAttached(dev1))
        );

        // MapVa через PASID-капабилити: first-stage таблица владельца
        // (fake_cr3) наполняется, трансляция видна.
        let gva = 0x4000_0000usize;
        let hpa = 0x6000_0000usize;
        map_va_token(&unit, ptok, gva, hpa, 2, IommuProtection::READ | IommuProtection::WRITE)
            .expect("map_va");
        {
            let space = resolve_space(stok).expect("space");
            let root = unsafe { space.as_ref() }.fs_root.lock();
            assert_eq!(*root, Some(fake_cr3), "SVA root не подменяется");
        }

        // Unbind освобождает слот квоты — dev3 теперь проходит.
        unbind_pasid_device(&unit, ptok, dev1).expect("unbind 1");
        bind_pasid_device(&unit, ptok, dev3).expect("bind 3 после unbind");

        // Destroy пространства с живым PASID — Occupied (цепь времён жизни).
        assert_eq!(destroy_space_token(&unit, stok), Err(RegistryError::Occupied));

        // Free PASID: дренаж привязок (dev2+dev3) + возврат id в пул.
        free_pasid_token(&unit, ptok).expect("free");
        assert!(matches!(resolve_pasid(ptok), Err(RegistryError::BadToken)));

        // Теперь пространство умирает; dedicated root (не наш — SVA) не трогаем.
        destroy_space_token(&unit, stok).expect("destroy space");
        assert!(matches!(resolve_space(stok), Err(RegistryError::BadToken)));
        destroy_domain_token(&unit, dtok, false).expect("destroy domain");
    }

    #[test]
    fn dedicated_space_shares_root_between_users() {
        let _g = setup();
        let unit = test_unit_scalable();

        // Dedicated-пространство: root выделяет бэкенд при ПЕРВОМ bind —
        // и переиспользуется вторым (v1 выделял по экземпляру на bind).
        let dtok = create_domain_token(&unit, OWNER_B).expect("domain");
        let stok = create_space_token(dtok, true, None, OWNER_B).expect("space");
        let ptok = alloc_pasid_token(&unit, stok, 0, OWNER_B).expect("pasid");

        let dev1 = PciAddress { segment: 0, bus: 2, device: 1, function: 0 };
        let dev2 = PciAddress { segment: 0, bus: 2, device: 2, function: 0 };
        bind_pasid_device(&unit, ptok, dev1).expect("bind 1");
        bind_pasid_device(&unit, ptok, dev2).expect("bind 2");

        let root = {
            let space = resolve_space(stok).expect("space");
            *unsafe { space.as_ref() }.fs_root.lock()
        };
        assert!(root.is_some(), "dedicated root выделен при первом bind");

        // MapVa пишется в общий root.
        map_va_token(&unit, ptok, 0x8000_0000, 0xA000_0000, 1, IommuProtection::READ)
            .expect("map_va");

        // Дренаж teardown: PASID и пространство умирают по owner.
        on_task_destroy(&unit, OWNER_B);
        assert!(matches!(resolve_pasid(ptok), Err(RegistryError::BadToken)));
        assert!(matches!(resolve_space(stok), Err(RegistryError::BadToken)));
        assert!(matches!(resolve_domain(dtok), Err(RegistryError::BadToken)));
    }
}
