use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};

use bitflags::bitflags;

bitflags! {
    /// Малогранулярные (групповые) права неймспейса.
    ///
    /// Это ЦЕЛЫЕ права на классы действий, общие для всей группы задач:
    /// отдельная capability на ресурс всегда остаётся высокогранулярной
    /// (конкретный регион памяти, конкретный вектор IRQ и т.д.), а вот
    /// *возможность вообще оперировать* классом ресурсов задаётся здесь.
    ///
    /// Модель приоритета: права неймспейса — ПОТОЛОК для прав любого потока
    /// группы. Итоговый доступ потока = (высокогранулярные права капабилити)
    /// ∩ (NamespaceRights его неймспейса). Если у потока прав "больше", чем
    /// даёт неймспейс, доступ будет ОТКАЗАН — см. `Namespace::check_rights`
    /// и `CapabilityObject::required_namespace_rights`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NamespaceRights: u16 {
        /// Создание/уничтожение задач в группе.
        const TASK_CREATE  = 1 << 0;
        /// Аллокация и маппинг обычной памяти (в т.ч. пулов IPC).
        const MEMORY_ALLOC = 1 << 1;
        /// Отображение MMIO-регионов.
        const MMIO_MAP     = 1 << 2;
        /// Привязка IRQ-векторов к задачам.
        const IRQ_BIND     = 1 << 3;
        /// Отправка IPC-сообщений.
        const IPC_SEND     = 1 << 4;
        /// Пересылка capability через IPC.
        const CAP_TRANSFER = 1 << 5;
        /// Mint/clone capability (производные копии с сужением прав).
        const CAP_MINT     = 1 << 6;
        /// Создание/уничтожение capability-объектов и неймспейсов.
        const CAP_MANAGE   = 1 << 7;
        /// Подключение устройств к IOMMU-доменам (DMA-доступ).
        const DMA_ATTACH   = 1 << 8;
        /// Чтение статистики задач (снапшоты TASK_STATS). Самоинспекция
        /// (собственная задача) права не требует.
        const STATS_READ   = 1 << 9;
        /// Обработка фолтов: создание/пересылка фолт-эндпоинтов,
        /// привязка обработчика (FAULT_SET_ENDPOINT) и ответы на
        /// фолты (FAULT_REPLY) — см. ipc::fault.
        const FAULT_HANDLE = 1 << 10;
    }
}

/// Квота ресурсов группы задач (task group).
///
/// Все поля — атомарные. Причина двойная:
///   1. RBSlabIO::get(&self) -> Option<&V> — единственный способ достать
///      существующую запись из дерева (get_mut принципиально не
///      предоставляется интрузивным деревом), значит вся мутация идёт
///      через `&self`.
///   2. `CapabilityObject::TaskGroupNamespace` хранит сырой
///      `NonNull<Namespace>` прямо в этот узел дерева. Как и зиготы,
///      Namespace НИКОГДА не удаляется из дерева по-настоящему
///      (AccessManager::destroy_namespace её только тумбстоунит) —
///      адрес узла обязан жить, пока не будет переиспользован in-place
///      через `recycle`. `generation` здесь — то же ABA-предохранение,
///      что у CapabilityZygote, только для дерева namespaces.
pub struct Namespace {
    max_task_count: AtomicUsize,
    current_task_count: AtomicUsize,

    max_memory_alloc_per_namespace: AtomicUsize,
    current_memory_alloc: AtomicUsize,

    /// Бейдж, прикладываемый к capability, выданным через этот
    /// namespace (аналог badge в seL4).
    persistency_badge: AtomicUsize,

    /// Учёт KERNEL-объектов capability (записи cspace + мембраны слотов)
    /// группы. Причина: записи/мембраны БЕССМЕРТНЫ (tombstone/recycle
    /// на месте — см. LinkedRecord; slab-память возвращается только с
    /// GTcb задачи) — без квоты один поток раздувает kernel slab до
    /// E_SLAB для ВСЕЙ системы (mint/clone/IPC-пересылка в новые слоты).
    max_cap_objects: AtomicUsize,
    current_cap_objects: AtomicUsize,

    /// Малогранулярные права группы (см. NamespaceRights) — потолок для
    /// высокогранулярных прав отдельных потоков. Хранится атомарно по тем
    /// же причинам, что и квоты: единственный способ достать Namespace из
    /// дерева — `RBSlabIO::get(&self) -> Option<&V>`, мутация только через
    /// `&self`.
    rights: AtomicU16,

    generation: AtomicU64,
    /// Живой ли слот прямо сейчас (в отличие от zygote, у Namespace нет
    /// Option-обёртки — квоты просто зануляются при tombstone). Нужно,
    /// чтобы AccessManager::destroy_namespace не мог дважды поставить
    /// один и тот же id в очередь переиспользования.
    alive: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceError {
    TaskLimitExceeded,
    MemoryLimitExceeded,
    /// release/free вызван больше раз, чем было успешных reserve/alloc.
    Underflow,
    /// Запрошенное право не покрыто правами неймспейса. Права неймспейса
    /// имеют приоритет над правами отдельных потоков: даже если
    /// высокогранулярная capability потока формально разрешает действие,
    /// неймспейс может его запретить — и запретит.
    RightsDenied,
    /// Исчерпана квота kernel-объектов capability (записи/мембраны).
    CapObjectLimitExceeded,
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceError::TaskLimitExceeded => write!(f, "task limit exceeded"),
            NamespaceError::MemoryLimitExceeded => write!(f, "memory limit exceeded"),
            NamespaceError::CapObjectLimitExceeded => {
                write!(f, "capability object limit exceeded")
            }
            NamespaceError::Underflow => write!(f, "accounting underflow"),
            NamespaceError::RightsDenied => write!(f, "right denied by namespace"),
        }
    }
}

impl Namespace {
    pub fn new(
        max_task_count: usize,
        max_memory_alloc_per_namespace: usize,
        persistency_badge: usize,
        rights: NamespaceRights,
        max_cap_objects: usize,
    ) -> Self {
        Self {
            max_task_count: AtomicUsize::new(max_task_count),
            current_task_count: AtomicUsize::new(0),
            max_memory_alloc_per_namespace: AtomicUsize::new(max_memory_alloc_per_namespace),
            current_memory_alloc: AtomicUsize::new(0),
            persistency_badge: AtomicUsize::new(persistency_badge),
            max_cap_objects: AtomicUsize::new(max_cap_objects),
            current_cap_objects: AtomicUsize::new(0),
            rights: AtomicU16::new(rights.bits()),
            generation: AtomicU64::new(0),
            alive: AtomicBool::new(true),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(super) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub fn persistency_badge(&self) -> usize {
        self.persistency_badge.load(Ordering::Acquire)
    }

    /// Текущие малогранулярные права группы. Неизвестные биты (появившиеся
    /// из-за расширения набора прав в будущих версиях) отбрасываются.
    pub fn rights(&self) -> NamespaceRights {
        NamespaceRights::from_bits_truncate(self.rights.load(Ordering::Acquire))
    }

    /// Центральная точка проверки "приоритет неймспейса": запрошенные
    /// права должны ПОЛНОСТЬЮ покрываться правами группы. Вызывать вместе
    /// с проверкой высокогранулярной capability потока — отказ здесь
    /// имеет приоритет над любым разрешением на уровне capability.
    pub fn check_rights(&self, requested: NamespaceRights) -> Result<(), NamespaceError> {
        if self.rights().contains(requested) {
            Ok(())
        } else {
            Err(NamespaceError::RightsDenied)
        }
    }

    /// Сужает права группы (только потолок вниз — монотонность, как у
    /// CapabilityMembrane::narrow). Расширить права через этот метод
    /// нельзя; полный пересбор прав — только recycle() слота.
    pub fn narrow_rights(&self, ceiling: NamespaceRights) {
        let _ = self.rights.fetch_and(ceiling.bits(), Ordering::AcqRel);
    }

    fn max_task_count(&self) -> usize {
        self.max_task_count.load(Ordering::Acquire)
    }

    fn max_memory(&self) -> usize {
        self.max_memory_alloc_per_namespace.load(Ordering::Acquire)
    }

    pub fn task_count(&self) -> usize {
        self.current_task_count.load(Ordering::Acquire)
    }

    pub fn memory_in_use(&self) -> usize {
        self.current_memory_alloc.load(Ordering::Acquire)
    }

    pub fn remaining_task_slots(&self) -> usize {
        self.max_task_count().saturating_sub(self.task_count())
    }

    pub fn remaining_memory(&self) -> usize {
        self.max_memory().saturating_sub(self.memory_in_use())
    }

    /// Резервирует один слот задачи. Вызывать ДО фактического создания
    /// TCB — если возвращён Err, TCB создавать нельзя.
    pub fn try_reserve_task(&self) -> Result<(), NamespaceError> {
        self.current_task_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= self.max_task_count() {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .map(|_| ())
            .map_err(|_| NamespaceError::TaskLimitExceeded)
    }

    /// Освобождает слот задачи (вызывать при уничтожении TCB).
    pub fn release_task(&self) -> Result<(), NamespaceError> {
        self.current_task_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .map(|_| ())
            .map_err(|_| NamespaceError::Underflow)
    }

    /// Резервирует `bytes` в квоте памяти namespace.
    pub fn try_alloc_memory(&self, bytes: usize) -> Result<(), NamespaceError> {
        self.current_memory_alloc
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let new_total = current.checked_add(bytes)?;
                if new_total > self.max_memory() {
                    None
                } else {
                    Some(new_total)
                }
            })
            .map(|_| ())
            .map_err(|_| NamespaceError::MemoryLimitExceeded)
    }

    /// Возвращает `bytes` в квоту (вызывать при освобождении памяти).
    pub fn free_memory(&self, bytes: usize) -> Result<(), NamespaceError> {
        self.current_memory_alloc
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| NamespaceError::Underflow)
    }

    /// Резервирует ОДИН kernel-объект capability (запись cspace или
    /// мембрану слота) против квоты группы. Вызывать ДО slab-аллокации
    /// нового объекта; при последующем отказе аллокации — release.
    pub fn try_reserve_cap_object(&self) -> Result<(), NamespaceError> {
        self.current_cap_objects
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current >= self.max_cap_objects.load(Ordering::Acquire) {
                    None
                } else {
                    Some(current + 1)
                }
            })
            .map(|_| ())
            .map_err(|_| NamespaceError::CapObjectLimitExceeded)
    }

    /// Возвращает учёт объекта (slab-память реально освобождена —
    /// дроп GTcb задачи или destroy мембраны). Underflow молча
    /// игнорируется: учёт может стартовать раньше счётчика (legacy).
    pub fn release_cap_object(&self) {
        let _ = self.current_cap_objects.try_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_sub(1),
        );
    }

    pub fn is_task_limit_reached(&self) -> bool {
        self.task_count() >= self.max_task_count()
    }

    pub fn is_memory_limit_reached(&self) -> bool {
        self.memory_in_use() >= self.max_memory()
    }

    /// Тумбстоунит слот: зануляет квоты/счётчики и бампит generation.
    /// Узел остаётся в дереве — адрес не меняется, поэтому любой
    /// `NonNull<Namespace>` в CapabilityObject::TaskGroupNamespace
    /// остаётся валидной памятью (просто перестаёт резолвиться, см.
    /// CapabilityObject::resolve_namespace). Вызывать только когда
    /// namespace гарантированно пуст — это проверяет AccessManager
    /// ДО вызова.
    pub(super) fn tombstone(&self) {
        self.alive.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.max_task_count.store(0, Ordering::Release);
        self.current_task_count.store(0, Ordering::Release);
        self.max_memory_alloc_per_namespace
            .store(0, Ordering::Release);
        self.current_memory_alloc.store(0, Ordering::Release);
        self.persistency_badge.store(0, Ordering::Release);
        self.max_cap_objects.store(0, Ordering::Release);
        self.current_cap_objects.store(0, Ordering::Release);
        self.rights
            .store(NamespaceRights::empty().bits(), Ordering::Release);
    }

    /// Переиспользует уже существующий (обычно затумбстоуненный) слот
    /// под новую конфигурацию квот, бампя generation — старые
    /// TaskGroupNamespace, хранящие снимок предыдущего generation,
    /// перестают резолвиться.
    pub(super) fn recycle(
        &self,
        max_task_count: usize,
        max_memory_alloc_per_namespace: usize,
        persistency_badge: usize,
        rights: NamespaceRights,
        max_cap_objects: usize,
    ) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.max_task_count.store(max_task_count, Ordering::Release);
        self.current_task_count.store(0, Ordering::Release);
        self.max_memory_alloc_per_namespace
            .store(max_memory_alloc_per_namespace, Ordering::Release);
        self.current_memory_alloc.store(0, Ordering::Release);
        self.persistency_badge
            .store(persistency_badge, Ordering::Release);
        self.max_cap_objects.store(max_cap_objects, Ordering::Release);
        self.current_cap_objects.store(0, Ordering::Release);
        self.rights.store(rights.bits(), Ordering::Release);
        self.alive.store(true, Ordering::Release);
    }
}
