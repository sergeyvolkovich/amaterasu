//! Единое ABI-пространство системных вызовов NOMAD.
//!
//! КОНВЕНЦИЯ ВЫЗОВА (x86_64; entry-стаб ядра обязан ей следовать):
//!   - номер сисколла: RAX
//!   - аргументы: RDI, RSI, RDX, R10, R8, R9 (порядок SysV, R10 вместо RCX)
//!   - возврат: RAX (старший бит = ошибка, см. syscall_result)
//!   - портится: RCX, R11 (железо SYSCALL), RAX
//!   - вход: SYSCALL; выход из стаба: SYSRET (или их ручные аналоги)
//!
//! Возвращаемое значение: успех — 0 или результат (например, id созданной
//! capability; id 0 валиден, успех/ошибка различаются старшим битом
//! [`SYSCALL_ERROR_FLAG`]).

/// Старший бит возвращаемого значения = ошибка.
pub const SYSCALL_ERROR_FLAG: u64 = 0x8000_0000_0000_0000;

/// Коды ошибок сисколлов (зеркало kernel_base::traits::syscall::syscall_result).
pub mod result {
    use super::SYSCALL_ERROR_FLAG;

    pub const OK: u64 = 0;
    pub const E_NO_CURRENT_TASK: u64 = SYSCALL_ERROR_FLAG | 1;
    pub const E_RIGHTS_DENIED: u64 = SYSCALL_ERROR_FLAG | 2;
    pub const E_NOT_FOUND: u64 = SYSCALL_ERROR_FLAG | 3;
    pub const E_SLOT_OCCUPIED: u64 = SYSCALL_ERROR_FLAG | 4;
    pub const E_SLOT_EMPTY: u64 = SYSCALL_ERROR_FLAG | 5;
    pub const E_CAP_REVOKED: u64 = SYSCALL_ERROR_FLAG | 6;
    pub const E_RIGHTS_EXCEEDED: u64 = SYSCALL_ERROR_FLAG | 7;
    pub const E_SLAB: u64 = SYSCALL_ERROR_FLAG | 8;
    pub const E_QUOTA: u64 = SYSCALL_ERROR_FLAG | 9;
    pub const E_IDS_EXHAUSTED: u64 = SYSCALL_ERROR_FLAG | 10;
    pub const E_INVALID_ARG: u64 = SYSCALL_ERROR_FLAG | 11;
    pub const E_INTERNAL: u64 = SYSCALL_ERROR_FLAG | 12;
    /// Сисколл известен, но не реализован ядром (зеркало kernel_base).
    pub const E_NOT_IMPLEMENTED: u64 = SYSCALL_ERROR_FLAG | 13;
    /// Ресурс занят DMA-привязкой (FREE_PAGES под pin'ом IOMMU).
    pub const E_BUSY: u64 = SYSCALL_ERROR_FLAG | 14;
    /// Истёк дедлайн IPC_WAIT (deadline > 0).
    pub const E_TIMEOUT: u64 = SYSCALL_ERROR_FLAG | 15;

    /// Успех/ошибка по старшему биту.
    #[inline]
    pub const fn is_error(code: u64) -> bool {
        code & SYSCALL_ERROR_FLAG != 0
    }
}

/// Номера сисколлов (плоское пространство; kernel_base::syscall/* выровнены).
pub mod nr {
    /// Планировщик: добровольная передача ядра.
    pub const SCHED_YIELD: u64 = 0;
    /// Регистрация runtime-метаданных задачи.
    pub const SCHED_REGISTER_TASK: u64 = 1;
    /// Уничтожение задачи (в т.ч. self-exit: crt0 зовёт со своим cap id).
    pub const SCHED_DESTROY_TASK: u64 = 2;
    /// Сон задачи на объекте ожидания.
    pub const SCHED_BLOCK_ON_OBJECT: u64 = 3;
    /// Пробуждение ожидающих объект.
    pub const SCHED_RELEASE_OBJECT: u64 = 4;

    /// Память: выделить страницы задачи (возврат — VA).
    pub const ALLOC_PAGES: u64 = 5;
    /// Память: снять аллокацию по базовому VA.
    pub const FREE_PAGES: u64 = 6;
    /// Память: смонтировать MMIO-регион из capability (возврат — VA).
    pub const MOUNT_CAP_REGION: u64 = 7;
    /// Память: снять MMIO-отображение по VA.
    pub const UNMOUNT_CAP_REGION: u64 = 8;

    /// IPC: синхронная отправка (rendezvous) — (слот получателя, msg,
    /// размер, caps-массив, число caps).
    pub const IPC_SEND: u64 = 10;
    /// IPC: ожидание (open/closed wait) — (слот отправителя | ANY, буфер,
    /// ёмкость, база приёмного окна, размер окна).
    pub const IPC_WAIT: u64 = 11;

    /// Capability: создать неймспейс.
    pub const CAP_CREATE_NAMESPACE: u64 = 16;
    /// Capability: создать пул памяти IPC.
    pub const CAP_CREATE_IPC_POOL: u64 = 17;
    /// Capability: создать MMIO-регион.
    pub const CAP_CREATE_MMIO: u64 = 18;
    /// Capability: создать капу на ЛОГИЧЕСКУЮ линию IRQ (v2 — не
    /// «cpu+вектор», а GSI/MSI платформы). Аргументы: owner_task_cap,
    /// dst_slot, line, trigger (0=edge, 1=level). Линия обязана быть
    /// свободна (иначе E_BUSY); успех — линия занята владельцем,
    /// замаскирована, капа в dst_slot.
    pub const CAP_CREATE_IRQ: u64 = 19;
    /// Capability: mint (производная копия с сужением прав).
    pub const CAP_MINT: u64 = 20;
    /// Capability: clone (копия в той же мембране).
    pub const CAP_CLONE: u64 = 21;
    /// Capability: revoke слота.
    pub const CAP_REVOKE: u64 = 22;
    /// Capability: снять запись со слота.
    pub const CAP_DESTROY: u64 = 23;
    /// [ЗАРЕЗЕРВИРОВАНО] Бывший CAP_TRANSFER: удалён — ambient authority
    /// (голые task_cap-id отправителя/получателя). Пересылка capability
    /// живёт только в IPC_SEND/IPC_WAIT (map items + приёмное окно
    /// получателя). Номер не переиспользовать.
    pub const _CAP_TRANSFER_REMOVED: u64 = 24;
    /// Capability: разделяемый регион СОБСТВЕННОЙ памяти задачи (shm;
    /// физику резолвит ядро, монтаж получателем — MOUNT_CAP_REGION).
    pub const CAP_CREATE_SHARED: u64 = 25;
    /// Capability: фолт-эндпоинт — фиксирует ТЕКУЩУЮ задачу как
    /// обработчика фолтов (handler = вызывающий).
    pub const CAP_CREATE_FAULT_ENDPOINT: u64 = 26;

    /// Фолты: привязать эндпоинт к задаче-цели (её TaskTCB-слот) —
    /// фолты цели пойдут обработчику через IPC_WAIT.
    pub const FAULT_SET_ENDPOINT: u64 = 27;

    /// Фолты: ответить на фолт (resume упавшей задачи; new_rip/new_rsp =
    /// 0 — повтор упавшей инструкции).
    pub const FAULT_REPLY: u64 = 30;

    /// Задачи: спавн ELF-образа boot-модуля в неймспейс.
    /// Authority: капа неймспейса (слот) + капа образа TaskImage (слот);
    /// возврат — task_cap_id ребёнка (кладётся и в dst_slot создателя).
    pub const TASK_CREATE: u64 = 48;

    /// Задачи: exec ELF-образа из ЧИТАЕМОЙ памяти ВЫЗЫВАЮЩЕГО (бинарь,
    /// загруженный файловым сервером и отданный map item'ом, или
    /// собственный ALLOC_PAGES-буфер). Ядро снимает снапшот ДО разбора —
    /// источник можно освободить сразу после вызова. Authority: капа
    /// неймспейса + потолок TASK_CREATE у ОБОИХ неймспейсов (вызывающего
    /// и целевого). Возврат — task_cap_id ребёнка (кладётся в dst_slot).
    pub const TASK_CREATE_FROM_MEM: u64 = 49;

    /// IRQ (v2): сон до срабатывания линий; линии адресуются КАПАМИ
    /// IrqLine (список слотов cspace вызывающего), а не сырым битмапом.
    /// caps_ptr — VA массива слотов (u64), caps_len 1..=8; mask_ptr —
    /// VA результата `[count][line]...` (обе массы — в одной странице).
    /// WAIT размаскирует линии набора (claim маскирует — уровневые
    /// линии не спамят между ожиданиями).
    pub const IRQ_WAIT: u64 = 28;

    /// IRQ (v2): выделить MSI-линии (message-backed) из пространства чипа:
    /// count линий, корневые капы в слоты first_dst_slot.., MSI-сообщения
    /// (по 4 u64: [line, address, data, trigger]) в буфер msgs_ptr.
    /// Линия остаётся замаскированной до первого WAIT (для MSI маска
    /// программная — доставка вектора без ждущих роняется диспетчером).
    pub const IRQ_MSI_ALLOC: u64 = 51;

    /// IRQ (v2): владелец возвращает линию платформе (маска + снятие
    /// записи реестра + тумбстоун капы в слоте slot).
    pub const IRQ_RELEASE: u64 = 52;

    /// Статистика: снапшот счётчиков задачи + глобальные тики/частота
    /// (перенос статистики в юзерспейс; самоинспекция — без прав).
    pub const TASK_STATS: u64 = 29;

    /// Debug: запись строки задачи в лог ядра (serial + кольцо).
    pub const DBG_LOG_WRITE: u64 = 47;

    /// Debug: чтение дельты лога ядра (для init-консоли).
    pub const DBG_LOG_READ: u64 = 46;

    // РАСКЛАД NR (зеркало ядра v2): sched/mem 0..8, ipc 10/11,
    // capability 16..26, fault 27/30, irq 28/51/52, stats 29, IOMMU
    // 32..45 + MapDmaVa 50, log 46/47, exec 48/49.

    /// IOMMU: создать DMA-домен.
    pub const IOMMU_CREATE_DOMAIN: u64 = 32;
    /// IOMMU: присоединить устройство к домену.
    pub const IOMMU_ATTACH_DEVICE: u64 = 33;
    /// IOMMU: DMA-маппинг в домен.
    pub const IOMMU_MAP_DMA: u64 = 34;
    /// IOMMU: снять DMA-маппинг.
    pub const IOMMU_UNMAP_DMA: u64 = 35;
    /// IOMMU: создать PASID-пространство (SVA/GCR3).
    pub const IOMMU_CREATE_PASID_SPACE: u64 = 36;
    /// IOMMU (v2): выделить PASID — капабилити с потолком одновременных
    /// пользователей (bind сверх потолка — E_QUOTA).
    pub const IOMMU_ALLOC_PASID: u64 = 37;
    /// IOMMU (v2): уничтожить PASID (сняв все привязки устройств).
    pub const IOMMU_FREE_PASID: u64 = 38;
    /// IOMMU (v2): устройство-пользователь в PASID (квота: E_QUOTA).
    pub const IOMMU_BIND_PASID_DEVICE: u64 = 39;
    /// IOMMU (v2): отвязать устройство от PASID.
    pub const IOMMU_UNBIND_PASID_DEVICE: u64 = 40;
    /// IOMMU (v2): first-stage маппинг через PASID-капабилити.
    pub const IOMMU_MAP_VA: u64 = 41;
    /// IOMMU (v2): снять first-stage маппинг.
    pub const IOMMU_UNMAP_VA: u64 = 42;
    /// IOMMU (v2): уничтожить PASID-пространство (без живых PASID).
    pub const IOMMU_DESTROY_PASID_SPACE: u64 = 43;
    /// IOMMU (v2): уничтожить DMA-домен.
    pub const IOMMU_DESTROY_DOMAIN: u64 = 44;
    /// IOMMU (v2): отвязать устройство от домена.
    pub const IOMMU_DETACH_DEVICE: u64 = 45;

    /// IOMMU (DMA-buf): DMA-маппинг ИЗ ПАМЯТИ ВЫЗЫВАЮЩЕГО — ядро резолвит
    /// VA -> физика по VmapRegion, пинит регион (FREE_PAGES под пином —
    /// E_BUSY), UnmapDma снимает pin. task_cap/cap_slot — капа домена,
    /// iova — устройство видит этот адрес, va — источник в СВОЁМ
    /// пространстве (обязан лежать в одной ALLOC_PAGES-аллокации).
    pub const IOMMU_MAP_DMA_VA: u64 = 50;
}

/// Биты NamespaceRights (зеркало kernel_base::access::namespace::
/// NamespaceRights — u16-битфлаги ядра; здесь u64 для аргумента
/// rights_mask CAP_CREATE_NAMESPACE). Неизвестные биты ядро отбрасывает,
/// права ребёнка всегда ⊆ прав создателя (ceilings).
pub mod ns_rights {
    /// Спавн задач в неймспейс / приём задач ИЗ него (TARGET-ceiling).
    pub const TASK_CREATE: u64 = 1 << 0;
    /// Выделение памяти (ALLOC_PAGES и пр.) в группе.
    pub const MEMORY_ALLOC: u64 = 1 << 1;
    /// Монтирование регионов по capability (MOUNT_CAP_REGION).
    pub const MMIO_MAP: u64 = 1 << 2;
    /// Привязка IRQ (CAP_CREATE_IRQ, IRQ_WAIT).
    pub const IRQ_BIND: u64 = 1 << 3;
    /// Отправка IPC.
    pub const IPC_SEND: u64 = 1 << 4;
    /// Пересылка capability через IPC (map items).
    pub const CAP_TRANSFER: u64 = 1 << 5;
    /// Создание производных кап (CAP_MINT).
    pub const CAP_MINT: u64 = 1 << 6;
    /// Управление капами (создание/уничтожение объектов).
    pub const CAP_MANAGE: u64 = 1 << 7;
    /// Присоединение устройств к IOMMU-доменам.
    pub const DMA_ATTACH: u64 = 1 << 8;
    /// Чтение статистики задач.
    pub const STATS_READ: u64 = 1 << 9;
    /// Обработка фолтов чужих задач (keeper).
    pub const FAULT_HANDLE: u64 = 1 << 10;
}

/// AUXV-теги (раскладка стартового стека — см. kernel_x86::exec).
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_PAGESZ: u64 = 7;
    pub const AT_ENTRY: u64 = 9;
    /// id TaskTCB-капабилити этой задачи (self-exit через SCHED_DESTROY_TASK).
    pub const AT_NOMAD_SELF_CAP: u64 = 0xC170_0001;
    /// id корневой capability неймспейса задачи.
    pub const AT_NOMAD_NS_CAP: u64 = 0xC170_0002;
    /// VA фреймбуфера в пространстве задачи (0 — FB не замаплен).
    pub const AT_NOMAD_FB_ADDR: u64 = 0xC170_0003;
    /// Байт на строку развёртки.
    pub const AT_NOMAD_FB_PITCH: u64 = 0xC170_0004;
    /// Пикселей в ширину.
    pub const AT_NOMAD_FB_WIDTH: u64 = 0xC170_0005;
    /// Пикселей в высоту.
    pub const AT_NOMAD_FB_HEIGHT: u64 = 0xC170_0006;
    /// Бит на пиксель.
    pub const AT_NOMAD_FB_BPP: u64 = 0xC170_0007;
    /// Физический адрес RSDP (ACPI): init монтирует таблицы через
    /// CAP_CREATE_MMIO — диапазоны зарегистрированы ядром в phys_guard
    /// (acpi-allow-list). Отсутствие тега — ACPI не найден загрузчиком.
    pub const AT_NOMAD_ACPI_RSDP: u64 = 0xC170_0008;

    /// Bootstrap-слоты cspace системного сервера.
    pub const BOOT_SLOT_SELF: u64 = 0;
    pub const BOOT_SLOT_NAMESPACE: u64 = 1;
    /// Первый слот peer-TaskTCB (i-й boot-сервер — слот 2+i).
    pub const BOOT_SLOT_PEER_BASE: u64 = 2;
    /// Слот TaskTCB СОЗДАТЕЛЯ у динамической задачи (TASK_CREATE):
    /// адресация IPC-ответа родителю без map item'ов.
    pub const BOOT_SLOT_PARENT: u64 = 2;
    /// Первый слот TaskImage-кап boot-образов у init-сервера
    /// (j-й образ реестра — слот 32+j; authority для TASK_CREATE).
    pub const BOOT_SLOT_IMAGE_BASE: u64 = 32;
}

/// Значения auxv (зеркало kernel_exec::spawn::at_tags).
pub mod auxv_values {
    pub const AT_NULL: u64 = 0;
    pub const AT_PAGESZ: u64 = 7;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_NOMAD_SELF_CAP: u64 = 0xC170_0001;
    pub const AT_NOMAD_NS_CAP: u64 = 0xC170_0002;
    pub const AT_NOMAD_FB_ADDR: u64 = 0xC170_0003;
    pub const AT_NOMAD_FB_PITCH: u64 = 0xC170_0004;
    pub const AT_NOMAD_FB_WIDTH: u64 = 0xC170_0005;
    pub const AT_NOMAD_FB_HEIGHT: u64 = 0xC170_0006;
    pub const AT_NOMAD_FB_BPP: u64 = 0xC170_0007;
    pub const AT_NOMAD_ACPI_RSDP: u64 = 0xC170_0008;
}
