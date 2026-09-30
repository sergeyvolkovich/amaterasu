use crate::{
    lctl::LocalKernelCTL,
    traits::{
        irq::{IRQArchDefinedContext, IrqChip},
        memory::{FrameAllocator, MemoryInterfaceKernel, MemoryInterfaceUserspace},
        syscall::SyscallDomain,
    },
};

pub mod dma;
pub mod hwinfo;
pub mod iommu;
pub mod ipi;
pub mod irq;
pub mod memory;
pub mod scheduller;
pub mod syscall;

pub trait ArchImplementation: Sized + 'static {
    type Umap: MemoryInterfaceUserspace;
    type KMap: MemoryInterfaceKernel;

    /// Архитектурный контекст прерываний/исключений. ОБЕЗЛИЧЕНО: общий
    /// слой знает только семантические интерфейсы (InterruptId,
    /// CpuContext, PageFaultFlags — см. traits::irq); конкретные
    /// представления (номер вектора, error code) — собственность порта.
    type IRQContext: IRQArchDefinedContext;

    /// IOMMU-юнит платформы (Intel VT-d / AMD-Vi) — см. traits::iommu.
    /// Контракт: трейты архитектурно-независимы, вся логика (ACPI-парсинг
    /// DRHD/IVHD, регистры, таблицы трансляции) живёт в реализации порта.
    /// Порты БЕЗ IOMMU реализуют трейт на тип-заглушку и отдают `None` из
    /// [`ArchImplementation::iommu`].
    type Iommu: self::iommu::IommuUnit;

    /// Бэкенд контроллеров прерываний платформы (см. traits::irq::IrqChip):
    /// x86 — IO-APIC+LAPIC, ARM64 — GICv3, RISC-V — APLIC/IMSIC. Логика
    /// (парсинг MADT/DT-узлов, регистры, векторы доставки) — собственность
    /// порта; общий слой видит только логические линии. `None` — IRQ-
    /// подсистема ещё не инициализирована (ранний бут) или платформа
    /// без настраиваемого контроллера.
    type IrqChip: IrqChip;

    /// Контроллер межъядерных прерываний (см. traits::ipi::IpiController):
    /// x86 — LAPIC ICR, ARM64 — GICv3 SGI (IC_SGI1R_EL1), RISC-V — IMSIC.
    /// Протоколы надстройки (TLB-shootdown с ack, кик планировщика) —
    /// собственность порта; контракт отдаёт только семантику IpiKind.
    type Ipi: self::ipi::IpiController;

    fn init_base_state() -> Self;

    fn reclaim_memory(allocator: &dyn FrameAllocator) -> Self::KMap;
    fn create_new_kmap() -> Self::KMap;

    fn irq_enable();
    fn irq_disable();

    /// Регистрация обработчиков прерываний/page-fault — НЕ входит в
    /// этот трейт (обезличивание): generic-мосты над произвольным
    /// IRQArchDefinedContext без аллокатора оказались мёртвой сложностью.
    /// Порты держат собственные КОНКРЕТНЫЕ реестры (x86_64:
    /// kernel_x86::irq::register_irq_line_handler(line, hook) для линий
    /// 0..63 и register_pf_hook для #PF); kernel_base обращается к ним
    /// только через хук онлайна/бута порта.
    ///
    /// Регистрирует домен сисколлов. `'static` обязателен: реализация
    /// хранит домен-хэндл в статическом реестре (без аллокатора кучи).
    fn register_syscalls<D: SyscallDomain + 'static>(handle: D);

    fn set_ktls_block(ptr: &LocalKernelCTL<Self::Umap>);
    fn get_local_base() -> &'static mut LocalKernelCTL<Self::Umap>;

    /// Единственная точка доступа к IOMMU из архитектурно-независимого кода.
    /// `None` — платформа без IOMMU либо порт ещё не инициализировал юниты.
    fn iommu() -> Option<&'static Self::Iommu>;

    /// Единственная точка доступа к контроллерам прерываний из
    /// архитектурно-независимого кода (syscall-слой IRQ-домена).
    /// `None` — подсистема не инициализирована портом.
    fn irq_chip() -> Option<&'static Self::IrqChip>;

    /// Единственная точка доступа к IPI-контроллеру из архитектурно-
    /// независимого кода (межъядерные wake, SVA-инвалидации). `None` —
    /// пер-CPU идентификация ещё не поднята портом (ранний бут).
    fn ipi() -> Option<&'static Self::Ipi>;

    /// Создаёт пользовательское адресное пространство задачи из ядерной
    /// таблицы (верхняя половина копируется). Связывает KMap::UserspaceMap
    /// и Umap: порт гарантирует их совместимость (обычно Umap = UserspaceMap).
    fn create_task_umap(
        kmap: &Self::KMap,
        allocator: &(dyn FrameAllocator + Sync),
    ) -> Result<Self::Umap, crate::traits::memory::ErrorCode>;

    /// Индекс слова РЕЗУЛЬТАТА в слоте возобновления задачи (формат
    /// кадра сисколла — собственность ПОРТА). Нужен IPC-транспорту: код
    /// ошибки доставки сообщается СПЯЩЕМУ отправителю перезаписью слова
    /// результата в сохранённом кадре (TCB::patch_resume_result) —
    /// планировщик разбудит задачу, а она продолжится после `syscall`
    /// уже с новым кодом возврата. Имя намеренно НЕ упоминает регистр
    /// конкретной архитектуры: на x86_64 это слово RAX, порт волен
    /// хранить кадр иначе.
    const RESUME_RESULT_WORD: usize;

    /// Индексы слов ТОЧКИ ПРОДОЛЖЕНИЯ и СТЕКА в слоте возобновления
    /// (формат кадра — собственность порта; на x86_64 это RIP и RSP).
    /// Нужен фолт-механизму (ipc::fault): FAULT_REPLY опционально
    /// возобновляет упавшую задачу с НОВОГО адреса/стека (эмуляция
    /// инструкции, сигнальный трамплин) — 0 в аргументе означает
    /// «оставить как было» (повтор упавшей инструкции, пейджер).
    const RESUME_RIP_WORD: usize;
    const RESUME_RSP_WORD: usize;
}
