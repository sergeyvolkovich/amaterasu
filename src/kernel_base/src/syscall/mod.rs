use crate::{
    KernelCTL,
    syscall::{capability::*, fault::*, ipc::*, irq::*, log::*, memory::*, syscall_task::*},
    traits::ArchImplementation,
};

pub mod capability;
pub mod fault;
pub mod ipc;
pub mod iommu;
pub mod irq;
pub mod log;
pub mod memory;
pub mod syscall_task;

pub fn init_syscalls<A: ArchImplementation + crate::traits::iommu::IommuTokenLayer>(kctl: &'static KernelCTL<A>) {
    A::register_syscalls(DomainScheduler::<_, SyscallHandleYield>::new(kctl));
    A::register_syscalls(DomainScheduler::<_, SyscallRegisterTask>::new(kctl));
    A::register_syscalls(DomainScheduler::<_, SyscallDestroyTask>::new(kctl));
    A::register_syscalls(DomainScheduler::<_, SyscallBlockOnObject>::new(kctl));
    A::register_syscalls(DomainScheduler::<_, SyscallReleaseObject>::new(kctl));
    A::register_syscalls(DomainScheduler::<_, SyscallTaskStats>::new(kctl));

    A::register_syscalls(DomainMemory::<_, SyscallAllocPages>::new(kctl));
    A::register_syscalls(DomainMemory::<_, SyscallFreePages>::new(kctl));
    A::register_syscalls(DomainMemory::<_, SyscallMountCapRegion>::new(kctl));
    A::register_syscalls(DomainMemory::<_, SyscallUnmountCapRegion>::new(kctl));

    A::register_syscalls(IPCSyscallDomain::<_, SyscallIPCSend>::new(kctl));
    A::register_syscalls(IPCSyscallDomain::<_, SyscallIPCWait>::new(kctl));

    // Домен IRQ: сон задачи до срабатывания линии + маска сработавших
    // в userspace-массиве (ABI в syscall::irq / task::irq_wait).
    A::register_syscalls(DomainIrq::<_, SyscallWaitIrq>::new(kctl));

    // Домен Debug: чтение лога ядра userspace (init-сервер dumping в FB)
    // и запись строк задачи в лог (наблюдаемость userspace).
    A::register_syscalls(DomainDebug::<_, SyscallDebugLogRead>::new(kctl));
    A::register_syscalls(DomainDebug::<_, SyscallDebugLogWrite>::new(kctl));

    // Домен IOMMU: seL4-стиль инвокации DMA-доменов и PASID-пространств
    // (фасад IommuTokenLayer реализует порт).
    crate::syscall::iommu::init_iommu_syscalls(kctl);

    // Домен capability: создание объектов всех типов (неймспейс, пул IPC,
    // MMIO, IRQ, фолт-эндпоинт), mint/clone/revoke/destroy. Сисколл 24
    // (CAP_TRANSFER, голые task_cap-id) удалён как ambient authority —
    // пересылка capability живёт только в IPC-транспорте (map items).
    // Номер 24 зарезервирован.
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateNamespace>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateIpcPool>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateMmio>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateShared>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateIrq>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapCreateFaultEndpoint>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapMint>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapClone>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapRevoke>::new(kctl));
    A::register_syscalls(DomainCapability::<_, SyscallCapDestroy>::new(kctl));

    // Домен фолтов (seL4/KeyKOS-модель, см. ipc::fault): привязка
    // обработчика к задаче-цели + ответ на фолт (resume упавшей).
    A::register_syscalls(DomainFault::<_, SyscallFaultSetEndpoint>::new(kctl));
    A::register_syscalls(DomainFault::<_, SyscallFaultReply>::new(kctl));
}
