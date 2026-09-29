//! kernel_exec — подсистема исполняемых образов NOMAD.
//!
//! Архитектурно-НЕЗАВИСИМА: форматы (`ExecFormat`, реестр), загрузка
//! сегментов в умап задачи (`load_image`), раскладка стартового стека
//! (`build_initial_stack`) и спавн системных серверов
//! (`spawn_boot_servers`) — всё поверх трейтов kernel_base
//! (`MemoryInterfaceUserspace`, `ArchImplementation`), без единой
//! строчки про x86. Конкретный формат регистрирует порт.
//!
//! Раскладка стартового стека (совместима с SysV; crt0 читает это):
//!   строки argv/envp наверху, ниже auxv, ниже envp/argv-массивы,
//!   argc внизу; начальный RSP = ячейка argc (кратен 16).
//!
//! AUXV NOMAD: 7=PAGESZ, 9=ENTRY, 0xC170_0001=SELF_CAP,
//! 0xC170_0002=NS_CAP, 0xC170_0003..=FB (ADDR/PITCH/WIDTH/HEIGHT/BPP),
//! 0xC170_0008=ACPI_RSDP (физический адрес RSDP).
#![no_std]

pub mod elf;
pub mod modules;
pub mod registry;
pub mod spawn;
pub mod syscall;

pub use registry::{
    ExecError, ExecFormat, FormatRegistry, ImageInfo, SegmentDesc, MAX_FORMATS, MAX_SEGMENTS,
};

// Реэкспорт трейтов kernel_base ПОД ПУТЬ crate::traits: derive
// (SyscallArguments) генерирует `impl crate::traits::syscall::...
// for #name` — сисколл-домен этого крейта (TASK_CREATE) обязан
// резолвить этот путь внутри kernel_exec. Реэкспорт = тот же трейт
// (орфан-правила соблюдены: тип локальный, трейт чужой).
pub use kernel_base::traits;
pub use spawn::{
    build_initial_stack, load_image, spawn_boot_servers, AuxEntry, SpawnedServer, SpawnError,
    StackSetup, TaskArgs, AT_CINTOS_ACPI_RSDP, AT_CINTOS_FB_ADDR, AT_CINTOS_FB_BPP,
    AT_CINTOS_FB_HEIGHT, AT_CINTOS_FB_PITCH, AT_CINTOS_FB_WIDTH, AT_CINTOS_NS_CAP,
    AT_CINTOS_SELF_CAP, AT_ENTRY, AT_NULL, AT_PAGESZ, BOOT_SLOT_IMAGE_BASE, BOOT_SLOT_NAMESPACE,
    BOOT_SLOT_PARENT, BOOT_SLOT_PEER_BASE, BOOT_SLOT_SELF, INIT_MODULE_NAME,
};
pub use syscall::{
    init_exec_syscalls, MAX_EXEC_IMAGE_BYTES, SyscallTaskCreate, SyscallTaskCreateFromMem,
};

/// Странично выровненный leaks-нутый буфер для тестов (std-харнесс).
#[cfg(test)]
pub(crate) mod test_alloc_fallback {
    extern crate std;
    use spin::mutex::SpinMutex;

    /// Глобальная сериализация тестов (HHDM-статика общая).
    pub static GLOBAL_TEST: SpinMutex<()> = SpinMutex::new(());

}
