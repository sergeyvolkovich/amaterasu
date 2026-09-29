use core::ffi::CStr;

use bitflags::bitflags;

use crate::frame_manager::UsableMemoryRegion;

// ─── BootModule ──────────────────────────────────────────────────────────────

pub struct BootModule<'a> {
    begin_addr: usize,
    begin_size: usize,
    module_name: &'a CStr,
}

impl<'a> BootModule<'a> {
    /// Конструктор для портов загрузки (например, Limine-фронтенд
    /// копирует имена boot-модулей в статические NUL-буферы и собирает
    /// массив модулей до создания BootInfo).
    ///
    /// `begin_addr` — ФИЗИЧЕСКИЙ адрес образа модуля (spawn-путь
    /// читает его через HHDM), `module_name` — NUL-терминированное имя.
    pub const fn new(begin_addr: usize, begin_size: usize, module_name: &'a CStr) -> Self {
        Self {
            begin_addr,
            begin_size,
            module_name,
        }
    }

    pub fn addr(&self) -> usize {
        self.begin_addr
    }
    pub fn size(&self) -> usize {
        self.begin_size
    }
    pub fn name(&self) -> &'a CStr {
        self.module_name
    }
}

// ─── BootHWModel ─────────────────────────────────────────────────────────────

pub enum BootHWModel {
    AcpiRsdp { version: u8, begin: usize },
    AcpiXsdt { begin: usize },
    AcpiRsdt { begin: usize },
    Dtb { begin: usize, size: usize },
    Unknown,
}

// ─── BootFlags ───────────────────────────────────────────────────────────────

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct BootFlags: u8 {
        const MemoryRellocationHHDM = 1;
        const KernelRelocated = 1 << 1;
    }
}

// ─── CpuInfo ─────────────────────────────────────────────────────────────────

pub struct CpuInfo {
    pub processor_id: u32,
    pub lapic_id: u32,
    pub is_bsp: bool,
    pub entry_point: Option<extern "C" fn(*const CpuInfo) -> !>,
}

// ─── Framebuffer ─────────────────────────────────────────────────────────────

pub struct Framebuffer {
    pub addr: usize,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u16,
}

// ─── BootInfo ────────────────────────────────────────────────────────────────

pub struct BootInfo<'a> {
    memory_regions: &'a [UsableMemoryRegion],
    boot_modules: &'a [BootModule<'a>],
    boot_hw_info_model: BootHWModel,

    boot_flags: BootFlags,
    hhdm_offset: Option<usize>,
    cmdline: Option<&'a CStr>,

    bootloader_name: Option<&'a str>,
    bootloader_version: Option<&'a str>,

    framebuffer: Option<Framebuffer>,
    cpus: &'a [CpuInfo],
}

impl<'a> BootInfo<'a> {
    // ── ACPI / HW ──

    pub fn get_acpi_version(&self) -> Option<u8> {
        match &self.boot_hw_info_model {
            BootHWModel::AcpiRsdp { version, .. } => Some(*version),
            _ => None,
        }
    }

    pub fn hw_model(&self) -> &BootHWModel {
        &self.boot_hw_info_model
    }

    // ── Memory ──

    pub fn memory_regions(&self) -> &'a [UsableMemoryRegion] {
        self.memory_regions
    }

    pub fn hhdm_offset(&self) -> Option<usize> {
        self.hhdm_offset
    }

    // ── Modules ──

    pub fn boot_modules(&self) -> &'a [BootModule<'a>] {
        self.boot_modules
    }

    // ── Flags ──

    pub fn flags(&self) -> BootFlags {
        self.boot_flags
    }

    pub fn is_hhdm(&self) -> bool {
        self.boot_flags.contains(BootFlags::MemoryRellocationHHDM)
    }

    pub fn is_kernel_relocated(&self) -> bool {
        self.boot_flags.contains(BootFlags::KernelRelocated)
    }

    // ── Cmdline / Bootloader ──

    pub fn cmdline(&self) -> Option<&'a CStr> {
        self.cmdline
    }

    pub fn bootloader_name(&self) -> Option<&'a str> {
        self.bootloader_name
    }

    pub fn bootloader_version(&self) -> Option<&'a str> {
        self.bootloader_version
    }

    // ── Framebuffer ──

    pub fn framebuffer(&self) -> Option<&Framebuffer> {
        self.framebuffer.as_ref()
    }

    // ── CPUs ──

    pub fn cpus(&self) -> &'a [CpuInfo] {
        self.cpus
    }

    pub fn bsp(&self) -> Option<&CpuInfo> {
        self.cpus.iter().find(|c| c.is_bsp)
    }

    pub fn ap_count(&self) -> usize {
        self.cpus.iter().filter(|c| !c.is_bsp).count()
    }
}

// ─── BootInfoBuilder ─────────────────────────────────────────────────────────

pub struct BootInfoBuilder<'a> {
    memory_regions: &'a [UsableMemoryRegion],
    boot_modules: &'a [BootModule<'a>],
    boot_hw_info_model: BootHWModel,

    boot_flags: BootFlags,
    hhdm_offset: Option<usize>,
    cmdline: Option<&'a CStr>,

    bootloader_name: Option<&'a str>,
    bootloader_version: Option<&'a str>,

    framebuffer: Option<Framebuffer>,
    cpus: &'a [CpuInfo],
}

impl<'a> BootInfoBuilder<'a> {
    pub fn new() -> Self {
        Self {
            memory_regions: &[],
            boot_modules: &[],
            boot_hw_info_model: BootHWModel::Unknown,
            boot_flags: BootFlags::empty(),
            hhdm_offset: None,
            cmdline: None,
            bootloader_name: None,
            bootloader_version: None,
            framebuffer: None,
            cpus: &[],
        }
    }

    pub fn memory_regions(mut self, regions: &'a [UsableMemoryRegion]) -> Self {
        self.memory_regions = regions;
        self
    }

    pub fn boot_modules(mut self, modules: &'a [BootModule<'a>]) -> Self {
        self.boot_modules = modules;
        self
    }

    pub fn hw_model(mut self, model: BootHWModel) -> Self {
        self.boot_hw_info_model = model;
        self
    }

    pub fn flags(mut self, flags: BootFlags) -> Self {
        self.boot_flags = flags;
        self
    }

    pub fn set_hhdm(mut self, offset: usize) -> Self {
        self.boot_flags |= BootFlags::MemoryRellocationHHDM;
        self.hhdm_offset = Some(offset);
        self
    }

    pub fn cmdline(mut self, cmdline: &'a CStr) -> Self {
        self.cmdline = Some(cmdline);
        self
    }

    pub fn bootloader_name(mut self, name: &'a str) -> Self {
        self.bootloader_name = Some(name);
        self
    }

    pub fn bootloader_version(mut self, version: &'a str) -> Self {
        self.bootloader_version = Some(version);
        self
    }

    pub fn framebuffer(mut self, fb: Framebuffer) -> Self {
        self.framebuffer = Some(fb);
        self
    }

    pub fn cpus(mut self, cpus: &'a [CpuInfo]) -> Self {
        self.cpus = cpus;
        self
    }

    pub fn build(self) -> BootInfo<'a> {
        BootInfo {
            memory_regions: self.memory_regions,
            boot_modules: self.boot_modules,
            boot_hw_info_model: self.boot_hw_info_model,
            boot_flags: self.boot_flags,
            hhdm_offset: self.hhdm_offset,
            cmdline: self.cmdline,
            bootloader_name: self.bootloader_name,
            bootloader_version: self.bootloader_version,
            framebuffer: self.framebuffer,
            cpus: self.cpus,
        }
    }
}

impl<'a> Default for BootInfoBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}
