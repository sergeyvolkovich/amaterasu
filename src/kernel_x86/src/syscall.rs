//! Реестр сисколлов x86 + per-CPU блок ядра через GS base.
//!
//! Реестр БЕЗ аллокатора кучи (в kernel_base нет #[global_allocator] —
//! `define_allocation_hooks!` экспортирует символы для slab-аллокатора, а
//! не GlobalAlloc): домен-хэндл `D` хранится ПО ЗНАЧЕНИЮ в фиксированном
//! слоте статического массива, тип стирается сырым указателем + fn-указателем.
//! Всё, что больше слота по размеру/выравниванию, ловится на этапе
//! регистрации.
//!
//! Типовой контракт `D::Umap == X86Umap` задаётся kernel_base::init_syscalls:
//! домены создаются над тем же ArchImplementation, что и этот реестр.
//! `LocalKernelCTL<D::Umap>` в call_impl восстанавливается из erased-указателя
//! — раскладка LocalKernelCTL не зависит от параметра-типа (PhantomData —
//! ZST), а различие Umов исключено контрактом регистрации.

use core::mem::{align_of, size_of, MaybeUninit};

use spin::mutex::SpinMutex;

use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::syscall::{SyscallArguments, SyscallDomain, syscall_result};

use crate::paging::X86Umap;

/// Максимальное число зарегистрированных доменов сисколлов.
pub const MAX_SYSCALLS: usize = 64;

/// Размер слота под значение домена-хэндла (домены kernel_base —
/// `(&'static KernelCTL, PhantomData)` — 8 байт).
const SLOT_BYTES: usize = 64;
const SLOT_ALIGN: usize = 8;

/// Вызов `D::handle` над значением в статическом слоте.
type ErasedCall = unsafe fn(*const u8, *mut u8, &[u64]) -> u64;

#[derive(Clone, Copy)]
struct SyscallSlot {
    /// Значение `D`, записанное при регистрации (живёт в статике вечно).
    storage: [MaybeUninit<u8>; SLOT_BYTES],
    /// Стиратель: init_from_regs + handle.
    call: ErasedCall,
}

/// Реестр: SYSCALL_ID -> слот.
static REGISTRY: SpinMutex<[Option<SyscallSlot>; MAX_SYSCALLS]> =
    SpinMutex::new([None; MAX_SYSCALLS]);

/// Записывает значение домена в слот. Сбой по размеру/выравниванию.
fn store_domain<D: SyscallDomain + 'static>(domain: D) -> Result<SyscallSlot, &'static str> {
    if size_of::<D>() > SLOT_BYTES {
        return Err("domain handle exceeds slot size");
    }
    if align_of::<D>() > SLOT_ALIGN {
        return Err("domain handle alignment exceeds slot alignment");
    }
    let mut storage = [MaybeUninit::uninit(); SLOT_BYTES];
    // SAFETY: MaybeUninit<u8> корректно хранит сырые байты D; чтение —
    // только как &'static D в call_impl (та же раскладка, что при записи).
    unsafe {
        (storage.as_mut_ptr() as *mut D).write(domain);
    }
    Ok(SyscallSlot {
        storage,
        call: call_impl::<D>,
    })
}

/// Типизированный хвост эразуры: восстанавливает `&'static D` и
/// `&mut LocalKernelCTL<D::Umap>` из erased-указателей и вызывает handle.
///
/// SAFETY-контракт вызова: storage — указатель на слот, куда при
/// регистрации записано значение `D`; lctl — указатель на per-CPU
/// `LocalKernelCTL` порта (Umap совпадает по контракту регистрации).
unsafe fn call_impl<D: SyscallDomain + 'static>(
    storage: *const u8,
    lctl: *mut u8,
    regs: &[u64],
) -> u64 {
    // SAFETY: значение записано в статический слот при регистрации и
    // никогда не удаляется; D: Send проверен при регистрации.
    let domain: &'static D = unsafe { &*(storage as *const D) };
    // SAFETY: per-CPU lctl живёт на GS-base блока ядра; тип согласован
    // контрактом D::Umap == Umap порта (см. модульный комментарий).
    let lctl: &mut LocalKernelCTL<D::Umap> = unsafe { &mut *(lctl as *mut LocalKernelCTL<D::Umap>) };
    let args = D::Args::init_from_regs(regs);
    D::handle(domain, lctl, args)
}

/// Регистрирует домен сисколлов под его `SYSCALL_ID`.
///
/// КОНТРАКТЫ:
///   - `SYSCALL_ID` глобально уникален по всем доменам (нумерация
///     kernel_base выровнена: scheduler 0..4, memory 5..8, ipc 10/11,
///     capability 16..26, irq 28, fault 27/30, iommu 32..45, log 46/47,
///     exec 48/49; коллизия даёт ошибку регистрации на старте);
///   - `D: Send` — значение разделяется всеми ядрами (проверка
///     компиляцией через `_assert_send`);
///   - `D::Umap == Umap` порта — контракт init_syscalls (см. шапку).
pub fn register_erased_syscall<D: SyscallDomain + 'static>(domain: D) -> Result<(), &'static str> {
    // Контракт D: Send не выводится в generic-теле (SyscallDomain его не
    // требует); его даёт фактическая конструкция доменов в
    // kernel_base::init_syscalls — все они содержат только &'static
    // KernelCTL (Sync => Send).

    let id = D::SYSCALL_ID;
    if id >= MAX_SYSCALLS {
        return Err("syscall id out of range");
    }
    let slot = store_domain(domain)?;
    let mut registry = REGISTRY.lock();
    if registry[id].is_some() {
        return Err("syscall id already registered");
    }
    registry[id] = Some(slot);
    Ok(())
}

/// Диспетчеризация из entry-стаба: id сисколла + регистры аргументов.
pub fn dispatch_syscall(lctl: &mut LocalKernelCTL<X86Umap>, id: usize, regs: &[u64]) -> u64 {
    let (call, storage) = {
        let registry = REGISTRY.lock();
        match registry.get(id).and_then(|slot| slot.as_ref()) {
            Some(slot) => (slot.call, slot.storage.as_ptr() as *const u8),
            None => return syscall_result::E_NOT_FOUND,
        }
    };
    // SAFETY: слот статический, значение записано при регистрации;
    // lctl — per-CPU блок порта, тип согласован контрактом регистрации.
    unsafe { call(storage, lctl as *mut LocalKernelCTL<X86Umap> as *mut u8, regs) }
}

// ─── Per-CPU (KTLS) через GS base ────────────────────────────────────────────

/// Кладёт per-CPU блок ядра в область ТЕКУЩЕГО ядра (GS base — см.
/// cswitch::install_lctl: BSP выделяет слот, AP использует свой).
///
/// # Safety
/// Вызывать один раз на ядро при старте (контракт трейта).
pub unsafe fn set_ktls_block(ptr: &LocalKernelCTL<X86Umap>) {
    // Контракт вызова — один вызов на ядро; install_lctl безопасна
    // (разыменований нет, только запись в свободный слот статики).
    crate::cswitch::install_lctl(ptr).expect("per-CPU слоты исчерпаны/не установлены");
}

/// Читает per-CPU блок текущего ядра (GS base → PerCpuArea.lctl).
///
/// # Safety
/// GS base обязан быть установлен set_ktls_block на этом ядре; не
/// вызывать дважды — две &mut на один блок.
pub unsafe fn get_local_base() -> &'static mut LocalKernelCTL<X86Umap> {
    // Контракт GS base (install_lctl/ap_cpu_setup) — безопасность
    // берёт на себя вызывающий; current_lctl сама по себе безопасна.
    crate::cswitch::current_lctl()
}

/// Включает механизм SYSCALL/SYSRET (EFER.SCE + STAR/LSTAR/FMASK).
///
/// `kernel_cs` — кодовый сегмент ядра: SYSCALL загружает cs=kernel_cs,
/// ss=kernel_cs+8.
///
/// `star_user_base` — БАЗА пользовательской части STAR (НЕ сам селектор
/// кода!): аппаратное правило SYSRET64 — ss ← base+8|3, cs ← base+0x10|3
/// (Linux пишет сюда __USER_CS-0x10). При базе 0x18 и раскладке GDT
/// «0x20=user data, 0x28=user code» SYSRET даёт ровно cs=0x2B, ss=0x23.
/// Прежняя трактовка «сюда приходит сам user_cs» при раскладке
/// user_cs=0x18/TSS=0x28 отправляла SYSRET в CS по селектору TSS —
/// неисполняемый дескриптор, который «работал» до первого IRETQ
/// (возврат из таймер-IRQ) и валился #GP(0x28).
///
/// # Safety
/// LSTAR обязан указывать на готовый entry-стаб; вызывать после
/// построения GDT.
pub unsafe fn enable_syscall_entry(kernel_cs: u16, star_user_base: u16, entry_virt: usize) {
    use x86_64::registers::model_specific::{Msr, SFMask};
    const MSR_EFER: u32 = 0xC000_0080;
    const MSR_STAR: u32 = 0xC000_0081;
    const MSR_LSTAR: u32 = 0xC000_0082;
    const EFER_SCE: u64 = 1;

    // SAFETY: privileged MSR-записи по контракту функции.
    unsafe {
        let star = ((kernel_cs as u64) << 32) | ((star_user_base as u64) << 48);
        Msr::new(MSR_STAR).write(star);
        Msr::new(MSR_LSTAR).write(entry_virt as u64);
        // FMASK: БИТЫ, КОТОРЫЕ SYSCALL СБРАСЫВАЕТ в RFLAGS (загружаемом
        // из R11). Обязательно IF — иначе весь путь сисколла живёт с
        // включёнными прерываниями: тик прерывает произвольную точку
        // ядра, включая удержание спин-локов (дедлок, ловился в QEMU:
        // RFL=0x202 на syscall-путях). TF — гигиена (user-трассировка не
        // должна шагать ядро). ВАЖНО: раньше маска была инвертирована
        // (!(1<<9) = «всё, кроме IF») — сбрасывалось всё КРОМЕ IF.
        //
        // HARDENING (практика Linux): DF — ring3 не управляет направлением
        // копирования в ядре (Rust/compiler-builtins рассчитывают на DF=0;
        // раньше требовался cld в стабе); NT — каскадные IRET-цепочки;
        // RF — resume-флаг; AC — alignment-check (ядро не гуляет по
        // user-страницам через AC); IOPL — I/O-привилегии ring3 (0):
        // иначе пользовательский порт-IN/OUT мимо capability-модели.
        SFMask::write(x86_64::registers::rflags::RFlags::from_bits_retain(
            (1u64 << 9)      // IF
                | (1u64 << 8)    // TF
                | (1u64 << 10)   // DF
                | (1u64 << 14)   // NT
                | (1u64 << 16)   // RF
                | (1u64 << 18)   // AC
                | (0b11u64 << 12), // IOPL
        ));
        let mut efer = Msr::new(MSR_EFER);
        efer.write(efer.read() | EFER_SCE);
    }
}
