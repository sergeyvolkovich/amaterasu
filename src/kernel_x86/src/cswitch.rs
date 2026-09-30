//! Переключение контекста x86_64: GDT, IDT, точка входа SYSCALL,
//! первый вход в задачу (ring3), возобновление по сохранённому кадру
//! и возврат в цикл планировщика.
//!
//! Контракт v3 (PER-CPU, SMP): вся статика диспетчеризации — стеки,
//! GS-указатели, GDT/TSS — живёт в массивах с индексом ядра (слотом
//! per-CPU). Naked-стабы адресуют её ЧЕРЕЗ GS:[офсет] (fixed-поля
//! [`PerCpuArea`]); GS base каждого ядра указывает на его область —
//! ставится `set_ktls_block` (BSP: слот из очереди; AP: слот из
//! `Cpu.extra` протокола, см. smp.rs). Один слот — одно ядро.
//!
//!   - Цикл планировщика ядра получает ChangeTask(id), находит TCB и
//!     входит в задачу: с кадром — [`resume_user`] (CR3 + iretq по
//!     кадру), без — [`dispatch_user`] (первый вход: CR3 + iretq-кадр
//!     entry/стек/RFLAGS=0x202).
//!   - Задача живёт в ring3 до SYSCALL: LSTAR-стаб сохраняет кадр на
//!     PER-CPU ядерном стеке сисколлов (gs:[OFF_KSTACK]), диспетчеризует
//!     домен, затем спрашивает планировщика, кто должен исполняться
//!     теперь (current_task):
//!       * та же задача — SYSRET (обычный сисколл);
//!       * другая — кадр текущей сохраняется в её TCB (слот
//!         возобновления) и управление уходит хуку порта (вход в
//!         следующую задачу с её кадром или с точки входа);
//!       * никого (все уснули) — кадр в TCB, выход в цикл
//!         планировщика (idle-опрос; пробуждённая задача подхватится
//!         с resume).
//!   - Self-exit (SCHED_DESTROY_TASK): после домена текущая задача
//!     отсутствует → [`return_to_scheduler`]: CR3 ← gs:[OFF_ROOT],
//!     стек → gs:[OFF_SCHED_STACK], jmp на gs:[OFF_SCHED_LOOP].
//!
//! Инвариант одного ядерного стека сисколлов — НА ЯДРО: в любой
//! момент на ядре исполняется максимум одна задача (переключение —
//! только внутри syscall_frame_dispatch, который не возвращается в
//! покинутый кадр); следующий SYSCALL любой задачи начинает запись
//! кадра с TOP — покинутые кадры перезатираются.
//!
//! FPU/SSE (eager-модель, БЕЗ CR0.TS-фолтов): XMM/x87-состояние
//! сохраняется при КАЖДОМ входе из ring3 (SYSCALL/IRQ/исключение —
//! fxsave64 в per-CPU скретч gs:[OFF_FPU]) и восстанавливается при
//! выходе (SYSRET/iretq — fxrstor64). При переключении задач скретч
//! копируется в FPU-область TCB уходящей задачи (stash_fpu_to_tcb —
//! рядом с save_resume), при входе — fxrstor из TCB через bounce-копию
//! в скретч (FXRSTOR требует 16-выровненный операнд; TCB-область —
//! только 8-выровненная). В ядерном режиме FPU не сохраняется
//! (IRQ/исключение из ring0 не трогают скретч — там может лежать ещё
//! живое ring3-состояние сисколла; SSE-опасности ЯДРА — отдельная
//! тема, см. docs/kernel.md).
//!
//! Порядок инициализации (важно!):
//!   1. [`early_boot_init`] — ДО KernelCTL::new_and_init: загрузка GDT
//!      (слот 0 BSP) перезагружает сегментные регистры, а `mov gs, ...`
//!      ОБНУЛЯЕТ IA32_GS_BASE — GS base области ставится ПОЗЖЕ (в
//!      new_and_init → set_ktls_block) и не должен затираться.
//!   2. [`late_boot_init`] — после init_syscalls: заполнение fixed-полей
//!      области BSP + MSR STAR/LSTAR/FMASK + EFER.SCE (с этого момента
//!      `syscall` из ring3 живой). Дублируется на каждом AP (smp.rs).

use core::arch::{asm, naked_asm};

use crate::syscall::dispatch_syscall;
use crate::X86Backend;
use kernel_base::lctl::LocalKernelCTL;
use kernel_base::traits::ArchImplementation as _;

// ─── Селекторы сегментов ─────────────────────────────────────────────────────

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
/// Пользовательский код; в кадрах — с RPL=3 (0x2B).
///
/// ВАЖНО: селектор 0x28, а не «третий слот» — раскладка привязана к
/// правилу SYSRET (см. STAR_USER_BASE): ядро ставит STAR[63:48] = 0x18,
/// и SYSRET загружает SS ← 0x18+8 = 0x20|3, CS ← 0x18+0x10 = 0x28|3.
/// Прежняя раскладка (user_cs=0x18, TSS=0x28) давала SYSRET-у в CS
/// ДЕСКРИПТОР TSS (неисполняемый!): SYSCALL/SYSRET не валидируют
/// дескрипторы, задача «работала», пока первый же IRETQ (возврат из
/// таймер-IRQ) не пытался перезагрузить этот CS → #GP(0x28)
/// (поймано в QEMU на первом тике PIT).
pub const USER_CS: u16 = 0x28;
/// База пользовательской части STAR: SYSRET ждёт ДАННЫЕ на +8 и КОД на
/// +0x10 от неё (Linux ставит туда __USER_CS-0x10). Слот 0x18 в GDT
/// зарезервирован под эту базу (дескриптор не используется).
pub const STAR_USER_BASE: u16 = 0x18;
/// Пользовательские данные; с RPL=3 (0x23).
pub const USER_DS: u16 = 0x20;

// Границы секции .text (экспорт линкер-скрипта порта): примитивный
// бэктрейс обработчика исключений ищет адреса возврата в этом диапазоне.
unsafe extern "C" {
    static __text_begin: u8;
    static __text_end: u8;
}

// ─── Per-CPU области (GS-relative) ───────────────────────────────────────────

/// Офсеты fixed-полей PerCpuArea для naked-стабов (gs:[офсет]).
pub const OFF_KSTACK: usize = 0x00; // верх ядерного стека сисколлов
pub const OFF_USER_RSP: usize = 0x08; // скретч: пользовательский RSP
pub const OFF_SCHED_STACK: usize = 0x10; // верх стека цикла планировщика
pub const OFF_SCHED_LOOP: usize = 0x18; // адрес scheduler_loop_entry
pub const OFF_ROOT: usize = 0x20; // физический корень таблицы ядра
pub const OFF_FPU: usize = 0x28; // указатель на per-CPU FPU-скретч (fxsave/fxrstor)

/// Fixed-часть per-CPU области: читается naked-стабами через GS.
/// Раскладка ЗАФИКСИРОВАНА (офсеты — константы выше).
#[repr(C)]
pub struct PerCpuFixed {
    pub syscall_kstack_top: u64,
    pub user_rsp_save: u64,
    pub sched_stack_top: u64,
    pub sched_loop_entry: u64,
    pub kernel_root_phys: u64,
    /// Указатель на 512-байтный fxsave-скретч ЭТОГО ядра
    /// ([`FpuScratch`]; 16-выровнен — требование FXSAVE/FXRSTOR).
    pub fpu_scratch: u64,
}

const _: () = assert!(core::mem::offset_of!(PerCpuFixed, syscall_kstack_top) == OFF_KSTACK);
const _: () = assert!(core::mem::offset_of!(PerCpuFixed, user_rsp_save) == OFF_USER_RSP);
const _: () = assert!(core::mem::offset_of!(PerCpuFixed, sched_stack_top) == OFF_SCHED_STACK);
const _: () = assert!(core::mem::offset_of!(PerCpuFixed, sched_loop_entry) == OFF_SCHED_LOOP);
const _: () = assert!(core::mem::offset_of!(PerCpuFixed, kernel_root_phys) == OFF_ROOT);
const _: () = assert!(core::mem::offset_of!(PerCpuFixed, fpu_scratch) == OFF_FPU);

/// Per-CPU область ядра: GS base каждого ядра указывает сюда.
/// fixed — для стабов; lctl — per-core блок ядра (LocalKernelCTL).
#[repr(C)]
pub struct PerCpuArea {
    pub fixed: PerCpuFixed,
    pub lctl: LocalKernelCTL<crate::paging::X86Umap>,
}

/// Per-CPU FPU-скретч: цель fxsave64 стаба при входе из ring3 и
/// источник fxrstor64 при возврате в ту же задачу; для входа в ДРУГУЮ
/// задачу — bounce-буфер (копия из TCB, затем fxrstor — операнд
/// FXRSTOR обязан быть 16-выровнен, TCB-область гарантирует только 8).
#[repr(C, align(16))]
pub struct FpuScratch(pub(crate) [u8; kernel_base::task::tcb::FpuArea::SIZE]);

const _: () = assert!(core::mem::size_of::<FpuScratch>() == 512);
const _: () = assert!(core::mem::align_of::<FpuScratch>() == 16);

impl PerCpuArea {
    const fn zeroed() -> Self {
        Self {
            fixed: PerCpuFixed {
                syscall_kstack_top: 0,
                user_rsp_save: 0,
                sched_stack_top: 0,
                sched_loop_entry: 0,
                kernel_root_phys: 0,
                fpu_scratch: 0,
            },
            lctl: LocalKernelCTL::new(),
        }
    }
}

/// Максимум поддерживаемых ядер (слоты per-CPU).
pub const MAX_CPUS: usize = 64;

// ─── GDT + TSS (per-CPU) ─────────────────────────────────────────────────────

/// Селектор TSS (дескриптор 16-байтовый в long mode — слоты 6-7).
pub const TSS_SEL: u16 = 0x30;

/// 8 записей: null, KCODE, KDATA, (база STAR), UDATA, UCODE, TSS_lo, TSS_hi.
/// TSS-дескриптор в long mode системный 16-байтовый — занимает 2 слота.
///
/// static mut (НЕ read-only static): загрузка сегментного регистра
/// заставляет CPU выставить бит Accessed В ДЕСКРИПТОРЕ — это запись
/// в таблицу GDT. В .rodata Limine мапит сегмент R-- и первый же
/// `mov ds` даёт page fault (поймано в QEMU: CR2 = &GDT + 0x14).
///
/// Раскладка (см. USER_CS/STAR_USER_BASE — правило SYSRET +8/+0x10):
///   0x00 null | 0x08 kernel code | 0x10 kernel data | 0x18 (база STAR,
///   не используется) | 0x20 user data | 0x28 user code | 0x30/0x38 TSS.
#[repr(align(16))]
struct GdtTable([u64; 8]);

/// TSS64 (104 байта, canonical layout Intel SDM Vol.3 Fig.8-11).
/// Хранится как байтовый массив: раскладка TSS НЕ соответствует
/// естественному выравниванию Rust-полей (RSP0 по смещению 0x04),
/// поэтому доступ — через unaligned-записи по константам смещений.
///
/// БЕЗ загруженного TSS любое исключение в ring3 — фатально: доставка
/// требует смены стека CPL3→CPL0, CPU читает RSP0 из TSS, а TR указывает
/// в пустоту → #TS при доставке #PF → #DF → triple fault (поймано в
/// QEMU). SYSCALL/SYSRET стек НЕ переключает — там RSP переключается
/// вручную (см. syscall_entry), TSS нужен именно для аппаратных входов.
#[repr(align(16))]
struct Tss(#[allow(dead_code)] [u8; 104]);

const TSS_RSP0_OFF: usize = 0x04;
const TSS_IOPB_OFF: usize = 0x66;
const TSS_SIZE: usize = 104;

/// Стек аппаратных входов из ring3 (исключения). Отдельный от
/// сисколл-стека: прерывание может прийти и в ring3, и в ядре —
/// пересечение с активным сисколл-стеком недопустимо.
#[repr(align(16))]
struct EStack(#[allow(dead_code)] [u8; 16 * 1024]);

/// Ядерный стек сисколлов и стек цикла планировщика (per-CPU, в .bss,
/// НЕ в reclaimable-памяти загрузчика).
#[repr(align(16))]
struct KStack(#[allow(dead_code)] [u8; 32 * 1024]);
#[repr(align(16))]
struct SStack(#[allow(dead_code)] [u8; 32 * 1024]);

static mut PER_CPU_GDT: [GdtTable; MAX_CPUS] = [const {
    GdtTable([
        0,
        0x00AF_9A00_0000_FFFF, // 0x08 kernel code: L=1 P=1 S=1 type=A DPL=0
        0x00CF_9200_0000_FFFF, // 0x10 kernel data: W P S DPL=0
        0,                      // 0x18 база STAR (дескриптор не используется)
        0x00CF_F200_0000_FFFF, // 0x20 user data: DPL=3 (SYSRET SS ← 0x23)
        0x00AF_FA00_0000_FFFF, // 0x28 user code: DPL=3 (SYSRET CS ← 0x2B)
        0,                      // 0x30 TSS (заполняется в load_gdt)
        0,
    ])
}; MAX_CPUS];
static mut PER_CPU_TSS: [Tss; MAX_CPUS] = [const { Tss([0; TSS_SIZE]) }; MAX_CPUS];
static mut PER_CPU_EXC_STACK: [EStack; MAX_CPUS] =
    [const { EStack([0; 16 * 1024]) }; MAX_CPUS];
static mut PER_CPU_KSTACK: [KStack; MAX_CPUS] = [const { KStack([0; 32 * 1024]) }; MAX_CPUS];
static mut PER_CPU_SCHED_STACK: [SStack; MAX_CPUS] =
    [const { SStack([0; 32 * 1024]) }; MAX_CPUS];
static mut PER_CPU_AREAS: [PerCpuArea; MAX_CPUS] = [const { PerCpuArea::zeroed() }; MAX_CPUS];
/// Per-CPU FPU-скретчи (fxsave/fxrstor; 16-выровнены статически —
/// требование операнда FXSAVE/FXRSTOR, #GP иначе). Указатель на элемент
/// слота кладётся в fixed.fpu_scratch (setup_cpu_area).
static mut PER_CPU_FPU: [FpuScratch; MAX_CPUS] =
    [const { FpuScratch([0; kernel_base::task::tcb::FpuArea::SIZE]) }; MAX_CPUS];

/// Общий для всех ядер физический корень ядерной таблицы (AP читает до
/// установки своего GS base — ещё на бут-таблицах).
static KERNEL_ROOT_SHARED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Общий адрес цикла планировщика порта (копируется в per-CPU области).
static SCHED_LOOP_SHARED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Следующий свободный per-CPU слот (BSP берёт 0 на boot-пути).
static NEXT_CPU_SLOT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Доступ к per-CPU области по слоту (smp.rs / syscall.rs).
///
/// # Safety
/// Один слот — одно ядро; мутабельный доступ — только «владелец» слота
/// либо однопоточный boot-путь.
pub unsafe fn per_cpu_area(slot: usize) -> Option<&'static mut PerCpuArea> {
    if slot >= MAX_CPUS {
        return None;
    }
    // SAFETY: контракт вызова (слот закреплён за одним ядром).
    Some(unsafe {
        &mut (*core::ptr::addr_of_mut!(PER_CPU_AREAS).cast::<[PerCpuArea; MAX_CPUS]>())[slot]
    })
}

/// Выделить следующий per-CPU слот (BSP — первый).
pub fn alloc_cpu_slot() -> Option<usize> {
    let slot = NEXT_CPU_SLOT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    (slot < MAX_CPUS).then_some(slot)
}

/// Заполнить fixed-поля области слота (стеки/цикл/корень) — до
/// установки GS base. Повторный вызов перезаписывает.
///
/// `paint` — заливка стека цикла паттерном 0x5A для high-water
/// замеров. Разрешена ТОЛЬКО когда на стеке слота НИКТО не живёт
/// (BSP-путь до запуска ядра слота): AP вызывает с paint=false — он
/// УЖЕ стоит на этом стеке, заливка затёрла бы собственные кадры
/// (поймано в QEMU -smp 4: AP зависали в цикле заливки, итератор и
/// адреса возврата перекрывались паттерном).
pub fn setup_cpu_area(
    slot: usize,
    sched_loop: u64,
    kernel_root_phys: u64,
    paint: bool,
) -> Option<()> {
    let area = unsafe { per_cpu_area(slot)? };
    // Верх стеков: база + размер (alignment 16 гарантирован repr).
    // Чтение адресов статических массивов (Rust-2024: addr_of! безопасен).
    let kbase = core::ptr::addr_of!(PER_CPU_KSTACK).cast::<u8>() as usize;
    let sbase = core::ptr::addr_of!(PER_CPU_SCHED_STACK).cast::<u8>() as usize;
    // FPU-скретч слота: статический массив 16-выровненных областей.
    let fpu_ptr = core::ptr::addr_of!(PER_CPU_FPU).cast::<FpuScratch>() as usize
        + slot * core::mem::size_of::<FpuScratch>();
    area.fixed = PerCpuFixed {
        syscall_kstack_top: (kbase + slot * core::mem::size_of::<KStack>()
            + core::mem::size_of::<KStack>()) as u64,
        user_rsp_save: 0,
        sched_stack_top: (sbase + slot * core::mem::size_of::<SStack>()
            + core::mem::size_of::<SStack>()) as u64,
        sched_loop_entry: sched_loop,
        kernel_root_phys,
        fpu_scratch: fpu_ptr as u64,
    };
    if paint {
        // SAFETY: слот валиден (per_cpu_area выше), массив — static mut с
        // сырым доступом; на стеке слота никто не живёт (контракт paint).
        unsafe {
            let stacks = &mut *core::ptr::addr_of_mut!(PER_CPU_SCHED_STACK)
                .cast::<[SStack; MAX_CPUS]>();
            for b in stacks[slot].0.iter_mut() {
                *b = STACK_PATTERN;
            }
        }
    }
    Some(())
}

/// Паттерн заливки стеков для high-water замеров.
pub const STACK_PATTERN: u8 = 0x5A;

/// Сколько байтов стека цикла планировщика слота было затронуто
/// (high-water: минимальный затронутый адрес). 0 — стек не тронут
/// (или слот невалиден).
pub fn sched_stack_used(slot: usize) -> usize {
    // SAFETY: чтение static mut через сырой указатель (Rust-2024).
    let stacks = unsafe { &*core::ptr::addr_of!(PER_CPU_SCHED_STACK)
        .cast::<[SStack; MAX_CPUS]>() };
    if slot >= MAX_CPUS {
        return 0;
    }
    for (i, b) in stacks[slot].0.iter().enumerate() {
        if *b != STACK_PATTERN {
            return stacks[slot].0.len() - i;
        }
    }
    0
}

/// Установка GS base на per-CPU область. Вызывать ПОСЛЕ load_gdt
/// (mov gs обнуляет базу!): set_ktls_block (BSP) и smp::ap_entry (AP).
///
/// # Safety
/// Слот закреплён за ТЕКУЩИМ ядром (double-mapping GS недопустим).
pub unsafe fn install_gs_base(slot: usize) {
    use x86_64::registers::model_specific::Msr;
    let Some(area) = (unsafe { per_cpu_area(slot) }) else {
        return;
    };
    let mut msr = Msr::new(0xC000_0101); // IA32_GS_BASE
    // SAFETY: privileged MSR-запись (ring0), контракт выше.
    unsafe { msr.write(area as *const PerCpuArea as u64) };
}

/// Физический корень ядерной таблицы (общий; для AP до GS-настройки).
pub fn kernel_root_phys_shared() -> u64 {
    KERNEL_ROOT_SHARED.load(core::sync::atomic::Ordering::Acquire)
}

/// Слот текущего ядра по GS base (None — GS base вне per-CPU областей:
/// ещё не установлен или чужой).
fn gs_base_slot() -> Option<usize> {
    use x86_64::registers::model_specific::Msr;
    // SAFETY: чтение MSR.
    let gs = unsafe { Msr::new(0xC000_0101).read() } as usize;
    // Адрес статического массива (addr_of! безопасен в Rust-2024).
    let base = core::ptr::addr_of!(PER_CPU_AREAS) as usize;
    let len = MAX_CPUS * core::mem::size_of::<PerCpuArea>();
    if gs < base || gs >= base + len {
        return None;
    }
    let off = gs - base;
    if !off.is_multiple_of(core::mem::size_of::<PerCpuArea>()) {
        return None;
    }
    Some(off / core::mem::size_of::<PerCpuArea>())
}

/// Слот ТЕКУЩЕГО ядра (публично: IPI-слой и отладка). `None` — per-CPU
/// область ещё не установлена (ранний бут; ядро в этот момент одно и
/// межъядерные протоколы вырождаются в no-op).
pub fn current_cpu_slot() -> Option<usize> {
    gs_base_slot()
}

/// Установка per-CPU lctl (реализация ArchImplementation::set_ktls_block).
///
/// ДВА ПУТИ: AP уже настроил свою область (smp::ap_entry → GS base) —
/// lctl копируется туда; BSP (GS base обнулён load_gdt) — выделяется
/// следующий слот, lctl копируется, GS base ставится. Возврат — слот.
pub fn install_lctl(lctl: &LocalKernelCTL<crate::paging::X86Umap>) -> Option<usize> {
    let slot = match gs_base_slot() {
        Some(slot) => slot,
        None => alloc_cpu_slot()?,
    };
    let area = unsafe { per_cpu_area(slot)? };
    // Побитовая копия (LocalKernelCTL не Copy из-за NonNull-полей; обе
    // стороны — тривиально перемещаемые данные).
    // SAFETY: слот закреплён за этим ядром; источник — свежий
    // LocalKernelCTL::new() из write_core_state (никем не разделяется).
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(area.lctl),
            core::ptr::read(lctl as *const _),
        );
    }
    // BSP-пути GS base ещё нет — ставим (AP-путь: уже стоит, повторная
    // запись того же значения безвредна).
    unsafe { install_gs_base(slot) };
    Some(slot)
}

/// per-core блок ядра ТЕКУЩЕГО CPU (GS base → область → lctl).
/// Реализация ArchImplementation::get_local_base.
pub fn current_lctl() -> &'static mut LocalKernelCTL<crate::paging::X86Umap> {
    let Some(slot) = gs_base_slot() else {
        gs_base_diagnostics();
    };
    let area = unsafe { per_cpu_area(slot) }.expect("слот в диапазоне по построению");
    &mut area.lctl
}

/// Диагностика «GS base вне per-CPU областей»: значение MSR, CR3/RSP
/// и стек-скан адресов возврата (.text) — КАКОЙ путь вошёл с чужим GS.
/// Вызывается только на ошибочном пути (cold), производительность не
/// важна.
#[cold]
#[inline(never)]
fn gs_base_diagnostics() -> ! {
    use x86_64::registers::model_specific::Msr;
    let gs = unsafe { Msr::new(0xC000_0101).read() };
    let kgs = unsafe { Msr::new(0xC000_0102).read() };
    let cr3: u64;
    let rsp: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3);
        asm!("mov {}, rsp", out(reg) rsp);
    }
    crate::serial::write_str("\n=== GS-BASE DIAG ===\n");
    crate::serial::write_str("GS_BASE=");
    crate::serial::write_str(uxtostr(gs));
    crate::serial::write_str(" KERNEL_GS_BASE=");
    crate::serial::write_str(uxtostr(kgs));
    crate::serial::write_str(" CR3=");
    crate::serial::write_str(uxtostr(cr3));
    crate::serial::write_str(" RSP=");
    crate::serial::write_str(uxtostr(rsp));
    crate::serial::write_str("\n[BT] ");
    let (text_lo, text_hi) = (
        core::ptr::addr_of!(__text_begin) as usize,
        core::ptr::addr_of!(__text_end) as usize,
    );
    let mut printed = 0usize;
    for i in 0..160 {
        let addr = rsp as usize + i * 8;
        if crate::paging::translate_page(cr3 as usize, addr).is_none() {
            break;
        }
        // SAFETY: страница отображена (translate прошёл до листа).
        let v = unsafe { core::ptr::read_unaligned(addr as *const u64) } as usize;
        if (text_lo..text_hi).contains(&v) {
            crate::serial::write_str(uxtostr(v as u64));
            crate::serial::write_str(" ");
            printed += 1;
            if printed >= 24 {
                break;
            }
        }
    }
    crate::serial::write_str("\n");
    panic!("GS base вне per-CPU областей (диагностика выше)");
}

fn exception_stack_top(slot: usize) -> u64 {
    // Чтение адреса статического массива (addr_of! безопасен).
    let base = core::ptr::addr_of!(PER_CPU_EXC_STACK).cast::<u8>() as usize;
    (base + slot * core::mem::size_of::<EStack>() + core::mem::size_of::<EStack>()) as u64
}

/// Системный TSS64-дескриптор (16 байт, long mode): [lo, hi].
fn tss_descriptor(base: u64) -> [u64; 2] {
    let limit = (TSS_SIZE - 1) as u64; // 0x67
    let lo = (limit & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (0x89 << 40) // P=1 DPL=0 S=0 Type=1001 (TSS64 available)
        | ((base >> 24 & 0xFF) << 56);
    let hi = base >> 32;
    [lo, hi]
}

#[repr(C, packed)]
struct DtablePtr {
    limit: u16,
    base: u64,
}

/// Загружает GDT (+ TSS-дескриптор и TR) с индексом per-CPU слота и
/// перезагружает сегментные регистры. ВАЖНО: затирает IA32_GS_BASE
/// (`mov gs` сбрасывает базу) — вызывать ДО установки GS base области.
pub fn load_gdt(slot: usize) {
    // Rust-2024: static mut — только сырые указатели (addr_of_mut!
    // безопасен; unsafe нужен лишь на арифметике указателей ниже).
    let gdt: *mut GdtTable = core::ptr::addr_of_mut!(PER_CPU_GDT)
        .cast::<[GdtTable; MAX_CPUS]>() as *mut GdtTable;
    // SAFETY: слот в границах (проверил вызывающий/boot-путь).
    let gdt = unsafe { gdt.add(slot) };
    let tss: *mut Tss = core::ptr::addr_of_mut!(PER_CPU_TSS)
        .cast::<[Tss; MAX_CPUS]>() as *mut Tss;
    // SAFETY: как gdt.
    let tss = unsafe { tss.add(slot) };
    let tss_bytes = tss.cast::<u8>();
    unsafe {
        // RSP0 = верх стека аппаратных входов из ring3; IOPB-офсет
        // за пределами лимита (IO-карты нет). Дескриптор — слоты 6-7
        // (селекторы 0x30/0x38).
        tss_bytes.add(TSS_RSP0_OFF).cast::<u64>().write_unaligned(exception_stack_top(slot));
        tss_bytes.add(TSS_IOPB_OFF).cast::<u16>().write_unaligned(TSS_SIZE as u16);
        let desc = tss_descriptor(tss_bytes as u64);
        (*gdt).0[6] = desc[0];
        (*gdt).0[7] = desc[1];
    }
    let ptr = DtablePtr {
        limit: (core::mem::size_of::<GdtTable>() - 1) as u16,
        base: gdt.cast::<u8>() as u64,
    };
    unsafe {
        asm!(
            "lgdt [{}]",
            // В сегментный регистр нельзя mov immediate — только из GPR.
            "mov ax, {kds}",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "push {kcs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // TR: без него исключения из ring3 → #TS → triple fault.
            "mov ax, {tss}",
            "ltr ax",
            in(reg) &ptr,
            out("ax") _,
            kds = const KERNEL_DS,
            kcs = const KERNEL_CS,
            tss = const TSS_SEL,
            tmp = out(reg) _,
        );
    }
}

// ─── IDT ─────────────────────────────────────────────────────────────────────

/// Кадр исключения (раскладка idt_common; низ → верх). pub(crate):
/// читает фолт-доставка crate::fault (конвертация в кадр возобновления).
#[repr(C)]
pub(crate) struct IntFrame {
    pub(crate) rdi: u64, pub(crate) rsi: u64, pub(crate) rdx: u64, pub(crate) rcx: u64,
    pub(crate) rax: u64, pub(crate) rbx: u64, pub(crate) rbp: u64,
    pub(crate) r8: u64, pub(crate) r9: u64, pub(crate) r10: u64, pub(crate) r11: u64,
    pub(crate) r12: u64, pub(crate) r13: u64, pub(crate) r14: u64, pub(crate) r15: u64,
    // стаб: номер вектора и код ошибки (0, если CPU его не кладёт)
    pub(crate) nr: u64,
    pub(crate) err: u64,
    // аппаратный кадр
    pub(crate) rip: u64, pub(crate) cs: u64, pub(crate) rflags: u64, pub(crate) rsp: u64,
    pub(crate) ss: u64,
}

/// Кадр ВНЕШНЕГО ПРЕРЫВАНИЯ (раскладка irq_common; низ → верх).
/// Отличие от IntFrame: у внешних IRQ CPU НЕ кладёт код ошибки — поле
/// err отсутствует (офсеты asm-хвоста привязаны assert-ами ниже).
/// pub(crate): читает хвост преемпции irq::irq_vector_dispatch_erased.
#[repr(C)]
pub(crate) struct IrqFrame {
    pub(crate) rdi: u64, pub(crate) rsi: u64, pub(crate) rdx: u64, pub(crate) rcx: u64,
    pub(crate) rax: u64, pub(crate) rbx: u64, pub(crate) rbp: u64,
    pub(crate) r8: u64, pub(crate) r9: u64, pub(crate) r10: u64, pub(crate) r11: u64,
    pub(crate) r12: u64, pub(crate) r13: u64, pub(crate) r14: u64, pub(crate) r15: u64,
    // стаб: номер вектора (код ошибки у внешних IRQ отсутствует)
    pub(crate) nr: u64,
    // аппаратный кадр
    pub(crate) rip: u64, pub(crate) cs: u64, pub(crate) rflags: u64, pub(crate) rsp: u64,
    pub(crate) ss: u64,
}

// Контракты naked-хвоста irq_common: номер вектора по +120 (15 GPR),
// CPL-проверка по CS на +136 (без err — в отличие от исключений).
const _: () = assert!(core::mem::size_of::<IrqFrame>() == 21 * 8);
const _: () = assert!(core::mem::offset_of!(IrqFrame, nr) == 120);
const _: () = assert!(core::mem::offset_of!(IrqFrame, rip) == 128);
const _: () = assert!(core::mem::offset_of!(IrqFrame, cs) == 136);

/// Число информирующих векторов (0..31 — исключения; 32..255 —
/// линии IRQ/MSI через irq::irq_vector_dispatch; 255 молчит — спурьё).
const EXCEPTION_VECTORS: usize = 32;

#[repr(align(16))]
struct IdtTable([u64; 512]);
static mut IDT: IdtTable = IdtTable([0; 512]);
static mut IDT_PTR: DtablePtr = DtablePtr { limit: 0, base: 0 };

/// Строит и загружает IDT: векторы 0..31 — информирующие стабы (печать
/// регистров + halt), 32..254 — линии IRQ + MSI-пул (диспетчер
/// irq::irq_vector_dispatch: хуки порта + пробуждение irq_wait-ждущих),
/// 255 — спурьё LAPIC: тихая заглушка.
pub fn load_idt() {
    // Указатели на стабы через fn-типы (прямой cast fn-item -> usize
    // даёт warning fn_to_numeric_cast).
    type StubFn = unsafe extern "C" fn() -> !;
    let stubs: [StubFn; EXCEPTION_VECTORS] = [
        stub0, stub1, stub2, stub3, stub4, stub5, stub6, stub7,
        stub8, stub9, stub10, stub11, stub12, stub13, stub14, stub15,
        stub16, stub17, stub18, stub19, stub20, stub21, stub22, stub23,
        stub24, stub25, stub26, stub27, stub28, stub29, stub30, stub31,
    ];
    // Стабы векторов 32..=254 (линии + MSI-пул); 255 — спурьё LAPIC,
    // молчит (stub_ignore).
    let irq_stubs: [StubFn; 223] = [
        irq32, irq33, irq34, irq35, irq36, irq37, irq38, irq39,
        irq40, irq41, irq42, irq43, irq44, irq45, irq46, irq47,
        irq48, irq49, irq50, irq51, irq52, irq53, irq54, irq55,
        irq56, irq57, irq58, irq59, irq60, irq61, irq62, irq63,
        irq64, irq65, irq66, irq67, irq68, irq69, irq70, irq71,
        irq72, irq73, irq74, irq75, irq76, irq77, irq78, irq79,
        irq80, irq81, irq82, irq83, irq84, irq85, irq86, irq87,
        irq88, irq89, irq90, irq91, irq92, irq93, irq94, irq95,
        irq96, irq97, irq98, irq99, irq100, irq101, irq102, irq103,
        irq104, irq105, irq106, irq107, irq108, irq109, irq110, irq111,
        irq112, irq113, irq114, irq115, irq116, irq117, irq118, irq119,
        irq120, irq121, irq122, irq123, irq124, irq125, irq126, irq127,
        irq128, irq129, irq130, irq131, irq132, irq133, irq134, irq135,
        irq136, irq137, irq138, irq139, irq140, irq141, irq142, irq143,
        irq144, irq145, irq146, irq147, irq148, irq149, irq150, irq151,
        irq152, irq153, irq154, irq155, irq156, irq157, irq158, irq159,
        irq160, irq161, irq162, irq163, irq164, irq165, irq166, irq167,
        irq168, irq169, irq170, irq171, irq172, irq173, irq174, irq175,
        irq176, irq177, irq178, irq179, irq180, irq181, irq182, irq183,
        irq184, irq185, irq186, irq187, irq188, irq189, irq190, irq191,
        irq192, irq193, irq194, irq195, irq196, irq197, irq198, irq199,
        irq200, irq201, irq202, irq203, irq204, irq205, irq206, irq207,
        irq208, irq209, irq210, irq211, irq212, irq213, irq214, irq215,
        irq216, irq217, irq218, irq219, irq220, irq221, irq222, irq223,
        irq224, irq225, irq226, irq227, irq228, irq229, irq230, irq231,
        irq232, irq233, irq234, irq235, irq236, irq237, irq238, irq239,
        irq240, irq241, irq242, irq243, irq244, irq245, irq246, irq247,
        irq248, irq249, irq250, irq251, irq252, irq253, irq254,
    ];
    let ignore: StubFn = stub_ignore;
    for i in 0..256 {
        let handler: usize = if i < EXCEPTION_VECTORS {
            stubs[i] as usize
        } else if i < 255 {
            irq_stubs[i - 32] as usize
        } else {
            ignore as usize // 255 — спурьё LAPIC: молча
        };
        // Запись: off_lo:16 | sel:16 | ist:8 | type:8 | off_mid:16 | off_hi:32 | rsv:32
        let h = handler as u64;
        let lo = (h & 0xFFFF)
            | ((KERNEL_CS as u64) << 16)
            | (0x8E << 40) // Present, interrupt gate, DPL=0, IST=0
            | ((h >> 16 & 0xFFFF) << 48);
        let hi = (h >> 32) & 0xFFFF_FFFF;
        unsafe {
            IDT.0[i * 2] = lo;
            IDT.0[i * 2 + 1] = hi;
        }
    }
    unsafe {
        IDT_PTR = DtablePtr {
            limit: (512 * 8 - 1) as u16,
            base: core::ptr::addr_of!(IDT).cast::<IdtTable>().cast::<u8>() as u64,
        };
        asm!("lidt [{}]", in(reg) &raw const IDT_PTR);
    }
}

/// Rust-обработчик исключения: #PF-хук (demand-paging, если заре-
/// гистрирован) → ФОЛТ-ЭНДПОИНТ (seL4/KeyKOS: доставка в юзерспейс,
/// см. crate::fault и kernel_base::ipc::fault — при успехе обработчик
/// НЕ ВОЗВРАЩАЕТСЯ, упавшая задача блокируется в ожидании FAULT_REPLY)
/// → фатальный дамп + останов. Возврат true — ТОЛЬКО для #PF,
/// устранённого зарегистрированным хуком: кадр восстанавливается,
/// исполнение продолжится на упавшей инструкции. Легитимных
/// неустранимых источников в ядре нет — любой неустранённый фат это
/// баг, который надо видеть целиком.
#[unsafe(no_mangle)]
extern "C" fn idt_c_handler(frame: &mut IntFrame) -> bool {
    // #PF: сначала шанс зарегистрированному хуку (demand-paging).
    if frame.nr == 14 {
        let cr2: u64 = unsafe {
            let v;
            asm!("mov {}, cr2", out(reg) v);
            v
        };
        let mut ctx = crate::irq::X86CpuContext {
            instruction_pointer: frame.rip as usize,
            stack_pointer: frame.rsp as usize,
        };
        if crate::irq::page_fault_dispatch(cr2 as usize, frame.err, &mut ctx) {
            // Хук мог подправить точку продолжения (ip/sp).
            frame.rip = ctx.instruction_pointer as u64;
            frame.rsp = ctx.stack_pointer as u64;
            return true;
        }
    }
    // Фолт-эндпоинт: доставка юзерспейс-обработчику. При успехе НЕ
    // ВОЗВРАЩАЕТСЯ (упавшая блокируется, управление — планировщику).
    // Отказ (нет обработчика/ресурсов/вектор недоставим) — фатальный
    // путь ниже, как до фолт-эндпоинтов.
    // SAFETY: контракт модуля — исключение, ядерный GS активен (стаб).
    if unsafe { crate::fault::user_fault_entry(frame) } {
        return true; // фактически недостижимо: user_fault_entry не возвращается
    }
    // ПОЛИТИКА ФАТАЛЬНОСТИ: фолт из ring3 БЕЗ доставимого обработчика
    // (нет keeper'а, вектор вне списка, реестры переполнены) убивает
    // ВИНОВНУЮ задачу и возвращает управление планировщику. Иначе ud2,
    // NULL-разыменование, #DB после popf или неканоничный RSP навсегда
    // останавливают CPU — полный DoS системы одним ring3-потоком.
    // Фатальный дамп+halt ниже — ТОЛЬКО для исключений ЯДРА (CS&3==0):
    // их кадр/стек ядерные, а ring3-атакующий на этот путь больше не
    // попадает (значит, дамп по RSP задачи больше не даёт ring3
    // примитив утечки памяти ядра на serial).
    // NMI/MC — аппаратные события (не вина задачи): фатальны даже из
    // ring3 (убивать невиновную задачу бессмысленно).
    if frame.cs & 3 == 3 && frame.nr != 2 && frame.nr != 18 {
        // SAFETY: контракт user_fault_entry (исключение, IF=0, ядерный GS).
        unsafe { crate::fault::kill_current_and_schedule() };
    }
    let name = match frame.nr {
        0 => "DE divide", 1 => "DB debug", 2 => "NMI", 3 => "BP int3",
        4 => "OF", 5 => "BR", 6 => "UD invalid-opcode", 7 => "NM no-FPU",
        8 => "DF double-fault", 10 => "TS", 11 => "NP", 12 => "SS",
        13 => "GP general", 14 => "PF page-fault", 16 => "MF x87",
        17 => "AC align", 18 => "MC", 19 => "XF simd", 21 => "CP", 29 => "VC",
        30 => "SX", _ => "??",
    };
    let cr2: u64 = unsafe {
        let v;
        asm!("mov {}, cr2", out(reg) v);
        v
    };
    crate::serial::write_str("\n=== EXCEPTION #");
    crate::serial::write_str(uxtostr(frame.nr));
    crate::serial::write_str(" ");
    crate::serial::write_str(name);
    crate::serial::write_str(" ===\n");
    crate::serial::write_str("RIP=");
    crate::serial::write_str(uxtostr(frame.rip));
    crate::serial::write_str(" CS=");
    crate::serial::write_str(uxtostr(frame.cs));
    crate::serial::write_str(" ERR=");
    crate::serial::write_str(uxtostr(frame.err));
    crate::serial::write_str(" CR2=");
    crate::serial::write_str(uxtostr(cr2));
    crate::serial::write_str("\nRSP=");
    crate::serial::write_str(uxtostr(frame.rsp));
    crate::serial::write_str(" RFLAGS=");
    crate::serial::write_str(uxtostr(frame.rflags));
    crate::serial::write_str("\nRAX=");
    crate::serial::write_str(uxtostr(frame.rax));
    crate::serial::write_str(" RBX=");
    crate::serial::write_str(uxtostr(frame.rbx));
    crate::serial::write_str(" RCX=");
    crate::serial::write_str(uxtostr(frame.rcx));
    crate::serial::write_str(" RDX=");
    crate::serial::write_str(uxtostr(frame.rdx));
    crate::serial::write_str("\nRSI=");
    crate::serial::write_str(uxtostr(frame.rsi));
    crate::serial::write_str(" RDI=");
    crate::serial::write_str(uxtostr(frame.rdi));
    crate::serial::write_str(" RBP=");
    crate::serial::write_str(uxtostr(frame.rbp));
    crate::serial::write_str("\nR8=");
    crate::serial::write_str(uxtostr(frame.r8));
    crate::serial::write_str(" R9=");
    crate::serial::write_str(uxtostr(frame.r9));
    crate::serial::write_str(" R10=");
    crate::serial::write_str(uxtostr(frame.r10));
    crate::serial::write_str(" R11=");
    crate::serial::write_str(uxtostr(frame.r11));
    crate::serial::write_str("\nR12=");
    crate::serial::write_str(uxtostr(frame.r12));
    crate::serial::write_str(" R13=");
    crate::serial::write_str(uxtostr(frame.r13));
    crate::serial::write_str(" R14=");
    crate::serial::write_str(uxtostr(frame.r14));
    crate::serial::write_str(" R15=");
    crate::serial::write_str(uxtostr(frame.r15));
    crate::serial::write_str("\n[STACK] ");
    // Первые 16 qword стека задачи: адрес возврата покажет, откуда прыжок.
    // Дамп ЗАЩИЩЁННЫЙ: RSP упавшей ring3-задачи может указывать ниже
    // замапленного стека (stack-probe ушёл в дыру) — чтение такого
    // адреса из обработчика даёт вложенный #PF и молчаливый завис
    // (поймано в QEMU). Перед чтением проверяем отображение страницы
    // обходом ТЕКУЩИХ таблиц (CR3 задачи — исключение его CR3 и не сменило).
    {
        let cr3: usize = unsafe {
            let v;
            asm!("mov {}, cr3", out(reg) v);
            v
        };
        let mut any = false;
        for i in 0..16 {
            let addr = frame.rsp as usize + i * 8;
            if crate::paging::translate_page(cr3, addr).is_none() {
                crate::serial::write_str(if any { " …" } else { "(unmapped)" });
                break;
            }
            // SAFETY: страница отображена (translate прошёл до листа).
            let v = unsafe { core::ptr::read_unaligned(addr as *const u64) };
            if i % 4 == 0 {
                crate::serial::write_str("\n       ");
            }
            crate::serial::write_str(uxtostr(v));
            crate::serial::write_str(" ");
            any = true;
        }

        // Примитивный бэктрейс: кадры не всегда хранят RBP-цепочку
        // (debug-сборка смешивает), поэтому СКАНИРУЕМ стек вверх и
        // печатаем все значения, попадающие в диапазон .text ядра —
        // это кандидаты в адреса возврата (внутренние — раньше).
        // Символизация — офлайн (addr2line по адресу из [BT]).
        crate::serial::write_str("\n[BT] ");
        let (text_lo, text_hi) = (
            core::ptr::addr_of!(__text_begin) as usize,
            core::ptr::addr_of!(__text_end) as usize,
        );
        let mut printed = 0usize;
        for i in 0..160 {
            let addr = frame.rsp as usize + i * 8;
            if crate::paging::translate_page(cr3, addr).is_none() {
                break;
            }
            // SAFETY: страница отображена (translate прошёл до листа).
            let v = unsafe { core::ptr::read_unaligned(addr as *const u64) } as usize;
            if (text_lo..text_hi).contains(&v) {
                crate::serial::write_str(uxtostr(v as u64));
                crate::serial::write_str(" ");
                printed += 1;
                if printed >= 24 {
                    break;
                }
            }
        }
        if printed == 0 {
            crate::serial::write_str("(нет .text-адресов в кадре)");
        }
    }
    crate::serial::write_str("\n(halted)\n");
    // В кольцо лога тоже — init-сервер (если жив) это увидит.
    kernel_base::kernel_log!(
        "EXCEPTION #{} {} rip={:#x} err={:#x} rsp={:#x} cr2={:#x}\n",
        frame.nr, name, frame.rip, frame.err, frame.rsp, cr2
    );
    loop {
        unsafe { asm!("hlt"); }
    }
}

/// HEX-вывод без fmt-аллокаций (обработчик исключения обязан быть
/// тривиальным — паника в панике не диагностируема).
fn uxtostr(v: u64) -> &'static str {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    static mut BUF: [u8; 19] = [b'0'; 19];
    let buf: &'static mut [u8; 19] = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    buf[0] = b'0';
    buf[1] = b'x';
    if v == 0 {
        buf[2] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..3]) };
    }
    let mut i = 2usize;
    let mut started = false;
    for shift in (0..16).rev() {
        let nib = ((v >> (shift * 4)) & 0xF) as usize;
        if nib != 0 || started || shift == 0 {
            buf[i] = HEX[nib];
            i += 1;
            started = true;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buf[..i]) }
}

// Макрос-генератор стабов: векторы с кодом ошибки CPU кладёт err сам,
// остальные получают фальшивый 0 — кадр единообразен.
macro_rules! idt_stub {
    ($name:ident, $n:expr, err) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> ! {
            naked_asm!(concat!("push ", stringify!($n)), "jmp idt_common");
        }
    };
    ($name:ident, $n:expr, noerr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> ! {
            naked_asm!("push 0", concat!("push ", stringify!($n)), "jmp idt_common");
        }
    };
}

idt_stub!(stub0, 0, noerr);
idt_stub!(stub1, 1, noerr);
idt_stub!(stub2, 2, noerr);
idt_stub!(stub3, 3, noerr);
idt_stub!(stub4, 4, noerr);
idt_stub!(stub5, 5, noerr);
idt_stub!(stub6, 6, noerr);
idt_stub!(stub7, 7, noerr);
idt_stub!(stub8, 8, err);
idt_stub!(stub9, 9, noerr);
idt_stub!(stub10, 10, err);
idt_stub!(stub11, 11, err);
idt_stub!(stub12, 12, err);
idt_stub!(stub13, 13, err);
idt_stub!(stub14, 14, err);
idt_stub!(stub15, 15, noerr);
idt_stub!(stub16, 16, noerr);
idt_stub!(stub17, 17, err);
idt_stub!(stub18, 18, noerr);
idt_stub!(stub19, 19, noerr);
idt_stub!(stub20, 20, noerr);
idt_stub!(stub21, 21, noerr);
idt_stub!(stub22, 22, noerr);
idt_stub!(stub23, 23, noerr);
idt_stub!(stub24, 24, noerr);
idt_stub!(stub25, 25, noerr);
idt_stub!(stub26, 26, noerr);
idt_stub!(stub27, 27, noerr);
idt_stub!(stub28, 28, noerr);
idt_stub!(stub29, 29, err);
idt_stub!(stub30, 30, err);
idt_stub!(stub31, 31, noerr);

/// Заглушка для векторов 96..255: тихий iretq.
#[unsafe(naked)]
unsafe extern "C" fn stub_ignore() -> ! {
    naked_asm!("iretq");
}

/// Общий хвост IDT-стабов исключений: сохраняет GPR, зовёт
/// Rust-обработчик. Кадр (низ→верх): [GPR x15][nr][err][rip][cs]
/// [rflags][rsp][ss]. Обработчик возвращает bool в AL: true — фат
/// устранён зарегистрированным хуком (#PF: demand-paging), кадр
/// восстанавливается и исполнение продолжается; false — ud2 (фатальный
/// путь обработчика уже напечатал диагностику и остановил машину).
/// Успешная фолт-доставка (crate::fault) из обработчика не
/// возвращается вовсе — задача покидается через return_to_scheduler
/// с ядерным GS (обратный swapgs не нужен).
///
/// Исключение может прийти из ring3 (GS base пользовательский, =0):
/// как в irq_common, делается УСЛОВНЫЙ swapgs по CPL сегмента CS кадра.
/// Офсет CS — 144 (15*8 GPR + 8 nr + 8 err + 8 rip; в irq_common без
/// кода ошибки CS на 136 — раскладки кадров РАЗЛИЧАЮТСЯ, офсеты не
/// синхронизированы намеренно). Без swapgs фолт-путь ядра (чтение
/// per-CPU через GS) паникует «GS base вне per-CPU» (см.
/// syscall_return — поймано в QEMU). Перед iretq — обратный swapgs
/// (только если входили из ring3).
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn idt_common() -> ! {
    naked_asm!(
        "push rdi", "push rsi", "push rdx", "push rcx", "push rax",
        "push rbx", "push rbp", "push r8", "push r9", "push r10",
        "push r11", "push r12", "push r13", "push r14", "push r15",
        // Пришли из ring3? (CS кадра: +144 — у исключений ЕСТЬ код ошибки)
        "mov rax, [rsp + 144]",
        "test al, 3",
        "jz 1f",
        "swapgs",                       // GS ← ядерный per-CPU
        // FPU/SSE: fxsave только для ring3-входов (как в irq_common).
        "mov rbx, gs:[{fpu}]",
        "fxsave64 [rbx]",
        "1:",
        "mov rdi, rsp",
        "call idt_c_handler",
        "test al, al",
        "jz 3f",
        // Возврат в ring3 — вернуть пользовательский GS (если входили из него).
        "mov rax, [rsp + 144]",
        "test al, 3",
        "jz 4f",
        // FPU/SSE: вернуть пользовательское состояние ДО обратного swapgs
        // (gs:[OFF_FPU] требует ядерного GS). Для ядерного входа (#PF
        // demand-paging в ядре) скретч не наш — не трогаем.
        "mov rbx, gs:[{fpu}]",
        "fxrstor64 [rbx]",
        "swapgs",
        "4:",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rbp", "pop rbx", "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
        "add rsp, 16",              // nr + err
        "iretq",
        "3:",
        "ud2",
        fpu = const OFF_FPU,
    )
}

// ─── IRQ-векторы 32..95 (линии 0..63) ───────────────────────────────────────
// Индивидуальные стабы: CPU не кладёт номер внешнего прерывания на
// стек — знает только стаб. Хвост irq_common сохраняет GPR, зовёт
// irq_vector_dispatch (линия = вектор − 32) и ВОЗВРАЩАЕТСЯ iretq:
// IRQ-обработка всегда продолжает прерванный поток (WaitIrq будит
// задачи, а фатальные исключения идут через idt_common).

macro_rules! irq_stub {
    ($name:ident, $n:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> ! {
            naked_asm!(concat!("push ", stringify!($n)), "jmp irq_common");
        }
    };
}

irq_stub!(irq32, 32); irq_stub!(irq33, 33); irq_stub!(irq34, 34); irq_stub!(irq35, 35);
irq_stub!(irq36, 36); irq_stub!(irq37, 37); irq_stub!(irq38, 38); irq_stub!(irq39, 39);
irq_stub!(irq40, 40); irq_stub!(irq41, 41); irq_stub!(irq42, 42); irq_stub!(irq43, 43);
irq_stub!(irq44, 44); irq_stub!(irq45, 45); irq_stub!(irq46, 46); irq_stub!(irq47, 47);
irq_stub!(irq48, 48); irq_stub!(irq49, 49); irq_stub!(irq50, 50); irq_stub!(irq51, 51);
irq_stub!(irq52, 52); irq_stub!(irq53, 53); irq_stub!(irq54, 54); irq_stub!(irq55, 55);
irq_stub!(irq56, 56); irq_stub!(irq57, 57); irq_stub!(irq58, 58); irq_stub!(irq59, 59);
irq_stub!(irq60, 60); irq_stub!(irq61, 61); irq_stub!(irq62, 62); irq_stub!(irq63, 63);
irq_stub!(irq64, 64); irq_stub!(irq65, 65); irq_stub!(irq66, 66); irq_stub!(irq67, 67);
irq_stub!(irq68, 68); irq_stub!(irq69, 69); irq_stub!(irq70, 70); irq_stub!(irq71, 71);
irq_stub!(irq72, 72); irq_stub!(irq73, 73); irq_stub!(irq74, 74); irq_stub!(irq75, 75);
irq_stub!(irq76, 76); irq_stub!(irq77, 77); irq_stub!(irq78, 78); irq_stub!(irq79, 79);
irq_stub!(irq80, 80); irq_stub!(irq81, 81); irq_stub!(irq82, 82); irq_stub!(irq83, 83);
irq_stub!(irq84, 84); irq_stub!(irq85, 85); irq_stub!(irq86, 86); irq_stub!(irq87, 87);
irq_stub!(irq88, 88); irq_stub!(irq89, 89); irq_stub!(irq90, 90); irq_stub!(irq91, 91);
irq_stub!(irq92, 92); irq_stub!(irq93, 93); irq_stub!(irq94, 94); irq_stub!(irq95, 95);
irq_stub!(irq96, 96);irq_stub!(irq97, 97);irq_stub!(irq98, 98);irq_stub!(irq99, 99);
irq_stub!(irq100, 100);irq_stub!(irq101, 101);irq_stub!(irq102, 102);irq_stub!(irq103, 103);
irq_stub!(irq104, 104);irq_stub!(irq105, 105);irq_stub!(irq106, 106);irq_stub!(irq107, 107);
irq_stub!(irq108, 108);irq_stub!(irq109, 109);irq_stub!(irq110, 110);irq_stub!(irq111, 111);
irq_stub!(irq112, 112);irq_stub!(irq113, 113);irq_stub!(irq114, 114);irq_stub!(irq115, 115);
irq_stub!(irq116, 116);irq_stub!(irq117, 117);irq_stub!(irq118, 118);irq_stub!(irq119, 119);
irq_stub!(irq120, 120);irq_stub!(irq121, 121);irq_stub!(irq122, 122);irq_stub!(irq123, 123);
irq_stub!(irq124, 124);irq_stub!(irq125, 125);irq_stub!(irq126, 126);irq_stub!(irq127, 127);
irq_stub!(irq128, 128);irq_stub!(irq129, 129);irq_stub!(irq130, 130);irq_stub!(irq131, 131);
irq_stub!(irq132, 132);irq_stub!(irq133, 133);irq_stub!(irq134, 134);irq_stub!(irq135, 135);
irq_stub!(irq136, 136);irq_stub!(irq137, 137);irq_stub!(irq138, 138);irq_stub!(irq139, 139);
irq_stub!(irq140, 140);irq_stub!(irq141, 141);irq_stub!(irq142, 142);irq_stub!(irq143, 143);
irq_stub!(irq144, 144);irq_stub!(irq145, 145);irq_stub!(irq146, 146);irq_stub!(irq147, 147);
irq_stub!(irq148, 148);irq_stub!(irq149, 149);irq_stub!(irq150, 150);irq_stub!(irq151, 151);
irq_stub!(irq152, 152);irq_stub!(irq153, 153);irq_stub!(irq154, 154);irq_stub!(irq155, 155);
irq_stub!(irq156, 156);irq_stub!(irq157, 157);irq_stub!(irq158, 158);irq_stub!(irq159, 159);
irq_stub!(irq160, 160);irq_stub!(irq161, 161);irq_stub!(irq162, 162);irq_stub!(irq163, 163);
irq_stub!(irq164, 164);irq_stub!(irq165, 165);irq_stub!(irq166, 166);irq_stub!(irq167, 167);
irq_stub!(irq168, 168);irq_stub!(irq169, 169);irq_stub!(irq170, 170);irq_stub!(irq171, 171);
irq_stub!(irq172, 172);irq_stub!(irq173, 173);irq_stub!(irq174, 174);irq_stub!(irq175, 175);
irq_stub!(irq176, 176);irq_stub!(irq177, 177);irq_stub!(irq178, 178);irq_stub!(irq179, 179);
irq_stub!(irq180, 180);irq_stub!(irq181, 181);irq_stub!(irq182, 182);irq_stub!(irq183, 183);
irq_stub!(irq184, 184);irq_stub!(irq185, 185);irq_stub!(irq186, 186);irq_stub!(irq187, 187);
irq_stub!(irq188, 188);irq_stub!(irq189, 189);irq_stub!(irq190, 190);irq_stub!(irq191, 191);
irq_stub!(irq192, 192);irq_stub!(irq193, 193);irq_stub!(irq194, 194);irq_stub!(irq195, 195);
irq_stub!(irq196, 196);irq_stub!(irq197, 197);irq_stub!(irq198, 198);irq_stub!(irq199, 199);
irq_stub!(irq200, 200);irq_stub!(irq201, 201);irq_stub!(irq202, 202);irq_stub!(irq203, 203);
irq_stub!(irq204, 204);irq_stub!(irq205, 205);irq_stub!(irq206, 206);irq_stub!(irq207, 207);
irq_stub!(irq208, 208);irq_stub!(irq209, 209);irq_stub!(irq210, 210);irq_stub!(irq211, 211);
irq_stub!(irq212, 212);irq_stub!(irq213, 213);irq_stub!(irq214, 214);irq_stub!(irq215, 215);
irq_stub!(irq216, 216);irq_stub!(irq217, 217);irq_stub!(irq218, 218);irq_stub!(irq219, 219);
irq_stub!(irq220, 220);irq_stub!(irq221, 221);irq_stub!(irq222, 222);irq_stub!(irq223, 223);
irq_stub!(irq224, 224);irq_stub!(irq225, 225);irq_stub!(irq226, 226);irq_stub!(irq227, 227);
irq_stub!(irq228, 228);irq_stub!(irq229, 229);irq_stub!(irq230, 230);irq_stub!(irq231, 231);
irq_stub!(irq232, 232);irq_stub!(irq233, 233);irq_stub!(irq234, 234);irq_stub!(irq235, 235);
irq_stub!(irq236, 236);irq_stub!(irq237, 237);irq_stub!(irq238, 238);irq_stub!(irq239, 239);
irq_stub!(irq240, 240);irq_stub!(irq241, 241);irq_stub!(irq242, 242);irq_stub!(irq243, 243);
irq_stub!(irq244, 244);irq_stub!(irq245, 245);irq_stub!(irq246, 246);irq_stub!(irq247, 247);
irq_stub!(irq248, 248);irq_stub!(irq249, 249);irq_stub!(irq250, 250);irq_stub!(irq251, 251);
irq_stub!(irq252, 252);irq_stub!(irq253, 253);irq_stub!(irq254, 254);

/// Хвост IRQ-стабов. Кадр (низ→верх): [GPR x15][nr][rip][cs][rflags]
/// [rsp][ss] — у внешних прерываний CPU НЕ кладёт код ошибки, стаб
/// кладёт только номер вектора. IRQ может прийти и в ring3 (GS base в
/// этот момент пользовательский) — для чтения per-CPU блока делается
/// условный swapgs по CPL сегмента CS кадра. Диспетчеру передаётся И
/// кадр (rsi): если тик таймера выбрал преемпцию ring3-задачи, хвост
/// диспетчера сохранит кадр в её TCB и уйдёт в следующую задачу БЕЗ
/// возврата сюда (iretq — только для продолжения прерванного потока).
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn irq_common() -> ! {
    naked_asm!(
        "push rdi", "push rsi", "push rdx", "push rcx", "push rax",
        "push rbx", "push rbp", "push r8", "push r9", "push r10",
        "push r11", "push r12", "push r13", "push r14", "push r15",
        // Пришли из ring3? (CS кадра: +136 = 15*8 GPR + 8 nr + 8 rip)
        "mov rax, [rsp + 136]",
        "test al, 3",
        "jz 1f",
        "swapgs",                       // GS ← ядерный per-CPU
        // FPU/SSE: только для ring3-входов (при ядерном входе скретч
        // может хранить ещё живое fxsave-состояние сисколла — трогать
        // нельзя). rbx уже в кадре — безопасный скретч. При преемпции
        // сюда-путь не дойдёт (диспетчер уйдёт в stash_fpu_to_tcb + hook).
        "mov rbx, gs:[{fpu}]",
        "fxsave64 [rbx]",
        "1:",
        "mov rdi, [rsp + 120]",         // nr (вектор)
        "mov rsi, rsp",                 // кадр IrqFrame (низ кадра)
        "call {dispatch}",              // lctl берёт сам, через GS base
        "mov rax, [rsp + 136]",
        "test al, 3",
        "jz 2f",
        // FPU/SSE: вернуть пользовательское состояние (GS ещё ядерный;
        // rbx ещё не восстановлен — скретч). Пропуск для ядерного входа:
        // скретч не наш (см. вход).
        "mov rbx, gs:[{fpu}]",
        "fxrstor64 [rbx]",
        "swapgs",                       // GS ← пользовательский
        "2:",
        // Восстановление: 15 GPR + nr (кода ошибки нет), iretq.
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rbp", "pop rbx", "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
        "add rsp, 8",
        "iretq",
        dispatch = sym crate::irq::irq_vector_dispatch_erased,
        fpu = const OFF_FPU,
    )
}

// ─── Преемпция ring3 (тик таймера → хвост IRQ-диспетчера) ────────────────────

/// Кадр внешнего прерывания → ПОЛНЫЙ слот возобновления TCB
/// (RESUME_WORDS слов). Раскладка тождественна сисколл-кадру SysFrame,
/// НО: у SYSCALL регистры RCX/R11 портятся самой инструкцией (там лежат
/// RIP/RFLAGS — кадр их хранит в своих полях), а IRQ сохраняет РЕАЛЬНЫЕ
/// пользовательские RCX/R11 — они уходят в расширение фолт-доставки
/// (слова 18/19, читает resume_from_frame). Слова 20..24 — нули
/// (RESUME_WORDS=24 > 20 используемых).
pub(crate) fn irq_frame_resume_words(frame: &IrqFrame) -> [u64; kernel_base::task::tcb::RESUME_WORDS] {
    let mut w = [0u64; kernel_base::task::tcb::RESUME_WORDS];
    w[0] = frame.rdi;
    w[1] = frame.rsi;
    w[2] = frame.rdx;
    w[3] = frame.rax;
    w[4] = frame.rbx;
    w[5] = frame.rbp;
    w[6] = frame.r8;
    w[7] = frame.r9;
    w[8] = frame.r10;
    w[9] = frame.r12;
    w[10] = frame.r13;
    w[11] = frame.r14;
    w[12] = frame.r15;
    w[13] = frame.rip; // SysFrame.rip (+104)
    w[14] = frame.cs;
    w[15] = frame.rflags;
    w[16] = frame.rsp;
    w[17] = frame.ss;
    w[18] = frame.rcx; // SYSFRAME_RCX_WORD: реальные RCX/R11 прерванной задачи
    w[19] = frame.r11; // SYSFRAME_R11_WORD
    w
}

/// Хвост преемпции (зывается из irq::irq_vector_dispatch_erased после
/// полного прохождения диспетчеризации — хуков, пробуждения ждущих, EOI):
/// если тик таймера в ЭТОМ ЖЕ прерывании выбрал другую задачу, а
/// прерванный контекст — ring3, кадр уходит в TCB вытесненной задачи и
/// управление передаётся выбранной (НЕ ВОЗВРАЩАЕТСЯ — тот же путь, что
/// уступка внутри сисколла: hook(next) → enter_task порта).
///
/// Почему только ring3: тик, заставший ядро (сисколл/цикл планировщика),
/// НЕ крутит карусель вовсе (ротация state планировщика разъехалась бы с
/// семантикой assign_current_task_to_wait/unregister_task, которые
/// оперируют «текущей» серединой сисколла); такие тики просто не
/// отнимают квант — вытеснение случится на первом тике в ring3 либо
/// задача уступит/уснёт сама.
///
/// GS/CR3-контракт: идентичен пути уступки — swapgs уже сделан стабом
/// (GS ядерный), return_to_scheduler внутри enter_task сам переключит
/// CR3 и стек; брошенный exception-стек перезапишется следующим входом
/// из ring3 (TSS.RSP0).
pub(crate) fn irq_preempt_tail(frame: &mut IrqFrame) {
    // Двойная проверка CPL: хвост зовётся только для ring3-входов.
    if frame.cs & 3 != 3 {
        return;
    }
    let lctl = X86Backend::get_local_base();
    let Some(next) = lctl.take_preempt_next() else {
        return; // обычный IRQ: прерванный поток продолжается (iretq)
    };
    // Карусель могла оставить текущую (одна живая) — продолжаем без смены.
    let Some(cur) = lctl.current_task_cap_id() else {
        return;
    };
    if next == cur {
        return;
    }
    // Кадр — реальное CPU-состояние (каноничен по построению); гард
    // страховочный: нарушение означало бы порчу стаба — честно видим.
    if !is_user_canonical(frame.rip) || !is_user_canonical(frame.rsp) {
        kernel_base::kernel_log!(
            "preempt: неканоничный кадр ring3 rip={:#x} rsp={:#x} — вытеснение отменено\n",
            frame.rip,
            frame.rsp
        );
        return;
    }
    // Кадр вытесненной задачи — в её TCB (возобновление с места тика);
    // FPU/SSE — тоже (fxsave стаба в скретче, копия — сюда).
    if let Some(tcb) = lctl.get_current_task() {
        tcb.save_resume(&irq_frame_resume_words(frame));
        stash_fpu_to_tcb(lctl);
    }
    kernel_base::task::stats::count_preempt(lctl);
    // Управление — выбранной планировщиком задаче (не возвращается).
    match switch_hook() {
        Some(hook) => hook(next),
        None => panic!("cswitch: хук переключения не установлен (set_switch_hook)"),
    }
}

// ─── SYSCALL entry ───────────────────────────────────────────────────────────

/// Кадр сисколла (раскладка syscall_entry; RSP при `mov rdi, rsp`).
/// Порядок полей = порядок памяти (низ→верх) — push идёт в обратном.
#[repr(C)]
pub struct SysFrame {
    pub rdi: u64,   // +0
    pub rsi: u64,   // +8
    pub rdx: u64,   // +16
    pub rax: u64,   // +24
    pub rbx: u64,   // +32
    pub rbp: u64,   // +40
    pub r8: u64,    // +48
    pub r9: u64,    // +56
    pub r10: u64,   // +64
    pub r12: u64,   // +72
    pub r13: u64,   // +80
    pub r14: u64,   // +88
    pub r15: u64,   // +96
    pub rip: u64,   // +104
    pub cs: u64,    // +112
    pub rflags: u64, // +120
    pub rsp: u64,   // +128
    pub ss: u64,    // +136
}

/// Точка входа SYSCALL (LSTAR). Кладёт ручной iret-кадр на СВОЙ
/// per-CPU ядерный стек сисколлов (gs:[OFF_KSTACK] — после swapgs),
/// сохраняет GPR и зовёт Rust-диспетчер.
///
/// ABI (cintos_user::abi): RAX=номер, RDI/RSI/RDX/R10/R8/R9=аргументы;
/// SYSCALL кладёт RCX=RIP пользователя, R11=RFLAGS пользователя.
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        // IF гасим ЗДЕСЬ, первым делом: FMASK тоже сбрасывает его, но
        // это страховка от «весь путь сисколла с включёнными
        // прерываниями» (класс багов: тик посреди удержания лока).
        "cli",
        "swapgs",
        // Пользовательский RSP — ДО смены стека (GS уже ядерный).
        "mov gs:[{user_rsp}], rsp",
        "mov rsp, gs:[{kstack}]",
        // Ручной кадр (восстановление через SYSRET по rdi-оффсетам).
        "push 0x23",                      // SS
        "push gs:[{user_rsp}]",           // RSP пользователя
        "push r11",                       // RFLAGS
        "push 0x2B",                      // CS (USER_CS|3 — см. правило SYSRET)
        "push rcx",                       // RIP
        // GPR (порядок обратен полям SysFrame)
        "push r15", "push r14", "push r13", "push r12",
        "push r10", "push r9", "push r8", "push rbp",
        "push rbx", "push rax", "push rdx", "push rsi", "push rdi",
        // FPU/SSE: fxsave в per-CPU скретч. ПОСЛЕ сохранения кадра:
        // все 15 GPR уже в памяти, регистр-скретч (rbx) можно портить —
        // свободных регистров до этого нет (кадр хранит ВСЕ GPR, а
        // RCX/R11 заняты RIP/RFLAGS). До любого Rust-кода: компилятор
        // вправе генерировать SSE — на входе в Rust пользовательские
        // XMM уже спасены. Возврат: syscall_return (fxrstor отсюда) или
        // stash_fpu_to_tcb (копия в TCB при переключении задач).
        "mov rbx, gs:[{fpu}]",
        "fxsave64 [rbx]",
        // 5*8 + 13*8 = 144 байта от 16-выровненного TOP: RSP%16==0 —
        // вызов по SysV корректен (callee видит rsp%16==8).
        "mov rdi, rsp",
        "call syscall_frame_dispatch",
        "ud2",
        user_rsp = const OFF_USER_RSP,
        kstack = const OFF_KSTACK,
        fpu = const OFF_FPU,
    )
}

/// Число u64-слов в кадре сисколла (repr(C), 18 полей u64 — раскладка
/// идентична [u64; SYSFRAME_WORDS]). Единый формат обмена с TCB-слотом
/// возобновления (kernel_base::task::tcb::RESUME_WORDS >= SYSFRAME_WORDS).
pub const SYSFRAME_WORDS: usize = core::mem::size_of::<SysFrame>() / 8;
const _: () = assert!(core::mem::size_of::<SysFrame>().is_multiple_of(8));
const _: () = assert!(SYSFRAME_WORDS <= kernel_base::task::tcb::RESUME_WORDS);
/// Слово RAX в кадре (смещение 24) — для IPC-патча кода доставки.
pub const SYSFRAME_RAX_WORD: usize = 3;
/// Расширение фолт-доставки (crate::fault): SysFrame НЕ хранит RCX/R11
/// (SYSCALL ими портится — ABI). Исключение их СОХРАНЯЕТ: упавшая задача
/// кладёт их в слова 18/19 слота возобновления (за пределами
/// SYSFRAME_WORDS), а resume_from_frame восстанавливает — повтор
/// упавшей инструкции обязан видеть ВСЕ регистры. Для обычного
/// сисколл-кадра слова — нули (безвредно: RCX/R11 и так портятся).
pub const SYSFRAME_RCX_WORD: usize = 18;
pub const SYSFRAME_R11_WORD: usize = 19;
const _: () =
    assert!(SYSFRAME_R11_WORD < kernel_base::task::tcb::RESUME_WORDS);

/// Каноничность НИЖНЕЙ (пользовательской) половины: всё, что выше —
/// ядерные отображения; возврат в ring3 туда запрещён (SYSRET с
/// неканоничным RCX = #GP в ring0 на пользовательском стеке — класс
/// SYSRET-уязвимостей; все гейты IDT IST=0).
#[inline]
fn is_user_canonical(v: u64) -> bool {
    (v as usize) < kernel_base::traits::memory::USER_SPACE_LIMIT
}

/// Кадр -> слова слота возобновления (битовое представление тождественно:
/// repr(C)-структура из u64-полей подряд).
fn frame_words(frame: &SysFrame) -> [u64; SYSFRAME_WORDS] {
    // SAFETY: чтение тех же байтов другим указателем POD-типа той же
    // раскладки (assert размера выше).
    unsafe { core::ptr::read(frame as *const SysFrame as *const [u64; SYSFRAME_WORDS]) }
}

/// FPU-скретч ТЕКУЩЕГО ядра (Rust-пути: bounce-копия перед fxrstor в
/// dispatch_user, stash_fpu_to_tcb). Указатель берётся из fixed-поля
/// (gs:[OFF_FPU] — тем же путём, что и стабы).
fn current_fpu_scratch() -> &'static mut FpuScratch {
    let Some(slot) = gs_base_slot() else {
        panic!("cswitch: FPU-скретч без per-CPU GS base (ранний бут?)");
    };
    // SAFETY: слот закреплён за текущим ядром (gs_base_slot).
    let area = unsafe { per_cpu_area(slot) }.expect("слот в диапазоне по построению");
    let ptr = area.fixed.fpu_scratch as *mut FpuScratch;
    assert!(
        !ptr.is_null(),
        "cswitch: FPU-скретч слота не настроен (setup_cpu_area)"
    );
    // SAFETY: указатель из области своего слота (16-выровнен по построению).
    unsafe { &mut *ptr }
}

/// Складывает fxsave-состояние из per-CPU скретча в FPU-область TCB
/// уходящей задачи. Вызывается в путях переключения (сисколл-свитч,
/// IRQ-преемпция, фолт-доставка) РЯДОМ с save_resume: скретч будет
/// перезаписан следующим входом из ring3, а состояние задачи обязано
/// пережить переключение (fxrstor при её следующем входе).
pub(crate) fn stash_fpu_to_tcb(lctl: &LocalKernelCTL<crate::paging::X86Umap>) {
    let Some(tcb) = lctl.get_current_task() else {
        return; // задачи нет (self-exit/ранний бут) — сохранять нечего
    };
    let scratch = current_fpu_scratch();
    // SAFETY: задача уходит с CPU (единственный легальный момент записи
    // её FPU-области); источник — скретч ЭТОГО же ядра (512 Б, валиден).
    unsafe { tcb.fpu_area().store_raw(scratch.0.as_ptr()) };
}

/// Хук входа в задачу, выбранную планировщиком (ставит фронтенд порта —
/// kernel_limine владеет KernelCTL/TaskManager). Вызывается диспетчером
/// сисколлов ПОСЛЕ сохранения кадра уступившей задачи в её TCB.
/// Обязана не возвращаться: вход в следующую задачу или возврат в цикл
/// планировщика.
pub type SwitchHook = fn(next_task_cap_id: u64) -> !;

static mut SWITCH_HOOK: Option<SwitchHook> = None;

/// Регистрирует хук переключения (фронтенд порта — до первого входа
/// в задачу).
pub fn set_switch_hook(hook: SwitchHook) {
    // Rust-2024: static mut — только сырые указатели.
    let slot: *mut Option<SwitchHook> = core::ptr::addr_of_mut!(SWITCH_HOOK);
    unsafe { slot.write(Some(hook)) };
}

fn switch_hook() -> Option<SwitchHook> {
    let slot: *const Option<SwitchHook> = core::ptr::addr_of!(SWITCH_HOOK);
    unsafe { slot.read() }
}

/// Rust-диспетчер сисколла: вызывает домен, затем решает — SYSRET в ту
/// же задачу, переключение на выбранную планировщиком или выход в цикл
/// планировщика (self-exit / все уснули).
#[unsafe(no_mangle)]
extern "C" fn syscall_frame_dispatch(frame: *mut SysFrame) -> ! {
    let frame = unsafe { &mut *frame };
    let lctl = X86Backend::get_local_base();
    let args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    let ret = dispatch_syscall(lctl, frame.rax as usize, &args);
    frame.rax = ret;

    // ── Кто должен исполняться теперь? ──
    // Планировщик мог выбрать другую задачу (yield поставил следующую,
    // текущая ушла в wait-очередь) — тогда кадр текущей уходит в её TCB
    // (слот возобновления), а управление — выбранной задаче. Совпадение
    // (обычный сисколл) — SYSRET в ту же задачу. Self-exit — цикл.
    let Some(cur_id) = lctl.current_task_cap_id() else {
        // Self-exit: возвращаться в ring3 некуда.
        // SAFETY: naked-переход на стек планировщика; контракт модуля.
        #[allow(unused_unsafe)]
        unsafe {
            return_to_scheduler()
        }
    };

    let sched_cur = lctl.scheduler_current_task();
    if sched_cur == Some(cur_id) {
        // SYSRET-ГАРД: RIP/RSP пользователя обязаны быть каноничной
        // нижней половиной. SYSCALL сам даёт каноничный RCX (адрес
        // инструкции), но кадр — общая структура расширений порта;
        // неканоничный возврат = #GP в ring0 на ПОЛЬЗОВАТЕЛЬСКОМ стеке
        // (все гейты IDT IST=0). Виновная задача убивается — система
        // продолжает планирование.
        if !is_user_canonical(frame.rip) || !is_user_canonical(frame.rsp) {
            kernel_base::kernel_log!(
                "kill: неканоничный syscall-кадр rip={:#x} rsp={:#x}\n",
                frame.rip,
                frame.rsp
            );
            // SAFETY: сисколл-контекст, ядерный GS активен, локов не держим.
            unsafe { crate::fault::kill_current_and_schedule() };
        }
        // Обычный сисколл: задача продолжает.
        // SAFETY: контракт модуля (кадр на сисколл-стеке).
        #[allow(unused_unsafe)]
        unsafe {
            syscall_return(frame)
        }
    }

    // Текущая уступила/уснула: кадр — в её TCB (возобновление с места
    // остановки, а не с точки входа). TCB жив: destroy чистит ОБА поля
    // lctl (id и указатель) до нашего сведения — раз id был Some, жив и
    // указатель. FPU/SSE — тоже в TCB (скретч перезапишется следующим
    // SYSCALL; состояние задачи обязано пережить переключение).
    if let Some(tcb) = lctl.get_current_task() {
        tcb.save_resume(&frame_words(frame));
        stash_fpu_to_tcb(lctl);
    }

    match sched_cur {
        Some(next_id) => match switch_hook() {
            Some(hook) => hook(next_id),
            // Проводка порта сломана — честная паника (ловится на
            // первом же yield в отладочном прогоне).
            None => panic!("cswitch: хук переключения не установлен (set_switch_hook)"),
        },
        None => {
            // Все задачи уснули: выходим в цикл планировщика (idle-опрос;
            // пробуждённая задача подхватится с возобновлением кадра).
            lctl.clear_current_task();
            // SAFETY: naked-переход на стек планировщика.
            #[allow(unused_unsafe)]
            unsafe {
                return_to_scheduler()
            }
        }
    }
}

/// Возврат в ring3 через SYSRET. Кадр читается по RDI (вызван обычным
/// `call`, стек диспetchера сверху кадра — pops недопустимы).
#[unsafe(naked)]
unsafe extern "C" fn syscall_return(_frame: *mut SysFrame) -> ! {
    naked_asm!(
        // FPU/SSE: вернуть пользовательское состояние из скретча (fxsave
        // syscall_entry). GS ещё ядерный — gs:[OFF_FPU] валиден; rax —
        // скретч (ниже перезаписывается из кадра). До загрузки GPR:
        // fxrstor GPR не трогает.
        "mov rax, gs:[{fpu}]",
        "fxrstor64 [rax]",
        // Порядок: сначала всё, что читает старый RDI, последним —
        // смена RSP; rdi восстанавливается уже после (источник ещё
        // валиден — перезапись rsp его не трогает).
        "mov rcx, [rdi + 104]",   // RIP пользователя
        "mov r11, [rdi + 120]",   // RFLAGS пользователя
        "mov rax, [rdi + 24]",
        "mov rbx, [rdi + 32]",
        "mov rbp, [rdi + 40]",
        "mov r8,  [rdi + 48]",
        "mov r9,  [rdi + 56]",
        "mov r10, [rdi + 64]",
        "mov r12, [rdi + 72]",
        "mov r13, [rdi + 80]",
        "mov r14, [rdi + 88]",
        "mov r15, [rdi + 96]",
        "mov rsi, [rdi + 8]",
        "mov rdx, [rdi + 16]",
        "mov rsp, [rdi + 128]",  // RSP пользователя
        "mov rdi, [rdi + 0]",    // последним: источник по старому rdi
        // Окно swapgs→sysretq обязано идти с IF=0 ((cli)): тик IRQ здесь
        // видит КАДР с ядерным CS → стаб НЕ делает swapgs → обработчик
        // работает с пользовательским GS (=0) → паника «GS base вне
        // per-CPU» (поймано в QEMU: первый тик PIT попадал в окно).
        // SYSRET восстанавливает RFLAGS из R11 (IF пользователя).
        "cli",
        "swapgs",
        "sysretq",
        fpu = const OFF_FPU,
    )
}

/// Возврат в цикл планировщика: CR3 ← gs:[OFF_ROOT], стек →
/// gs:[OFF_SCHED_STACK], jmp на gs:[OFF_SCHED_LOOP]. Оба стека (текущий
/// сисколловый и заброшенный) более не используются — цикл стартует с
/// чистого стека, инвариантов «на середине итерации» у него нет.
///
/// Публичен: хук переключения порта использует его как путь отказа
/// (выбранная задача исчезла/без таблиц — вернуть управление циклу).
///
/// # Safety
/// Naked-функция: обязана вызываться только из ядерного контекста с
/// загруженным ядерным GS base (после syscall_entry swapgs); бросает
/// текущий стек (кадр сисколла покидается без восстановления).
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn return_to_scheduler() -> ! {
    naked_asm!(
        "mov rax, gs:[{root}]",
        "mov cr3, rax",
        "mov rsp, gs:[{stack}]",
        "xor ebp, ebp",
        "mov rax, gs:[{loop}]",
        "jmp rax",
        root = const OFF_ROOT,
        stack = const OFF_SCHED_STACK,
        loop = const OFF_SCHED_LOOP,
    )
}

/// Первый вход в задачу: CR3 ← таблица задачи, swapgs, iretq в ring3.
///
/// После вызова ядро не получает управление, пока задача не сделает
/// SYSCALL (или не упадёт по исключению — см. IDT).
///
/// `fpu` — FPU-область TCB ([`kernel_base::task::tcb::FpuArea`]; для
/// новой задачи — шаблон масок): копируется в per-CPU скретч и
/// восстанавливается оттуда (FXRSTOR требует 16-выровненный операнд —
/// TCB-область гарантирует лишь 8). До смены CR3: TCB — ядерная память
/// (верхняя половина), ядерный CR3 её мапит гарантированно.
pub fn dispatch_user(task_cr3: usize, entry: usize, user_rsp: usize, fpu: *mut u8) -> ! {
    // Bounce: область задачи → per-CPU скретч (16-выровнен, см. FpuScratch).
    let scratch = current_fpu_scratch().0.as_mut_ptr();
    // SAFETY: обе области живы на 512 Б; не пересекаются (TCB-слэб vs
    // per-CPU статика); задача только создаётся — никто не читает FPU.
    unsafe {
        core::ptr::copy_nonoverlapping(fpu.cast::<u8>(), scratch, kernel_base::task::tcb::FpuArea::SIZE)
    };
    unsafe {
        asm!(
            // Окно смены CR3 открывается УЖЕ с IF=0: тик в нём бежал бы
            // по таблицам задачи (безвредно, но незачем) — а главное,
            // никакое прерывание не должно стоять между решением «уходим
            // в ring3» и iretq.
            "cli",
            // FPU/SSE: детерминированный старт (шаблон масок). До смены
            // CR3: скретч — ядерная память.
            "fxrstor64 [{scratch}]",
            "mov cr3, {cr3}",
            // Окно swapgs→iretq с IF=0: иначе тик IRQ посреди окна видит
            // ядерный CS кадра, стаб НЕ swapgs-ит — и обработчик уходит
            // с пользовательским GS (паника GS-base, см. syscall_return).
            // iretq восстанавливает IF из RFLAGS кадра (0x202).
            "swapgs",               // ядерный GS ↔ пользовательский (0)
            "push 0x23",            // SS
            "push {rsp}",           // RSP задачи (стартовый стек)
            "push 0x202",           // RFLAGS: IF | reserved bit 1
            "push 0x2B",            // CS (USER_CS|3)
            "push {rip}",           // entry
            "iretq",
            cr3 = in(reg) task_cr3,
            rsp = in(reg) user_rsp,
            rip = in(reg) entry,
            scratch = in(reg) scratch,
            options(noreturn)
        )
    }
}

/// naked-ядро возобновления: rdi = CR3 задачи, rsi = *const SysFrame
/// (ядерная память — верхняя половина, валидна после смены CR3),
/// rdx = FPU-область TCB (kernel_base::task::tcb::FpuArea::raw_ptr()).
/// Читает и слова 18/19 (RCX/R11 — расширение фолт-доставки, см.
/// SYSFRAME_RCX_WORD): кадр берётся из ПОЛНОГО слота возобновления
/// TCB, у сисколл-кадра там нули.
#[unsafe(naked)]
unsafe extern "C" fn resume_from_frame(cr3: usize, frame: *const SysFrame, fpu: *mut u8) -> ! {
    naked_asm!(
        // IF=0 ДО смены CR3 (см. dispatch_user): окно не должно ловить
        // прерываний.
        "cli",
        "mov cr3, rdi",
        // FPU/SSE: bounce TCB-области (8-выровнена) → per-CPU скретч
        // (16-выровнен) → fxrstor оттуда. rep movsq: rsi=источник (rdx),
        // rdi=назначение (скретч из gs). rbx/rbp — временные хранилища
        // (оба перезаписываются из кадра ниже); rdi/rsi/rcx — расходники
        // копии, восстанавливаются позже тоже из кадра.
        "mov rbx, rsi",            // кадр — сохранить
        "mov rbp, rdx",            // источник FPU — сохранить
        "mov rsi, rdx",            // rep movsq: источник
        "mov rdi, gs:[{fpu}]",     // назначение — per-CPU скретч
        "mov rcx, 64",             // 512 / 8
        "rep movsq",
        "fxrstor64 [rdi]",         // rdi ещё = скретч
        "mov rsi, rbx",            // кадр обратно
        // GPR из кадра (rdi/rsi — последними: rsi ещё источник).
        "mov rax, [rsi + 24]",
        "mov rbx, [rsi + 32]",
        "mov rbp, [rsi + 40]",
        "mov r8,  [rsi + 48]",
        "mov r9,  [rsi + 56]",
        "mov r10, [rsi + 64]",
        "mov r12, [rsi + 72]",
        "mov r13, [rsi + 80]",
        "mov r14, [rsi + 88]",
        "mov r15, [rsi + 96]",
        "mov rdx, [rsi + 16]",
        // Расширение фолт-доставки: RCX/R11 лежат СРАЗУ за полями
        // SysFrame (+144/+152) в полном слоте возобновления. RCX/R11
        // стабом НЕ используются как скретч — загрузка безопасна.
        "mov rcx, [rsi + 144]",
        "mov r11, [rsi + 152]",
        // Аппаратный кадр iretq (SS/RSP/RFLAGS/CS/RIP — из кадра,
        // записанного syscall_entry при уступке/усыпании).
        "push qword ptr [rsi + 136]",
        "push qword ptr [rsi + 128]",
        "push qword ptr [rsi + 120]",
        "push qword ptr [rsi + 112]",
        "push qword ptr [rsi + 104]",
        "mov rdi, [rsi + 0]",
        "mov rsi, [rsi + 8]",
        // IF=0 на окно swapgs→iretq (см. dispatch_user): тик посреди
        // окна оставил бы обработчик без per-CPU. Кадр восстанавливает
        // RFLAGS задачи (её IF).
        "cli",
        "swapgs",
        "iretq",
        fpu = const OFF_FPU,
    )
}

/// Возобновление задачи по сохранённому в TCB кадру (уступала/спала/
/// упала по фолту): CR3 ← таблица задачи, iretq по кадру — задача
/// продолжает С МЕСТА остановки (регистры, стек, флаги — как при её
/// SYSCALL или упавшей инструкции).
///
/// `words` — ПОЛНЫЙ слот возобновления TCB (RESUME_WORDS слов):
/// первые SYSFRAME_WORDS — раскладка SysFrame, слова 18/19 — RCX/R11
/// (фолт-доставка); массив обязан жить в ядерной памяти (верхняя
/// половина — отображена в таблицах всех задач): стек планировщика
/// или сисколл-стек.
pub fn resume_user(
    task_cr3: usize,
    words: &[u64; kernel_base::task::tcb::RESUME_WORDS],
    fpu: *mut u8,
) -> ! {
    // Раскладка repr(C) SysFrame == первые SYSFRAME_WORDS слов слота
    // (assert в модуле): приведение указателя тождественно; хвост
    // (18/19) naked-ядро читает напрямую.
    let frame = words.as_ptr() as *const SysFrame;
    // IRETQ-ГАРД: возобновляемый кадр приходит из слота TCB, куда
    // FAULT_REPLY может записать ПРОИЗВОЛЬНЫЕ new_rip/new_rsp (эмуляция
    // инструкции/сигнальный трамплин — ABI). IRETQ с неканоничным RIP
    // даёт #GP в ring0, с неканоничным RSP — #SS в ring0 (об оба — на
    // стеке планировщика, IST=0). Виновная задача убивается, система
    // продолжает планирование; легитимный keeper'ы такого не пишут.
    let rip = words[13]; // SysFrame.rip (+104)
    let cs = words[14]; // SysFrame.cs (+112)
    let rsp = words[16]; // SysFrame.rsp (+128)
    if (cs & 3) != 3 || !is_user_canonical(rip) || !is_user_canonical(rsp) {
        kernel_base::kernel_log!(
            "kill: неканоничный кадр возобновления rip={:#x} cs={:#x} rsp={:#x}\n",
            rip,
            cs,
            rsp
        );
        // SAFETY: контекст планировщика/входа в задачу, ядерный GS, локов нет.
        unsafe { crate::fault::kill_current_and_schedule() };
    }
    // SAFETY: naked-переход без возврата; контракт модуля.
    unsafe { resume_from_frame(task_cr3, frame, fpu) }
}

// ─── Инициализация ───────────────────────────────────────────────────────────

/// Ранняя инициализация BSP: GDT (слот 0) + IDT + FPU/SSE. Вызывать ДО
/// KernelCTL::new_and_init (load_gdt обнуляет GS base — см. шапку).
pub fn early_boot_init() {
    load_gdt(0);
    load_idt();
    unsafe { enable_fpu() };
}

/// Поздняя инициализация BSP: fixed-поля области слота 0 + MSR
/// SYSCALL/SYSRET. Вызывать после init_syscalls — с этого момента
/// `syscall` из ring3 валиден. GS base слота 0 уже стоит
/// (new_and_init → set_ktls_block), здесь только заполняются числа.
pub fn late_boot_init(kernel_root_phys: usize, sched_loop: extern "C" fn() -> !) {
    KERNEL_ROOT_SHARED.store(kernel_root_phys as u64, core::sync::atomic::Ordering::Release);
    SCHED_LOOP_SHARED.store(sched_loop as usize as u64, core::sync::atomic::Ordering::Release);
    setup_cpu_area(0, sched_loop as usize as u64, kernel_root_phys as u64, true)
        .expect("BSP: слот 0 per-CPU области");
    unsafe {
        let entry_fn: extern "C" fn() -> ! = syscall_entry;
        crate::syscall::enable_syscall_entry(KERNEL_CS, STAR_USER_BASE, entry_fn as usize);
    }
}

/// Настройка per-CPU ядра на AP (smp.rs): слот, стеки, GDT/TSS, FPU,
/// MSR, GS base. После возврата ядро готово к ring3-диспетчеризации.
///
/// # Safety
/// Вызывается ОДИН раз на старте AP (до любых задач на нём); слот
/// закреплён за этим ядром и не совпадает с BSP.
pub unsafe fn ap_cpu_setup(slot: usize) -> bool {
    let root = KERNEL_ROOT_SHARED.load(core::sync::atomic::Ordering::Acquire);
    let sched_loop = SCHED_LOOP_SHARED.load(core::sync::atomic::Ordering::Acquire);
    if root == 0 || sched_loop == 0 || slot == 0 || slot >= MAX_CPUS {
        return false;
    }
    if setup_cpu_area(slot, sched_loop, root, false).is_none() {
        return false;
    }
    load_gdt(slot); // обнуляет GS base — ПОСЛЕДНИЙ раз для этого ядра
    unsafe { enable_fpu() };
    unsafe {
        let entry_fn: extern "C" fn() -> ! = syscall_entry;
        crate::syscall::enable_syscall_entry(KERNEL_CS, STAR_USER_BASE, entry_fn as usize);
        // GS base → per-CPU область (lctl уже zeroed при статике; хук
        // фронта поставит планировщик через get_local_base).
        install_gs_base(slot);
    }
    true
}

/// Верх per-CPU стека планировщика (smp.rs: старт AP-цикла на нём).
pub fn sched_stack_top(slot: usize) -> Option<u64> {
    let area = unsafe { per_cpu_area(slot)? };
    Some(area.fixed.sched_stack_top)
}

/// Начальный MXCSR (все SIMD-исключения замаскированы, округление к
/// ближайшему) — то же значение, что и в байтовом шаблоне FpuArea::new.
const MXCSR_INIT: u32 = 0x1F80;

/// Включает FPU/SSE (CR0: EM=0 TS=0 MP=1; CR4: OSFXSR|OSXMMEXCPT) —
/// rustc генерирует SSE даже в no_std (форматирование, копирование),
/// и ring3-код задачи упадёт #UD без этих бит.
unsafe fn enable_fpu() {
    unsafe {
        asm!(
            "mov rax, cr0",
            "and rax, ~(1 << 2)",   // CR0.EM = 0
            "and rax, ~(1 << 3)",   // CR0.TS = 0 (eager-модель: без #NM-фолтов)
            "or rax, (1 << 1)",     // CR0.MP = 1
            "mov cr0, rax",
            "mov rax, cr4",
            "or rax, (1 << 9)",     // CR4.OSFXSR
            "or rax, (1 << 10)",    // CR4.OSXMMEXCPT
            "mov cr4, rax",
            // Детерминированное начальное FPU-состояние ядра/первой
            // задачи: полный сброс x87 (FCW=0x037F, стек пуст) + MXCSR
            // = все исключения замаскированы. Шаблон новых задач —
            // байтовый (FpuArea::new), поэтому это только для ядра.
            // LDMXCSR в LLVM промоделирован ТОЛЬКО с операндом-памятью
            // (r/m32-регистр не парсится) — через адрес локальной
            // переменной.
            "fninit",
            "ldmxcsr [{mxcsr_ptr}]",
            out("rax") _,
            mxcsr_ptr = in(reg) &MXCSR_INIT,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Конверсия кадра IRQ → слот возобновления: раскладка обязана быть
    /// тождественна SysFrame (читает resume_from_frame), а РЕАЛЬНЫЕ
    /// пользовательские RCX/R11 — ложиться в слова 18/19 (расширение
    /// фолт-доставки). Ноль на слове = потеря регистра на возобновлении.
    #[test]
    fn irq_frame_resume_words_layout() {
        let frame = IrqFrame {
            rdi: 0xA000, rsi: 0xA001, rdx: 0xA002, rcx: 0xA003,
            rax: 0xA004, rbx: 0xA005, rbp: 0xA006,
            r8: 0xA007, r9: 0xA008, r10: 0xA009, r11: 0xA00A,
            r12: 0xA00B, r13: 0xA00C, r14: 0xA00D, r15: 0xA00E,
            nr: 36, // вектор не попадает в слот
            rip: 0x4001_0000,
            cs: 0x2B, // USER_CS|3
            rflags: 0x202,
            rsp: 0x7FF0_00F0,
            ss: 0x23,
        };
        let w = irq_frame_resume_words(&frame);
        // GPR — тождественно SysFrame (+0..+96, без RCX/R11).
        assert_eq!(w[0], 0xA000); // rdi
        assert_eq!(w[1], 0xA001); // rsi
        assert_eq!(w[2], 0xA002); // rdx
        assert_eq!(w[3], 0xA004, "rax: SysFrame+24 (в IRQ-кадре после rcx)");
        assert_eq!(w[4], 0xA005); // rbx
        assert_eq!(w[5], 0xA006); // rbp
        assert_eq!(w[6], 0xA007); // r8
        assert_eq!(w[7], 0xA008); // r9
        assert_eq!(w[8], 0xA009); // r10
        assert_eq!(w[9], 0xA00B); // r12 (SysFrame не хранит r11 рядом)
        assert_eq!(w[10], 0xA00C); // r13
        assert_eq!(w[11], 0xA00D); // r14
        assert_eq!(w[12], 0xA00E); // r15
        // Аппаратный кадр — позиции SysFrame (+104..+136).
        assert_eq!(w[13], 0x4001_0000, "rip");
        assert_eq!(w[14], 0x2B, "cs");
        assert_eq!(w[15], 0x202, "rflags");
        assert_eq!(w[16], 0x7FF0_00F0, "rsp");
        assert_eq!(w[17], 0x23, "ss");
        // Расширение фолт-доставки: РЕАЛЬНЫЕ RCX/R11 (у SysFrame их нет).
        assert_eq!(w[SYSFRAME_RCX_WORD], 0xA003, "пользовательский RCX");
        assert_eq!(w[SYSFRAME_R11_WORD], 0xA00A, "пользовательский R11");
        // Хвост слота — нули (RESUME_WORDS=24 > 20 используемых).
        for i in 20..kernel_base::task::tcb::RESUME_WORDS {
            assert_eq!(w[i], 0, "слово {i} обязано быть нулевым");
        }
        // Вектор не просачивается в слот (не регистр пользователя).
        assert!(!w.contains(&36), "nr — служебное слово стаба, в слоте не место");
    }

    /// Резюме-гард resume_user (cs&3==3, каноничность) срабатывает на
    /// кадрах IRQ-преемпции: cs/rflags/rip/rsp — реальное ring3-состояние.
    #[test]
    fn irq_frame_user_fields_pass_resume_guards() {
        let frame = IrqFrame {
            rdi: 0, rsi: 0, rdx: 0, rcx: 0, rax: 0, rbx: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            nr: 32,
            rip: 0x4010_0000,
            cs: USER_CS as u64 | 3,
            rflags: 0x202,
            rsp: 0x7FFF_FFF0,
            ss: USER_DS as u64 | 3,
        };
        let w = irq_frame_resume_words(&frame);
        assert_eq!(w[14] & 3, 3, "CPL3 в кадре возобновления");
        assert!(is_user_canonical(w[13]) && is_user_canonical(w[16]));
    }
}
