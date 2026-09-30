//! SMP: подъём AP-ядер — логика ПОЛНОСТЬЮ в arch-бэкенде (x86_64).
//!
//! Фронтенд (kernel_limine) только: (а) защищает BOOTLOADER_RECLAIMABLE
//! регионы от reclaim ДО онлайна всех AP (паркованные Limine AP и
//! бут-таблицы живут в них) и (б) передаёт их сюда для отложенного
//! освобождения; (в) даёт хук политики (планировщик + цикл) —
//! [`ApOnlineHook`].
//!
//! ПОСЛЕДОВАТЕЛЬНОСТЬ НА AP (ap_entry, старт по goto_address):
//!   1. AP исполняется на бут-таблицах Limine (ВА ядра в них отображены)
//!      со своим бут-стеком — первым делом CR3 ← физический корень
//!      ядерной таблицы (общий, cswitch::kernel_root_phys_shared).
//!   2. Стек → собственный per-CPU стек планировщика слота.
//!   3. per-CPU инициализация (cswitch::ap_cpu_setup): GDT/TSS, FPU,
//!      MSR SYSCALL/SYSRET, GS base → per-CPU область (слот из
//!      `Cpu.extra`, записан BSP до goto_address).
//!   4. Счётчик онлайна инкрементится, зовётся хук фронта (или safe-park
//!      hlt-циклом — хука нет/отказ).
//!
//! ОСВОБОЖДЕНИЕ ОТЛОЖЕННЫХ РЕГИОНОВ: только после онлайна ВСЕХ AP
//! (бут-таблицы больше никому не нужны); при таймауте регионы НЕ
//! освобождаются (безопаснее утечка, чем use-after-free под паркой).

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_base::frame_manager::phys_frame_manager::FrameManager;
use kernel_base::kernel_log;
use limine::mp::Cpu;

use crate::cswitch;

/// Хук политики фронта: ставится на AP после полной per-CPU
/// инициализации; получив управление, обязан не возвращаться (цикл
/// планировщика ядра — свой планировщик + scheduler_loop_entry).
pub type ApOnlineHook = fn(core_slot: usize) -> !;

/// Счётчик AP, прошедших per-CPU инициализацию (BSP не считается).
static APS_ONLINE: AtomicUsize = AtomicUsize::new(0);

/// Беспрогонная диагностика AP (по lapic_id): (cpu_ptr, extra, setup_ok).
/// AP пишут одновременно — гоняют serial; BSP читает и печатает ОДНИМ
/// логом после таймаута ожидания.
static AP_DIAG: [(AtomicUsize, AtomicUsize, AtomicUsize); 8] = {
    // Классический паттерн const-иниализации атомиков в static-массиве:
    // значение используется только в compile-time для [ZERO; 8].
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: (AtomicUsize, AtomicUsize, AtomicUsize) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    [ZERO; 8]
};

/// Поднимает AP-ядра по ответу Limine SMP.
///
/// `deferred_regions` — (физбаза, страницы) BOOTLOADER_RECLAIMABLE
/// регионов, защищённых фронтендом от reclaim: освобождаются здесь,
/// когда ВСЕ AP онлайн (или не освобождаются вовсе при таймауте —
/// возврат false).
///
/// Возврат — число поднятых AP.
///
/// `frames` — конкретный FrameManager (не dyn): отложенные регионы
/// освобождаются pow2-чанками (free_range_phys), а не «одним блоком
/// с округлением вверх», которое для НЕ-степенных регионов освобождало
/// чужие страницы за его пределами.
pub fn bringup_aps(
    cpus: &[&Cpu],
    bsp_lapic_id: u32,
    deferred_regions: &[(usize, usize)],
    frames: &'static FrameManager,
    online_hook: Option<ApOnlineHook>,
) -> (usize, bool) {
    let aps_total = cpus.iter().filter(|c| c.lapic_id != bsp_lapic_id).count();
    if aps_total == 0 {
        return (0, true);
    }

    // Слоты: BSP — 0; AP — 1.. (порядок перечисления в ответе SMP).
    let mut slot = 1usize;
    let mut launched = 0usize;
    for cpu in cpus.iter() {
        if cpu.lapic_id == bsp_lapic_id {
            continue;
        }
        if slot >= cswitch::MAX_CPUS {
            kernel_log!(
                "smp: ядро lapic={} сверх лимита {} — не поднято\n",
                cpu.lapic_id,
                cswitch::MAX_CPUS
            );
            break;
        }
        // Хук (политика) становится циклом планировщика этого ядра:
        // return_to_scheduler (self-exit) прыгнет на него же.
        let hook_addr = online_hook
            .map(|h| h as *const () as usize as u64)
            .unwrap_or(safe_park as *const () as usize as u64);
        // paint=true: AP ещё не запущен — на стеке слота никто не живёт
        // (AP при повторном вызове из ap_cpu_setup льёт паттерн уже
        // стоя на этом стеке — там paint=false).
        cswitch::setup_cpu_area(
            slot,
            hook_addr,
            cswitch::kernel_root_phys_shared(),
            true,
        );

        // Слот — в Cpu.extra (AP прочитает первым делом), затем запуск.
        // GotoAddress::write синхронизирует записи — AP увидит слот.
        // ДИАГНОСТИКА: адрес структуры + lapic + записанный слот.
        kernel_log!(
            "smp[bsp]: lapic={} cpu={:#x} extra←{}\n",
            cpu.lapic_id,
            core::ptr::addr_of!(*cpu) as usize,
            slot
        );
        cpu.extra.store(slot as u64, Ordering::SeqCst);
        // Контракт Limine MP — AP прыгает на функцию с (&Cpu) в RDI,
        // 64КиБ стеком загрузчика и выключенными прерываниями.
        cpu.goto_address.write(ap_entry);
        launched += 1;
        slot += 1;
    }

    // Ожидание онлайна: bounded-спин (таймера нет — грубый счётчик
    // pause; AP в QEMU/реальном железе поднимается за микросекунды).
    // 2^27 pause ≈ единицы секунд даже в TCG (2^30 тянулось >100 с —
    // диагностика онлайна не дожидалась).
    let mut spins: u64 = 0;
    let spin_limit: u64 = 1 << 27;
    while APS_ONLINE.load(Ordering::Acquire) < launched && spins < spin_limit {
        unsafe { asm!("pause") };
        spins += 1;
    }

    let online = APS_ONLINE.load(Ordering::Acquire);
    let all = online >= launched;
    // Диагностика AP одним чистым логом (безserial-гонки).
    for (i, d) in AP_DIAG.iter().enumerate() {
        let (p, e, ok) = (
            d.0.load(Ordering::Acquire),
            d.1.load(Ordering::Acquire),
            d.2.load(Ordering::Acquire),
        );
        if p != 0 || e != 0 || ok != 0 {
            kernel_log!(
                "smp: AP[lapic {}] cpu={:#x} extra={:#x} setup={}\n",
                i,
                p,
                e,
                ok
            );
        }
    }
    // ДИАГНОСТИКА RDI (что Limine реально передал) удалена после
    // отладки: указатели и слоты подтверждаются самим AP_DIAG.
    if !all {
        kernel_log!(
            "smp: он-лайн {} из {} AP — reclaimable-регионы НЕ освобождены\n",
            online,
            launched
        );
        return (online, false);
    }

    // Все AP на ядерных таблицах: бут-таблицы/стеки парковки можно
    // возвращать в пул кадров — pow2-чанками (см. сигнатуру).
    for (begin, pages) in deferred_regions.iter() {
        frames.free_range_phys(0, *begin, *pages);
    }
    if !deferred_regions.is_empty() {
        kernel_log!(
            "smp: освобождено отложенных reclaimable-регионов: {}\n",
            deferred_regions.len()
        );
    }
    (online, true)
}

/// Точка входа AP (Limine прыгает сюда по goto_address).
///
/// # Safety
/// Контракт Limine MP (см. bringup_aps); вызывается ровно один раз
/// каждым AP.
unsafe extern "C" fn ap_entry(cpu: &Cpu) -> ! {
    // ВСЁ чтение структуры Cpu — ДО смены CR3/стека (под бут-CR3
    // Limine): и адрес, и lapic, и назначенный слот.
    let lapic = (cpu.lapic_id as usize) & 7;
    let cpu_ptr = core::ptr::addr_of!(*cpu) as usize;
    let slot = cpu.extra.load(Ordering::SeqCst) as usize;
    AP_DIAG[lapic].0.store(cpu_ptr, Ordering::SeqCst);
    AP_DIAG[lapic].1.store(slot, Ordering::SeqCst);

    // Ядерная таблица (бут-таблицы могли быть переиспользованы;
    // ВА ядра в ядерной таблице отображены). Читаем статику — она
    // доступна и под бут-CR3, и под ядерным.
    let root = cswitch::kernel_root_phys_shared() as usize;

    // Собственный стек (бут-стек Limine жив в reclaimable-регионе —
    // до освобождения он валиден, но уходим на свой немедленно).
    // Разрешаем и слоту 0 (BSP-область) — валидацию делает ap_cpu_setup.
    let stack_top = match cswitch::sched_stack_top(slot) {
        Some(top) => top as usize,
        None => {
            // Слота нет (превышен лимит): парковка прямо на бут-стеке.
            kernel_log!("smp: AP lapic={} без слота — park\n", cpu.lapic_id);
            park()
        }
    };

    // Смена CR3 и стека — ТОЛЬКО через naked-трамплин. Прежний код
    // делал «mov rsp» inline-asm'ом ВНУТРИ этой функции: после смены
    // все rsp-relative локалы (slot/lapic) читались из НОВОГО,
    // ещё не заполненного стека (залит паттерном 0x5A в
    // setup_cpu_area) — мусорные индексы AP_DIAG[0x5A5A..] и
    // мусорный slot в ap_cpu_setup (OOB-паника «len 8», поймана в
    // QEMU -smp 4). Тот же класс бага, что и _start (см. main.rs):
    // смена стека — только без живого кадра Rust.
    unsafe { ap_trampoline(root, stack_top, slot, lapic) }
}

/// naked-переход AP: CR3 ← ядерные таблицы, RSP ← собственный стек
/// цикла, затем jmp в [`ap_main`] — обычную функцию УЖЕ на новом
/// стеке (кадр ap_entry на бут-стеке Limine больше не используется).
/// Регистры (SysV): rdi = CR3, rsi = stack_top, rdx = slot, rcx = lapic.
#[unsafe(naked)]
unsafe extern "C" fn ap_trampoline(
    root: usize,
    stack_top: usize,
    slot: usize,
    lapic: usize,
) -> ! {
    naked_asm!(
        "mov rax, rdi",
        "mov cr3, rax",           // бут-таблицы Limine больше не нужны
        "mov rsp, rsi",           // свой стек цикла планировщика
        "sub rsp, 8",             // выравнивание входа ap_main: rsp ≡ 8 (mod 16)
        "xor ebp, ebp",           // обрыв кадровой цепочки бут-стека
        "mov rdi, rdx",           // аргумент 1: slot
        "mov rsi, rcx",           // аргумент 2: lapic
        "jmp {ap_main}",
        ap_main = sym ap_main,
    );
}

/// Продолжение AP НА СВОЁМ стеке (вызывается только из трамплина):
/// per-CPU механика arch-бэкенда, LAPIC+локальный таймер, отметка
/// он-лайна и вход в цикл планировщика порта (политика фронтенда).
unsafe extern "C" fn ap_main(slot: usize, lapic: usize) -> ! {
    // per-CPU: GDT/TSS, FPU, MSR, GS base (lctl в области нулевой).
    let setup_ok = unsafe { cswitch::ap_cpu_setup(slot) };
    AP_DIAG[lapic].2.store(setup_ok as usize, Ordering::SeqCst);
    if !setup_ok {
        kernel_log!("smp: AP slot={:#x} init fail — park\n", slot);
        park()
    }

    // LAPIC ЭТОГО ядра + локальный таймер: до них ядро не могло ни
    // подтверждать прерывания (EOI), ни получать IPI (TLB-shootdown),
    // ни тикать. Без LAPIC ядро НЕ включается в онлайновую маску
    // (ipi::mark_cpu_online фронт вызовет только из хука ниже — сюда
    // без LAPIC мы не доходим) и паркуется: включить его в SMP-протоколы
    // без EOI/шутдауна нельзя.
    if !crate::apic::init_ap() {
        kernel_log!("smp: AP slot={} без LAPIC — park (вне SMP-протоколов)\n", slot);
        park()
    }
    crate::timer::start_ap_tick();

    APS_ONLINE.fetch_add(1, Ordering::AcqRel);
    kernel_log!("smp: AP-ядро {} онлайн (lapic {})\n", slot, lapic);

    // Политика фронта: планировщик + цикл (фронт отметит ядро в
    // ipi-маске и включит прерывания). Без хука — парковка.
    let hook_addr = {
        let area = unsafe { cswitch::per_cpu_area(slot) }.expect("слот валиден");
        area.fixed.sched_loop_entry as usize
    };
    let hook: fn(usize) -> ! = unsafe { core::mem::transmute(hook_addr) };
    hook(slot)
}

/// Спокойная парковка ядра без работы (hlt-цикл: пробуждений нет —
/// прерывания выключены, энергосбережение до появления IPI/таймера).
fn safe_park(_slot: usize) -> ! {
    park()
}

fn park() -> ! {
    loop {
        unsafe { asm!("hlt") };
    }
}
