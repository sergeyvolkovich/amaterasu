//! Межъядерные прерывания + синхронный TLB-shootdown (x86_64).
//!
//! РЕАЛИЗУЕТ переносимый контракт kernel_base::traits::ipi::IpiController
//! поверх LAPIC ICR (см. apic.rs: xAPIC MMIO / x2APIC MSR).
//!
//! ВЕКТОРЫ IPI: верхняя часть пространства IDT, НЕ пересекается с
//! линиями (32+GSI) и MSI-пулом (ёмкость MSI ограничена
//! IPI_VECTOR_SPACE_BASE — см. irq.rs):
//!   - 250 — локальный LVT-таймер LAPIC (тик AP; не IPI, но живёт в том
//!     же «служебном» диапазоне и диспетчеризуется там же);
//!   - 252 — IPI TLB-shootdown;
//!   - 253 — IPI Halt (зарезервирован; обработчик — только EOI);
//!   - 254 — IPI Reschedule (зарезервирован; кик цикла планировщика).
//!   255 — спурьё LAPIC (apic.rs), не входит.
//!
//! ПРОТОКОЛ TLB-SHOOTDOWN (синхронный, без аллокаций — обработка в
//! контексте прерывания):
//!   1. ОТПРАВИТЕЛЬ (после очистки PTE и ЛОКАЛЬНОГО invlpg):
//!      под irq-safe локом кладёт запись {root, virt, pages} в очередь
//!      фиксированной ёмкости и увеличивает ГЕНЕРАЦИЮ; снимает лок;
//!      отправляет IPI 252 всем онлайновым ядрам кроме себя.
//!   2. ПОЛУЧАТЕЛЬ (IPI-диспетчер, IF=0): под локом снимает копию
//!      очереди + поколение; вне лока — invlpg страниц тех записей,
//!      чей корень совпадает с ТЕКУЩИМ CR3 (чужие корни в TLB не живут:
//!      GLOBAL-бит не ставится, смена CR3 вычищает TLB целиком);
//!      диапазоны крупнее INVLPg-капы и переполнение очереди
//!      вырождаются в ПОЛНУЮ вычистку TLB (перезапись CR3 тем же
//!      значением). Подтверждение — Release-запись наблюдаемого
//!      поколения в per-CPU acked.
//!   3. ОТПРАВИТЕЛЬ ждёт acked ≥ своего поколения от всех целей
//!      (bounded-спин; re-send застрявшим каждые RESEND_SPINS; по
//!      таймауту — громкий лог и ВЫХОД, не hang: протокол гарантирует
//!      доставку только при IF=1 на целях, что проверяется маской
//!      онлайна).
//!
//! БЕЗОПАСНОСТЬ: отправитель ждёт подтверждений БЕЗ удерживаемых
//! локов (push/pop под локом — короткие секции), получатель не ждёт
//! отправителя — циклов нет. Кромка гонок закрыта поколением: ack ≥ G
//! возможен только после дренажа записи поколения G (получатель
//! подтверждает СНИМОК поколения, видимый ему при обработке).
//!
//! ЦЕЛЕВАЯ МАСКА: только ядра, отмеченные онлайн ([mark_cpu_online] —
//! фронт, непосредственно перед STI). Паркованные/упавшие AP в маску
//! не попадают и Shootdown их не блокирует.

use core::sync::atomic::{AtomicU64, Ordering};

use kernel_base::irqsafe::IrqSafeSpinMutex;
use kernel_base::kernel_log;
use kernel_base::traits::ipi::{IpiController, IpiError, IpiKind};
use kernel_base::traits::memory::PAGE_SIZE;
use x86_64::registers::control::Cr3;
use x86_64::VirtAddr;

use crate::apic;
use crate::cswitch;

// ─── Векторы служебного пространства ─────────────────────────────────────────

/// Локальный LVT-вектор таймера LAPIC (тик на AP; BSP — PIT/IO-APIC).
pub const LOCAL_TIMER_VECTOR: u8 = 250;
/// IPI: TLB shootdown.
pub const IPI_TLB_SHOOTDOWN_VECTOR: u8 = 252;
/// IPI: останов ядра (зарезервирован).
pub const IPI_HALT_VECTOR: u8 = 253;
/// IPI: кик планировщика (зарезервирован).
pub const IPI_RESCHED_VECTOR: u8 = 254;
/// Нижняя граница служебного пространства: MSI-пул векторов не заходит
/// сюда (cap в irq.rs::init_from_boot).
pub const IPI_VECTOR_SPACE_BASE: u32 = 250;

// ─── Маска онлайновых ядер ───────────────────────────────────────────────────

/// Битмаска онлайновых ядер (бит i — слот i отвечает на IPI).
static ONLINE_CPUS: AtomicU64 = AtomicU64::new(0);
/// LAPIC id по слоту (для адресации ICR: слот ≠ lapic id на платформах
/// с кластерной нумерацией; заполняется mark_cpu_online на самом ядре).
static SLOT_LAPIC: [AtomicU64; crate::cswitch::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; crate::cswitch::MAX_CPUS]
};

/// Отмечает ТЕКУЩЕЕ ядро онлайн: запоминает его LAPIC id по слоту и
/// ставит бит в маске. Вызывается фронтом (BSP: time_up; AP: ap_online)
/// непосредственно перед включением прерываний — с этого момента ядро
/// ОБЯЗАНО подтверждать IPI (обработчики уже стоят, IF станет 1).
pub fn mark_cpu_online() {
    let Some(slot) = self_slot() else {
        // Ранний бут: per-CPU область не установлена — ядро не может
        // участвовать в межъядерных протоколах (и не нужно: оно одно).
        return;
    };
    if slot >= crate::cswitch::MAX_CPUS {
        return;
    }
    SLOT_LAPIC[slot].store(apic::lapic_id() as u64, Ordering::Release);
    ONLINE_CPUS.fetch_or(1 << slot, Ordering::Release);
}

/// Битмаска онлайновых ядер (бит i = слот i отвечает на IPI).
pub fn online_mask() -> u64 {
    ONLINE_CPUS.load(Ordering::Acquire) & valid_cpu_mask()
}

/// Маска валидных слотов (MAX_CPUS бит).
fn valid_cpu_mask() -> u64 {
    ((1u128 << crate::cswitch::MAX_CPUS) - 1) as u64
}

/// Слот текущего ядра для протоколов IPI. В ХОСТ-ТЕСТАХ RDMSR недоступен
/// (ring3 → #GP → SIGSEGV) — протокол вырождается в no-op, тот же
/// приём, что is_active() в paging.rs (чтение CR3 у хоста запрещено).
#[cfg(test)]
fn self_slot() -> Option<usize> {
    None
}

#[cfg(not(test))]
fn self_slot() -> Option<usize> {
    cswitch::current_cpu_slot()
}

/// LAPIC id онлайнового слота (None — не онлайн).
fn slot_lapic(slot: usize) -> Option<u32> {
    if slot >= crate::cswitch::MAX_CPUS {
        return None;
    }
    let id = SLOT_LAPIC[slot].load(Ordering::Acquire) as u32;
    (id != 0 || ONLINE_CPUS.load(Ordering::Relaxed) & (1 << slot) != 0).then_some(id)
}

// ─── Очередь shootdown ───────────────────────────────────────────────────────

/// Ёмкость очереди записей (slab-подход: фиксированный массив, обработка
/// в IRQ-контексте — аллокации запрещены; переполнение → полная вычистка
/// TLB у всех целей, корректность не страдает).
const MAX_SHOOTDOWN_ENTRIES: usize = 32;
/// Капа invlpg на запись: диапазоны крупнее → полная вычистка TLB
/// (invlpg сотен страниц дороже одного CR3-reload).
const MAX_SHOOTDOWN_INVLPG: usize = 64;

/// Запись инвалидации: корень таблицы + диапазон 4К-страниц + поколение
/// публикации (retract забирает запись по СВОЕМУ поколению — очередь
/// общая, отправителей может быть несколько).
#[derive(Clone, Copy)]
struct ShootdownEntry {
    generation: u64,
    root_phys: usize,
    virt: usize,
    pages: usize,
}

impl ShootdownEntry {
    fn generation(&self) -> u64 {
        self.generation
    }
}

/// Состояние очереди (под irq-safe локом).
struct ShootdownState {
    /// Текущее поколение (счётчик публикаций запросов).
    generation: u64,
    /// Очередь записей; пустые слоты — None.
    entries: [Option<ShootdownEntry>; MAX_SHOOTDOWN_ENTRIES],
    /// Поколение запроса ПОЛНОЙ вычистки (0 — нет). Переполнение очереди
    /// вырождает запись в full-flush: получатель перезагружает CR3.
    full_flush_gen: u64,
}

impl ShootdownState {
    const fn new() -> Self {
        Self {
            generation: 0,
            entries: [const { None }; MAX_SHOOTDOWN_ENTRIES],
            full_flush_gen: 0,
        }
    }
}

static SHOOTDOWN: IrqSafeSpinMutex<ShootdownState> = IrqSafeSpinMutex::new(ShootdownState::new());

/// Подтверждённые поколения per-CPU (бит/слот по индексу).
static ACKED_GEN: [AtomicU64; crate::cswitch::MAX_CPUS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; crate::cswitch::MAX_CPUS]
};

/// Публикует запрос инвалидации и ДОЖИДАЕТСЯ подтверждений всех целей.
///
/// Контракт вызова: отправитель УЖЕ очистил PTE и сделал локальный флаш
/// (flush_if_active); вызов может быть в любом IF-состоянии, но не под
/// irq-safe локами (ждёт подтверждений без них). Ранний бут (per-CPU
/// область не установлена / других онлайн-ядер нет) — no-op.
pub fn shootdown_range(root_phys: usize, virt: usize, pages: usize) {
    if pages == 0 {
        return;
    }
    let Some(me) = self_slot() else {
        return; // ранний бут: ядро одно, локального флаша достаточно
    };
    let targets = online_mask() & !(1 << me);
    if targets == 0 {
        return; // унипроцессор: никто не мог увидеть старые записи
    }

    let mut base = virt;
    let mut left = pages;
    while left > 0 {
        // Батч: invlpg-капа (или полная вычистка при переполнении).
        let batch = left.min(MAX_SHOOTDOWN_INVLPG);
        let generation = publish(root_phys, base, batch);
        // Доставка: по маске целей (fixed-dest), ack через per-CPU generation.
        send_to_mask(targets, IPI_TLB_SHOOTDOWN_VECTOR);
        wait_acks(targets, generation);
        retract(generation);
        base += batch * PAGE_SIZE;
        left -= batch;
    }
}

/// Кладёт запись в очередь (или вырождает в full-flush при переполнении)
/// и возвращает поколение запроса. Лок удерживается только здесь.
fn publish(root_phys: usize, virt: usize, pages: usize) -> u64 {
    let mut st = SHOOTDOWN.lock();
    st.generation += 1;
    let generation = st.generation;
    let overflow = st.entries.iter_mut().all(|e| e.is_some());
    if overflow {
        st.full_flush_gen = generation;
    } else {
        for slot in st.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(ShootdownEntry {
                    generation,
                    root_phys,
                    virt,
                    pages,
                });
                break;
            }
        }
    }
    generation
}

/// Убирает из очереди СВОЮ запись после подтверждений (по поколению).
fn retract(generation: u64) {
    let mut st = SHOOTDOWN.lock();
    for slot in st.entries.iter_mut() {
        // Запись поколения generation — та, что мы положили в publish(generation):
        // записи без порядковых меток различимы тем, что наш generation был
        // актуальным при публикации; забираем ОДНУ запись, чей диапазон
        // ещё не забран. Сопоставление по generation хранится в записи.
        if let Some(e) = slot {
            if e.generation() == generation {
                *slot = None;
                break;
            }
        }
    }
    if st.full_flush_gen == generation {
        st.full_flush_gen = 0;
    }
}

/// Снимок очереди для обработчика IPI: (поколение, копия записей,
/// full-flush поколение).
fn snapshot() -> (u64, [Option<ShootdownEntry>; MAX_SHOOTDOWN_ENTRIES], u64) {
    let st = SHOOTDOWN.lock();
    (st.generation, st.entries, st.full_flush_gen)
}

// ─── Обработка IPI (контекст прерывания, IF=0) ───────────────────────────────

/// Обработчик IPI TLB-shootdown (irq.rs::irq_vector_dispatch): дренит
/// очередь, инвалидирует СВОЙ (текущий CR3) диапазон, подтверждает
/// поколение. БЕЗ ожиданий и аллокаций.
pub fn on_shootdown_ipi() {
    let (generation, batch, full_flush_gen) = snapshot();
    let my_root = current_cr3();

    let mut need_full_flush = full_flush_gen != 0;
    for entry in batch.iter().flatten() {
        if entry.root_phys != my_root {
            continue; // чужой корень: TLB текущего ядра его не держит
        }
        if entry.pages > MAX_SHOOTDOWN_INVLPG {
            need_full_flush = true;
            continue;
        }
        for i in 0..entry.pages {
            // SAFETY: invlpg по произвольному VA безопасен (ядерный
            // режим); невалидация отсутствующего отображения — no-op.
            unsafe {
                x86_64::instructions::tlb::flush(VirtAddr::new(
                    (entry.virt + i * PAGE_SIZE) as u64,
                ))
            };
        }
    }
    if need_full_flush {
        flush_whole_tlb();
    }

    // Подтверждение — Release: инвалидиции ВЫШЕ по программе видны
    // отправителю, дожидающемуся этого ack (Acquire в wait_acks).
    let Some(slot) = self_slot() else {
        return; // не может быть: IPI шлётся только онлайн-ядрам (GS готов)
    };
    let ack = generation.max(full_flush_gen);
    ACKED_GEN[slot].store(ack, Ordering::Release);
}

/// Обработчик IPI Reschedule (v1 — no-op: циклы планировщика поллят;
/// будущий кик пустого ядра из спящего состояния).
pub fn on_resched_ipi() {}

/// Обработчик IPI Halt (v1 — no-op: семантика парковки ещё не введена;
/// вектор зарезервирован за контрактом IpiKind::Halt).
pub fn on_halt_ipi() {}

/// Текущий CR3 (физический адрес корня).
fn current_cr3() -> usize {
    let (frame, _) = Cr3::read();
    frame.start_address().as_u64() as usize
}

/// Полная вычистка TLB текущего ядра: перезапись CR3 тем же значением
/// (GLOBAL-бит в ядре не ставится — вычистится всё не-глобальное).
fn flush_whole_tlb() {
    let (frame, flags) = Cr3::read();
    // SAFETY: запись того же корня + флагов — эквивалент FlushAll.
    unsafe { Cr3::write(frame, flags) };
}

// ─── Доставка и ожидание ─────────────────────────────────────────────────────

/// Отправляет вектор маске целей (fixed-dest по SLOT_LAPIC).
fn send_to_mask(targets: u64, vector: u8) {
    for slot in 0..crate::cswitch::MAX_CPUS {
        let bit = 1u64 << slot;
        if targets & bit == 0 {
            continue;
        }
        match slot_lapic(slot) {
            Some(lapic) => apic::send_ipi(lapic, vector),
            None => kernel_log!("ipi: слот {} в маске без LAPIC id — пропуск\n", slot),
        }
    }
}

/// Дожидается acked >= generation от всех целей: bounded-спин, re-send
/// застрявшим каждые RESEND_SPINS (edge-IPI может слиться с обработкой
/// предыдущего), по таймауту — лог и выход (не hang ядра).
fn wait_acks(targets: u64, generation: u64) {
    const RESEND_SPINS: u64 = 1 << 20;
    const LIMIT_SPINS: u64 = 1 << 31;
    let mut spins: u64 = 0;
    loop {
        let pending = pending_targets(targets, generation, |slot| {
            ACKED_GEN[slot].load(Ordering::Acquire)
        });
        if pending == 0 {
            return;
        }
        unsafe { core::arch::x86_64::_mm_pause() };
        spins += 1;
        if spins >= LIMIT_SPINS {
            kernel_log!(
                "ipi: shootdown ack timeout (generation {}, цели {:#x}) — продолжаем с риском устаревшего TLB\n",
                generation,
                pending
            );
            return;
        }
        if spins % RESEND_SPINS == 0 {
            send_to_mask(pending, IPI_TLB_SHOOTDOWN_VECTOR);
        }
    }
}

/// Чистая функция подсчёта не-подтвердивших целей (тестируема на хосте).
fn pending_targets(targets: u64, generation: u64, acked: impl Fn(usize) -> u64) -> u64 {
    let mut pending = 0u64;
    for slot in 0..crate::cswitch::MAX_CPUS {
        let bit = 1u64 << slot;
        if targets & bit != 0 && acked(slot) < generation {
            pending |= bit;
        }
    }
    pending
}

// ─── IpiController (переносимый контракт) ────────────────────────────────────

/// Реализация IpiController поверх LAPIC ICR.
pub struct X86IpiController;

static IPI_CONTROLLER: X86IpiController = X86IpiController;

/// Единственная точка доступа к IPI-контроллеру (как irq::chip()).
pub fn controller() -> &'static X86IpiController {
    &IPI_CONTROLLER
}

impl IpiController for X86IpiController {
    fn current_cpu(&self) -> Option<usize> {
        self_slot()
    }

    fn cpu_count(&self) -> usize {
        crate::cswitch::MAX_CPUS
    }

    fn online_mask(&self) -> u64 {
        online_mask()
    }

    fn mark_current_online(&self) {
        mark_cpu_online()
    }

    fn send_to_cpu(&self, cpu: usize, kind: IpiKind) -> Result<(), IpiError> {
        if !apic::active() {
            return Err(IpiError::NotReady);
        }
        if online_mask() & (1u64 << cpu) == 0 {
            return Err(IpiError::BadTarget);
        }
        let vector = ipi_vector(kind);
        match slot_lapic(cpu) {
            Some(lapic) => {
                apic::send_ipi(lapic, vector);
                Ok(())
            }
            None => Err(IpiError::BadTarget),
        }
    }

    fn broadcast_others(&self, kind: IpiKind) -> Result<(), IpiError> {
        if !apic::active() {
            return Err(IpiError::NotReady);
        }
        let me = self.current_cpu().ok_or(IpiError::NotReady)?;
        if online_mask() & !(1 << me) == 0 {
            return Ok(()); // унипроцессор: некому слать — не ошибка
        }
        apic::send_ipi_all_excluding_self(ipi_vector(kind));
        Ok(())
    }
}

// Хост-тесты: протокол гоняется на чистых функциях (publish/snapshot/
// retract/pending_targets), MMIO/MSR-пути недостижимы (self_slot() → None).

/// Семантика IpiKind → вектор служебного пространства.
fn ipi_vector(kind: IpiKind) -> u8 {
    match kind {
        IpiKind::TlbShootdown => IPI_TLB_SHOOTDOWN_VECTOR,
        IpiKind::Reschedule => IPI_RESCHED_VECTOR,
        IpiKind::Halt => IPI_HALT_VECTOR,
    }
}

// ─── Тесты (хост: чистая логика, без MMIO/ICR) ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipi_vectors_reserve_top_space() {
        // Служебное пространство: >= 250, не задевает спурьё 255,
        // векторы попарно различны.
        for v in [
            LOCAL_TIMER_VECTOR,
            IPI_TLB_SHOOTDOWN_VECTOR,
            IPI_HALT_VECTOR,
            IPI_RESCHED_VECTOR,
        ] {
            assert!(v as u32 >= IPI_VECTOR_SPACE_BASE);
            assert!(v < 255, "вектор {} задевает спурьё", v);
        }
        assert_ne!(IPI_TLB_SHOOTDOWN_VECTOR, IPI_RESCHED_VECTOR);
        assert_ne!(IPI_TLB_SHOOTDOWN_VECTOR, IPI_HALT_VECTOR);
        assert_ne!(LOCAL_TIMER_VECTOR, IPI_TLB_SHOOTDOWN_VECTOR);
        // MSI-пул cap в irq.rs: базис+ёмкость <= IPI_VECTOR_SPACE_BASE.
        let vec_base = 48u32; // QEMU: 24 GSI → align16(32+24)
        assert!(vec_base + 64 <= IPI_VECTOR_SPACE_BASE);
    }

    #[test]
    fn pending_targets_respects_mask_and_gen() {
        // Цели {1, 3, 5}: acked 1-го >= generation, 3-го < generation, 5-го >= generation.
        let targets = 0b101010u64;
        let pending = pending_targets(targets, 7, |slot| match slot {
            1 => 7,
            3 => 6,
            5 => 9,
            _ => 0,
        });
        assert_eq!(pending, 0b001000, "не подтвердил только слот 3");
    }

    #[test]
    fn pending_targets_zero_when_all_acked() {
        let targets = 0b1111u64;
        assert_eq!(pending_targets(targets, 3, |_| 3), 0);
        assert_eq!(pending_targets(targets, 3, |_| 10), 0);
    }

    #[test]
    fn publish_snapshot_retract_roundtrip() {
        // Полный цикл протокола без железа: publish → (снимок получателя)
        // → retract → очередь пуста; переполнение → full-flush.
        let g1 = publish(0x123_000, 0x5000, 2);
        assert_eq!(g1, 1);
        let (generation, batch, ff) = snapshot();
        assert_eq!(generation, 1);
        assert_eq!(ff, 0);
        assert_eq!(batch.iter().flatten().count(), 1);
        let e = batch.iter().flatten().next().unwrap();
        assert_eq!(e.root_phys, 0x123_000);
        assert_eq!(e.pages, 2);

        retract(g1);
        let (_, batch, _) = snapshot();
        assert!(batch.iter().all(|s| s.is_none()));
    }

    #[test]
    fn queue_overflow_degrades_to_full_flush() {
        // MAX записей заполняют очередь, (MAX+1)-я вырождается в full-flush.
        let mut gens = [0u64; MAX_SHOOTDOWN_ENTRIES];
        for g in gens.iter_mut() {
            *g = publish(0xABC_000, 0x7000, 1);
        }
        let overflow_gen = publish(0xDEF_000, 0x9000, 1);
        let (generation, batch, ff) = snapshot();
        assert_eq!(ff, overflow_gen, "переполнение → full-flush");
        assert_eq!(batch.iter().flatten().count(), MAX_SHOOTDOWN_ENTRIES);
        assert_eq!(generation, overflow_gen);

        // Разбор: все цели подтвердили overflow-поколение → записи убираются.
        for g in gens.iter_mut() {
            retract(*g);
        }
        retract(overflow_gen);
        let (_, batch, ff) = snapshot();
        assert!(batch.iter().all(|s| s.is_none()));
        assert_eq!(ff, 0);
    }

    #[test]
    fn valid_cpu_mask_covers_max_cpus() {
        // 64 слота → маска полная; (1 << 64) не переполняет через wrapping.
        assert_eq!(valid_cpu_mask(), u64::MAX);
    }

    #[test]
    fn shootdown_entry_layout_fits_irq_stack() {
        // Копия очереди на стеке IRQ-обработчика: ~768 Б — в лимитах
        // 32-КиБ стека. Константа — защита от молчаливого роста.
        assert!(MAX_SHOOTDOWN_ENTRIES * core::mem::size_of::<ShootdownEntry>() <= 1024);
    }
}
