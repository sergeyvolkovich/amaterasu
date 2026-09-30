//! Переносимый реестр ЛОГИЧЕСКИХ линий прерываний (v2).
//!
//! ЧТО ЗДЕСЬ: единственная истина по владению линиями платформы —
//! кто (какая capability/задача) держит линию и в каком режиме она
//! срабатывает. Реестр slab-овый (идиома ядра: RBSlabIO, без фиксированных
//! массивов) — число линий платформы произвольно (x86: суммарные GSI
//! из MADT + MSI-пул; ARM64: SPI/LPI; RISC-V: sources APLIC), ограничивать
//! его константой в общем слое — та же ошибка, что «255 векторов».
//!
//! ЧЕГО ЗДЕСЬ НЕТ: аппаратных операций (маскирование/режим — только через
//! `IrqChip` порта, вызовы из syscall-слоя), диспетчеризации срабатываний
//! (порт сам мапит вектор→линию и зовёт irq_wait::on_irq_fired) и хуков
//! ядра-потребителей (таймер — у порта; реестр хуков — тоже забота порта,
//! т.к. сигнатура хука привязана к его Umap).
//!
//! БЛОКИРОВКИ: структурные операции реестра — под SpinMutex (гасить
//! прерывания не нужно: реестр НЕ трогается из IRQ-контекста — диспетчер
//! ходит только в irq_wait::on_irq_fired и хуки порта). Тейдаун вызывает
//! ЗАРЕГИСТРИРОВАННЫЙ портом колбэк маскирования ПОСЛЕ снятия записей
//! (маскирование без лока — MMIO-записи).

use core::sync::atomic::{AtomicU64, Ordering};

use spin::mutex::SpinMutex;

use crate::collection::RBSlabIO;
use crate::traits::irq::TriggerMode;

/// Максимальное число линий, снимаемых тейдауном за один проход (возврат
/// из teardown_task — фиксированный буфер без alloc; больше линий на
/// задачу не бывает: MSI-аллокация ограничена 8 за сисколл, проводные
/// линии — по одной на капу, а кап у задачи конечное число; 64 — запас).
pub const MAX_TASK_LINES: usize = 64;

/// Ошибка операций над линией реестра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineError {
    /// Линия уже занята другим владельцем.
    Busy,
    /// Линия не зарегистрирована (свободна).
    NotFound,
    /// Slab-аллокатор исчерпан (дерево не выросло).
    Slab,
}

/// Запись линии в реестре.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineEntry {
    /// task_cap_id задачи-владельца (создателя корневой капы линии).
    /// Нужен teardown'у: смерть задачи возвращает её линии платформе.
    pub owner_task: u64,
    /// Режим срабатывания (программная истина, синхронна с чипом).
    pub trigger: TriggerMode,
    /// Проводная линия (true) или message-backed MSI (false).
    pub wired: bool,
}

type LineTable = RBSlabIO<u32, LineEntry, false>;

/// Обёртка Send/Sync над slab-деревом.
///
/// RBSlabIO с NoLock-кэшем формально !Send: контракт NoLock требует,
/// чтобы ВСЕ структурные операции (insert/remove) шли под внешним локом.
/// Обёртка обеспечивает это: любой доступ — через SpinMutex (см. table()).
/// Побочного безлокового доступа нет: записи читаются только под локом
/// и только Copy-полями.
#[repr(transparent)]
struct SendLineTable(SpinMutex<LineTable>);
// SAFETY: NoLock-контракт закрыт SpinMutex обёртки — структурные операции
// дерева идут только под lock(); конкурентный &-доступ сериализован тем же
// локом (все методы &self и блокируют).
unsafe impl Send for SendLineTable {}
unsafe impl Sync for SendLineTable {}

impl SendLineTable {
    fn new(table: LineTable) -> Self {
        Self(SpinMutex::new(table))
    }
}

/// Дерево лениво: slab-хуки поднимаются позже статических инициализаторов
/// (boot-путь), поэтому RBSlabIO::new() нельзя звать в const-контексте.
/// `None` внутри Once — slab OOM при инициализации (навсегда; операции
/// возвращают LineError::Slab).
static LINE_TABLE: spin::Once<Option<SendLineTable>> = spin::Once::new();

/// Гард реестра: None — slab OOM при инициализации дерева.
fn table() -> Option<&'static SendLineTable> {
    LINE_TABLE
        .call_once(|| RBSlabIO::new().ok().map(SendLineTable::new))
        .as_ref()
}

/// Зарегистрированный портом колбэк маскирования линии. Вызывается
/// teardown'ом ПОСЛЕ снятия записи (вне лока реестра): порт маскирует
/// линию в железе, не зная ничего о реестре. Один колбэк — один порт.
static MASK_CALLBACK: AtomicU64 = AtomicU64::new(0);

/// Регистрирует колбэк маскирования (вызывает порт при инициализации
/// IRQ-подсистемы, до первого unmask). Повторная установка — заменяет
/// (единственный порт в адресном пространстве ядра).
pub fn set_mask_callback(f: fn(line: u32)) {
    MASK_CALLBACK.store(f as usize as u64, Ordering::Release);
}

fn mask_via_callback(line: u32) {
    let raw = MASK_CALLBACK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: raw — fn-указатель, записанный set_mask_callback портом.
        let f: fn(u32) = unsafe { core::mem::transmute(raw) };
        f(line);
    }
}

/// Свободна ли линия (не занята владельцем в реестре). Линии вне
/// пространства платформы вызывающий отсекает ДО (по IrqChip); здесь
/// только программная истина занятости.
pub fn line_is_free(line: u32) -> bool {
    match table() {
        Some(t) => t.0.lock().get(&line).is_none(),
        // Нет реестра (slab OOM при инициализации): «занята» —
        // безопасный отказ в сторону запрета.
        None => false,
    }
}

/// Занимает линию владельцем. Ошибка Busy — линия уже занята.
pub fn claim_line(line: u32, entry: LineEntry) -> Result<(), LineError> {
    let Some(t) = table() else {
        return Err(LineError::Slab);
    };
    let mut t = t.0.lock();
    if t.get(&line).is_some() {
        return Err(LineError::Busy);
    }
    t.insert(line, entry).map_err(|_| LineError::Slab)
}

/// Освобождает линию и возвращает её запись (владелец/режим — для
/// логирования и диагностики вызывающим). Маскирование в железе — на
/// вызывающем (syscall-слой имеет чип) либо через mask_via_callback.
pub fn release_line(line: u32) -> Result<LineEntry, LineError> {
    let Some(t) = table() else {
        return Err(LineError::Slab);
    };
    let mut t = t.0.lock();
    let (_, entry) = t.remove(&line).ok_or(LineError::NotFound)?;
    Ok(entry)
}

/// Снимает ВСЕ линии задачи (teardown погибшего владельца) и маскирует
/// их через зарегистрированный колбэк порта. Возвращает число снятых
/// линий (диагностика).
pub fn teardown_task(task_cap_id: u64) -> usize {
    let Some(t) = table() else {
        return 0;
    };
    // Двухфазно: сбор ключей под локом (удаление во время обхода дерева
    // инвалидировало бы итератор), маскирование и удаление — вторым
    // проходом. Сбор — в фиксированный буфер (см. MAX_TASK_LINES).
    let mut owned = [0u32; MAX_TASK_LINES];
    let mut count = 0usize;
    {
        let t = t.0.lock();
        t.for_each_kv(|line, entry| {
            if entry.owner_task == task_cap_id && count < MAX_TASK_LINES {
                owned[count] = *line;
                count += 1;
            }
        });
    }
    for &line in &owned[..count] {
        // Маскируем ДО снятия записи: между снятием и маской линия могла
        // бы сработать и разбудить... никого (ожидания задачи уже сняты) —
        // но EOI-спам без владельца хуже молчаливой маски.
        mask_via_callback(line);
        let _ = release_line(line);
        // Wake ждущих mint-копий погибшей линии: teardown не должен
        // оставлять чужие задачи спать навсегда (см. task::irq_wait::
        // on_line_released — пустое пробуждение → re-WAIT → E_CAP_REVOKED).
        crate::task::irq_wait::on_line_released(line);
    }
    count
}

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use crate::traits::memory::{init_hooks, FrameAllocator, MemoryPTR, PAGE_SIZE};

    /// Бесконечный bump-аллокатор кадров для slab (страницы с 1).
    struct TestFrames(AtomicUsize);
    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            let first = self.0.fetch_add(count, Ordering::SeqCst);
            MemoryPTR::new(first * PAGE_SIZE, count)
        }
        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    /// Поднимает slab-хуки (один раз на процесс тестов).
    fn init_slab() {
        static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));
        init_hooks::init_allocator(&FRAMES);
    }

    fn entry(task: u64) -> LineEntry {
        LineEntry {
            owner_task: task,
            trigger: TriggerMode::Edge,
            wired: true,
        }
    }

    #[test]
    fn claim_release_teardown_lifecycle() {
        // ГАРД: teardown_task теперь зовёт task::irq_wait::on_line_released
        // (ленивый WAITERS-иниц + slab) — без сериализации тесты, двигающие
        // HHDM-offset/slab-хуки параллельно, рвут друг другу память
        // (ловилось как glibc malloc-assert в irq_wait-тесте).
        let _guard = crate::test_guard::GLOBAL.lock();
        init_slab();
        // Занять две линии разным владельцем.
        claim_line(2, entry(0x11)).expect("claim 2");
        claim_line(7, entry(0x22)).expect("claim 7");
        assert!(!line_is_free(2));
        assert!(!line_is_free(7));
        assert!(line_is_free(3));

        // Повторное занятие той же линии — Busy.
        assert_eq!(claim_line(2, entry(0x33)), Err(LineError::Busy));

        // Владелец виден.
        {
            let t = table().unwrap().0.lock();
            let e = t.get(&2).expect("entry");
            assert_eq!(e.owner_task, 0x11);
            assert_eq!(e.trigger, TriggerMode::Edge);
            assert!(e.wired);
        }

        // Освобождение возвращает запись, линия снова свободна.
        let e = release_line(2).expect("release 2");
        assert_eq!(e.owner_task, 0x11);
        assert!(line_is_free(2));

        // Повторное освобождение — NotFound.
        assert_eq!(release_line(2), Err(LineError::NotFound));

        // Тейдаун снимает только линии СВОЕГО владельца и не трогает чужие.
        claim_line(2, entry(0x22)).expect("claim 2 by 0x22");
        claim_line(9, entry(0x22)).expect("claim 9 by 0x22");
        let n = teardown_task(0x22);
        assert_eq!(n, 3, "линии 7, 2, 9 владельца 0x22");
        assert!(line_is_free(7));
        assert!(line_is_free(2));
        assert!(line_is_free(9));
    }
}
