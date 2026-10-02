//! Dekker-мьютекс поверх разделяемой памяти NOMAD.
//!
//! ДВА РЕЖИМА:
//!   1. lock/unlock — чистый Деккер поверх syscall 3/4
//!      (SCHED_BLOCK_ON_OBJECT / SCHED_RELEASE_OBJECT). Работает на
//!      текущем ядре БЕЗ изменений, но НЕСТРОГО КОРРЕКТЕН: существует
//!      окно «проверил значение → встал в очередь ядра», внутри которого
//!      unlocker'овский RELEASE уходит в пустую очередь, а задача
//!      засыпает навсегда (syscall 3 таймаута не имеет). Протокол
//!      Деккера (waiters++ + SeqCst-fence) закрывает гонку ЗНАЧЕНИЙ,
//!      но не гонку ПРИХОДА В ОЧЕРЕДЬ — это доказано экспериментально
//!      (стенд dekker_experiment: сценарий 1 воспроизводит lost wakeup
//!      детерминированно).
//!   2. lock_pred/unlock_pred — тот же протокол, но сон через
//!      FUTEX_WAIT (syscall 53, требует патча ядра из kernel/futex.rs):
//!      ядро проверяет `*uaddr == expected` ПОД WAKE_LOCK, атомарно с
//!      постановкой в очередь — ровно то, что NOMAD уже делает внутри
//!      IPC (block_on_object_if). Строго корректен (сценарий 2/3 стенда).
//!
//! СОГЛАШЕНИЯ:
//!   - Состояние мьютекса лежит в shm-регионе (#[repr(C)], AtomicU32 ×2):
//!     владелец региона размещает ShmMutex по выровненному смещению и
//!     передаёт партнёру через CAP_CREATE_SHARED + map item.
//!   - Обе задачи договариваются о wait-key заранее (bootstrap-слот,
//!     константа протокола или заголовок shm). Ключ обязан ЛЕЖАТЬ ВНЕ
//!     резервов ядра (см. syscall_task.rs::is_kernel_wait_object):
//!       id < 64; [0x1_0000..0x1_3000) — IPC; [0x3000..0x3010) — фолты;
//!       0x2_0000 — IRQ-база. Рекомендация: KEY_BASE = 0x100_0000+.
//!   - unlock зовёт только владелец; спурийные пробуждения допустимы и
//!     обрабатываются циклом.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{abi::nr, syscall::{syscall1, syscall2, syscall3}};

/// Рекомендуемая база ключей (вне всех ядерных резервов ядра).
pub const KEY_BASE: u64 = 0x0100_0000;

/// Ячейки мьютекса в разделяемой памяти.
#[repr(C)]
#[derive(Debug)]
pub struct ShmMutex {
    /// 0 = свободен, 1 = занят.
    pub state: AtomicU32,
    /// Dekker-армирование: число задач в медленном пути (инкремент до
    /// повторной проверки и сна, декремент только при захвате).
    pub waiters: AtomicU32,
}

impl ShmMutex {
    pub const fn zeroed() -> Self {
        Self {
            state: AtomicU32::new(0),
            waiters: AtomicU32::new(0),
        }
    }
}

/// Привязка протокола к wait-ключу. Две задачи обязаны построить
/// NomadPark с ОДИНАКОВЫМ key (вне резервов ядра — см. модульный док).
pub struct NomadPark {
    pub key: u64,
}

impl NomadPark {
    pub fn new(key: u64) -> Self {
        debug_assert!(key >= KEY_BASE, "ключ обязан быть вне резервов ядра");
        Self { key }
    }

    #[inline]
    /// syscall 3: безусловный сон. ОПАСНОЕ ОКНО прихода в очередь —
    /// см. обсуждение в модульном доке.
    pub fn park(&self) {
        // SAFETY: конвенция ABI; аргумент — object_id (u64).
        unsafe { syscall1(nr::SCHED_BLOCK_ON_OBJECT, self.key) };
    }

    #[inline]
    /// syscall 4: разбудить одного (OneShot), пустая очередь — no-op.
    pub fn unpark(&self) {
        // SAFETY: конвенция ABI; аргумент — object_id (u64).
        unsafe { syscall1(nr::SCHED_RELEASE_OBJECT, self.key) };
    }

    #[inline]
    /// syscall 53 (требует патча): сон, ЕСЛИ *uaddr == expected; проверка
    /// в ядре атомарна с постановкой в очередь (WAKE_LOCK). Ошибка
    /// сисколла (старый ядро-образ) трактуется как «не уснул».
    pub fn park_if(&self, uaddr: u64, expected: u32) -> bool {
        // SAFETY: конвенция ABI; (key, uaddr, expected) — FUTEX_WAIT.
        let r = unsafe { syscall3(nr::FUTEX_WAIT, self.key, uaddr, expected as u64) };
        // Ядро возвращает 0 и в обоих исходах («спал и разбудили» /
        // «предикат сработал до сна») — вызывающий цикл всё равно
        // перепроверяет состояние; раскладывать исходы здесь незачем.
        let _ = r;
        true
    }

    #[inline]
    /// syscall 54 (требует патча ядра): разбудить до `count` ждущих ключа.
    /// nr-кратно, но мьютекс-протокол зовёт с count = 1 (OneShot).
    pub fn unpark_nr(&self, count: u32) {
        // SAFETY: конвенция ABI; (key, nr) — FUTEX_WAKE.
        unsafe { syscall2(nr::FUTEX_WAKE, self.key, count as u64) };
    }
}

// ─── Режим 1: чистый Деккер (работает на текущем ядре; см. оговорку) ────────

/// Захват (нестрогий). Fast path — CAS без syscall; slow path —
/// Dekker-армирование + syscall 3.
pub fn lock(m: &ShmMutex, park: &NomadPark) {
    if m.state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    // locked RMW: полный барьер на x86 — армирование до повторной проверки.
    m.waiters.fetch_add(1, Ordering::AcqRel);
    loop {
        if m.state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            m.waiters.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        // ⚠ ОКНО ПРИХОДА В ОЧЕРЕДЬ: между этой точкой и входом в очередь
        // ядра unlocker может отработать unpark в пустую очередь →
        // вечный сон (без syscall-таймаута). Только lock_pred строг.
        park.park();
    }
}

/// Освобождение (нестрогий режим).
pub fn unlock(m: &ShmMutex, park: &NomadPark) {
    m.state.store(0, Ordering::Release);
    // Деккер-полубарьер: стора state=0 видна ДО чтения waiters
    // (x86-стобуфер иначе спрячет её от waker'а).
    core::sync::atomic::fence(Ordering::SeqCst);
    if m.waiters.load(Ordering::Acquire) > 0 {
        park.unpark();
    }
}

// ─── Режим 2: Деккер + предикатный сон (строгий; патч syscall 53/54) ────────

/// Захват (строгий). Отличие от lock(): сон идёт через FUTEX_WAIT —
/// проверка `*uaddr == 1` выполняется ядром ПОД WAKE_LOCK атомарно с
/// постановкой в очередь, окно прихода закрыто по построению.
///
/// SAFETY-контракт uaddr: адрес обязан лежать В ТОМ ЖЕ shm-регионе, что
/// и m, и указывать на валидные 4 байта (ядро дополнительно гейтит
/// is_user_range + U/S-семантику translate_user).
pub fn lock_pred(m: &ShmMutex, park: &NomadPark) {
    if m.state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    m.waiters.fetch_add(1, Ordering::AcqRel);
    loop {
        if m.state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            m.waiters.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let _ = park.park_if(m.state.as_ptr() as u64, 1);
        // true/false — оба исхода означают «перепроверь и пробуй снова»:
        // false = ядро увидело state==0 под локом (мы почти захватили),
        // true = нас разбудил unlocker (возможно, спурийно).
    }
}

/// Освобождение (строгий режим). Оптимизация «waiters == 0 → без syscall»
/// корректна благодаря Dekker-фенсу: если мы прочли 0, то ни одна задача
/// не прошла точку армирования (waiters++ линеаризуем), значит спящих нет.
/// Будим ровно ОДНОГО: мьютекс освобождён на одного претендента (FUTEX_WAKE
/// с nr=1 семантически эквивалентен syscall 4, но гейтится тем же ключом,
/// что и WAIT в 53).
pub fn unlock_pred(m: &ShmMutex, park: &NomadPark) {
    m.state.store(0, Ordering::Release);
    core::sync::atomic::fence(Ordering::SeqCst);
    if m.waiters.load(Ordering::Acquire) > 0 {
        park.unpark_nr(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host-тест структуры: раскладка ShmMutex стабильна для shm.
    #[test]
    fn shm_mutex_layout() {
        assert_eq!(core::mem::size_of::<ShmMutex>(), 8);
        assert_eq!(core::mem::align_of::<ShmMutex>(), 4);
    }
}
