//! Сисколлы 53/54: FUTEX_WAIT / FUTEX_WAKE — предикатный сон на слове
//! разделяемой памяти.
//!
//! ЗАЧЕМ. Сисколл 3 (SCHED_BLOCK_ON_OBJECT) — безусловный сон: между
//! проверкой значения в ring3 и фактической постановкой в очередь ядра
//! существует окно, внутри которого waker'овский RELEASE уходит в пустую
//! очередь, а решившая спать задача засыпает навсегда (таймаута у
//! syscall 3 нет). Dekker-протокол в userspace (waiters++ + SeqCst-fence)
//! закрывает гонку ЗНАЧЕНИЙ, но НЕ гонку ПРИХОДА В ОЧЕРЕДЬ. Здесь она
//! закрыта проверкой предиката ПОД WAKE_LOCK, атомарно с постановкой в
//! очередь — тот же механизм, что уже работает внутри IPC-транспорта
//! (lctl::scheduler_block_on_object_if) и в Linux futex_wait (recheck
//! значения под hb->lock). Экспериментальное подтверждение: стенд
//! dekker_experiment (сценарий 1 — детерминированное воспроизведение
//! lost wakeup на syscall 3/4, сценарии 2/3 — предикатный сон корректен).
//!
//! ПОРЯДОК ЛОКОВ. `pred` зовётся под WAKE_LOCK (см. lctl.rs) и читает
//! ТОЛЬКО через HHDM volatile-ом — ни одного лока внутри pred (контракт
//! «pred короткий» соблюдён). permission_backend берётся ДО WAKE_LOCK и
//! отпускается до сна: порядок permission_backend → WAKE_LOCK не
//! инвертируется.
//!
//! ЧТЕНИЕ СЛОВА. Физика фиксируется ДО WAKE_LOCK (аналог get_futex_key
//! в Linux): is_user_range + translate_user с U/S-семантикой отвергают
//! ядерные VA (COPYIN-гейт, traits/memory::translate_user). Ключ обязан
//! быть публичным (вне резервов is_kernel_wait_object) — иначе ring3
//! смог бы встать в очередь доставочных механизмов ядра.
//!
//! ОГРАНИЧЕНИЯ v1 (сознательные):
//!   - страница НЕ пинится: UNMOUNT/FREE_PAGES партнёра в окне
//!     «translate → сон» оставит pred читать вышедшую страницу. v2 —
//!     флаг wait_pins в VmapEntry по образцу dma_pins (FREE_PAGES →
//!     E_BUSY, прецедент IOMMU_MAP_DMA_VA);
//!   - дедлайна нет: v2 — task::deadline::register по образцу
//!     IPC-таймаутов; резолвер обязан ветвиться по диапазону object_id
//!     (futex-ключи — публичные, IPC — резервы);
//!   - слово 32-битное, чтение (translate_user for_write = false).

use crate::{
    lctl::LocalKernelCTL,
    traits::{
        ArchImplementation,
        memory::{MemoryInterfaceUserspace, is_user_range, phys_to_virt},
        scheduller::WaitModel,
        syscall::{SyscallDomain, syscall_result as res},
    },
};
use syscall_macros::SyscallArguments;

use super::syscall_task::{DomainScheduler, is_kernel_wait_object};

#[derive(SyscallArguments)]
pub struct SyscallFutexWait {
    /// Публичный wait-ключ (вне резервов ядра; обе задачи — один ключ,
    /// договорённость протокола: bootstrap-слот, константа или заголовок
    /// shm-региона).
    object_key: u64,
    /// VA 4-байтового слова в памяти ВЫЗЫВАЮЩЕЙ задачи (shm-регион).
    uaddr: u64,
    /// Ожидаемое значение: спать только если *uaddr == expected.
    expected: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallFutexWake {
    /// Публичный wait-ключ (симметричен WAIT).
    object_key: u64,
    /// Сколько ждущих разбудить (клампится в 64 — защита от спам-будок).
    nr: u64,
}

/// Валидация публичного ключа: не резерв ядра и не ноль.
fn key_is_public(key: u64) -> bool {
    key != 0 && !is_kernel_wait_object(key as usize)
}

/// Кламп числа пробуждений.
fn clamp_nr(nr: u64) -> usize {
    (nr as u32).min(64) as usize
}

/// 53: FUTEX_WAIT(key, uaddr, expected).
///
/// Возврат 0 в ОБОИХ исходах («спал и разбужен» / «предикат сработал до
/// сна») — спурийные пробуждения суть контракт примитива (как в Linux);
/// вызывающий цикл обязан перепроверять значение.
impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallFutexWait> {
    const SYSCALL_ID: usize = 53;

    type Args = SyscallFutexWait;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.expected > u32::MAX as u64 || !key_is_public(args.object_key) {
            return res::E_INVALID_ARG;
        }

        // Фиксация слова (ДО WAKE_LOCK): гейт ядерных VA + USER-семантика.
        let access = self.0.permission_backend.lock();
        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };
        let umap = gtcb.userspace_map();
        if !is_user_range(args.uaddr as usize, 4) {
            return res::E_INVALID_ARG;
        }
        let Some(word_phys) = umap.translate_user(args.uaddr as usize, false) else {
            return res::E_INVALID_ARG;
        };
        drop(access);
        if word_phys % 4 != 0 {
            return res::E_INVALID_ARG;
        }
        let word_ptr = phys_to_virt(word_phys) as *const u32;
        let expected = args.expected as u32;

        // Предикат ПОД WAKE_LOCK (внутри scheduler_block_on_object_if):
        // true → задача НЕ засыпает (событие уже случилось). Чтение —
        // volatile через HHDM, локов внутри нет.
        // SAFETY: word_ptr — живая 4-байтовая ячейка региона задачи,
        // валидирована is_user_range + translate_user выше; страница не
        // пинится — ограничение v1 (см. модульный док).
        let _slept = lctl.scheduler_block_on_object_if(
            args.object_key as usize,
            WaitModel::OneShot,
            || unsafe { core::ptr::read_volatile(word_ptr) == expected },
        );
        res::OK
    }
}

/// 54: FUTEX_WAKE(key, nr) — до nr OneShot-пробуждений ключа.
///
/// Симметричен SCHED_RELEASE_OBJECT (syscall 4), но: (а) nr-кратность,
/// (б) тот же гейт ключа, что у WAIT. Кросс-ядерное пробуждение даёт
/// release_object_global внутри scheduler_release_object (Resched-IPI).
impl<A: ArchImplementation> SyscallDomain for DomainScheduler<A, SyscallFutexWake> {
    const SYSCALL_ID: usize = 54;

    type Args = SyscallFutexWake;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        if !key_is_public(args.object_key) {
            return res::E_INVALID_ARG;
        }
        for _ in 0..clamp_nr(args.nr) {
            lctl.scheduler_release_object(args.object_key as usize);
        }
        res::OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Публичные ключи (в т.ч. рекомендованная база модуля dekker.rs)
    /// проходят, резервы ядра — отвергаются.
    #[test]
    fn key_space_rejects_kernel_reserved_ranges() {
        assert!(key_is_public(0x0100_0000)); // KEY_BASE dekker.rs
        assert!(key_is_public(0xAA)); // mt_test/mt_waker (публичный)
        assert!(!key_is_public(0));
        assert!(!key_is_public(63)); // id < 64
        assert!(!key_is_public(crate::ipc::endpoint::IPC_OBJECT_BASE as u64));
        assert!(!key_is_public((crate::ipc::fault::FAULT_OBJECT_BASE) as u64));
    }

    /// Кламп nr: 0 — «не будить никого» (валидный no-op), переполнение
    /// u32 и превышение 64 — режется.
    #[test]
    fn wake_nr_is_clamped() {
        assert_eq!(clamp_nr(0), 0);
        assert_eq!(clamp_nr(1), 1);
        assert_eq!(clamp_nr(1000), 64);
        assert_eq!(clamp_nr(u64::MAX), 64);
    }
}
