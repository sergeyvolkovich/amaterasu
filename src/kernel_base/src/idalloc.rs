//! Пулы аппаратных идентификаторов IOMMU (domain-ID, PASID) на slab-очереди.
//!
//! ЗАЧЕМ (v2 IOMMU): прежняя реализация — атомарный счётчик + ФИКСИРОВАННЫЙ
//! стек возвращённых id `[Option<u16>; 16]`. Три дефекта:
//!   1. переполненный стек МОЛЧА терял id (free при полном стеке — no-op),
//!      чурнинг драйверов истощал пул;
//!   2. у AMD-Vi пул PASID был ОДИН с пулом domain-ID (`next_domain_id` /
//!      `free_ids`) — два независимых аппаратных пространства делили один
//!      счётчик: 64K доменов съедали все PASID и наоборот;
//!   3. O(n) поиск свободного слота стека под спинлоком.
//!
//! КАК ТЕПЕРЬ: выдача — bump-счётчик, возврат — slab-очередь
//! [`LLSlabIO`] (тот же паттерн reusable-очередей AccessManager: узлы
//! в slab-аллокаторе, память растёт динамически, потерь id нет).
//! Сложность alloc/free — O(1).
//!
//! СПЕЦИФИКА SLAB: узел очереди выделяется из `SlabCache` постранично
//! (4096-байтные slab-страницы, по много узлов на страницу) — пул не
//! резервирует память заранее и не ограничен фиксированным стеком.
//!
//! ЛЕНИВАЯ ИНИЦИАЛИЗАЦИЯ: slab-хуки ядра (`init_hooks::init_allocator`)
//! поднимаются ПОЗЖЕ `iommu_early_init` (см. boot-путь kernel_limine),
//! поэтому `LLSlabIO::new()` нельзя звать в конструкторе пула. Очередь
//! создаётся при первом использовании; если slab в тот момент недоступен
//! (OOM), пул НАВСЕГДА деградирует до bump-only (free теряет id — то же
//! поведение, что у старого стека при переполнении, но только при OOM).

use core::sync::atomic::{AtomicU32, Ordering};

use spin::Once;
use spin::mutex::SpinMutex;

use crate::collection::LLSlabIO;

/// Slab-очередь возвратов, пригодная для Sync-юнитов.
///
/// LLSlabIO с NoLock-кэшем формально !Send/!Sync: контракт NoLock — «весь
/// доступ к slab-кэшу идёт под ВНЕШНИМ локом». Обёртка документирует и
/// обеспечивает этот контракт: единственный доступ к очереди и её slab-кэшу
/// (push_back = alloc узла, pop_front = free узла) идёт под нашей
/// SpinMutex внутри IdPool::alloc/release. Поэтому Send законен — Sync
/// обеспечивается самим SpinMutex.
struct SendQueue(SpinMutex<LLSlabIO<u64, false>>);
// SAFETY: см. выше — NoLock-контракт закрыт SpinMutex обёртки; все методы
// (&self) блокируют её, так что конкурентный &-доступ сериализован.
unsafe impl Send for SendQueue {}
unsafe impl Sync for SendQueue {}

impl SendQueue {
    fn new() -> Option<Self> {
        LLSlabIO::new().ok().map(SpinMutex::new).map(Self)
    }

    fn pop_front(&self) -> Option<u64> {
        self.0.lock().pop_front()
    }

    fn push_back(&self, id: u64) -> bool {
        self.0.lock().push_back(id).is_ok()
    }
}

/// Пул идентификаторов: bump-выдача + slab-очередь возвратов.
///
/// Инвариант владения: `release(id)` законен только для id, выданного
/// `alloc()` и НЕ выданного повторно (строгое владение у вызывающего —
/// двойной release вернул бы id дважды; контракт как у slab-freelist).
pub struct IdPool {
    /// Верхняя (исключающая) граница пула: железо (CAP.ND / размер
    /// PASID-таблицы / 1<<16 у AMD).
    limit: u32,
    /// Следующий невыданный id (0 резервируется вызывающей стороной:
    /// DID 0 и PASID 0 — «без домена/контекста»).
    next: AtomicU32,
    /// Slab-очередь возвращённых id. `None` — slab недоступен (деградация).
    free: Once<Option<SendQueue>>,
}

impl IdPool {
    /// Пул на `[1, limit)` (0 — резерв вызывающей стороны).
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            next: AtomicU32::new(1),
            free: Once::new(),
        }
    }

    /// Slab-очередь возвратов (лениво; см. документацию модуля).
    fn free_queue(&self) -> Option<&SendQueue> {
        // spin 0.12: call_once возвращает &Option<T> (инициализация под
        // капотом); as_ref() разворачивает внешний Option.
        self.free.call_once(SendQueue::new).as_ref()
    }

    /// Выдаёт id или `None`, если пул исчерпан.
    pub fn alloc(&self) -> Option<u32> {
        // Сначала — возвращённые (переиспользование до роста счётчика).
        if let Some(queue) = self.free_queue() {
            if let Some(id) = queue.pop_front() {
                return Some(id as u32);
            }
        }
        // Bump-выдача: fetch_add уникален между ядрами; на исчерпании
        // счётчик клипсируется (последующие alloc не откатывают его назад).
        let id = self.next.fetch_add(1, Ordering::AcqRel);
        if id >= self.limit {
            self.next.store(self.limit, Ordering::Release);
            None
        } else {
            Some(id)
        }
    }

    /// Возвращает id в пул. При недоступном slab id теряется
    /// (деградация — см. документацию модуля).
    pub fn release(&self, id: u32) {
        if id == 0 || id >= self.limit {
            return; // резерв/вне пула — игнор (защита от мусора)
        }
        if let Some(queue) = self.free_queue() {
            // OOM slab-узла: id теряется (best-effort, как и прежний стек).
            queue.push_back(id as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{FrameAllocator, MemoryPTR, PAGE_SIZE, init_hooks, set_hhdm_offset};
    use core::sync::atomic::AtomicUsize;

    struct TestFrames(AtomicUsize);
    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));

    impl FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
            let first = self.0.fetch_add(count, core::sync::atomic::Ordering::SeqCst);
            MemoryPTR::new(first * PAGE_SIZE, count)
        }
        fn deallocate_pages(&self, _ptr: MemoryPTR) {}
    }

    static std_once: std::sync::Once = std::sync::Once::new();
    fn ensure_slab() {
        std_once.call_once(|| {
            let mem = unsafe {
                // Странично выровненный leaks-буфер под HHDM + slab-страницы.
                let layout = std::alloc::Layout::from_size_align(16 * 1024 * 1024, PAGE_SIZE)
                    .expect("layout");
                let ptr = std::alloc::alloc_zeroed(layout);
                assert!(!ptr.is_null(), "oom");
                core::slice::from_raw_parts_mut(ptr, 16 * 1024 * 1024 / PAGE_SIZE)
            };
            set_hhdm_offset(mem.as_ptr() as usize);
            init_hooks::init_allocator(&FRAMES);
        });
    }

    #[test]
    fn pool_bump_and_reuse() {
        ensure_slab();
        let pool = IdPool::new(8);
        assert_eq!(pool.alloc(), Some(1));
        assert_eq!(pool.alloc(), Some(2));
        pool.release(1);
        // Возвращённый id выдаётся первым (slab-очередь).
        assert_eq!(pool.alloc(), Some(1));
        assert_eq!(pool.alloc(), Some(3));
        // Исчерпание: [4..8) добираются, дальше None.
        for _ in 0..4 {
            assert!(pool.alloc().is_some());
        }
        assert_eq!(pool.alloc(), None);
        // release вне пула/резерв — игнор без паники.
        pool.release(0);
        pool.release(8);
        pool.release(u32::MAX);
        // Возврат живого id снова доступен.
        pool.release(2);
        assert_eq!(pool.alloc(), Some(2));
    }
}
