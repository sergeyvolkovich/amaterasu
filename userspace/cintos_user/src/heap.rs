//! GlobalAlloc поверх [`crate::arena`]: рост кучи через ALLOC_PAGES.
//!
//! ## Как это работает (и почему не mmap)
//!
//! В NOMAD нет mmap: динамическая память задачи — сисколлы ядра.
//! [`crate::arena::HeapArena`] стартует ПУСТОЙ (нулевой резерв:
//! задача без коллекций не платит ни страницы, ни сисколла), а при
//! первом неудачном выделении обвязка просит ядро окно страниц:
//!
//! ```text
//! ALLOC_PAGES(n) -> VA (ядро выделило физику + замапило в задачу,
//!                      зарядило квоту MEMORY_ALLOC неймспейса)
//!      -> arena::add_chunk(va, n * PAGE_SIZE) -> retry
//! ```
//!
//! Стратегия роста: max(4 страницы, потребность) — мелкие запросы
//! растят кучу по 16 КиБ (амортизация сисколлов), крупные — ровно
//! сколько нужно (+запас на служебные слова). FREE_PAGES обвязка НЕ
//! зовёт вовсе: усечения кучи нет, вся память возвращается ядру при
//! уничтожении задачи (SCHED_DESTROY_TASK) — это исключает класс ошибок
//! «блок арены пережил FREE_PAGES своего чанка».
//!
//! ## Отказ кучи
//!
//! E_QUOTA/E_SLAB от ядра -> alloc возвращает null -> `handle_alloc_error`
//! -> паник-хендлер cintos_user (crt0) -> аварийный self-exit. Для
//! серверов NOMAD это честная семантика: без памяти задача не живет.
//!
//! ## Однопоточность
//!
//! Арена без локов: задача NOMAD однопоточна. GlobalAlloc требует
//! Sync — даём его явно с обоснованием (см. unsafe impl Sync ниже).

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi;
use crate::arena::HeapArena;
use crate::syscall;

/// Размер страницы (auxv AT_PAGESZ; 4096 до первого чтения — порт
/// x86_64 работает на 4К, bootstrap уточняет при первом аллоке).
static PAGE_SIZE: AtomicU64 = AtomicU64::new(4096);

/// Минимальный шаг роста кучи (страниц). 4 * 4 КиБ = 16 КиБ.
const MIN_GROW_PAGES: u64 = 4;

/// Запас на служебные слова блока (hdr+маркер+footer+округление) при
/// расчёте потребности в страницах.
const OVERHEAD_SLACK: usize = 64;

pub use crate::arena::{ArenaError as HeapError, ArenaStats};

/// Снапшот состояния кучи (для диагностики/демо).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapStats {
    /// Полный размер всех чанков (байт).
    pub chunk_bytes: usize,
    /// Число чанков (= успешных ростов; стартовый резерв отсутствует).
    pub chunks: usize,
    /// Свободно (полные размеры свободных блоков).
    pub free_bytes: usize,
    /// Занято (полные размеры живых блоков).
    pub used_bytes: usize,
}

impl From<ArenaStats> for HeapStats {
    fn from(s: ArenaStats) -> Self {
        Self {
            chunk_bytes: s.chunk_bytes,
            chunks: s.chunks,
            free_bytes: s.free_bytes,
            used_bytes: s.used_bytes,
        }
    }
}

/// Глобальный аллокатор NOMAD-задачи: арена + рост через ALLOC_PAGES.
pub struct KernelHeap {
    arena: UnsafeCell<HeapArena>,
}

// SAFETY: задача NOMAD однопоточна (ядро не прерывает середину
// аллокации: IRQ в ring3 сохраняет контекст и возвращается в тот же
// поток; SYSCALL-путей изнутри аллокации нет). Синхронизация не нужна;
// Sync требуется трейтом GlobalAlloc.
unsafe impl Sync for KernelHeap {}

// SAFETY: статический глобал без инициализации — арена стартует
// пустой (нулевой резерв); первый аллок зовёт ALLOC_PAGES.
#[global_allocator]
static HEAP: KernelHeap = KernelHeap::new();

impl KernelHeap {
    const fn new() -> Self {
        Self {
            arena: UnsafeCell::new(HeapArena::new()),
        }
    }

    /// Снапшот счётчиков кучи (для логов/демо; None — арена повреждена
    /// вызовом из не-задачного контекста, что в однопоточном мире не бывает).
    pub fn stats(&self) -> HeapStats {
        // SAFETY: однопоточность (см. unsafe impl Sync).
        let arena = unsafe { &*self.arena.get() };
        arena.stats().into()
    }

    /// Снапшот счётчиков кучи ТЕКУЩЕЙ задачи (статический глобал).
    pub fn current_stats() -> HeapStats {
        // SAFETY: однопоточность; HEAP — единственный экземпляр.
        unsafe { (*core::ptr::addr_of!(HEAP)).stats() }
    }

    /// Размер страницы ядра (уточняется по auxv при первом аллоке).
    pub fn page_size() -> usize {
        PAGE_SIZE.load(Ordering::Relaxed) as usize
    }

    /// Стратегия роста: сколько страниц запросить у ядра под `layout`.
    fn grow_pages(layout: Layout, page: usize) -> u64 {
        let need = layout.size() + OVERHEAD_SLACK;
        let exact = need.div_ceil(page) as u64;
        exact.max(MIN_GROW_PAGES)
    }
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: однопоточность (см. unsafe impl Sync).
        let arena = unsafe { &mut *self.arena.get() };
        let p = arena.alloc(layout);
        if !p.is_null() {
            return p;
        }

        // ── Рост: ALLOC_PAGES -> add_chunk -> retry ──
        // Уточняем размер страницы из auxv (AT_PAGESZ) один раз.
        if PAGE_SIZE.load(Ordering::Relaxed) == 4096 {
            if let Some(ps) = crate::crt0::auxv_get(abi::auxv::AT_PAGESZ) {
                if ps != 0 {
                    PAGE_SIZE.store(ps, Ordering::Relaxed);
                }
            }
        }
        let page = PAGE_SIZE.load(Ordering::Relaxed) as usize;
        let pages = Self::grow_pages(layout, page);

        // SAFETY: сисколл по конвенции crate::abi.
        let va = unsafe { syscall::syscall1(abi::nr::ALLOC_PAGES, pages) };
        match syscall::check(va) {
            Err(_e) => {
                // E_QUOTA / E_RIGHTS_DENIED / E_SLAB / E_IDS_EXHAUSTED:
                // ядру нечего дать — null -> handle_alloc_error -> паника.
                core::ptr::null_mut()
            }
            Ok(base) => {
                // SAFETY: ядро вернуло page-aligned VA-окно pages страниц,
                // замапленное в адресное пространство задачи.
                // Ошибки add_chunk (нулевая база/невыровненность/размер) —
                // признак бага ядра/обвязки: превращаем в отказ аллока.
                if arena
                    .add_chunk(base as *mut u8, pages as usize * page)
                    .is_err()
                {
                    return core::ptr::null_mut();
                }
                arena.alloc(layout)
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: однопоточность; контракт GlobalAlloc (ptr из alloc).
        unsafe { (*self.arena.get()).dealloc(ptr, layout) };
    }
}
