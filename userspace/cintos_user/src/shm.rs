//! shm — длинные IPC-сообщения через РАЗДЕЛЯЕМУЮ ПАМЯТЬ (без ядра).
//!
//! АРХИТЕКТУРА (решение пользователя: датапуть — целиком юзерспейс):
//!   ЯДРО участвует ТОЛЬКО в разовой настройке:
//!     - отправитель: ALLOC_PAGES + CAP_CREATE_SHARED (физику резолвит
//!       ядро — юзерспейс адресов не видит) + пересылка capability
//!       IPC map-item'ом;
//!     - получатель: MOUNT_CAP_REGION — те же физические фреймы
//!       появляются в его пространстве (внешний маппинг).
//!   ДАЛЬШЕ ядро НЕ ВИДИТ данные: SPSC-кольцо (однократная запись
//!   производителя / однократное чтение потребителя) в общих страницах;
//!   короткие IPC-«двери» (doorbell) сигнализируют готовность —
//!   полезная нагрузка произвольного размера ядром не копируется.
//!
//! WIRE-ФОРМАТ кольца (u64-слова, little-endian; пишет производитель
//! при инициализации, далее — атомарные индексы):
//!   [0] magic SHM_RING_MAGIC
//!   [1] capacity — ёмкость области данных (байт)
//!   [2] head — атомарно, ТОЛЬКО производитель: всего записано байт
//!   [3] tail — атомарно, ТОЛЬКО потребитель: всего освобождено байт
//!   [4..] данные: кадры [len: u64][len байт] по модулю capacity
//!
//! ПОРЯДОК ПАМЯТИ (Release/Acquire): производитель пишет кадр, fence
//! (Release), публикует head; потребитель читает head (Acquire), читает
//! кадр, fence (Acquire), публикует tail (Release); производитель читает
//! tail (Acquire). На x86_64 (TSO) корректно; волатильность данных
//! обеспечивают копии через сырые указатели по обе стороны кольца.
//!
//! ОГРАНИЧЕНИЕ v1 (задокументировано): внешний маппинг получателя не
//! держит ссылку на фреймы владельца — FREE_PAGES/смерть отправителя
//! ДО окончания потребителя оставят у него висячие страницы
//! (полная модель отзыва — отдельный этап; демо живёт по протоколу
//! «отправитель ждёт финального ACK»).

use core::sync::atomic::{AtomicU64, Ordering};

/// Волшебное слово кольца (версия 1).
pub const SHM_RING_MAGIC: u64 = 0x5348_4D31_0000_0001;

/// Метки IPC-«дверей» протокола shm (кастомный диапазон демо).
pub mod labels {
    /// Предложение shm: capability региона передана map-item'ом,
    /// payload = глобальный id capability (u64 LE).
    pub const SHM_OFFER: u64 = 0xC1A0_0011;
    /// Получатель смонтировал регион, кольцо прочитано, готов принимать.
    pub const SHM_READY: u64 = 0xC1A0_0012;
    /// Дверь «в кольце есть кадр» (payload = порядковый номер).
    pub const SHM_DATA: u64 = 0xC1A0_0013;
    /// Дверь «кадр потреблён» (payload = освобождено байт).
    pub const SHM_ACK: u64 = 0xC1A0_0014;
    /// Финал: payload = контрольная сумма потребителя (u64 LE).
    pub const SHM_DONE: u64 = 0xC1A0_0015;
}

/// Слова заголовка кольца ДО области данных.
pub const HDR_WORDS: usize = 4;

// ─── Кольцевые копии (wraparound) ────────────────────────────────────────────

/// Кладёт u64 в кольцо по байтовому смещению `at` (без выравнивания
/// относительно начала данных: кадры идут вплотную).
fn ring_write_u64(data: *mut u8, at: u64, cap: u64, value: u64) {
    let bytes = value.to_le_bytes();
    for (i, b) in bytes.iter().enumerate() {
        // SAFETY: (at + i) % cap внутри области данных живого маппинга.
        unsafe { data.add(((at + i as u64) % cap) as usize).write_volatile(*b) };
    }
}

/// Читает u64 из кольца по байтовому смещению `at`.
fn ring_read_u64(data: *const u8, at: u64, cap: u64) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        // SAFETY: как ring_write_u64.
        *b = unsafe { data.add(((at + i as u64) % cap) as usize).read_volatile() };
    }
    u64::from_le_bytes(bytes)
}

/// Копирует `bytes` в кольцо по смещению `at` (двумя сегментами на стыке).
fn ring_write(data: *mut u8, at: u64, cap: u64, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        // SAFETY: (at + i) % cap внутри области данных.
        unsafe { data.add(((at + i as u64) % cap) as usize).write_volatile(*b) };
    }
}

/// Копирует `len` байт из кольца по смещению `at` в `out`.
fn ring_read(data: *const u8, at: u64, cap: u64, out: &mut [u8]) {
    for (i, o) in out.iter_mut().enumerate() {
        // SAFETY: (at + i) % cap внутри области данных.
        *o = unsafe { data.add(((at + i as u64) % cap) as usize).read_volatile() };
    }
}

// ─── Общие поля кольца ───────────────────────────────────────────────────────

/// Ссылки на атомарные индексы кольца в общих страницах.
struct RingIndex {
    head: &'static AtomicU64,
    tail: &'static AtomicU64,
    /// Указатель на область данных (сразу за заголовком).
    data: *mut u8,
    /// Ёмкость области данных (байт).
    capacity: u64,
}

// SAFETY: кольцо живёт в разделяемых страницах, замапленных в адресном
// пространстве владельца структуры; указатель валиден, пока жив маппинг.
unsafe impl Send for RingIndex {}

impl RingIndex {
    /// Разбор заголовка отображённых страниц (общий код open-путей).
    /// `None` — чужие/битые страницы (magic не совпал) или нулевая
    /// ёмкость. Индексы НЕ трогает — можно переоткрывать живое кольцо.
    ///
    /// # Safety
    /// `va` обязан указывать на живой маппинг `pages` страниц, общий
    /// с производителем (одни и те же физические фреймы).
    unsafe fn open_existing(va: usize, pages: usize) -> Option<RingIndex> {
        if pages == 0 {
            return None;
        }
        let base = va as *mut u8;
        // SAFETY: заголовок (4 слова) — первая страница маппинга.
        let magic = unsafe { (base as *const u64).read_volatile() };
        if magic != SHM_RING_MAGIC {
            return None;
        }
        // SAFETY: см. выше.
        let capacity = unsafe { (base.add(8) as *const u64).read_volatile() };
        let data_bytes = (pages * 4096 - HDR_WORDS * 8) as u64;
        if capacity == 0 || capacity > data_bytes {
            return None;
        }
        Some(RingIndex {
            // SAFETY: смещения 16/24 выровнены на 8 внутри страницы.
            head: unsafe { &*(base.add(16) as *const AtomicU64) },
            tail: unsafe { &*(base.add(24) as *const AtomicU64) },
            data: unsafe { base.add(HDR_WORDS * 8) },
            capacity,
        })
    }

    /// Байт занято (head − tail).
    fn used(&self) -> u64 {
        self.head.load(Ordering::Acquire) - self.tail.load(Ordering::Acquire)
    }

    /// Байт свободно.
    fn free(&self) -> u64 {
        self.capacity - self.used()
    }
}

// ─── Производитель ───────────────────────────────────────────────────────────

/// Пишущая сторона кольца (владелец страниц).
pub struct Producer {
    ring: RingIndex,
}

impl Producer {
    /// Инициализирует кольцо в СОБСТВЕННЫХ страницах (результат
    /// ALLOC_PAGES): пишет заголовок, обнуляет индексы. Ёмкость — все
    /// страницы минус заголовок.
    ///
    /// # Safety
    /// `va` — живая собственная аллокация `pages` страниц (ALLOC_PAGES).
    pub unsafe fn init(va: usize, pages: usize) -> Option<Producer> {
        if pages == 0 {
            return None;
        }
        let base = va as *mut u8;
        let capacity = (pages * 4096 - HDR_WORDS * 8) as u64;
        // SAFETY: заголовок в первой странице собственной аллокации.
        unsafe {
            (base as *mut u64).write_volatile(SHM_RING_MAGIC);
            (base.add(8) as *mut u64).write_volatile(capacity);
            (base.add(16) as *mut u64).write_volatile(0);
            (base.add(24) as *mut u64).write_volatile(0);
        }
        core::sync::atomic::fence(Ordering::Release);
        Some(Producer {
            ring: RingIndex {
                head: unsafe { &*(base.add(16) as *const AtomicU64) },
                tail: unsafe { &*(base.add(24) as *const AtomicU64) },
                data: unsafe { base.add(HDR_WORDS * 8) },
                capacity,
            },
        })
    }

    /// Открывает УЖЕ ИНИЦИАЛИЗИРОВАННОЕ кольцо в собственных страницах
    /// (после [`Producer::init`] — например, в другом вызове C-ABI, где
    /// контекст между вызовами не хранится). Индексы НЕ трогает.
    ///
    /// # Safety
    /// `va` — живая собственная аллокация `pages` страниц, кольцо в ней
    /// инициализировано (magic на месте).
    pub unsafe fn open(va: usize, pages: usize) -> Option<Producer> {
        // SAFETY: контракт вызывающего — инициализированное кольцо.
        let ring = unsafe { RingIndex::open_existing(va, pages)? };
        Some(Producer { ring })
    }

    /// Пытается положить кадр [len][data]. `false` — кольцо переполнено
    /// (потребитель отстаёт): вызывающий ждёт ACK-дверь и повторяет.
    pub fn push(&mut self, data: &[u8]) -> bool {
        let need = 8 + data.len() as u64;
        if need > self.ring.free() {
            return false;
        }
        let head = self.ring.head.load(Ordering::Relaxed);
        let at = head % self.ring.capacity;
        ring_write_u64(self.ring.data, at, self.ring.capacity, data.len() as u64);
        ring_write(self.ring.data, at + 8, self.ring.capacity, data);
        // Публикация кадра: данные ДО индекса (Release).
        self.ring.head.store(head + need, Ordering::Release);
        true
    }

    /// Свободно байт (диагностика).
    pub fn free(&self) -> u64 {
        self.ring.free()
    }
}

// ─── Потребитель ─────────────────────────────────────────────────────────────

/// Читающая сторона кольца (внешний маппинг общих страниц).
pub struct Consumer {
    ring: RingIndex,
}

impl Consumer {
    /// Открывает кольцо в смонтированном регионе (MOUNT_CAP_REGION).
    ///
    /// # Safety
    /// `va` — живой внешний маппинг `pages` страниц, инициализированный
    /// производителем (после его Producer::init).
    pub unsafe fn open(va: usize, pages: usize) -> Option<Consumer> {
        // SAFETY: контракт вызывающего — живой общий маппинг.
        let ring = unsafe { RingIndex::open_existing(va, pages)? };
        Some(Consumer { ring })
    }

    /// Достаёт очередной кадр в `out`; возврат — длина кадра.
    /// `None` — кадров нет (ждём дверь SHM_DATA) ИЛИ кадр крупнее буфера
    /// (протокольная ошибка демо — буферы сторон согласованы).
    pub fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        let head = self.ring.head.load(Ordering::Acquire);
        let tail = self.ring.tail.load(Ordering::Relaxed);
        if head == tail {
            return None;
        }
        let at = tail % self.ring.capacity;
        let len = ring_read_u64(self.ring.data, at, self.ring.capacity) as usize;
        if len > out.len() {
            return None;
        }
        let buf = &mut out[..len];
        ring_read(self.ring.data, at + 8, self.ring.capacity, buf);
        // Освобождение кадра: данные прочитаны ДО публикации tail.
        self.ring.tail.store(tail + 8 + len as u64, Ordering::Release);
        Some(len)
    }

    /// Занято байт (диагностика).
    pub fn used(&self) -> u64 {
        self.ring.used()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Полный цикл кольца на хосте: init → push × N (с переполнением и
    /// ожиданием потребителя) → pop × N, контроль содержимого на стыке
    /// (wraparound) буфера.
    #[test]
    fn spsc_ring_roundtrip_with_wraparound() {
        // Две страницы «физики»: capacity = 8192 - 32 = 8160 байт.
        let pages = 2usize;
        let mem: &'static mut [u8] = {
            let layout =
                std::alloc::Layout::from_size_align(pages * 4096, 4096).unwrap();
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            unsafe { core::slice::from_raw_parts_mut(ptr, pages * 4096) }
        };
        let va = mem.as_mut_ptr() as usize;

        // SAFETY: mem — живая выровненная «аллокация» на pages страниц.
        let mut prod = unsafe { Producer::init(va, pages) }.expect("init");
        // SAFETY: то же отображение для потребителя (в тесте — тот же VA).
        let mut cons = unsafe { Consumer::open(va, pages) }.expect("open");
        assert_eq!(prod.free(), (pages * 4096 - HDR_WORDS * 8) as u64);

        // Кадры по 1000 байт: 8 кадров = 8064 байт — влезают; 9-й (8168)
        // уже нет (need = 8 + 1000).
        let mut frame = [0u8; 1000];
        for round in 0..8u64 {
            for (i, b) in frame.iter_mut().enumerate() {
                *b = (round as u8) ^ (i as u8);
            }
            assert!(prod.push(&frame), "кадр {round} должен влезть");
        }
        assert!(!prod.push(&frame), "9-й кадр обязан переполнить");

        // Потребление: содержимое совпадает, порядок сохранён.
        let mut out = [0u8; 1000];
        for round in 0..8u64 {
            let n = cons.pop(&mut out).expect("кадр в кольце");
            assert_eq!(n, 1000);
            for (i, b) in out.iter().enumerate() {
                assert_eq!(*b, (round as u8) ^ (i as u8), "round {round} byte {i}");
            }
        }
        assert!(cons.pop(&mut out).is_none(), "кольцо пусто");
        assert_eq!(prod.free(), (pages * 4096 - HDR_WORDS * 8) as u64);

        // Wraparound: head/tail ушли далеко за capacity — индексы
        // продолжаются, данные ложатся по модулю.
        for round in 8..24u64 {
            for (i, b) in frame.iter_mut().enumerate() {
                *b = (round as u8).wrapping_mul(7) ^ (i as u8);
            }
            assert!(prod.push(&frame));
            let n = cons.pop(&mut out).expect("кадр после стыка");
            assert_eq!(n, 1000);
            for (i, b) in out.iter().enumerate() {
                assert_eq!(*b, (round as u8).wrapping_mul(7) ^ (i as u8));
            }
        }

        // Переоткрытие живого кольца НЕ сбрасывает индексы
        // (контракт Producer::open для C-ABI).
        // SAFETY: кольцо живо.
        let mut prod2 = unsafe { Producer::open(va, pages) }.expect("reopen");
        assert!(prod2.push(b"tail"));
        let mut small = [0u8; 4];
        // SAFETY: кольцо живо.
        let mut cons2 = unsafe { Consumer::open(va, pages) }.expect("reopen");
        assert_eq!(cons2.pop(&mut small), Some(4));
        assert_eq!(&small, b"tail");
    }
}
