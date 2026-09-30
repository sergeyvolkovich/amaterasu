//! Арена-аллокатор userspace: чистое ядро без сисколлов (тестируется
//! на хосте); обвязка GlobalAlloc с ростом через ALLOC_PAGES — в
//! [`crate::heap`].
//!
//! ## Устройство памяти
//!
//! Аллокатор получает чанки от ядра (ALLOC_PAGES возвращает VA-окно;
//! окна между вызовами НЕ обязаны быть смежными) и ведёт ЕДИНЫЙ
//! address-ordered free-list по всем чанкам. Каждый блок:
//!
//! ```text
//! блок (total кратен 16, блок 16-выровнен):
//!   +0        hdr: total | PF     PF (bit0) = «предыдущий блок свободен»
//!   +8        слот-маркер: АДРЕС блока (восстановление блока по payload
//!             при dealloc; у свободных блоков здесь next-ссылка списка)
//!   +16..     payload
//!   конец-8   footer: total (ТОЛЬКО у свободных — обратный проход)
//! ```
//!
//! Свободный блок несёт в payload ссылки next/prev (двусвязный список,
//! O(1)-удаление) и footer для коалесценции назад. В конце чанка —
//! СЕНТИНЕЛ (16 Б, hdr = 16): реальным свободным блоком он не бывает
//! (size < MIN_TOTAL отсекает слияние), поэтому проверка соседа справа
//! никогда не выходит за чанк.
//!
//! ## Инвариант флага PF
//!
//! hdr(b) bit0 = 1 ⟺ блок ПЕРЕД b свободен. Выставляется при free,
//! снимается при выделении; forward-слияние для соседа b+total
//! проверяет (PF) И (size ≥ MIN_TOTAL) — второе условие отличает
//! свободный блок от сентинела.
//!
//! ## Политики
//!
//!   - first-fit по address-ordered списку (детерминизм + локальность:
//!     соседние по адресу блоки сливаются);
//!   - хвост расщепляется только если остаток ≥ MIN_TOTAL (меньший
//!     остаётся хвостовым балластом и вернётся при free);
//!   - выравнивание > 16 (редкое: коллекции используют ≤ 16) —
//!     овер-аллокация с балластом в голове, БЕЗ расщепления головы
//!     (балласт вернётся при free всего блока);
//!   - память НЕ возвращается ядру (FREE_PAGES не зовётся): усечения
//!     нет, вся память задачи уходит ядру при SCHED_DESTROY_TASK —
//!     это исключает разъезд блоков арены с FREE_PAGES по базовому VA.
//!
//! ## Однопоточность
//!
//! Состояние без локов: задача NOMAD однопоточна (ядро не прерывает
//! середину аллокации: IRQ в ring3 сохраняет контекст и возвращается в
//! тот же поток — см. kernel_x86::cswitch, FPU-модель).

use core::alloc::Layout;

/// Заголовок/маркер/ссылки/футер — по 8 Б (u64-мир).
const WORD: usize = 8;
/// Заголовок блока (hdr) + слот-маркер.
const BLOCK_OVERHEAD: usize = 2 * WORD;
/// Footer свободного блока.
const FOOTER: usize = WORD;
/// Минимальный ПОЛНЫЙ размер блока: hdr + маркер + payload 16 Б
/// (next/prev свободного блока) + footer, с округлением до 16.
const MIN_TOTAL: usize = 48;
/// Сентинел в конце чанка: одно hdr-слово (size = SENTINEL_TOTAL).
const SENTINEL_TOTAL: usize = 2 * WORD;
/// Бит «предыдущий блок свободен» в hdr.
const PREV_FREE: usize = 1;

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    debug_assert!(a.is_power_of_two());
    (v + a - 1) & !(a - 1)
}

#[inline]
fn hdr_of(block: usize) -> usize {
    // SAFETY: блок валиден (контракт арены), hdr — первое слово.
    unsafe { (block as *const usize).read() }
}

#[inline]
fn set_hdr(block: usize, value: usize) {
    // SAFETY: блок валиден (контракт арены), hdr — первое слово.
    unsafe { (block as *mut usize).write(value) }
}

/// Запись слова по адресу (footer/маркер/сентинел).
///
/// # Safety
/// `addr` валиден и 8-выровнен (внутри чанка арены).
#[inline]
unsafe fn write_word(addr: usize, value: usize) {
    // SAFETY: контракт вызова выше.
    unsafe { (addr as *mut usize).write(value) }
}

/// Чтение слова по адресу (hdr-слоты, маркер, footer).
///
/// # Safety
/// `addr` валиден и 8-выровнен (внутри чанка арены).
#[inline]
unsafe fn read_word(addr: usize) -> usize {
    // SAFETY: контракт вызова выше.
    unsafe { (addr as *const usize).read() }
}

/// Прочитать пару ссылок свободного блока (+8 next, +16 prev).
#[inline]
fn links_of(block: usize) -> (usize, usize) {
    // SAFETY: свободный блок валиден; +8/+16 — внутри payload (≥ 16 Б).
    unsafe {
        let p = (block + WORD) as *const usize;
        (*p, *p.add(1))
    }
}

/// Записать пару ссылок свободного блока (+8 next, +16 prev).
///
/// # Safety
/// `block` — валидный свободный блок (payload ≥ 16 Б).
#[inline]
unsafe fn set_links(block: usize, next: usize, prev: usize) {
    // SAFETY: контракт вызова выше.
    unsafe {
        let p = (block + WORD) as *mut usize;
        p.write(next);
        p.add(1).write(prev);
    }
}

/// Поправить бит PF у блока, следующего за [block, block+size).
#[inline]
fn set_flag_of_next(block: usize, size: usize, prev_free: bool) {
    let nb = block + size;
    let h = hdr_of(nb);
    set_hdr(nb, if prev_free { h | PREV_FREE } else { h & !PREV_FREE });
}

/// Счётчики арены (для диагностики; [`HeapArena::stats`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArenaStats {
    /// Полный размер всех добавленных чанков (байт).
    pub chunk_bytes: usize,
    /// Число чанков (= успешные роста + стартовый).
    pub chunks: usize,
    /// Сумма ПОЛНЫХ размеров свободных блоков (вкл. служебные слова).
    pub free_bytes: usize,
    /// Сумма ПОЛНЫХ размеров живых аллокаций (вкл. служебные слова).
    pub used_bytes: usize,
}

/// Ошибки добавления чанка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaError {
    /// Чанк слишком мал (нет места даже для блока + сентинела).
    TooSmall,
    /// База не выровнена на 16 (ядро возвращает page-aligned VA —
    /// признак порчи указателя).
    Misaligned,
    /// Нулевая база.
    NullBase,
}

/// Арена: address-ordered двусвязный список свободных блоков поверх
/// чанков ядра. Голова списка — сырой usize (0 = пусто; блоки
/// 16-выровнены, младший бит адреса всегда 0).
pub struct HeapArena {
    head: usize,
    stats: ArenaStats,
}

impl Default for HeapArena {
    fn default() -> Self {
        Self::new()
    }
}

impl HeapArena {
    pub const fn new() -> Self {
        Self {
            head: 0,
            stats: ArenaStats {
                chunk_bytes: 0,
                chunks: 0,
                free_bytes: 0,
                used_bytes: 0,
            },
        }
    }

    /// Снапшот счётчиков.
    pub fn stats(&self) -> ArenaStats {
        self.stats
    }

    /// Добавить чанк `[base, base+len)` в арену: весь чанк становится
    /// одним свободным блоком + 16-байтовый сентинел в конце.
    pub fn add_chunk(&mut self, base: *mut u8, len: usize) -> Result<(), ArenaError> {
        let base = base as usize;
        if base == 0 {
            return Err(ArenaError::NullBase);
        }
        if base % 16 != 0 {
            return Err(ArenaError::Misaligned);
        }
        if len < MIN_TOTAL + SENTINEL_TOTAL {
            return Err(ArenaError::TooSmall);
        }
        let usable = len - SENTINEL_TOTAL;
        // Первый блок чанка: PF = 0 (перед ним нет нашего блока).
        set_hdr(base, usable);
        // SAFETY: первый блок свободен, payload ≥ MIN_TOTAL - 32 ≥ 16 Б.
        unsafe { set_links(base, 0, 0) };
        // Footer свободного блока.
        // SAFETY: конец usable-блока — внутри чанка, 8-выровнен.
        unsafe { write_word(base + usable - FOOTER, usable) };
        // Сентинел: size = 16, PF = 0.
        // SAFETY: сентинел — последние 16 Б чанка (len ≥ MIN_TOTAL + 16).
        unsafe { write_word(base + usable, SENTINEL_TOTAL) };

        self.insert_sorted(base);
        self.stats.chunk_bytes += len;
        self.stats.chunks += 1;
        self.stats.free_bytes += usable;
        Ok(())
    }

    /// Вставить свободный блок в address-ordered список.
    fn insert_sorted(&mut self, block: usize) {
        let head = self.head;
        if head == 0 || head > block {
            // Вставка в голову (или список пуст): prev = None.
            // SAFETY: block — свободный блок (payload ≥ 16 Б).
            unsafe { set_links(block, head, 0) };
            if head != 0 {
                // У прежней головы поправить prev (next не меняется).
                // SAFETY: head — валидный свободный блок.
                let (hnext, _) = links_of(head);
                unsafe { set_links(head, hnext, block) };
            }
            self.head = block;
            return;
        }
        // Ищем первый узел с next > block (вставка между cur и next).
        let mut cur = head;
        loop {
            let (next, prev) = links_of(cur);
            if next == 0 || next > block {
                // SAFETY: block/cur/next — валидные свободные блоки.
                unsafe {
                    set_links(block, next, cur);
                    set_links(cur, block, prev);
                }
                if next != 0 {
                    // SAFETY: next — валидный свободный блок.
                    let (nn, _) = links_of(next);
                    unsafe { set_links(next, nn, block) };
                }
                return;
            }
            cur = next;
        }
    }

    /// Удалить свободный блок из списка.
    fn unlink(&mut self, block: usize) {
        let (next, prev) = links_of(block);
        if prev != 0 {
            // SAFETY: сосед по списку валиден.
            let (_, pp) = links_of(prev);
            unsafe { set_links(prev, next, pp) };
        } else {
            self.head = next;
        }
        if next != 0 {
            // SAFETY: сосед по списку валиден.
            let (nn, _) = links_of(next);
            unsafe { set_links(next, nn, prev) };
        }
    }

    /// Выделить `layout.size()` байт с выравниванием `layout.align()`.
    /// Null — нет места (обвязка [`crate::heap`] растит кучу через
    /// ALLOC_PAGES и пробует снова).
    pub fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        if size == 0 {
            // Размер 0: выделяем минимальный живой блок (указатель
            // valid-for-dangling; GlobalAlloc разрешает любое значение).
            let fake = Layout::from_size_align(1, layout.align().max(1))
                .expect("size 1 align pow2");
            return self.alloc(fake);
        }
        let align = layout.align().max(16);
        debug_assert!(align.is_power_of_two());
        let padded = align_up(size, 16);

        // First-fit по address-ordered списку.
        let mut cur = self.head;
        while cur != 0 {
            let total = hdr_of(cur) & !PREV_FREE;
            // Payload: fast path (align ≤ 16) — cur+16 (уже 16-выровнен);
            // больший align — align_up(cur+16, align), балласт в голове.
            let payload = align_up(cur + BLOCK_OVERHEAD, align);
            let end_payload = cur + total - FOOTER;
            if payload + padded <= end_payload {
                return self.carve(cur, total, payload, padded);
            }
            // SAFETY: cur — валидный свободный блок.
            let (next, _) = links_of(cur);
            cur = next;
        }
        core::ptr::null_mut()
    }

    /// Расщепление выбранного свободного блока и выдача payload.
    /// Предусловие: payload+padded ≤ block+total-footer.
    fn carve(&mut self, block: usize, total: usize, payload: usize, padded: usize) -> *mut u8 {
        let prev_flag = hdr_of(block) & PREV_FREE;
        // Полный размер нашего блока: payload-смещение + данные + footer,
        // ОКРУГЛЕННЫЙ до 16 (footer 8 Б даёт остаток 8 mod 16 — добиваем
        // балластом, чтобы хвост (и все блоки) остались 16-выровненными;
        // балласт вернётся при free). Инвариант: my_total ≤ total
        // (payload+padded ≤ block+total-8 проверил вызывающий).
        let my_total = align_up((payload - block) + padded + FOOTER, 16);
        let tail = block + my_total;
        let tail_size = total - my_total;

        self.unlink(block);

        if tail_size >= MIN_TOTAL {
            // ── Расщепление ──
            // Хвост — новый свободный блок; его prev (наш блок) АЛЛОЦИРОВАН.
            set_hdr(tail, tail_size);
            // SAFETY: tail — свежий свободный блок.
            unsafe { set_links(tail, 0, 0) };
            // SAFETY: footer хвоста — внутри чанка, 8-выровнен.
            unsafe { write_word(tail + tail_size - FOOTER, tail_size) };
            self.insert_sorted(tail);
            // Сосед ПОСЛЕ хвоста: prev теперь свободен (хвост).
            set_flag_of_next(tail, tail_size, true);
            self.stats.free_bytes = self.stats.free_bytes - total + tail_size;
            self.stats.used_bytes += my_total;
        } else {
            // ── Без расщепления: весь блок наш ──
            set_flag_of_next(block, total, false);
            self.stats.free_bytes -= total;
            self.stats.used_bytes += total;
            set_hdr(block, total | prev_flag);
            // SAFETY: маркер — внутри нашего блока (payload ≥ cur+16).
            unsafe { write_word(payload - WORD, block) };
            return payload as *mut u8;
        }
        set_hdr(block, my_total | prev_flag);
        // SAFETY: маркер — внутри нашего блока.
        unsafe { write_word(payload - WORD, block) };
        payload as *mut u8
    }

    /// Освободить payload `ptr` (раскладка — только для сигнатуры
    /// GlobalAlloc; размер блока восстанавливается по маркеру).
    ///
    /// # Safety
    /// `ptr` обязан быть живым payload'ом ЭТОЙ арены; `layout` — та же,
    /// что при alloc. Двойной free / чужой указатель = порча кучи:
    /// арена доверяет GlobalAlloc-контракту (как все аллокаторы Rust).
    pub unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let _ = layout;
        if ptr.is_null() {
            return;
        }
        let ptr = ptr as usize;
        // Маркер: адрес блока (записан в carve при выделении).
        // SAFETY: контракт вызова — ptr живой payload этой арены.
        let mut block = unsafe { read_word(ptr - WORD) };
        debug_assert!(block % 16 == 0);
        debug_assert!(block + BLOCK_OVERHEAD <= ptr);

        let head_hdr = hdr_of(block);
        let mut sz = head_hdr & !PREV_FREE;
        let mut prev_flag = head_hdr & PREV_FREE;
        // Блок перестаёт быть живым (объединённые соседи уже учтены в
        // free_bytes — их вычитание ниже).
        self.stats.used_bytes -= sz;

        // ── Слияние вперёд (сосед свободен?) ──
        // NB: PF(nb) говорит о свободности ПРЕДЫДУЩЕГО блока (нас),
        // а не о самом nb. nb свободен ⟺ PF блока ЗА nb (= 1) — флаг,
        // выставленный в момент освобождения nb (set_flag_of_next).
        // Размер nb ≥ MIN_TOTAL отсекает сентинел (size 16).
        let nb = block + sz;
        let nb_hdr = hdr_of(nb);
        let nb_size = nb_hdr & !PREV_FREE;
        if nb_size >= MIN_TOTAL {
            let nb2 = nb + nb_size;
            if hdr_of(nb2) & PREV_FREE != 0 {
                self.unlink(nb);
                self.stats.free_bytes -= nb_size;
                sz += nb_size;
            }
        }

        // ── Слияние назад (перед нами свободный?) ──
        if prev_flag != 0 {
            // SAFETY: prev свободен по инварианту PF → footer валиден.
            let prev_size = unsafe { read_word(block - FOOTER) };
            let prev_block = block - prev_size;
            self.unlink(prev_block);
            self.stats.free_bytes -= prev_size;
            // Флаг «перед объединённым блоком свободно» — от prev-блока.
            prev_flag = hdr_of(prev_block) & PREV_FREE;
            block = prev_block;
            sz += prev_size;
        }

        // ── Итоговый свободный блок ──
        set_hdr(block, sz | prev_flag);
        // SAFETY: объединённый блок — свободный (sz ≥ MIN_TOTAL).
        unsafe { set_links(block, 0, 0) };
        // SAFETY: footer — внутри чанка, 8-выровнен.
        unsafe { write_word(block + sz - FOOTER, sz) };
        // Сосед справа: его prev теперь свободен.
        set_flag_of_next(block, sz, true);
        self.insert_sorted(block);
        self.stats.free_bytes += sz;
    }
}

// ─── Хост-тесты (cargo test -p cintos-user --lib) ────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// Выровненный стековый буфер — «память от ядра».
    #[repr(align(4096))]
    struct Chunk<const N: usize>([MaybeUninit<u8>; N]);

    impl<const N: usize> Chunk<N> {
        fn base(&mut self) -> *mut u8 {
            self.0.as_mut_ptr().cast()
        }
    }

    /// Инвариант учёта: free + used = чанки минус сентинелы.
    fn assert_stats_ok(arena: &HeapArena, chunk_bytes: usize, chunks: usize) {
        let s = arena.stats();
        assert_eq!(
            s.free_bytes + s.used_bytes,
            chunk_bytes - SENTINEL_TOTAL * chunks,
            "free({}) + used({}) != чанки({}) - сентинелы({})",
            s.free_bytes,
            s.used_bytes,
            chunk_bytes,
            SENTINEL_TOTAL * chunks
        );
    }

    #[test]
    fn add_chunk_rejects_garbage() {
        let mut arena = HeapArena::new();
        assert_eq!(arena.add_chunk(core::ptr::null_mut(), 4096), Err(ArenaError::NullBase));
        // 16-выровненный буфер: база валидна, соседний байт — нет.
        #[repr(align(16))]
        struct Aligned([u8; 128]);
        let mut buf = Aligned([0; 128]);
        // SAFETY: буфер на стеке живёт дольше вызова.
        let ok = buf.0.as_mut_ptr();
        let mis = ok.wrapping_add(1);
        assert_eq!(arena.add_chunk(mis, 128), Err(ArenaError::Misaligned));
        assert_eq!(arena.add_chunk(ok, 32), Err(ArenaError::TooSmall));
        assert_eq!(arena.stats().chunks, 0);
    }

    #[test]
    fn alloc_basic_and_reuse() {
        let mut chunk = Chunk([MaybeUninit::uninit(); 16 * 1024]);
        let mut arena = HeapArena::new();
        arena.add_chunk(chunk.base(), 16 * 1024).expect("chunk");

        let l = Layout::from_size_align(100, 8).unwrap();
        let a = arena.alloc(l);
        assert!(!a.is_null());
        assert_eq!(a as usize % 16, 0, "payload 16-выровнен");
        assert_stats_ok(&arena, 16 * 1024, 1);

        // Повторное выделение — другой адрес (первый блок занят).
        let b = arena.alloc(l);
        assert_ne!(a, b);

        // Освободили — first-fit выдаёт ТОТ ЖЕ адрес (адрес-упорядоченный
        // список, освобождённая голова — первый кандидат).
        // SAFETY: a выдан этой ареной, жив.
        unsafe { arena.dealloc(a, l) };
        assert_stats_ok(&arena, 16 * 1024, 1);
        let c = arena.alloc(l);
        assert_eq!(a, c, "freed-голова должна переиспользоваться");
        // SAFETY: c (= a) выдан этой ареной.
        unsafe { arena.dealloc(c, l) };
        // SAFETY: b выдан этой ареной.
        unsafe { arena.dealloc(b, l) };
        let s = arena.stats();
        assert_eq!(s.used_bytes, 0);
    }

    #[test]
    fn coalesce_full_circle() {
        let mut chunk = Chunk([MaybeUninit::uninit(); 16 * 1024]);
        let mut arena = HeapArena::new();
        arena.add_chunk(chunk.base(), 16 * 1024).expect("chunk");
        let l1 = Layout::from_size_align(64, 8).unwrap();
        let l2 = Layout::from_size_align(128, 8).unwrap();

        let a = arena.alloc(l1).cast::<u8>();
        let b = arena.alloc(l2).cast::<u8>();
        let c = arena.alloc(l1).cast::<u8>();
        assert!(!a.is_null() && !b.is_null() && !c.is_null());

        // Освобождаем a и c (дыры по бокам b), затем b — всё сливается
        // в один блок, free_bytes возвращается к стартовому.
        // SAFETY: все три выданы этой ареной и живы.
        unsafe {
            arena.dealloc(a, l1);
            arena.dealloc(c, l1);
        }
        unsafe { arena.dealloc(b, l2) };

        let s = arena.stats();
        assert_eq!(s.used_bytes, 0);
        assert_eq!(
            s.free_bytes,
            16 * 1024 - SENTINEL_TOTAL,
            "после полного освобождения — один слитый блок"
        );
        // После слияния снова можно выделить размер исходного чанка
        // (макс payload = usable - 24 Б служебных, с запасом — 16000).
        let big = Layout::from_size_align(16000, 8).unwrap();
        let p = arena.alloc(big);
        assert!(!p.is_null(), "слияние должно вернуть полноразмерный блок");
        // SAFETY: p выдан этой ареной.
        unsafe { arena.dealloc(p, big) };
    }

    #[test]
    fn exhaustion_then_growth() {
        let mut chunk = Chunk::<{ 8 * 1024 }>([MaybeUninit::uninit(); 8 * 1024]);
        let mut arena = HeapArena::new();
        arena.add_chunk(chunk.base(), 8 * 1024).expect("chunk");

        let l = Layout::from_size_align(512, 8).unwrap();
        let mut live: [(*mut u8, Layout); 64] = [(core::ptr::null_mut(), l); 64];
        let mut n = 0;
        while n < live.len() {
            let p = arena.alloc(l);
            if p.is_null() {
                break;
            }
            live[n] = (p, l);
            n += 1;
        }
        assert!(n > 8, "чанк 8К обязан вместить больше 8 блоков по 512Б");
        assert!(arena.alloc(l).is_null(), "чанк исчерпан — null");

        // Рост: второй чанк.
        let mut chunk2 = Chunk::<{ 8 * 1024 }>([MaybeUninit::uninit(); 8 * 1024]);
        arena.add_chunk(chunk2.base(), 8 * 1024).expect("chunk2");
        let after = arena.alloc(l);
        assert!(!after.is_null(), "после add_chunk выделение живёт");
        assert_eq!(arena.stats().chunks, 2);

        // Освобождение всего — счётчики в ноль.
        // SAFETY: after выдан этой ареной и жив.
        unsafe { arena.dealloc(after, l) };
        for i in 0..n {
            // SAFETY: live[i] выдан этой ареной и жив.
            unsafe { arena.dealloc(live[i].0, live[i].1) };
        }
        let s = arena.stats();
        assert_eq!(s.used_bytes, 0);
        assert_eq!(s.free_bytes, 2 * (8 * 1024) - 2 * SENTINEL_TOTAL);
    }

    #[test]
    fn big_alignment_uses_ballast() {
        let mut chunk = Chunk([MaybeUninit::uninit(); 16 * 1024]);
        let mut arena = HeapArena::new();
        arena.add_chunk(chunk.base(), 16 * 1024).expect("chunk");

        // Перекос: два обычных аллока, чтобы сместить границу свободного
        // блока, затем запрос выравнивания 4096.
        let small = Layout::from_size_align(8, 8).unwrap();
        let _pad = arena.alloc(small);
        let big = Layout::from_size_align(100, 4096).unwrap();
        let p = arena.alloc(big);
        assert!(!p.is_null());
        assert_eq!(p as usize % 4096, 0, "payload обязан быть 4096-выровнен");

        // Освобождение возвращает весь блок (с балластом).
        // SAFETY: p выдан этой ареной.
        unsafe { arena.dealloc(p, big) };
        assert_stats_ok(&arena, 16 * 1024, 1);
    }

    #[test]
    fn fuzz_against_shadow_invariants() {
        // Детерминированный LCG — воспроизводимость без зависимостей.
        let mut seed: u64 = 0x2026_1001;
        let mut rnd = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };

        // 4 «чанка» — рвёт смежность (каждый на своём стековом буфере).
        const N: usize = 4;
        let mut chunks = [const { Chunk::<{ 4 * 1024 }>([MaybeUninit::uninit(); 4 * 1024]) }; N];
        let mut arena = HeapArena::new();
        let mut total_bytes = 0usize;
        for c in chunks.iter_mut().take(N) {
            arena.add_chunk(c.base(), 4 * 1024).expect("chunk");
            total_bytes += 4 * 1024;
        }

        // Тени: (ptr, layout, паттерн).
        let mut live: [(usize, Option<Layout>, u8); 128] =
            [(0, None, 0); 128];
        let mut live_n = 0usize;
        let mut next_id: u8 = 1;

        for step in 0..20_000 {
            let op = rnd() % 100;
            if op < 55 || live_n == 0 {
                // ALLOC
                let size = 1 + rnd() % 600;
                let align = [1usize, 2, 4, 8, 16][(rnd() % 5) as usize];
                let layout = Layout::from_size_align(size, align).unwrap();
                let p = arena.alloc(layout) as usize;
                if p == 0 {
                    continue; // исчерпано — легально
                }
                assert_eq!(p % 16, 0, "step {step}: payload 16-выровнен");
                assert_eq!(p % align.max(16), 0);
                // Паттерн: заполнить, чтобы ловить перекрытия при free.
                let pat = next_id.wrapping_mul(31) | 1;
                next_id = next_id.wrapping_add(1);
                // SAFETY: p — живой payload размером size.
                unsafe {
                    core::ptr::write_bytes(p as *mut u8, pat, size);
                }
                assert!(live_n < live.len(), "тени переполнены");
                live[live_n] = (p, Some(layout), pat);
                live_n += 1;
            } else {
                // FREE случайной живой тени
                let idx = rnd() % live_n;
                let (p, layout, pat) = live[idx];
                let layout = layout.expect("живая тень с layout");
                // Проверка целостности соседей: паттерн последней тени
                // обязан быть цел (перекрытия ломают его раньше).
                let size = layout.size();
                // SAFETY: p — живой payload размером size.
                let byte = unsafe { (p as *const u8).add(size - 1).read() };
                assert_eq!(
                    byte, pat,
                    "step {step}: хвост аллокации перезаписан (перекрытие)"
                );
                // SAFETY: p выдан ареной, жив.
                unsafe { arena.dealloc(p as *mut u8, layout) };
                live[idx] = live[live_n - 1];
                live_n -= 1;
            }
            if step % 97 == 0 {
                assert_stats_ok(&arena, total_bytes, N);
            }
        }
        // Полная уборка.
        for i in 0..live_n {
            let (p, layout, _) = live[i];
            let layout = layout.expect("живая тень с layout");
            // SAFETY: p выдан ареной, жив.
            unsafe { arena.dealloc(p as *mut u8, layout) };
        }
        let s = arena.stats();
        assert_eq!(s.used_bytes, 0, "после уборки used = 0");
        assert_eq!(s.free_bytes, total_bytes - SENTINEL_TOTAL * N);
        assert_stats_ok(&arena, total_bytes, N);
    }
}
