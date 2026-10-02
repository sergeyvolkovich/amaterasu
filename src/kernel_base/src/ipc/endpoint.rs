//! IPC-транспорт: проволочный формат + побайтовые копии userspace.
//!
//! МОДЕЛЬ (L4-минимализм, «ядро — только транспорт»):
//!   - Сообщение = НЕПРОЗРАЧНЫЕ байты (payload) + явные kernel-visible
//!     дескрипторы пересылки capability (аналог L4 map items). Ядро НЕ
//!     разбирает payload — сериализация (формат тела) — задача
//!     юзерспейса.
//!   - Rendezvous-состояние (кто кого ждёт) живёт в TCB участников
//!     (task::ipc_state) — классический L4: заблокированный отправитель
//!     держит сообщение в СВОЁМ буфере, получатель копирует напрямую
//!     через его умап. Почтовых ящиков в ядре нет: ни двойной копии,
//!     ни глобального пула под единым локом. Оркестрация — ipc::
//!     transport (логика) и syscall::ipc (сисколлы).
//!   - Адресация: (v1) capability-слоты cspace c TaskTCB-объектом
//!     (прямой send задаче, closed/open wait) и (v2) IPC-гейты
//!     (ipc::gate) — точки мультиплексирования «много клиентов →
//!     сервер».
//!
//! ПОТОКИ (см. также transport.rs):
//!   SEND быстрый путь: получатель в Receiving → claim (Receiving →
//!     Claimed) → пересылка capability → копия [заголовок|слоты|тело]
//!     в буфер получателя ПОСТРАНИЧНО (translate) → Idle + wake.
//!   SEND медленный путь: получателя нет → запись в очередь получателя
//!     (в его TCB) + сон на СВОЁМ объекте (sender_wait_object(свой id)).
//!   WAIT быстрый путь: очередь непуста → изъятие кандидата → копия из
//!     буфера ОТПРАВИТЕЛЯ (через его умап) → wake отправителя.
//!   WAIT медленный путь: регистрация Receiving + сон на СВОЁМ объекте
//!     (endpoint_wait_object(свой id)).
//!
//! ФОРМАТ доставки в буфер получателя (u64-слова, little-endian):
//!   [0] task_cap_id отправителя
//!   [1] размер тела в байтах
//!   [2] число доставленных capability (N)
//!   [3..3+N] слоты ПОЛУЧАТЕЛЯ, куда легли capability
//!   [3+N .. 3+N+size] тело сообщения (для юзерспейса)
//!
//! ОТКАЗЫ: негабаритное для буфера получателя сообщение НЕ доставляется
//! (отправитель получает ошибку в свой кадр — TCB::patch_resume_rax до
//! пробуждения); уничтожение задачи чистит очереди/состояния
//! (transport::on_task_destroyed).
//!
//! СИНХРОНИЗАЦИЯ: состояние IPC — листовые SpinMutex в TCB (task::
//! ipc_state) и гейты (ipc::gate). Внутри их секций чужих локов нет
//! (копирование userspace — через HHDM по переведённой физике).
//! Планировщик (scheduler_release_object) зовётся ТОЛЬКО с отпущенными
//! ipc/gate-локами. SMP: wake — task::wake::release_object_global
//! (все per-CPU планировщики + Resched-IPI).

use crate::traits::memory::{
    is_user_range, MemoryInterfaceUserspace, phys_to_virt, PAGE_SIZE,
};

/// Максимум payload одного сообщения (байт). Совпадает с
/// cintos_user::ipc::MAX_MSG — юзерспейс-сериализация вмещается.
pub const MAX_MSG: usize = 512;

/// Максимум дескрипторов пересылки capability в одном сообщении.
pub const MAX_CAPS: usize = 8;

/// Слова заголовка ДО списка слотов capability: отправитель, размер,
/// число capability.
pub const HEADER_WORDS: usize = 3;

/// Слот «ждать от кого угодно» (open wait, семантика L4 from-any).
pub const IPC_WAIT_ANY: u64 = u64::MAX;

/// База пространства wait-объектов IPC для планировщика. Не пересекается
/// с IRQ-линиями (0..64), фолтами (0x3_0000) и тестовыми объектами
/// (mt_test: 0xAA). Диапазоны ВНУТРИ базы разведены, чтобы id задач и
/// гейтов не коллидировали:
///   [BASE .. BASE+0x1000)          — объекты заблокированных отправителей
///                                    (sender_wait_object, ключ — task id)
///   [BASE+0x1000 .. BASE+0x2000)   — объекты ждущих получателей
///                                    (endpoint_wait_object, ключ — task id)
///   [BASE+0x2000 .. BASE+0x3000)   — гейты (gate_wait_object, ключ — gate id)
pub const IPC_OBJECT_BASE: usize = 0x1_0000;

/// Объект ожидания отправителя `task_cap_id`, спящего в ожидании доставки
/// своего сообщения (медленный путь SEND).
pub fn sender_wait_object(task_cap_id: u64) -> usize {
    IPC_OBJECT_BASE + (task_cap_id as usize & 0xFFF)
}

/// Объект ожидания получателя `task_cap_id`, спящего в регистрации
/// Receiving (медленный путь WAIT).
pub fn endpoint_wait_object(task_cap_id: u64) -> usize {
    IPC_OBJECT_BASE + 0x1000 + (task_cap_id as usize & 0xFFF)
}

/// Диагностика диапазонов (резолвер таймаутов — kernel_limine).
pub fn is_sender_wait_object(object_id: usize) -> bool {
    (IPC_OBJECT_BASE..IPC_OBJECT_BASE + 0x1000).contains(&object_id)
}

/// Диагностика диапазонов (резолвер таймаутов — kernel_limine).
pub fn is_endpoint_wait_object(object_id: usize) -> bool {
    (IPC_OBJECT_BASE + 0x1000..IPC_OBJECT_BASE + 0x2000).contains(&object_id)
}

/// Дескриптор пересылки одной capability (wire-формат userspace→ядро,
/// #[repr(C)] 3×u64: src_slot, dst_slot, права — DirectCapabilityRights).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapItem {
    pub src_slot: u64,
    pub dst_slot: u64,
    pub rights: u8,
}

// ─── Побайтовое копирование userspace↔kernel (постранично) ──────────────────

/// Копирует `buf.len()` байт из userspace-VA в ядерный буфер.
/// Постранично: буфер может пересекать границу страниц, а физика
/// соседних страниц НЕ обязана быть непрерывной. `false` — дыра.
pub fn read_from_user<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    buf: &mut [u8],
) -> bool {
    // COPYIN-ГЕЙТ: верхняя половина — ядерные отображения, разделяемые с
    // умапом задачи; translate() там успешен, а копирование ядром идёт в
    // обход U/S-бита. Без этого гейта ring3 читает память ядра.
    if !is_user_range(va, buf.len()) {
        return false;
    }
    let mut off = 0usize;
    while off < buf.len() {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, buf.len() - off);
        // USER-семантика copyin: нижняя половина + U/S (см. translate_user).
        let Some(phys) = umap.translate_user(va + off, false) else {
            return false;
        };
        // SAFETY: phys получен translate живого умапа; страница задачи
        // замаплена HHDM.
        let src = phys_to_virt(phys) as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(off), chunk);
        }
        off += chunk;
    }
    true
}

/// Копирует ядерный буфер в userspace-VA (постранично, как
/// read_from_user). Вызывать только после check_user_region.
pub fn write_to_user<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    buf: &[u8],
) -> bool {
    // COPYOUT-ГЕЙТ: симметрично read_from_user — без проверки ring3
    // получает ЗАПИСЬ в память ядра через tgt_ptr = ядерный VA.
    if !is_user_range(va, buf.len()) {
        return false;
    }
    let mut off = 0usize;
    while off < buf.len() {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, buf.len() - off);
        // USER-семантика copyout + WRITE: буфер обязан быть отображён с
        // R/W по всему пути (read-only страницы отклоняются).
        let Some(phys) = umap.translate_user(va + off, true) else {
            return false;
        };
        // SAFETY: как read_from_user.
        let dst = phys_to_virt(phys) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(off), dst, chunk);
        }
        off += chunk;
    }
    true
}

/// Полная проходимость диапазона [va, va+len) в пространстве задачи
/// (без записи). Проверка ДО доставки: частичная запись оставила бы
/// получателю полусообщение без возможности отката.
pub fn check_user_region<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    len: usize,
) -> bool {
    // Проверка проходимости диапазона бессмысленна в верхней половине —
    // там translate() всегда успешен (ядерные отображения).
    if !is_user_range(va, len) {
        return false;
    }
    let mut off = 0usize;
    while off < len {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, len - off);
        // USER-семантика + WRITE: диапазон — будущая цель записи ядра
        // (доставка сообщения), R/W обязателен по всему пути.
        if umap.translate_user(va + off, true).is_none() {
            return false;
        }
        off += chunk;
    }
    true
}

/// Пишет u64 в userspace-VA (выравнивание 8 проверяет вызывающий).
pub fn write_user_u64<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    value: u64,
) -> bool {
    write_to_user(umap, va, &value.to_le_bytes())
}

/// Читает u64 из userspace-VA (выравнивание 8 проверяет вызывающий).
pub fn read_user_u64<Umap: MemoryInterfaceUserspace>(umap: &Umap, va: usize) -> Option<u64> {
    let mut raw = [0u8; 8];
    if !read_from_user(umap, va, &mut raw) {
        return None;
    }
    Some(u64::from_le_bytes(raw))
}

/// Общий заголовок + слоты capability + payload = байты буфера.
pub fn delivery_bytes(caps_count: usize, msg_len: usize) -> usize {
    (HEADER_WORDS + caps_count) * 8 + msg_len
}

/// Копирует ТЕЛО сообщения отправителя (его userspace → буфер ядра).
/// Вызывается доставкой через умап ОТПРАВИТЕЛЯ: буфер стабильна, пока
/// отправитель спит (см. task::ipc_state::SendSpec).
pub fn copy_body_from_sender<Umap: MemoryInterfaceUserspace>(
    sender_umap: &Umap,
    spec_msg_va: usize,
    spec_msg_len: usize,
    kernel_buf: &mut [u8],
) -> bool {
    if kernel_buf.len() < spec_msg_len {
        return false;
    }
    read_from_user(sender_umap, spec_msg_va, &mut kernel_buf[..spec_msg_len])
}

/// Пишет заголовок доставки + тело в буфер получателя (вызывается после
/// check_user_region; слова слотов capability дописывает вызывающий —
/// слоты назначает ядро из приёмного окна ПОСЛЕ пересылки capability,
/// см. transport::deliver / write_cap_slot_headers).
pub fn write_delivery_header_and_body<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    tgt_va: usize,
    sender_task_cap: u64,
    body: &[u8],
    caps_dst_slots: &[u64],
) -> bool {
    let mut ok = write_user_u64(umap, tgt_va, sender_task_cap);
    ok &= write_user_u64(umap, tgt_va + 8, body.len() as u64);
    ok &= write_user_u64(umap, tgt_va + 16, caps_dst_slots.len() as u64);
    for (i, slot) in caps_dst_slots.iter().enumerate() {
        ok &= write_user_u64(umap, tgt_va + (HEADER_WORDS + i) * 8, *slot);
    }
    ok &= write_to_user(umap, tgt_va + (HEADER_WORDS + caps_dst_slots.len()) * 8, body);
    ok
}

/// Дописывает слова слотов ПОЛУЧАТЕЛЯ в заголовок доставки (медленный
/// путь wait): вызывается ПОСЛЕ успешной пересылки capability, когда
/// ядро уже назначило слоты из приёмного окна.
pub fn write_cap_slot_headers<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    tgt_va: usize,
    slots: &[u64],
) -> bool {
    let mut ok = true;
    for (i, slot) in slots.iter().enumerate() {
        ok &= write_user_u64(umap, tgt_va + (HEADER_WORDS + i) * 8, *slot);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{is_user_range, set_hhdm_offset};

    /// COPYIN/COPYOUT-гейт: верхняя половина (ядерные отображения, общие
    /// с умапом задачи) обязана отсекаться ДО translate — translate там
    /// УСПЕШЕН, и без гейта ring3 получает примитивы чтения/записи памяти
    /// ядра (msg_ptr/tgt_ptr = 0xffff....).
    #[test]
    fn copy_gate_rejects_kernel_half() {
        let user = 0x0000_0001_0000_0000usize; // нижняя половина (окно задач)
        let kernel = 0xffff_ffff_8000_0000usize; // higher-half ядро

        assert!(is_user_range(user, 512));
        assert!(is_user_range(user, 0)); // пустой диапазон валиден
        assert!(!is_user_range(kernel, 512));
        // Старт в юзерспейсе, хвост ЗА границей (0x8000_0000_0000):
        let straddle = 0x0000_7fff_ffff_ff00usize;
        assert!(!is_user_range(straddle, 512), "диапазон, пересекающий границу, обязан отсекаться");
        assert!(is_user_range(straddle, 0x100)); // ещё до границы — ок
        let _ = kernel; // (наглядность)
    }

    /// Фиктивный умап: VA = phys + DELTA, отображено [0, limit).
    struct FakeUmap {
        delta: usize,
        limit: usize,
    }

    impl MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _c: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _r: crate::traits::memory::MemoryPTR,
            _c: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, virt: usize) -> Option<usize> {
            let phys = virt.checked_sub(self.delta)?;
            (phys < self.limit).then_some(phys)
        }
    }

    /// Читатель/писатель u64 (read_user_u64/write_delivery_header):
    /// раундтрип заголовка доставки над фиктивным умапом.
    #[test]
    fn delivery_header_roundtrip() {
        let _guard = crate::test_guard::GLOBAL.lock();
        let mem = crate::traits::memory::test_alloc::page_aligned_leak(16);
        set_hhdm_offset(mem.as_ptr() as usize);
        let u = FakeUmap {
            delta: 0x1_0000_0000,
            limit: 0x4000,
        };
        let va = u.delta + 0x800;

        // Заголовок + тело, БЕЗ слов слотов (их допишет кап-транспорт).
        let body = [0x5Au8; 24];
        assert!(write_delivery_header_and_body(&u, va, 777, &body, &[]));
        assert_eq!(read_user_u64(&u, va), Some(777));
        assert_eq!(read_user_u64(&u, va + 8), Some(24));
        assert_eq!(read_user_u64(&u, va + 16), Some(0));
        // Дописанные слоты читаются тем же read_user_u64.
        assert!(write_cap_slot_headers(&u, va, &[42, 43]));
        assert_eq!(read_user_u64(&u, va + HEADER_WORDS * 8), Some(42));
        assert_eq!(read_user_u64(&u, va + (HEADER_WORDS + 1) * 8), Some(43));

        // Негабарит/дыра — отказ без частичной записи.
        assert!(!check_user_region(&u, va, 0x4001));
        assert!(check_user_region(&u, va, 0x4000 - 0x800));

        // delivery_bytes: 3 слова заголовка + слоты + тело.
        assert_eq!(delivery_bytes(2, 10), (3 + 2) * 8 + 10);
    }

    /// Wait-объекты IPC: диапазоны task-id/гейтов не пересекаются.
    #[test]
    fn wait_object_ranges_are_disjoint() {
        let s = sender_wait_object(1);
        let e = endpoint_wait_object(1);
        let g = crate::ipc::gate::gate_wait_object(1);
        assert!(s >= IPC_OBJECT_BASE && s < IPC_OBJECT_BASE + 0x1000);
        assert!(e >= IPC_OBJECT_BASE + 0x1000 && e < IPC_OBJECT_BASE + 0x2000);
        assert!(g >= IPC_OBJECT_BASE + 0x2000 && g < IPC_OBJECT_BASE + 0x3000);
    }
}
