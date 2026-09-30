//! Ожидание IRQ задачей: "спать до прерывания, получить список сработавших".
//!
//! Контракт с userspace (библиотека), v2 (per-line capability):
//!   1. Userspace выделяет массив из `1 + N` u64-ячеек: первая ячейка —
//!      СЧЁТЧИК сработавших IRQ, далее — НОМЕРА ЛИНИЙ (u32 в u64-слоте)
//!      в порядке срабатывания.
//!   2. Userspace выделяет массив из `M` u64-слотов cspace (номера слотов
//!      СВОЕЙ задачи), где каждая запись резолвится в CapabilityObject::
//!      IrqLine — право ждать на этой линии. Без капы линии ждать нельзя
//!      (per-line authority: перебор "угаданных" номеров линий закрыт).
//!   3. Ядро резолвит слоты → дедуплицированный список линий (до
//!      MAX_LINES_PER_WAIT), обнуляет счётчик, ставит задачу в ожидание.
//!   4. Когда линия срабатывает, диспетчер порта зовёт `on_irq_fired`:
//!      ядро ДОПИСЫВАЕТ номер линии в массив, снимает ожидание, будит.
//!   5. После пробуждения userspace читает счётчик и номера.
//!
//! Переносимость: линии — ЛОГИЧЕСКИЕ номера u32 (GSI/INTID/source id —
//! см. traits::irq), НИКАКОЙ привязки к 64/255 «векторам». Ограничение
//! 64 линии на один WAIT из v1 (u64-битмап) снято: wait-сет — список
//! кап-слотов; несколько WAIT покрывают произвольное число линий.
//!
//! Запись в userspace-память идёт через translate + HHDM: CR3 не
//! переключается. Страничное ограничение: массив результата обязан
//! целиком лежать в ОДНОЙ странице (проверка при регистрации — закрывает
//! latent-баг v1, где запись могла пересечь границу страницы при
//! трансляции только первого адреса).
//!
//! ОБЪЕКТЫ ОЖИДАНИЯ: каждая регистрация занимает СВОЙ слот slab-таблицы
//! (монотонный seq — никогда не переиспользуется) и блокирует задачу на
//! ОДНОМ объекте `IRQ_OBJECT_BASE + seq`. RELEASE этого объекта из ring3
//! отбрасывается ядром (kernel-reserved диапазон — см. syscall_task).
//!
//! Slab-first: таблица ожидающих — RBSlabIO (не фиксированный массив);
//! предел MAX_IRQ_WAITERS остаётся как системная квота ядра.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::collection::RBSlabIO;
use crate::irqsafe::IrqSafeSpinMutex;
use crate::lctl::LocalKernelCTL;
use crate::traits::memory::{MemoryInterfaceUserspace, is_user_range, phys_to_virt, PAGE_SIZE};

/// Максимальное число линий в ОДНОМ ожидании (дедуп после резолва кап).
/// Драйвер, которому нужно больше, разбивает ожидание на несколько.
pub const MAX_LINES_PER_WAIT: usize = 8;

/// Системная квота: максимум ОДНОВРЕМЕННЫХ ожидающих задач в ядре.
pub const MAX_IRQ_WAITERS: usize = 16;

/// База wait-объектов IRQ-ожидания (kernel-reserved; не пересекается
/// с IPC-объектами и тестовыми идентификаторами mt_test).
pub const IRQ_OBJECT_BASE: usize = 0x2_0000;

/// Объект ожидания регистрации с номером `seq`.
pub fn irq_wait_object(seq: u64) -> usize {
    IRQ_OBJECT_BASE + seq as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqWaitError {
    /// Системная квота ожидающих исчерпана.
    RegistryFull,
    /// Список линий пуст после резолва/дедупа.
    NoLines,
    /// Слишком много линий (после дедупа больше MAX_LINES_PER_WAIT).
    TooManyLines,
    /// Указатели вне умапа задачи / не выровнены / пересекают страницу.
    BadPointer,
    /// Ёмкость массива результата нулевая.
    ZeroMaskSlots,
}

/// Регистрация ожидания одной задачи.
#[derive(Debug, Clone, Copy)]
struct IrqWaiter {
    /// Capability id задачи-ожидателя.
    task_cap_id: u64,
    /// Физический адрес заголовка-счётчика массива (в странице задачи).
    mask_phys: usize,
    /// Ёмкость массива в u64-слотах (без счётчика).
    mask_slots: usize,
    /// Дедуплицированный список ожидаемых линий.
    lines: [u32; MAX_LINES_PER_WAIT],
    line_count: usize,
}

type WaiterTable = RBSlabIO<u64, IrqWaiter, false>;

/// Обёртка Send/Sync: NoLock-контракт RBSlabIO закрыт внешним
/// IrqSafeSpinMutex — все структурные операции под его локом (см. table()).
#[repr(transparent)]
struct SendWaiterTable(IrqSafeSpinMutex<WaiterTable>);
// SAFETY: структурные операции дерева идут только под IrqSafeSpinMutex
// (гасит прерывания на секции — таблицу берут и сисколлы, и диспетчер
// IRQ); конкурентный &-доступ сериализован тем же локом.
unsafe impl Send for SendWaiterTable {}
unsafe impl Sync for SendWaiterTable {}

/// Монотонный seq регистраций (ключ дерева; никогда не переиспользуется —
/// wait-объекты не дают ABA).
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Таблица ожидающих — ленивое slab-дерево (slab-хуки поднимаются позже
/// статических инициализаторов). None внутри Once — slab OOM (навсегда:
/// register возвращает RegistryFull).
static WAITERS: spin::Once<Option<SendWaiterTable>> = spin::Once::new();

fn table() -> Option<&'static SendWaiterTable> {
    WAITERS
        .call_once(|| RBSlabIO::new().ok().map(SendWaiterTable::new))
        .as_ref()
}

/// Число живых регистраций (квота MAX_IRQ_WAITERS).
static LIVE_WAITERS: AtomicU64 = AtomicU64::new(0);

impl SendWaiterTable {
    fn new(table: WaiterTable) -> Self {
        Self(IrqSafeSpinMutex::new(table))
    }
}

/// Устанавливает ожидание: обнуляет счётчик массива задачи и возвращает
/// SEQ регистрации — задача блокируется вызывающим сисколлом на
/// `irq_wait_object(seq)` ОДИН раз (все линии — одна блокировка).
///
/// `lines` — УЖЕ резолвленный по капам дедуплицированный список линий.
/// `mask_ptr` — виртуальный адрес массива результата В ПРОСТРАНСТВЕ
/// ЗАДАЧИ (обязан целиком лежать в одной странице вместе со счётчиком).
pub fn register_irq_wait<Umap: MemoryInterfaceUserspace>(
    task_cap_id: u64,
    umap: &Umap,
    lines: &[u32],
    mask_ptr: usize,
    mask_slots: usize,
) -> Result<u64, IrqWaitError> {
    if lines.is_empty() {
        return Err(IrqWaitError::NoLines);
    }
    if lines.len() > MAX_LINES_PER_WAIT {
        return Err(IrqWaitError::TooManyLines);
    }
    if mask_slots == 0 {
        return Err(IrqWaitError::ZeroMaskSlots);
    }
    // COPYOUT-ГЕЙТ: буфер маски — ядро пишет в него счётчики/линии;
    // без проверки ring3 получает запись в память ядра (mask_ptr из
    // верхней половины транслируется — верхняя половина умапа общая).
    if !is_user_range(mask_ptr, (mask_slots + 1) * 8) {
        return Err(IrqWaitError::BadPointer);
    }
    // USER-семантика + WRITE: буфер маски — цель записи ядра.
    let mask_phys = umap
        .translate_user(mask_ptr, true)
        .ok_or(IrqWaitError::BadPointer)?;
    // Выравнивание u64 обязательно: пишем счётчик/линии сырыми u64.
    if mask_phys % 8 != 0 {
        return Err(IrqWaitError::BadPointer);
    }
    // СТРАНИЧНОЕ ОГРАНИЧЕНИЕ: пишем до (1 + mask_slots) u64 по HHDM,
    // трансляция проверила только первый адрес — требуем, чтобы весь
    // массив лежал в одной странице (иначе хвост пришёлся бы на
    // непроверенную соседнюю страницу — запись в память ядра).
    let in_page = PAGE_SIZE - (mask_phys % PAGE_SIZE);
    if (mask_slots + 1) * 8 > in_page {
        return Err(IrqWaitError::BadPointer);
    }

    // Обнуляем счётчик ДО постановки в ожидание: след от прошлого цикла
    // userspace обязан прочитать до нового WaitIrq.
    write_u64_phys(mask_phys, 0);

    let Some(t) = table() else {
        return Err(IrqWaitError::RegistryFull);
    };

    // Дедуп входного списка (капы могут указывать на одну линию дважды).
    let mut dedup = [0u32; MAX_LINES_PER_WAIT];
    let mut count = 0usize;
    for &l in lines {
        if !dedup[..count].contains(&l) {
            dedup[count] = l;
            count += 1;
        }
    }
    if count == 0 {
        return Err(IrqWaitError::NoLines);
    }

    let mut t = t.0.lock();
    // Квота: slab-дерево не ограничено, ограничиваем ЯВНО (системная
    // константа; рост таблицы при флуде WaitIrq — не ресурс ядра).
    // Повторная регистрация той же задачи ЗАМЕЩАЕТ старую (череда
    // сисколлов без пробуждений не выжигает квоту) — квоту считаем
    // после снятия старой записи.
    let mut old_seq: Option<u64> = None;
    t.for_each_kv(|seq, w| {
        if w.task_cap_id == task_cap_id {
            old_seq = Some(*seq);
        }
    });
    if let Some(old) = old_seq {
        t.remove(&old);
    } else if LIVE_WAITERS.load(Ordering::Acquire) >= MAX_IRQ_WAITERS as u64 {
        return Err(IrqWaitError::RegistryFull);
    }
    let seq = NEXT_SEQ.fetch_add(1, Ordering::AcqRel);
    t.insert(
        seq,
        IrqWaiter {
            task_cap_id,
            mask_phys,
            mask_slots,
            lines: dedup,
            line_count: count,
        },
    )
    .map_err(|_| IrqWaitError::RegistryFull)?;
    if old_seq.is_none() {
        LIVE_WAITERS.fetch_add(1, Ordering::AcqRel);
    }
    Ok(seq)
}

/// Обработчик IRQ: линия `line` сработала. Для каждого ожидающего, чей
/// сет содержит линию: дописывает номер линии в его массив, снимает
/// ожидание и БУДИТ задачу через планировщик текущего ядра
/// (`scheduler_release_object(irq_wait_object(seq))`).
///
/// Ограничение v2: wake — через per-core планировщик текущего ядра;
/// корректно, когда ожидающие зарегистрированы на этом же ядре (все
/// boot-серверы — на BSP; межъядерный wake — вместе с IPI-механикой).
pub fn on_irq_fired<Umap: MemoryInterfaceUserspace>(
    lctl: &mut LocalKernelCTL<Umap>,
    line: u32,
) {
    let Some(t) = table() else {
        return;
    };
    // Двухфазно: будим и собираем снятые ключи под одним локом, удаляем
    // вторым проходом (удаление во время обхода дерева запрещено).
    let mut fired = [0u64; MAX_IRQ_WAITERS];
    let mut fired_count = 0usize;
    {
        let t = t.0.lock();
        t.for_each_kv(|seq, w| {
            if w.lines[..w.line_count].contains(&line) && fired_count < MAX_IRQ_WAITERS {
                append_line(w.mask_phys, w.mask_slots, line);
                // OneShot: ожидание снято, userspace перевызывает WaitIrq.
                fired[fired_count] = *seq;
                fired_count += 1;
            }
        });
    }
    if fired_count == 0 {
        return;
    }
    let mut t = t.0.lock();
    for &seq in &fired[..fired_count] {
        if t.remove(&seq).is_some() {
            LIVE_WAITERS.fetch_sub(1, Ordering::AcqRel);
            lctl.scheduler_release_object(irq_wait_object(seq));
        }
    }
}

/// Снимает ВСЕ ожидания задачи (уничтожение: реестр не должен течь).
pub fn unregister_task_wait(task_cap_id: u64) {
    let Some(t) = table() else {
        return;
    };
    let mut gone = [0u64; MAX_IRQ_WAITERS];
    let mut gone_count = 0usize;
    {
        let t = t.0.lock();
        t.for_each_kv(|seq, w| {
            if w.task_cap_id == task_cap_id && gone_count < MAX_IRQ_WAITERS {
                gone[gone_count] = *seq;
                gone_count += 1;
            }
        });
    }
    if gone_count == 0 {
        return;
    }
    let mut t = t.0.lock();
    for &seq in &gone[..gone_count] {
        if t.remove(&seq).is_some() {
            LIVE_WAITERS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Линия ПЕРЕСТАЛА существовать (RELEASE владельцем или teardown): будим
/// всех, кто ждал её mint-копией. Номер линии в их массивы НЕ дописывается
/// (события не было — это «линия ушла»): userspace после пустого
/// пробуждения перевызывает WaitIrq и получает E_CAP_REVOKED (проверка
/// живости линии в syscall-слое). Без этого wake-а ждущий протухшей
/// линии спал бы навсегда (revocation-vs-wait; полная механика —
/// cap-нотификации, отложены).
///
/// Возвращает число снятых регистраций (диагностика). Вызываемо из любого
/// контекста: скан/снятие под IrqSafe-локом таблицы, wake — глобальный
/// (task::wake, без lctl: дренит и своё ядро тоже).
pub fn on_line_released(line: u32) -> usize {
    let Some(t) = table() else {
        return 0;
    };
    // Двухфазно (как on_irq_fired): сбор seq под локом, снятие+wake вторым.
    let mut gone = [0u64; MAX_IRQ_WAITERS];
    let mut gone_count = 0usize;
    {
        let t = t.0.lock();
        t.for_each_kv(|seq, w| {
            if w.lines[..w.line_count].contains(&line) && gone_count < MAX_IRQ_WAITERS {
                gone[gone_count] = *seq;
                gone_count += 1;
            }
        });
    }
    if gone_count == 0 {
        return 0;
    }
    let mut woken = 0usize;
    let mut t = t.0.lock();
    for &seq in &gone[..gone_count] {
        if t.remove(&seq).is_some() {
            LIVE_WAITERS.fetch_sub(1, Ordering::AcqRel);
            crate::task::wake::release_object_global(irq_wait_object(seq), None);
            woken += 1;
        }
    }
    woken
}

/// Пишет u64 в физическую память через HHDM.
///
/// # Safety
/// `phys` обязан быть выровнен на 8 и указывать на живую, замапленную
/// HHDM память (здесь: страница задачи, полученная через translate).
fn write_u64_phys(phys: usize, value: u64) {
    // SAFETY: контракт функции (translate вернул физику страницы задачи).
    unsafe { (phys_to_virt(phys) as *mut u64).write_volatile(value) };
}

/// Дописывает номер линии в массив задачи: `[count][line0]...[lineN-1]`,
/// насыщенно по ёмкости (лишние срабатывания теряются, счётчик растёт
/// всегда — userspace видит, что события пропущены).
fn append_line(mask_phys: usize, mask_slots: usize, line: u32) {
    // SAFETY: phys получен из translate живого умапа задачи, выровнен
    // при регистрации и целиком лежит в одной странице (страничное
    // ограничение register_irq_wait); страницы задачи замаплены HHDM.
    let base = phys_to_virt(mask_phys) as *mut u64;
    unsafe {
        let count = base.read_volatile();
        if (count as usize) < mask_slots {
            base.add(1 + count as usize).write_volatile(line as u64);
        }
        // Счётчик растёт независимо от ёмкости: переполнение событий видно.
        base.write_volatile(count.saturating_add(1));
    }
}

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{MemoryPTR, set_hhdm_offset};
    /// Фиктивный умап: транслирует любой VA в "физику" (VA + MAGIC_DELTA),
    /// где DELTA выбрана так, чтобы физика указывала в тестовый буфер.
    struct FakeUmap {
        delta: usize,
    }

    impl MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _c: usize,
        ) -> Result<MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _r: MemoryPTR,
            _c: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: MemoryPTR,
            _v: usize,
        ) -> Result<MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: MemoryPTR,
            _v: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, virt: usize) -> Option<usize> {
            virt.checked_sub(self.delta)
        }
    }

    /// Поднимает slab-хуки (страницы "физики" с 1 — bump).
    fn init_slab() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use crate::traits::memory::{init_hooks, FrameAllocator};
        struct TestFrames(AtomicUsize);
        impl FrameAllocator for TestFrames {
            fn allocate_pages(&self, count: usize) -> Option<MemoryPTR> {
                let first = self.0.fetch_add(count, Ordering::SeqCst);
                MemoryPTR::new(first * PAGE_SIZE, count)
            }
            fn deallocate_pages(&self, _ptr: MemoryPTR) {}
        }
        static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));
        init_hooks::init_allocator(&FRAMES);
    }

    #[test]
    fn irq_wait_fills_mask_and_wakes() {
        let _guard = crate::test_guard::GLOBAL.lock();
        // Раскладка как у iommu-тестов: HHDM-offset = адрес буфера (физ 0
        // -> буфер), slab-страницы (с "физической" страницы 1) приземляются
        // в буфер. Буфер 64 страницы (общий bump-аллокатор мог уже выдать
        // slab-страницы до ~N — запас обязателен, см. endpoint-тест);
        // массив маски кладём на страницу 40 — подальше от slab-узлов.
        let mem = crate::traits::memory::test_alloc::page_aligned_leak(64);
        set_hhdm_offset(mem.as_ptr() as usize);
        init_slab();

        let umap = FakeUmap {
            delta: 0x1_0000_0000,
        };
        const MASK_PAGE: usize = 40;
        let mask_phys = MASK_PAGE * PAGE_SIZE + 0x100;
        let mask_va = mask_phys + 0x1_0000_0000; // внутри буфера

        let mut lctl = crate::lctl::LocalKernelCTL::<FakeUmap>::new();

        // Регистрация: линии 2 и 5, массив на 4 слота.
        let seq = register_irq_wait(
            0x42,
            &umap,
            &[2, 5, 5], // дубликат 5 дедуплицируется
            mask_va,
            4,
        )
        .expect("регистрация");
        assert_ne!(seq, 0);

        // Счётчик обнулён при регистрации.
        let hdr = unsafe { &*(mem.as_ptr().add(MASK_PAGE * PAGE_SIZE + 0x100) as *const u64) };
        assert_eq!(*hdr, 0);

        // Срабатывает линия 5 (не первая в списке).
        on_irq_fired(&mut lctl, 5);

        // Ожидание снято (OneShot), массив заполнен: count=1, line=5.
        let words = unsafe { std::slice::from_raw_parts(mem.as_ptr().add(MASK_PAGE * PAGE_SIZE + 0x100) as *const u64, 5) };
        assert_eq!(words[0], 1, "счётчик");
        assert_eq!(words[1], 5, "номер сработавшей линии");

        // Повторная регистрация (та же задача — старая запись замещена,
        // квота не течёт): узкий массив на 2 слота.
        let _seq2 = register_irq_wait(0x42, &umap, &[2, 5], mask_va, 2).expect("регистрация 2");
        on_irq_fired(&mut lctl, 2);
        // Счётчик обнулён второй регистрацией, линия 2: count=1.
        let words = unsafe { std::slice::from_raw_parts(mem.as_ptr().add(MASK_PAGE * PAGE_SIZE + 0x100) as *const u64, 3) };
        assert_eq!(words[0], 1);
        assert_eq!(words[1], 2);

        // Слишком много линий после дедупа.
        let err = register_irq_wait(1, &umap, &[1, 2, 3, 4, 5, 6, 7, 8, 9], mask_va, 4)
            .unwrap_err();
        assert_eq!(err, IrqWaitError::TooManyLines);

        // Пустой список, нулевая ёмкость, невыровненный указатель,
        // неотображённый адрес, массив пересекает страницу.
        assert_eq!(
            register_irq_wait(1, &umap, &[], mask_va, 4).unwrap_err(),
            IrqWaitError::NoLines
        );
        assert_eq!(
            register_irq_wait(1, &umap, &[3], mask_va, 0).unwrap_err(),
            IrqWaitError::ZeroMaskSlots
        );
        assert_eq!(
            register_irq_wait(1, &umap, &[3], mask_va + 4, 4).unwrap_err(),
            IrqWaitError::BadPointer,
            "физика не выровнена на 8"
        );
        assert_eq!(
            register_irq_wait(1, &umap, &[3], 0x1000, 4).unwrap_err(),
            IrqWaitError::BadPointer,
            "адрес ниже дельты: translate -> None (вне умапа)"
        );
        // Массив, выходящий за страницу: mask_phys близко к концу страницы.
        let tail_va = 0x1_0000_0000 + (MASK_PAGE * PAGE_SIZE) + PAGE_SIZE - 8;
        assert_eq!(
            register_irq_wait(1, &umap, &[3], tail_va, 2).unwrap_err(),
            IrqWaitError::BadPointer,
            "массив счётчик+2 слота не влезает в страницу"
        );

        // Тейдаун: регистрация исчезает, on_irq_fired её больше не будит.
        let _seq3 = register_irq_wait(0x77, &umap, &[3], mask_va, 4).expect("регистрация 3");
        unregister_task_wait(0x77);
        on_irq_fired(&mut lctl, 3); // не должно паниковать/писать массив

        // RELEASE линии: ожидание mint-копии снимается ПУСТЫМ пробуждением
        // (номер линии в массив не пишется — события не было).
        let _seq4 = register_irq_wait(0x88, &umap, &[9], mask_va, 4).expect("регистрация 4");
        let woken = on_line_released(9);
        assert_eq!(woken, 1, "ожидание линии 9 снято");
        // Массив НЕ дополнен (счётчик остался 0 — обнулён при регистрации).
        let words = unsafe { std::slice::from_raw_parts(mem.as_ptr().add(MASK_PAGE * PAGE_SIZE + 0x100) as *const u64, 1) };
        assert_eq!(words[0], 0, "пустое пробуждение: события не было");
        // Повторный release той же линии — никого.
        assert_eq!(on_line_released(9), 0);
        // Незадетые линии — нет ни снятий, ни эффектов.
        assert_eq!(on_line_released(42), 0);
    }
}
