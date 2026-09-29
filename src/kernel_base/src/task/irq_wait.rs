//! Ожидание IRQ задачей: "спать до прерывания, получить маску сработавших".
//!
//! Контракт с userspace (библиотека):
//!   1. Userspace выделяет массив из `1 + N` u64-ячеек: первая ячейка —
//!      СЧЁТЧИК сработавших IRQ, далее — номера линий в порядке срабатывания.
//!   2. Userspace вызывает сисколл WaitIrq{lines_mask, mask_ptr, mask_slots}:
//!      `lines_mask` — битмап ожидаемых линий (бит n = линия n, 0..64),
//!      `mask_ptr` — виртуальный адрес массива, `mask_slots` — ёмкость
//!      массива БЕЗ заголовка-счётчика.
//!   3. Ядро обнуляет счётчик, ставит задачу в ожидание и усыпляет её.
//!   4. Когда линия срабатывает, обработчик IRQ зовёт `on_irq_fired`:
//!      ядро ДОПИСЫВАЕТ номер линии в массив (насыщенно, по ёмкости),
//!      снимает ожидание и будит задачу.
//!   5. После пробуждения userspace читает счётчик и номера.
//!
//! Запись в userspace-память идёт через `MemoryInterfaceUserspace::translate`
//! (VA задачи -> физика) + HHDM: CR3 не переключается.
//!
//! Одноразовость: ожидание снимается после первого срабатывания ЛЮБОЙ из
//! ожидаемых линий (семантика OneShot); для следующего ожидания userspace
//! вызывает сисколл снова. Реестр фиксированной ёмкости (без alloc).
//!
//! ОБЪЕКТЫ ОЖИДАНИЯ: каждая регистрация занимает СВОЙ слот реестра и
//! блокирует задачу ровно на ОДИН объект `IRQ_OBJECT_BASE + слот`.
//! Раньше сисколл блокировал текущую задачю ПО ОДНОЙ ЛИНИИ за итерацию —
//! после первой итерации «текущей» становилась ДРУГАЯ задача, и её
//! блокировал уже её собственный вызов (баг: спящие не по своей воле).
//! Теперь будит `on_irq_fired` — по слоту ЗАРЕГИСТРИРОВАННОГО ждущего,
//! все линии его битмапа учтены одной регистрацией.

use crate::irqsafe::IrqSafeSpinMutex;
use crate::lctl::LocalKernelCTL;
use crate::traits::memory::{is_user_range, MemoryInterfaceUserspace, phys_to_virt};

/// Максимальное число ОДНОВРЕМЕННЫХ ожидающих задач.
pub const MAX_IRQ_WAITERS: usize = 16;

/// База wait-объектов IRQ-ожидания (не пересекается с IPC-объектами
/// и тестовыми идентификаторами mt_test).
pub const IRQ_OBJECT_BASE: usize = 0x2_0000;

/// Объект ожидания задачи, зарегистрированной в слоте `slot`.
pub fn irq_wait_object(slot: usize) -> usize {
    IRQ_OBJECT_BASE + slot
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqWaitError {
    /// Реестр переполнен — задач больше, чем MAX_IRQ_WAITERS.
    RegistryFull,
    /// Битмап линий пуст — ждать нечего.
    NoLines,
    /// Указатель на массив не отображён в адресном пространстве задачи.
    BadMaskPointer,
    /// Ёмкость массива нулевая.
    ZeroMaskSlots,
}

#[derive(Debug, Clone, Copy)]
struct IrqWaiter {
    /// Capability id задачи-ожидателя.
    task_cap_id: u64,
    /// Физический адрес заголовка-счётчика массива.
    mask_phys: usize,
    /// Ёмкость массива в u64-слотах (без счётчика).
    mask_slots: usize,
    /// Битмап ожидаемых линий (бит n = линия n).
    lines_mask: u64,
}

/// Слот реестра (None — свободен).
type Slot = Option<IrqWaiter>;

/// Глобальный реестр ожидающих. Статический: IRQ-путь вызывается из
/// обработчика прерывания, где нельзя ни аллоцировать, ни искать в
/// общем менеджере под локом. Лок — IRQ-БЕЗОПАСНЫЙ: реестр берут и
/// сисколлы (register), и обработчик IRQ (on_irq_fired); без гашения
/// прерываний тик таймера мог бы прервать поток, удерживающий лок,
/// и дедлокнуть ядро.
static WAITERS: IrqSafeSpinMutex<[Slot; MAX_IRQ_WAITERS]> =
    IrqSafeSpinMutex::new([None; MAX_IRQ_WAITERS]);

/// Выделение слота под регистрацию (замещает прежнюю регистрацию той
/// же задачи — череда сисколлов без пробуждений не выжигает реестр).
fn alloc_slot(waiters: &mut [Slot; MAX_IRQ_WAITERS], task_cap_id: u64) -> Option<usize> {
    let mut free: Option<usize> = None;
    for (idx, slot) in waiters.iter().enumerate() {
        match slot {
            Some(w) if w.task_cap_id == task_cap_id => return Some(idx),
            None if free.is_none() => free = Some(idx),
            _ => {}
        }
    }
    free
}

/// Устанавливает ожидание: обнуляет счётчик массива задачи и возвращает
/// НОМЕР СЛОТА реестра — задача блокируется вызывающим сисколлом на
/// `irq_wait_object(слот)` ОДИН раз (все линии битмапа — одна блокировка).
///
/// `mask_ptr` — виртуальный адрес массива В ПРОСТРАНСТВЕ ЗАДАЧИ.
pub fn register_irq_wait<Umap: MemoryInterfaceUserspace>(
    task_cap_id: u64,
    umap: &Umap,
    lines_mask: u64,
    mask_ptr: usize,
    mask_slots: usize,
) -> Result<usize, IrqWaitError> {
    if lines_mask == 0 {
        return Err(IrqWaitError::NoLines);
    }
    if mask_slots == 0 {
        return Err(IrqWaitError::ZeroMaskSlots);
    }
    // COPYOUT-ГЕЙТ: буфер маски — ядро пишет в него счётчики/линии;
    // без проверки ring3 получает запись в память ядра (mask_ptr из
    // верхней половины транслируется — верхняя половина умапа общая
    // с ядром).
    if !is_user_range(mask_ptr, mask_slots * 8) {
        return Err(IrqWaitError::BadMaskPointer);
    }
    // USER-семантика + WRITE: буфер маски — цель записи ядра (счётчики
    // линий); нижняя половина + U/S + R/W по пути (см. translate_user).
    let mask_phys = umap
        .translate_user(mask_ptr, true)
        .ok_or(IrqWaitError::BadMaskPointer)?;
    // Выравнивание u64 обязательно: пишем счётчик/линии сырыми u64.
    if mask_phys % 8 != 0 {
        return Err(IrqWaitError::BadMaskPointer);
    }

    // Обнуляем счётчик ДО постановки в ожидание: след от прошлого цикла
    // userspace обязан прочитать до нового WaitIrq.
    write_u64_phys(mask_phys, 0);

    let mut waiters = WAITERS.lock();
    let slot = alloc_slot(&mut waiters, task_cap_id).ok_or(IrqWaitError::RegistryFull)?;
    waiters[slot] = Some(IrqWaiter {
        task_cap_id,
        mask_phys,
        mask_slots,
        lines_mask,
    });
    Ok(slot)
}

/// Обработчик IRQ: линия `line` сработала. Для каждого ожидающего, чей
/// битмап содержит линию: дописывает номер линии в его массив, снимает
/// ожидание и БУДИТ задачу через планировщик текущего ядра
/// (`scheduler_release_object(irq_wait_object(слот))`).
///
/// Ограничение v1: wake — через per-core планировщик текущего ядра;
/// корректно, когда ожидающие зарегистрированы на этом же ядре (все
/// boot-серверы — на BSP).
pub fn on_irq_fired<Umap: MemoryInterfaceUserspace>(
    lctl: &mut LocalKernelCTL<Umap>,
    line: u32,
) {
    if line >= 64 {
        return;
    }
    let bit = 1u64 << line;

    let mut waiters = WAITERS.lock();
    for (slot, slot_ref) in waiters.iter_mut().enumerate() {
        let Some(w) = slot_ref else {
            continue;
        };
        if w.lines_mask & bit != 0 {
            append_line(w.mask_phys, w.mask_slots, line);
            // OneShot: ожидание снято, userspace перевызывает WaitIrq.
            *slot_ref = None;
            lctl.scheduler_release_object(irq_wait_object(slot));
        }
    }
}

/// Снимает ВСЕ ожидания задачи (уничтожение: реестр не должен течь).
pub fn unregister_task_wait(task_cap_id: u64) {
    let mut waiters = WAITERS.lock();
    for slot in waiters.iter_mut() {
        if let Some(w) = slot
            && w.task_cap_id == task_cap_id {
                *slot = None;
            }
    }
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
    // SAFETY: phys получен из translate живого умапа задачи и выровнен
    // при регистрации; страницы задачи замаплены HHDM.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::set_hhdm_offset;

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
            virt.checked_sub(self.delta)
        }
    }

    #[test]
    fn irq_wait_fills_mask_and_wakes() {
        // "Физическая память" = странично выровненный буфер; задача видит
        // его по VA = phys + 0x1_0000_0000 (офсет кратен странице).
        let mem = crate::traits::memory::test_alloc::page_aligned_leak(16);
        let phys_base = 0x40_0000usize; // "физика" буфера
        set_hhdm_offset(mem.as_ptr() as usize - phys_base);

        let umap = FakeUmap {
            delta: 0x1_0000_0000,
        };
        let mask_va = phys_base + 0x1_0000_0000 + 0x100; // внутри буфера

        let mut lctl = crate::lctl::LocalKernelCTL::<FakeUmap>::new();

        // Регистрация: линии 2 и 5, массив на 4 слота.
        register_irq_wait(0x42, &umap, (1 << 2) | (1 << 5), mask_va, 4)
            .expect("регистрация");

        // Счётчик обнулён при регистрации.
        let hdr = unsafe { &*(mem.as_ptr().add(0x100) as *const u64) };
        assert_eq!(*hdr, 0);

        // Срабатывает линия 5 (не самая младшая из ожидаемых).
        on_irq_fired(&mut lctl, 5);

        // Ожидание снято (OneShot), массив заполнен: count=1, line=5.
        let words = unsafe { std::slice::from_raw_parts(mem.as_ptr().add(0x100) as *const u64, 5) };
        assert_eq!(words[0], 1, "счётчик");
        assert_eq!(words[1], 5, "номер сработавшей линии");

        // Повторная регистрация: линии 2 и 5, узкий массив на 2 слота —
        // срабатывание обеих линий даёт saturation.
        register_irq_wait(0x42, &umap, (1 << 2) | (1 << 5), mask_va, 2).expect("регистрация 2");
        on_irq_fired(&mut lctl, 2);
        // Реестр снова принимает (ожидание снято первым срабатыванием);
        // третья регистрация обнуляет счётчик, линия 2 пишется заново.
        register_irq_wait(0x42, &umap, 1 << 2, mask_va, 2).expect("регистрация 3");
        on_irq_fired(&mut lctl, 2);
        let words = unsafe { std::slice::from_raw_parts(mem.as_ptr().add(0x100) as *const u64, 5) };
        // Второй цикл: count=1 (линия 2); третий цикл: count ещё 1 + старое
        // затёрто при регистрации третьего цикла... счётчик обнулён третьей
        // регистрацией, потом линия 2: count=1.
        assert_eq!(words[0], 1);
        assert_eq!(words[1], 2);

        // Отказы: пустой битмап, нулевая ёмкость, невыровненный указатель,
        // неотображённый адрес.
        assert_eq!(
            register_irq_wait(1, &umap, 0, mask_va, 4).unwrap_err(),
            IrqWaitError::NoLines
        );
        assert_eq!(
            register_irq_wait(1, &umap, 1 << 3, mask_va, 0).unwrap_err(),
            IrqWaitError::ZeroMaskSlots
        );
        assert_eq!(
            register_irq_wait(1, &umap, 1 << 3, mask_va + 4, 4).unwrap_err(),
            IrqWaitError::BadMaskPointer,
            "физика не выровнена на 8"
        );
        assert_eq!(
            register_irq_wait(1, &umap, 1 << 3, 0x1000, 4).unwrap_err(),
            IrqWaitError::BadMaskPointer,
            "адрес ниже дельты: translate -> None (адрес вне умапа)"
        );
    }
}
