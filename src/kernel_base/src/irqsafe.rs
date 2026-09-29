//! IRQ-безопасные примитивы синхронизации для архитектурно-независимого
//! слоя (обезличивание: ядро НЕ знает, как гасятся прерывания на
//! конкретной платформе, — порт регистрирует хуки).
//!
//! ЗАЧЕМ: с появлением таймера (и других источников IRQ) обработчик
//! прерывания начинает выполняться в ПРОИЗВОЛЬНОЙ точке кода ядра. Если
//! прерванный поток удерживает спин-лок, который берёт и IRQ-путь
//! (реестр irq_wait, планировщик), обычный `SpinMutex` даёт дедлок:
//! обработчик вечно крутится на локе, который никогда не освободится.
//!
//! РЕШЕНИЕ: [`IrqSafeSpinMutex`] гасит маскируемые прерывания на секции
//! (CLI/STI на x86_64, любой эквивалент на другом порту). Пока поток
//! держит лок, IRQ-обработчик физически не может начаться — реентераб
//! ельность исключена. Вложенность корректна: `irq_save` возвращает
//! прежнее состояние флага, `irq_restore` восстанавливает его.
//!
//! Хуки отключения прерываний — собственность ПОРТА: kernel_base
//! архитектурно-нейтрален и зовёт [`set_irq_hooks`] один раз при старте.
//! Без регистрации хуков (хостовые тесты, однопоточные окружения)
//! лок вырождается в обычный SpinMutex.

use spin::mutex::SpinMutex;

/// Хук «выключить прерывания, вернуть прежнее состояние».
pub type IrqSaveFn = fn() -> bool;
/// Хук «восстановить состояние прерываний».
pub type IrqRestoreFn = fn(bool);

static HOOKS: spin::Once<(IrqSaveFn, IrqRestoreFn)> = spin::Once::new();

/// Регистрирует хуки управления прерываниями (вызывает порт при старте,
/// ДО первого включения источников IRQ).
pub fn set_irq_hooks(save: IrqSaveFn, restore: IrqRestoreFn) {
    HOOKS.call_once(|| (save, restore));
}

/// Гасит маскируемые прерывания на текущем ядре; возвращает прежнее
/// состояние (true — были разрешены). Без зарегистрированных хуков — no-op.
pub fn irq_save() -> bool {
    HOOKS.get().is_none_or(|(save, _)| save())
}

/// Восстанавливает состояние прерываний после [`irq_save`].
pub fn irq_restore(was_enabled: bool) {
    if let Some((_, restore)) = HOOKS.get() {
        restore(was_enabled);
    }
}

/// Спин-лок с автоматическим гашением прерываний на критической секции.
///
/// Для структур, которых касаются ОБА пути: сисколлы задач И обработчики
/// прерываний (реестр irq_wait, планировщик). Обычные структуры
/// (IPC-реестр эндпоинтов — только сисколлы) остаются на `SpinMutex`.
pub struct IrqSafeSpinMutex<T> {
    inner: SpinMutex<T>,
}

impl<T> IrqSafeSpinMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: SpinMutex::new(value),
        }
    }

    /// Блокирует с гашением прерываний: пока жив гард, IRQ-обработчик
    /// на этом ядре не стартует.
    pub fn lock(&self) -> IrqSafeGuard<'_, T> {
        let flags = irq_save();
        IrqSafeGuard {
            guard: Some(self.inner.lock()),
            flags,
        }
    }
}

/// Гард [`IrqSafeSpinMutex`]: освобождение — СПЕРВА спин-лок, ПОТОМ
/// восстановление флага прерываний.
///
/// ПОРЯДОК КРИТИЧЕН (баг, пойманный живым QEMU-прогоном): тело
/// `Drop::drop` выполняется ДО дропа полей структуры. Если вернуть IF
/// (sti) в теле, спин-лок ещё удерживается — открывается окно «лок
/// занят + прерывания разрешены»: тик таймера прерывает владельца в
/// этом окне и навечно закручивается на занятом слове лока
/// (дедлок: RIP=spin_loop_hint, обработчик ждёт SCHEDULERS.inner).
/// Поэтому внутренний гард изымается и роняется ВНУТРИ тела drop —
/// ДО `irq_restore`.
pub struct IrqSafeGuard<'a, T> {
    /// Внутренний гард. `Option` — чтобы изъять и освободить лок
    /// ДО восстановления IF (drop-порядок полей тут не помощник:
    /// тело Drop идёт раньше дропа полей).
    guard: Option<spin::mutex::SpinMutexGuard<'a, T>>,
    /// Снимок IF на входе в критическую секцию.
    flags: bool,
}

impl<T> core::ops::Deref for IrqSafeGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // После take() (только внутри Drop) разыменования быть не может:
        // гард жив → Option всегда Some.
        self.guard.as_ref().map(|g| &**g).expect("IrqSafeGuard: гард изъят вне Drop")
    }
}

impl<T> core::ops::DerefMut for IrqSafeGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().map(|g| &mut **g).expect("IrqSafeGuard: гард изъят вне Drop")
    }
}

impl<T> Drop for IrqSafeGuard<'_, T> {
    fn drop(&mut self) {
        // 1) Спин-лок прочь: take() + drop освобождает слово лока
        //    (Some(guard) роняется ровно здесь, не «после» тела drop).
        // 2) Только потом IF: sti при удерживаемом локе — окно дедлока
        //    (см. комментарий к структуре).
        drop(self.guard.take());
        irq_restore(self.flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Без зарегистрированных хуков лок ведёт себя как обычный спин-лок
    /// (хостовые тесты): захват/освобождение/чтение работают, флаг
    /// «прошлое состояние» по умолчанию true (no-op). Вложенный захват
    /// РАЗНЫХ локов (как в реальном коде: irq_wait -> планировщик)
    /// не клинит.
    #[test]
    fn locks_without_hooks() {
        let a: IrqSafeSpinMutex<u64> = IrqSafeSpinMutex::new(0);
        let b: IrqSafeSpinMutex<u64> = IrqSafeSpinMutex::new(0);
        {
            let mut ga = a.lock();
            *ga += 1;
            {
                let mut gb = b.lock();
                *gb += 10;
            }
            assert_eq!(*ga, 1);
        }
        assert_eq!(*a.lock(), 1);
        assert_eq!(*b.lock(), 10);
    }
}
