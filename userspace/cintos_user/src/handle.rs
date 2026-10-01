//! handle — типизированные хендлы поверх raw u64.
//!
//! Сырой u64 в capability-модели перегружен: слот cspace, id
//! capability-объекта, TaskTCB-капа, VA, физика, счётчик страниц —
//! всё одно машинное слово. Newtype-обёртки превращают «напутал
//! слот с капой» в ошибку КОМПИЛЯЦИИ, а не в E_SLOT_EMPTY в QEMU
//! посреди ночи.
//!
//! Конвенция: new/raw на границах (wire-формат, auxv, C-ABI — там
//! всё ещё u64), внутри сигнатур библиотеки — только типы. Обратного
//! пути `From<u64>` НЕТ намеренно: через границу — явно new()/raw().
//!
//! ```text
//! Slot(u64)    — индекс записи в cspace задачи (адресация капы);
//! CapId(u64)   — id capability-объекта ядра (возврат create_*/mint);
//! TaskCap(u64) — id TaskTCB-капы (адресация ЗАДАЧИ: mint/clone/
//!                revoke/destroy, reply-цель; подтип CapId по смыслу);
//! Va(u64)      — userspace-виртуальный адрес;
//! Phys(u64)    — физический адрес (MMIO-диапазоны);
//! Pages(u64)   — счётчик страниц (не байты!).
//! ```

/// Индекс записи в cspace задачи. Единственный способ адресовать капу
/// в сисколлах — слот СВОЕГО cspace (или TaskTCB-капа + слот чужого).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot(u64);

/// Id capability-объекта ядра (возврат CAP_CREATE_*/MINT/CLONE).
/// Глобальный идентификатор: сам по себе authority НЕ даёт (ambient
/// authority закрыт — ядро принимает только слоты/TaskTCB-капы).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapId(u64);

/// Id TaskTCB-капы: «капа НА ЗАДАЧУ». Отличается от [`CapId`]
/// семантикой: аргумент src_task_cap/dst_task_cap в mint/clone,
/// owner в create_mmio, цель fault::reply — всегда TaskCap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskCap(u64);

/// Userspace-виртуальный адрес (возврат alloc_pages/mount_region).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Va(u64);

/// Физический адрес (база MMIO-диапазона в cap::create_mmio).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phys(u64);

/// Число страниц. Отдельный тип: перепутать с байтами/VA —
/// классическая ошибка (pages в ALLOC_PAGES/CREATE_SHARED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pages(u64);

macro_rules! handle {
    ($(#[$meta:meta])* $name:ident) => {
        impl $name {
            /// Обернуть raw-значение с границы (wire/auxv/C-ABI).
            pub const fn new(raw: u64) -> Self {
                Self(raw)
            }
            /// Достать raw-значение (вызов сисколла, C-ABI, лог).
            pub const fn raw(self) -> u64 {
                self.0
            }
        }
    };
}

handle!(Slot);
handle!(CapId);
handle!(TaskCap);
handle!(Va);
handle!(Phys);
handle!(Pages);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_roundtrip_is_const_compatible() {
        // new/raw — const: консты библиотеки (PEER_SLOT_BASE и др.)
        // строятся в const-контексте.
        const S: Slot = Slot::new(42);
        const R: u64 = S.raw();
        assert_eq!(R, 42);
        assert_eq!(Pages::new(7).raw(), 7);
        assert_eq!(TaskCap::new(u64::MAX), TaskCap::new(u64::MAX));
    }

    #[test]
    fn types_are_distinct_namespaces() {
        // Одинаковый raw — разные типы: присвоение/передача не скомпилятся.
        let s = Slot::new(16);
        let c = CapId::new(16);
        assert_eq!(s.raw(), c.raw()); // сравнение только по явному raw()
        fn takes_slot(_: Slot) {}
        takes_slot(s); // CapId сюда передать нельзя — компилятор стопит
    }
}
