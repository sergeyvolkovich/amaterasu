//! Реестр boot-образов для динамического спавна (TASK_CREATE).
//!
//! Boot-модули Limine живут в памяти загрузчика (физические адреса
//! стабильны всё время работы системы — кадры AcpiReclaimable/модулей
//! не возвращаются пулу, см. kernel_x86::reclaim_memory). Ядро
//! регистрирует каждый модуль ЗДЕСЬ при буте (до спавна серверов),
//! получая стабильный `module_id`. По капе
//! `CapabilityObject::TaskImage { module_id }` сисколл TASK_CREATE
//! загружает образ в НОВУЮ задачу — так init поднимает файловый
//! сервер/драйверы в своих неймспейсах без ambient authority:
//! имя модуля из ring3 неадресуемо, адресуется только капа.
//!
//! РЕЕСТР ТОЛЬКО РАСТЁТ (append-only): module_id неизменяемы, а
//! CapabilityObject::TaskImage хранит чистые данные (без указателей) —
//! resolve не требует generation-чеков. Переполнение реестра — модуль
//! не регистрируется (TASK_CREATE по нему невозможен; бут-спавн не
//! страдает — он читает BootInfo напрямую).
//!
//! Память образов: физический адрес + размер; чтение — через HHDM
//! (`phys_to_virt`), как в spawn-пути boot-серверов.

use kernel_base::irqsafe::IrqSafeSpinMutex;

/// Максимум регистрируемых образов (ростер boot-модулей — до 12,
/// запас под модули, добавляемые конфигом загрузчика).
pub const MAX_BOOT_IMAGES: usize = 16;

/// Максимальная длина имени образа (совпадает с лимитом имён серверов
/// в spawn — heapless::String<48>).
type ModuleName = heapless::String<48>;

/// Зарегистрированный boot-образ.
#[derive(Debug, Clone)]
pub struct BootModuleRecord {
    /// Имя модуля (basename пути Limine; для диагностики/argv[0]).
    pub name: ModuleName,
    /// Физический адрес начала образа (замаплен HHDM).
    pub phys: usize,
    /// Размер образа в байтах.
    pub size: usize,
}

static MODULES: IrqSafeSpinMutex<heapless::Vec<BootModuleRecord, MAX_BOOT_IMAGES>> =
    IrqSafeSpinMutex::new(heapless::Vec::new());

/// Регистрирует boot-образ; возврат — его `module_id` (индекс).
/// `None` — реестр полон либо имя не влезло в 48 байт.
///
/// Вызывается фронтом НА БУТЕ до старта AP (однопоточно); сисколлы
/// после бута читают реестр под тем же локом.
pub fn register_boot_module(name: &str, phys: usize, size: usize) -> Option<u32> {
    let mut modules = MODULES.lock();
    if modules.len() >= MAX_BOOT_IMAGES {
        return None;
    }
    let mut rec_name = ModuleName::new();
    rec_name.push_str(name).ok()?;
    modules
        .push(BootModuleRecord {
            name: rec_name,
            phys,
            size,
        })
        .ok()?;
    Some((modules.len() - 1) as u32)
}

/// Образ по `module_id` (копия — имя владеющее). `None` — id вне реестра.
pub fn boot_module(module_id: u32) -> Option<BootModuleRecord> {
    let modules = MODULES.lock();
    modules.get(module_id as usize).cloned()
}

/// Число зарегистрированных образов (диагностика/установка TaskImage-кап).
pub fn module_count() -> usize {
    MODULES.lock().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Реестр — глобальная статика: тесты сериализуются общим локом
    /// (как spawn-тесты kernel_exec — GLOBAL_TEST).
    #[test]
    fn registry_appends_and_reads_back() {
        let _guard = crate::test_alloc_fallback::GLOBAL_TEST.lock();

        let before = module_count();
        let id = register_boot_module("bin/fs_server", 0x200_0000, 0x1_0000)
            .expect("реестр не полон");
        assert_eq!(id as usize, before, "id = индекс записи");

        let rec = boot_module(id).expect("запись только что вставлена");
        assert_eq!(rec.name.as_str(), "bin/fs_server");
        assert_eq!(rec.phys, 0x200_0000);
        assert_eq!(rec.size, 0x1_0000);

        // Чтение вне диапазона — None (в т.ч. за концом u32-пространства).
        assert!(boot_module(u32::MAX).is_none());

        // Слишком длинное имя — None (запись не создаётся).
        // (Без alloc: 49 x'ов литеральным массивом.)
        let long_bytes = [b'x'; 49];
        let long_name = core::str::from_utf8(&long_bytes).unwrap();
        assert!(register_boot_module(long_name, 0, 0).is_none());
    }
}
