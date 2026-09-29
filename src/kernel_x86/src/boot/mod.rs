//! Бэкенд загрузки x86_64: ACPI.
//!
//! На x86_64 DT-загрузка в железе не существует — сознательно только ACPI:
//! RSDP (от загрузчика, см. BootHWModel) -> XSDT/RSDT -> таблицы
//! (DMAR -> Intel VT-d, IVRS -> AMD-Vi). Переносимость на DT-платформы —
//! вопрос отдельного arch-крейта (aarch64), а не подмешивания DTB сюда.

pub mod acpi;

use kernel_base::bootinfo::BootHWModel;

use crate::boot::acpi::{AcpiError, AcpiTables, Rsdp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    /// Модель загрузки не содержит данных для x86 (DTB на этой платформе
    /// отсутствует, Unknown — загрузчик не распознан).
    UnsupportedBackend(&'static str),
    /// Ошибка разбора ACPI.
    Acpi(AcpiError),
}

/// Разобранный boot-бэкенд.
#[derive(Debug, Clone, Copy)]
pub enum BootBackend {
    Acpi(AcpiTables),
}

impl BootBackend {
    /// Детект по информации загрузчика.
    ///
    /// # Safety
    /// Адреса в `BootHWModel` обязаны указывать на замапленную HHDM память
    /// с валидными структурами (контракт BootInfo).
    pub unsafe fn detect(boot: &BootHWModel) -> Result<Self, BootError> {
        match boot {
            BootHWModel::AcpiRsdp { begin, .. } => {
                // SAFETY: RSDP по физическому адресу от загрузчика.
                let rsdp = unsafe { Rsdp::from_physical(*begin) }.map_err(BootError::Acpi)?;
                let tables = AcpiTables::from_rsdp(&rsdp).map_err(BootError::Acpi)?;
                Ok(BootBackend::Acpi(tables))
            }
            BootHWModel::AcpiXsdt { begin } | BootHWModel::AcpiRsdt { begin } => {
                // SAFETY: адрес корневой таблицы от загрузчика.
                let tables = unsafe { AcpiTables::from_physical(*begin) }.map_err(BootError::Acpi)?;
                Ok(BootBackend::Acpi(tables))
            }
            BootHWModel::Dtb { .. } => Err(BootError::UnsupportedBackend(
                "dtb: на x86_64 DT-загрузка не существует",
            )),
            BootHWModel::Unknown => {
                Err(BootError::UnsupportedBackend("unknown boot hw model"))
            }
        }
    }

    /// Поиск ACPI-таблицы по сигнатуре.
    pub fn find_table(&self, signature: &[u8; 4]) -> Option<&[u8]> {
        match self {
            BootBackend::Acpi(tables) => tables.find_table(signature),
        }
    }
}

