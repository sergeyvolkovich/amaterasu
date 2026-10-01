//! task — спавн задач из пользовательского кода (динамический exec).
//!
//! Два источника образа (зеркало kernel_exec::syscall):
//!   - TASK_CREATE(44) — капа `TaskImage` на boot-модуль (у init: слот
//!     32+j, см. [`image_slot`]): реестр образов живёт в ядре;
//!   - TASK_CREATE_FROM_MEM(45) — ELF в ЧИТАЕМОЙ памяти вызывающего:
//!     бинарь, загруженный файловым сервером и отданный map item'ом
//!     (CAP_CREATE_SHARED → IPC → MOUNT_CAP_REGION), или собственный
//!     ALLOC_PAGES-буфер. Ядро снимает снапшот ДО разбора — источник
//!     можно освободить сразу после возврата (exec by-value).
//!
//! Authority (общая для обоих):
//!   1. потолок `TASK_CREATE` у неймспейса ВЫЗЫВАЮЩЕГО;
//!   2. капа `TaskGroupNamespace` на целевой неймспейс;
//!   3. потолок `TASK_CREATE` у ЦЕЛЕВОГО неймспейса — без него группа
//!      не ПРИНИМАЕТ задачи (target-ceiling), даже если у создателя всё
//!      есть. Хочешь дропать задачи в неймспейс — дай ему TASK_CREATE
//!      в rights_mask при CAP_CREATE_NAMESPACE; не хочешь, чтобы он сам
//!      спавнил — не давай его задачам кап на неймспейсы/образы
//!      (полномочия задают капы, потолок — вторая линия обороны).
//!
//! Полномочия ребёнка задаёт НЕЙМСПЕЙС, а не образ: он получает ровно
//! 3 bootstrap-капы (0 = self, 1 = неймспейс, 2 = родитель
//! [`abi::auxv::BOOT_SLOT_PARENT`]) и потолки своей группы. Ресурсы
//! (MMIO/IRQ/ACPI/память) доставляются обычным IPC — map item'ами.
//! Имя/путь ребёнок узнаёт по IPC от родителя (TASK_CREATE_FROM_MEM
//! стартует его с argv = []).

use crate::abi;
use crate::crt0;
use crate::handle::{Slot, TaskCap, Va};
use crate::ipc;
use crate::syscall::{self, SyscallError};

/// Спавн boot-образа по TaskImage-капе в слоте `image_slot` неймспейса
/// `ns_slot`. Возврат — TaskTCB-капа ребёнка ([`TaskCap`]; она кладётся
/// и в `dst` cspace вызывающего — адресация IPC).
pub fn create_from_boot_image(
    ns_slot: Slot,
    image_slot: Slot,
    dst: Slot,
) -> Result<TaskCap, SyscallError> {
    let code =
        unsafe { syscall::syscall3(abi::nr::TASK_CREATE, ns_slot.raw(), image_slot.raw(), dst.raw()) };
    syscall::check(code).map(TaskCap::new)
}

/// Exec ELF-образа `[image_va, image_va + image_size)` из ЧИТАЕМОЙ
/// памяти вызывающего в неймспейс `ns_slot`.
///
/// Выравнивание `image_va` не требуется; размер ограничен 16 МиБ
/// (MAX_EXEC_IMAGE_BYTES ядра). Ошибки: E_INVALID_ARG (пустой/чужой/
/// недоступный диапазон), E_RIGHTS_DENIED (потолки TASK_CREATE),
/// E_SLOT_EMPTY/E_CAP_REVOKED (капа неймспейса), E_QUOTA (квоты
/// целевой группы), E_SLAB (кадры/слаб под снапшот).
pub fn exec_from_memory(
    ns_slot: Slot,
    image_va: Va,
    image_size: u64,
    dst: Slot,
) -> Result<TaskCap, SyscallError> {
    let code = unsafe {
        syscall::syscall4(
            abi::nr::TASK_CREATE_FROM_MEM,
            ns_slot.raw(),
            image_va.raw(),
            image_size,
            dst.raw(),
        )
    };
    syscall::check(code).map(TaskCap::new)
}

/// Слот TaskImage-капы j-го образа реестра (есть только у init-сервера;
/// j — порядковый номер boot-модуля = порядок Limine-модулей).
pub const fn image_slot(j: u64) -> Slot {
    Slot::new(abi::auxv::BOOT_SLOT_IMAGE_BASE + j)
}

/// Слот peer'а по имени из бут-ростера: argv задачи содержит имена всех
/// boot-серверов (argv[0] — своё имя), i-е имя ростера — слот
/// [`ipc::PEER_SLOT_BASE`] + (i-1). Общая точка вместо копий в демо.
pub fn peer_slot_of(name: &str) -> Option<Slot> {
    let argc = crt0::args()?;
    for i in 1..argc {
        let p = crt0::argv_at(i)?;
        let mut len = 0usize;
        // SAFETY: argv — NUL-терминированные строки стартового стека.
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
        }
        let bytes = unsafe { core::slice::from_raw_parts(p, len) };
        let base = match bytes.iter().rposition(|&b| b == b'/') {
            Some(pos) => &bytes[pos + 1..],
            None => bytes,
        };
        if base == name.as_bytes() {
            return Some(Slot::new(ipc::PEER_SLOT_BASE.raw() + (i - 1) as u64));
        }
    }
    None
}
