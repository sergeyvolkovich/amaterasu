use crate::{
    lctl::LocalKernelCTL,
    traits::memory::MemoryInterfaceUserspace,
};

pub trait SyscallArguments {
    const MAX_ARG_COUNT: usize;

    fn init_from_regs(regs: &[u64]) -> Self;
    fn get_argument<const ID: usize>(&self) -> u64;
}

/// Коды возврата сисколлов (ArchImplementation::register_syscalls обязан
/// выдать результат handle() в возвращаемый регистр порта).
///
/// Договорённость: старший бит == 1 — ошибка; иначе значение — результат
/// (0 или, например, id созданной capability; id 0 — валидный, различение
/// успех/ошибка — по старшему биту, а не по нулю).
pub const SYSCALL_ERROR_FLAG: u64 = 0x8000_0000_0000_0000;

/// Единые коды ошибок для всех доменов сисколлов.
pub mod syscall_result {
    use super::SYSCALL_ERROR_FLAG;

    /// Успех (или 0-результат).
    pub const OK: u64 = 0;
    /// Сисколл без текущей задачи (kernel-bootstrap-контекст).
    pub const E_NO_CURRENT_TASK: u64 = SYSCALL_ERROR_FLAG | 1;
    /// Отказ групповых прав неймспейса (приоритет неймспейса над потоком).
    pub const E_RIGHTS_DENIED: u64 = SYSCALL_ERROR_FLAG | 2;
    /// Объект/задача не найдены.
    pub const E_NOT_FOUND: u64 = SYSCALL_ERROR_FLAG | 3;
    /// Слот cspace уже занят.
    pub const E_SLOT_OCCUPIED: u64 = SYSCALL_ERROR_FLAG | 4;
    /// Слот cspace пуст.
    pub const E_SLOT_EMPTY: u64 = SYSCALL_ERROR_FLAG | 5;
    /// Capability отозвана (эпоха/генерация не совпали).
    pub const E_CAP_REVOKED: u64 = SYSCALL_ERROR_FLAG | 6;
    /// Запрошенные права превышают доступные.
    pub const E_RIGHTS_EXCEEDED: u64 = SYSCALL_ERROR_FLAG | 7;
    /// Ошибка slab-аллокатора (нет памяти под служебные структуры).
    pub const E_SLAB: u64 = SYSCALL_ERROR_FLAG | 8;
    /// Квота namespace исчерпана/разъехался учёт.
    pub const E_QUOTA: u64 = SYSCALL_ERROR_FLAG | 9;
    /// Пространство id исчерпано.
    pub const E_IDS_EXHAUSTED: u64 = SYSCALL_ERROR_FLAG | 10;
    /// Некорректные аргументы сисколла.
    pub const E_INVALID_ARG: u64 = SYSCALL_ERROR_FLAG | 11;
    /// Сломан внутренний инвариант (требует внимания разработчика).
    pub const E_INTERNAL: u64 = SYSCALL_ERROR_FLAG | 12;
    /// Сисколл известен реестру, но ещё не реализован портом/доменом.
    ///
    /// ВАЖНО: незакрытые TODO в обработчиках обязаны возвращать этот код,
    /// а не `todo!()`: паника в no_std-ядре с panic=abort мгновенно
    /// убивает ВСЁ ядро (и все задачи) из-за одного вызова userspace.
    pub const E_NOT_IMPLEMENTED: u64 = SYSCALL_ERROR_FLAG | 13;

    /// Успех/ошибка по старшему бит (зеркало abi.rs::is_error).
    #[inline]
    pub const fn is_error(code: u64) -> bool {
        code & SYSCALL_ERROR_FLAG != 0
    }
}

pub trait SyscallDomain: Sized {
    const SYSCALL_ID: usize;

    type Args: SyscallArguments;
    type Umap: MemoryInterfaceUserspace;

    /// Обработка сисколла. Возвращаемое значение порт кладёт в
    /// возвращаемый регистр: старший бит 1 — ошибка (см. syscall_result),
    /// иначе — результат операции (id созданной capability и т.п.).
    fn handle(
        &'static self,
        lctl: &mut LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64;
}
