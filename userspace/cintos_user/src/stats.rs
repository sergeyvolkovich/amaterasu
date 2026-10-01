//! stats — чтение статистики задач (перенос отчётности в юзерспейс).
//!
//! Ядро только СЧИТАЕТ события (cpu_ticks, yields, ipc_sent/recv,
//! blocks — в момент их возникновения) и глобальный uptime; ВЛАДЕЛЕЦ
//! отчётности — юзерспейс: этот модуль забирает снапшоты сисколлом
//! TASK_STATS и разбирает wire-блок (зеркало kernel_base::task::stats).
//!
//! Политика доступа: собственная статистика — всегда; чужая — право
//! STATS_READ у группы задачи (namespace-потолок).

use crate::abi;
use crate::handle::TaskCap;
use crate::syscall::{self, SyscallResult};

/// Слов в wire-блоке статистики (зеркало kernel_base).
pub const STATS_WORDS: usize = 16;

/// Волшебное слово блока (зеркало kernel_base::task::stats::STATS_MAGIC).
pub const STATS_MAGIC: u64 = 0xC1A7_57A7_0000_0001;

/// Разобранный снапшот статистики задачи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStats {
    pub task_cap_id: u64,
    /// Тиков CPU, проведённых задачей текущей на ядре.
    pub cpu_ticks: u64,
    /// Добровольных уступок (SCHED_YIELD).
    pub yields: u64,
    /// Доставленных исходящих IPC.
    pub ipc_sent: u64,
    /// Принятых IPC.
    pub ipc_recv: u64,
    /// Блокировок на объектах ожидания.
    pub blocks: u64,
    /// Вытеснений таймером (невольная потеря CPU — карусель тика).
    pub preempts: u64,
    /// Глобальный uptime системы (тики) — точное время ядра
    /// (не теряет тики, пропущенные одноразовым WaitIrq).
    pub global_ticks: u64,
    /// Частота тика (Гц), объявленная портом (0 — без таймера).
    pub tick_hz: u64,
    /// Логическая линия тика таймера (u32::MAX — таймер не поднят):
    /// таймер-сервер берёт её капой (CAP_CREATE_IRQ) и ждёт WAIT'ом.
    pub timer_line: u64,
}

/// Буфер под снапшот (16 u64-слов, выравнивание u64).
pub type StatsBuf = [u64; STATS_WORDS];

/// Свежий буфер статистики.
pub const fn stats_buf() -> StatsBuf {
    [0; STATS_WORDS]
}

/// Забрать снапшот статистики задачи `task` (свой — из auxv
/// AT_NOMAD_SELF_CAP через bootstrap(), см. crt0). Буфер перезаписывается.
pub fn task_stats(task: TaskCap, buf: &mut StatsBuf) -> SyscallResult<TaskStats> {
    let code = unsafe {
        syscall::syscall3(
            abi::nr::TASK_STATS,
            task.raw(),
            buf.as_mut_ptr() as u64,
            (STATS_WORDS * 8) as u64,
        )
    };
    syscall::check(code)?;
    parse(buf).ok_or(syscall::SyscallError::Kernel(abi::result::E_INTERNAL))
}

/// Разбор wire-блока (выделен для C-ABI-переиспользования).
pub fn parse(buf: &StatsBuf) -> Option<TaskStats> {
    if buf[0] != STATS_MAGIC || buf[1] != 1 {
        return None;
    }
    Some(TaskStats {
        task_cap_id: buf[2],
        cpu_ticks: buf[3],
        yields: buf[4],
        ipc_sent: buf[5],
        ipc_recv: buf[6],
        blocks: buf[7],
        global_ticks: buf[8],
        tick_hz: buf[9],
        timer_line: buf[10],
        preempts: buf[11],
    })
}
