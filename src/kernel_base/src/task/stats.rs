//! Статистика задач и системы: ядро СЧИТАЕТ, юзерспейс ВЛАДЕЕТ отчётностью.
//!
//! РАЗДЕЛЕНИЕ ОТВЕТСТВЕННОСТИ (перенос статистики в юзерспейс):
//!   - Ядро — единственное место, где события ВИДИМЫ (переключения
//!     контекста, доставка IPC, блокировки, тики таймера), поэтому оно
//!     ведёт минимальные атомарные счётчики в TCB и глобальный счётчик
//!     тиков. Никакой агрегации, форматирования и ПОЛИТИКИ отчётности
//!     в ядре нет.
//!   - Юзерспейс забирает снапшоты сисколлом TASK_STATS (id 29):
//!     таймер-сервер/статс-сервер сами решают, что логировать и как
//!     интерпретировать (L4-философия: сервисные политики — вне ядра).
//!
//! АРХИТЕКТУРНАЯ НЕЙТРАЛЬНОСТЬ: «тик» — абстракция ядра, источник тиков
//! (PIT на x86_64, ARCH-таймер на aarch64, ...) — собственность ПОРТА.
//! Частота объявляется портом через [`set_tick_hz`] и уезжает в каждый
//! снапшот, чтобы юзерспейс мог переводить тики в секунды без знания
//! о платформе.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::lctl::LocalKernelCTL;
use crate::traits::memory::MemoryInterfaceUserspace;

/// Волшебное слово блока статистики (юзерспейс сверяет формат).
pub const STATS_MAGIC: u64 = 0xC1A7_57A7_0000_0001;
/// Версия формата блока (16 u64-слов).
pub const STATS_VERSION: u64 = 1;
/// Слов в блоке статистики (снапшот TASK_STATS).
pub const STATS_WORDS: usize = 16;

/// Глобальный счётчик тиков системы (uptime). Инкрементируется хуком
/// тика ПОРТА (см. `on_tick`) — единственная «времяподобная» величина
/// ядра; перевод в секунды — юзерспейс (частота в снапшоте).
static GLOBAL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Частота тика (Гц), объявленная портом при старте таймера
/// (0 — порт без таймера; юзерспейс видит это в снапшоте).
static TICK_HZ: AtomicU64 = AtomicU64::new(0);

/// Линия тика таймера (GSI платформы; u32::MAX — порт не поднял таймер).
/// Юзерспейс-таймер-сервер читает её из TASK_STATS: без знания линии
/// сервер не сможет занять её капой (IrqLine) и ждать тик.
static TIMER_LINE: AtomicU32 = AtomicU32::new(u32::MAX);

/// Порт объявляет линию тика при запуске таймера.
pub fn set_timer_line(line: u32) {
    TIMER_LINE.store(line, Ordering::Release);
}

/// Линия тика (u32::MAX — таймер не поднят портом).
pub fn timer_line() -> u32 {
    TIMER_LINE.load(Ordering::Acquire)
}

/// Порт объявляет частоту тика при запуске таймера.
pub fn set_tick_hz(hz: u64) {
    TICK_HZ.store(hz, Ordering::Release);
}

/// Текущая частота тика (0 — таймер не поднят портом).
pub fn tick_hz() -> u64 {
    TICK_HZ.load(Ordering::Acquire)
}

/// Uptime системы в тиках.
pub fn global_ticks() -> u64 {
    GLOBAL_TICKS.load(Ordering::Relaxed)
}

/// Атомарные счётчики событий одной задачи (владелец — TCB).
///
/// Только Relaxed: счётчики — статистика, не синхронизация; инкременты
/// происходят под локами соответствующих подсистем, а снапшот читает
/// их «как есть» (допустимы слегка несостыкованные значения полей —
/// это не инвариант, а наблюдение).
pub struct TaskStatsCell {
    /// Тиков процессора, проведённых задачей текущей на ядре
    /// (по данным таймера — квантование тиком, не тактами).
    pub cpu_ticks: AtomicU64,
    /// Добровольных уступок (SCHED_YIELD).
    pub yields: AtomicU64,
    /// Успешно доставленных отправленных IPC-сообщений.
    pub ipc_sent: AtomicU64,
    /// Принятых IPC-сообщений (успешный WAIT).
    pub ipc_recv: AtomicU64,
    /// Блокировок на объектах ожидания.
    pub blocks: AtomicU64,
    /// Вытеснений таймером (невольная потеря CPU — карусель тика;
    /// дополнение к добровольным `yields`).
    pub preempts: AtomicU64,
}

impl TaskStatsCell {
    pub const fn new() -> Self {
        Self {
            cpu_ticks: AtomicU64::new(0),
            yields: AtomicU64::new(0),
            ipc_sent: AtomicU64::new(0),
            ipc_recv: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            preempts: AtomicU64::new(0),
        }
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for TaskStatsCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Хук ТИКА таймера (вызывает порт из обработчика линии таймера,
/// прерывания на этом ядре погашены аппаратно).
///
/// Учитывает тик текущей задаче ядра (cpu_ticks) и глобальному uptime.
/// ТИПИЧНЫЙ хук порта: `stats::on_tick(lctl); irq_wait::on_irq_fired
/// (lctl, TIMER_LINE); pic::send_eoi(TIMER_LINE);`
pub fn on_tick<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    GLOBAL_TICKS.fetch_add(1, Ordering::Relaxed);
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().cpu_ticks);
    }
}

// ─── Счётчики событий (вызывают подсистемы ядра) ────────────────────────────

/// Уступка текущей задачей (SCHED_YIELD).
pub fn count_yield<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().yields);
    }
}

/// Блокировка текущей задачи на объекте ожидания.
pub fn count_block<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().blocks);
    }
}

/// Вытеснение текущей задачи таймером (хвост IRQ-диспетчера порта,
/// в момент фактического переключения — кадр уже сохранён в TCB).
pub fn count_preempt<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().preempts);
    }
}

/// Успешная отправка IPC текущей задачей (доставка подтверждена).
pub fn count_ipc_sent<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().ipc_sent);
    }
}

/// Приём IPC-сообщения текущей задачей (успешный WAIT).
pub fn count_ipc_recv<Umap: MemoryInterfaceUserspace>(lctl: &LocalKernelCTL<Umap>) {
    if let Some(tcb) = lctl.get_current_task() {
        TaskStatsCell::bump(&tcb.stats().ipc_recv);
    }
}

/// Успешная отправка IPC задачей ПО id (доставка подтверждена из ЧУЖОГО
/// контекста: будящийся отправитель не «текущая» задача — счётчик бампится
/// по прямому разрешению TCB через task_manager).
pub fn count_ipc_sent_id<Umap: MemoryInterfaceUserspace>(
    tasks: &crate::task::TaskManager<Umap>,
    task_cap_id: u64,
) {
    if let Some(tcb) = tasks.get_tcb(task_cap_id) {
        TaskStatsCell::bump(&tcb.stats().ipc_sent);
    }
}

/// Приём IPC-сообщения задачей ПО id (доставка спящему получателю из
/// контекста отправителя — быстрый путь SEND).
pub fn count_ipc_recv_id<Umap: MemoryInterfaceUserspace>(
    tasks: &crate::task::TaskManager<Umap>,
    task_cap_id: u64,
) {
    if let Some(tcb) = tasks.get_tcb(task_cap_id) {
        TaskStatsCell::bump(&tcb.stats().ipc_recv);
    }
}

/// Снапшот счётчиков задачи (для блока TASK_STATS).
pub struct TaskStatsSnapshot {
    pub task_cap_id: u64,
    pub cpu_ticks: u64,
    pub yields: u64,
    pub ipc_sent: u64,
    pub ipc_recv: u64,
    pub blocks: u64,
    pub preempts: u64,
}

impl TaskStatsSnapshot {
    pub fn take(task_cap_id: u64, cell: &TaskStatsCell) -> Self {
        Self {
            task_cap_id,
            cpu_ticks: cell.cpu_ticks.load(Ordering::Relaxed),
            yields: cell.yields.load(Ordering::Relaxed),
            ipc_sent: cell.ipc_sent.load(Ordering::Relaxed),
            ipc_recv: cell.ipc_recv.load(Ordering::Relaxed),
            blocks: cell.blocks.load(Ordering::Relaxed),
            preempts: cell.preempts.load(Ordering::Relaxed),
        }
    }

    /// Сериализация в 16 u64-слов (wire-формат сисколла TASK_STATS):
    /// [0] magic, [1] version, [2] task_cap_id, [3] cpu_ticks,
    /// [4] yields, [5] ipc_sent, [6] ipc_recv, [7] blocks,
    /// [8] global_ticks, [9] tick_hz, [10] timer_line, [11] preempts,
    /// [12..16] резерв (нули).
    pub fn to_words(&self) -> [u64; STATS_WORDS] {
        let mut w = [0u64; STATS_WORDS];
        w[0] = STATS_MAGIC;
        w[1] = STATS_VERSION;
        w[2] = self.task_cap_id;
        w[3] = self.cpu_ticks;
        w[4] = self.yields;
        w[5] = self.ipc_sent;
        w[6] = self.ipc_recv;
        w[7] = self.blocks;
        w[8] = global_ticks();
        w[9] = tick_hz();
        w[10] = timer_line() as u64;
        w[11] = self.preempts;
        w
    }
}
