//! Логгер ядра: кольцевой буфер, читаемый из userspace.
//!
//! Ядро пишет строки через [`kernel_log!`]; буфер хранит последние
//! KERNEL_LOG_BYTES байт. Userspace (init-сервер) читает дельту через
//! сисколл DBG_LOG_READ (NR 46): передаёт собственный счётчик `since`
//! (сколько байт уже видел), получает новые байты и новое значение
//! счётчика. Лог монотонный: since растёт, пропуски означают перезапись
//! (буфер кольцевой) — старое уже не вернуть.
//!
//! Потокобезопасность: один SpinMutex на весь буфер; запись из IRQ-
//! контекста допустима (никаких аллокаций).

use core::fmt::Write as _;
use spin::mutex::SpinMutex;

/// Размер кольцевого буфера лога.
pub const KERNEL_LOG_BYTES: usize = 32 * 1024;
/// Максимум байт за одну выдачу userspace.
pub const KERNEL_LOG_CHUNK_MAX: usize = 4096;

/// Тип консольного крючка (дублирующий вывод лога — serial-порт порта x86).
type ConsoleHook = Option<fn(&[u8])>;

/// Консольный крючок: куда дублируется лог (serial-порт порта x86).
/// None до установки портом (ранний бут пишет только в кольцо).
static CONSOLE_HOOK: SpinMutex<ConsoleHook> = SpinMutex::new(None);

/// Устанавливает дублирующий вывод лога (вызывает порт на старте,
/// до многопоточности). Повторная установка заменяет предыдущий крючок.
pub fn set_console_hook(hook: fn(&[u8])) {
    *CONSOLE_HOOK.lock() = Some(hook);
}

/// Быстрая проверка без лока — горячий путь append().
/// Читает спинлок: одна атомарная нагрузка, дешевле mutex-лайт вызова.
fn console_hook_fast() -> ConsoleHook {
    *CONSOLE_HOOK.lock()
}

struct LogRing {
    /// Кольцо: последние KERNEL_LOG_BYTES байт.
    ring: [u8; KERNEL_LOG_BYTES],
    /// Сколько всего байт записано с загрузки (монотонный счётчик).
    total: u64,
    /// Сколько валидных байт в кольце (<= total, <= KERNEL_LOG_BYTES).
    valid: usize,
}

static RING: SpinMutex<LogRing> = SpinMutex::new(LogRing {
    ring: [0; KERNEL_LOG_BYTES],
    total: 0,
    valid: 0,
});

/// fmt::Write-адаптер над кольцом.
struct RingWriter;

impl core::fmt::Write for RingWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        append(s.as_bytes());
        Ok(())
    }
}

/// Дописывает сырые байты в кольцо (под локом) и дублирует их в
/// консольный крючок (serial). Крючок зовётся ВНЕ лока кольца: его
/// реализация сама блокируется на готовности UART и не должна держать
/// ядро под лог-локом дольше необходимого.
fn append(bytes: &[u8]) {
    {
        let mut ring = RING.lock();
        for &b in bytes {
            let idx = (ring.total as usize) % KERNEL_LOG_BYTES;
            ring.ring[idx] = b;
            ring.total = ring.total.wrapping_add(1);
            if ring.valid < KERNEL_LOG_BYTES {
                ring.valid += 1;
            }
        }
    }
    if let Some(hook) = console_hook_fast() {
        hook(bytes);
    }
}

/// Публичная запись: форматирование как fmt::Arguments
/// (`kernel_log!` — обёртка).
pub fn kernel_log(args: core::fmt::Arguments<'_>) {
    let mut w = RingWriter;
    let _ = w.write_fmt(args);
}

/// Публичная запись СЫРЫХ байтов (без форматирования): сисколл
/// DBG_LOG_WRITE переносит строку userspace-задачи в кольцо лога —
/// она сразу видна на serial (консольный крючок) и в дельте
/// DBG_LOG_READ (консоль init на фреймбуфере).
pub fn kernel_log_bytes(bytes: &[u8]) {
    append(bytes);
}

/// Читает лог для userspace: байты с позиции `since` (монотонный счётчик)
/// до конца доступного. Возвращает (новое since, сколько записано в buf).
///
/// Если `since` отстал сильнее размера кольца — выдаётся то, что есть,
/// с новейшей позиции (старое утеряно безвозвратно).
pub fn kernel_log_read(since: u64, buf: &mut [u8]) -> (u64, usize) {
    let ring = RING.lock();
    let oldest = ring.total.saturating_sub(ring.valid as u64);
    let start = since.max(oldest);
    if start >= ring.total || buf.is_empty() {
        return (ring.total, 0);
    }
    let avail = (ring.total - start) as usize;
    let take = avail.min(buf.len()).min(KERNEL_LOG_CHUNK_MAX);
    let mut i = 0usize;
    while i < take {
        let idx = (start as usize + i) % KERNEL_LOG_BYTES;
        buf[i] = ring.ring[idx];
        i += 1;
    }
    (start + take as u64, take)
}

/// Запись в лог ядра: `kernel_log!("счётчик: {}", n)`.
#[macro_export]
macro_rules! kernel_log {
    ($($arg:tt)*) => {
        $crate::log::kernel_log(core::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Оба теста пишут в ГЛОБАЛЬНЫЙ RING: без сериализации параллельный
    /// харнесс интерливится, и дельта-ассерты ловят чужие строки
    /// (флаки: between `kernel_log!("line2")` и read вползала гигантская
    /// строка соседнего теста). Один мьютекс — тесты лога линейно упорядочены.
    static RING_TEST_LOCK: SpinMutex<()> = SpinMutex::new(());

    #[test]
    fn log_write_and_read_delta() {
        let _ring = RING_TEST_LOCK.lock();
        // Глобальный лог (другие тесты могут писать) — работаем по дельтам.
        let (base, _) = kernel_log_read(0, &mut []);

        kernel_log!("line1\n");
        let (total1, _) = kernel_log_read(base, &mut []);
        assert!(total1 >= base + 6);

        // Читаем дельту: сначала с base, потом только новое.
        let mut buf = [0u8; 256];
        let (t2, n2) = kernel_log_read(base, &mut buf);
        assert_eq!(t2, total1);
        assert!(n2 >= 6);

        kernel_log!("line2\n");
        let (t3, n3) = kernel_log_read(total1, &mut buf);
        assert!(t3 > t2 && n3 >= 6);
        let text = core::str::from_utf8(&buf[..n3]).unwrap();
        assert!(text.starts_with("line2\n"), "дельта содержит только новое: {text:?}");

        // Чтение из будущего — ничего не меняет.
        let (t4, n4) = kernel_log_read(t3 + 100, &mut buf);
        assert_eq!((t4, n4), (t3, 0));
    }

    #[test]
    fn log_ring_wraps_and_clamps_since() {
        let _ring = RING_TEST_LOCK.lock();
        // Переполняем кольцо: since из-за кольца зажимается к старейшему.
        kernel_log!("{}|", "x".repeat(KERNEL_LOG_BYTES - 4));
        let (_, n) = kernel_log_read(0, &mut [0u8; 16]);
        assert_eq!(n, 16, "чтение ограничено чанком");
        // since далеко в прошлом: выдаётся новейшее окно, ошибка не вылетает.
        let (_, _) = kernel_log_read(0, &mut [0u8; 4]);
    }
}
