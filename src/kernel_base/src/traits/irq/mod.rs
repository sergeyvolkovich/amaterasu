#![allow(dead_code)]

/// Идентификатор прерывания/исключения.
///
/// На одной архитектуре это может быть `u8`, на другой — `u16`,
/// enum, newtype или даже составной номер.
pub trait InterruptId: Copy + PartialEq + Eq + core::fmt::Debug {
    /// Преобразовать идентификатор в индекс для таблицы векторов.
    fn index(self) -> usize;
}

/// Минимальный переносимый интерфейс к контексту CPU.
///
/// Конкретная архитектура сама решает, что внутри:
/// регистры, стек, программный счетчик, флаги и т.д.
pub trait CpuContext {
    fn stack_pointer(&self) -> usize;
    fn set_stack_pointer(&mut self, sp: usize);
    fn instruction_pointer(&self) -> usize;
}

/// Переносимый смысл флагов ошибки страничного доступа.
///
/// Конкретные биты у архитектур могут отличаться, поэтому общий код
/// спрашивает не «бит 1», а семантически: write/user/fetch/present и т.д.
pub trait PageFaultFlags: Copy + core::fmt::Debug {
    fn present(self) -> bool;
    fn write(self) -> bool;
    fn user(self) -> bool;
    fn fetch(self) -> bool;
    fn reserved(self) -> bool;

    /// Сырые архитектурные биты, если нужно что-то специфичное.
    fn raw(self) -> u64;
}

/// Описание конкретной архитектуры.
pub trait IRQArchDefinedContext {
    type InterruptId: InterruptId;
    type CpuContext: CpuContext;
    type PageFaultFlags: PageFaultFlags;
}

/// Результат обработки аппаратного прерывания.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqResult {
    /// Прерывание успешно обработано.
    Handled,

    /// Прерывание не для этого обработчика или ложное.
    Ignored,

    /// Ошибка обработки.
    Failed,
}

/// Полезная нагрузка для обработчика прерывания.
pub struct IrqPayload<'a, A: IRQArchDefinedContext> {
    pub line: A::InterruptId,
    pub context: &'a mut A::CpuContext,
}

/// Динамический обработчик прерываний.
///
/// Если нужен статический номер, можно реализовать `StaticIrqHandler`,
/// для него уже есть автоматическая реализация `IrqHandler`.
pub trait IrqHandler<A: IRQArchDefinedContext>: Sync {
    fn line(&self) -> A::InterruptId;
    fn handle(&self, payload: IrqPayload<'_, A>) -> IrqResult;
}

/// Обработчик со статически известным номером линии.
///
/// Удобно для векторных таблиц, которые собираются на этапе компиляции.
pub trait StaticIrqHandler<A: IRQArchDefinedContext>: Sync {
    const LINE: A::InterruptId;

    fn handle_context(&self, ctx: &mut A::CpuContext) -> IrqResult;
}

impl<A: IRQArchDefinedContext, T: StaticIrqHandler<A>> IrqHandler<A> for T {
    fn line(&self) -> A::InterruptId {
        Self::LINE
    }

    fn handle(&self, payload: IrqPayload<'_, A>) -> IrqResult {
        self.handle_context(payload.context)
    }
}

/// Результат обработки ошибки страничного доступа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFaultResult {
    /// Ошибка устранена, исполнение можно продолжить.
    Handled,

    /// Ошибка неустранима.
    Fatal,
}

/// Информация об ошибке страничного доступа.
pub struct PageFault<'a, A: IRQArchDefinedContext> {
    pub address: usize,
    pub flags: A::PageFaultFlags,
    pub context: &'a mut A::CpuContext,
}

/// Обработчик ошибки страничного доступа.
pub trait PageFaultHandler<A: IRQArchDefinedContext>: Sync {
    fn handle(&self, fault: PageFault<'_, A>) -> PageFaultResult;
}

/// Ошибка регистрации обработчика.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    OutOfRange,
    AlreadyRegistered,
}

// ─── Переносимая подсистема прерываний (v2: IO-APIC/MSI/GIC-нейтрально) ─────
//
// Контракт v2: линия прерывания — ЛОГИЧЕСКИЙ номер u32, семантику
// перечисления задаёт порт (x86: GSI из MADT для проводных линий +
// выделенный диапазон для MSI; ARM64: INTID GIC; RISC-V: source id
// APLIC/PLIC). Ядро НЕ знает ни про «255 векторов», ни про «16 legacy
// линий» — векторы/дескрипторы доставки (IDT slot, LPI, claim id) —
// собственность порта, спрятанная за [IrqChip].
//
// Границы: трейт вызывается ТОЛЬКО из syscall-слоя (slow path). Диспет-
// черизация срабатываний идёт мимо трейта: порт сам мапит вектор→линию
// и зовёт kernel_base::task::irq_wait::on_irq_fired + собственные хуки.

/// Режим срабатывания линии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Фронт: одно событие на переход 0→1 (MSI, ISA-таймер, PCIe).
    Edge,
    /// Уровень: события, пока линия активна (PCIe INTx, shared-линии).
    Level,
}

impl TriggerMode {
    /// Провожу ABI-число (0/1) в режим; None — некорректный аргумент.
    pub fn from_abi(bits: u64) -> Option<Self> {
        match bits {
            0 => Some(Self::Edge),
            1 => Some(Self::Level),
            _ => None,
        }
    }

    /// Обратное преобразование для ABI-массивов (MSI-аллокация).
    pub fn to_abi(self) -> u64 {
        match self {
            Self::Edge => 0,
            Self::Level => 1,
        }
    }
}

/// MSI-сообщение (message-signalled interrupt) в переносимой форме:
/// устройство выполняет ОДНУ запись `data` по физическому адресу
/// `address`, контроллер прерываний платформы трактует пару как
/// «поднять линию». Формат пары — собственность порта (x86: address
/// 0xFEExxxxx + dest APIC id, data = вектор; ARM64 GICv3: doorbell ITS;
/// RISC-V: IMSIC). Драйвер только копирует пару в BAR устройства.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiMessage {
    /// Физический адрес, по которому устройство пишет `data`.
    pub address: u64,
    /// Полезная нагрузка записи.
    pub data: u32,
}

/// Ошибка аппаратной операции над линией (уходит в коды сисколлов).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqHwError {
    /// Линия вне пространства, известного чипу.
    OutOfRange,
    /// Операция не поддерживается (например, MSI на платформе без
    /// message-backed контроллера).
    Unsupported,
    /// Контроллер аппаратно недоступен.
    Hardware,
}

/// Бэкенд контроллеров прерываний платформы (x86: IO-APIC+LAPIC; ARM64:
/// GICv3; RISC-V: APLIC+IMSIC). Реализует ПОРТ; общему слою доступны
/// только переносимые операции над ЛОГИЧЕСКИМИ линиями.
///
/// ИНВАРИАНТЫ:
///   - линий два класса: проводные `0..wired_line_count()` и
///     message-backed `msi_line_base()..msi_line_base()+msi_capacity()`;
///     диапазоны не пересекаются (проверяется тестом порта);
///   - после успешного `unmask` линия доставляет прерывания; после
///     `mask` — нет (программная истина: при старте порт маскирует всё);
///   - все операции неблокирующие и короткие (MMIO-записи), вызываются
///     под permission-локом сисколлов — нельзя звать планировщик.
pub trait IrqChip: Sync {
    /// Число проводных линий (пространство 0..N).
    fn wired_line_count(&self) -> u32;

    /// Начало MSI-пространства логических линий.
    fn msi_line_base(&self) -> u32;

    /// Ёмкость MSI-пространства (0 — MSI не поддержан).
    fn msi_capacity(&self) -> u32;

    /// Текущий режим срабатывания линии (программная истина чипа).
    fn trigger_mode(&self, line: u32) -> TriggerMode;

    /// Установить режим срабатывания (программирование контроллера).
    fn set_trigger(&self, line: u32, mode: TriggerMode) -> Result<(), IrqHwError>;

    /// Замаскировать линию (прерывания не доставляются).
    fn mask(&self, line: u32) -> Result<(), IrqHwError>;

    /// Размаскировать линию.
    fn unmask(&self, line: u32) -> Result<(), IrqHwError>;

    /// MSI-сообщение для линии MSI-пространства. Стабильно для жизни
    /// линии (пара не меняется между alloc и release).
    fn msi_message(&self, line: u32) -> Result<MsiMessage, IrqHwError>;
}
