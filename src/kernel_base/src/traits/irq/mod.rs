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
