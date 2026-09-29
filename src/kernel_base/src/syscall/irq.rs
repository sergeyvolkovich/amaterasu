//! Сисколл ожидания IRQ: задача засыпает, ядро пишет сработавшие линии
//! в userspace-массив и будит задачу.
//!
//! ABI массива (см. task::irq_wait — шапку): `[count: u64][line0..]`.
//! userspace-библиотека передаёт УКАЗАТЕЛЬ на этот массив; валидность
//! указателя проверяется трансляцией через умап задачи (translate) —
//! сырые пользовательские указатели ядро не разыменовывает.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    traits::{ArchImplementation, syscall::SyscallDomain, syscall::syscall_result as res},
};

/// Ожидание IRQ: уснуть до срабатывания одной из линий `lines_mask`.
#[derive(SyscallArguments)]
pub struct SyscallWaitIrq {
    /// Битмап ожидаемых линий (бит n = линия n, 0..64).
    lines_mask: u64,
    /// Виртуальный адрес массива результата в пространстве задачи:
    /// `[count: u64][line0: u64]...[lineN-1: u64]`.
    mask_ptr: u64,
    /// Ёмкость массива в u64-слотах БЕЗ заголовка-счётчика.
    mask_slots: u64,
}

pub struct DomainIrq<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainIrq<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainIrq<A, SyscallWaitIrq> {
    const SYSCALL_ID: usize = 28;
    type Args = SyscallWaitIrq;
    type Umap = A::Umap;

    fn handle(&'static self, lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>, args: Self::Args) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        if args.lines_mask == 0 || args.mask_slots == 0 {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend.lock();

        // Групповой потолок: спать на IRQ может поток из группы с правом
        // IRQ_BIND — приоритет неймспейса над правами потока.
        if access.check_task_rights(current, crate::access::namespace::NamespaceRights::IRQ_BIND).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        let Some(gtcb_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение задачи невозможно.
        let gtcb = unsafe { gtcb_ptr.as_ref() };
        drop(access);

        // АТОМАРНОСТЬ РЕГИСТРАЦИИ И БЛОКИРОВКИ (фикс lost wakeup):
        // между register_irq_wait и постановкой в wait-очередь мог
        // сработать тик таймера — on_irq_fired снял бы регистрацию и
        // разбудил задачу, КОТОРАЯ ЕЩЁ НЕ УСПЕЛА УСНУТЬ: пробуждение
        // попадало в пустоту, задача засыпала навсегда. Гашение
        // прерываний на секции (irqsafe) исключает обработчик между
        // двумя шагами; после постановки в очередь пробуждение
        // корректно кладёт задачу в готовые (она ещё «текущая» —
        // планировщик её же и выберет).
        let flags = crate::irqsafe::irq_save();
        let outcome = crate::task::irq_wait::register_irq_wait(
            current,
            gtcb.userspace_map(),
            args.lines_mask,
            args.mask_ptr as usize,
            args.mask_slots as usize,
        );
        match outcome {
            Ok(slot) => {
                crate::task::stats::count_block(lctl);
                // ОДНА блокировка на весь битмап: будит
                // irq_wait::on_irq_fired по слоту регистрации (раньше
                // блокировали ПО ЛИНИИ за итерацию — после первой
                // итерации «текущей» становилась другая задача).
                let _ = lctl.scheduler_block_on_object(
                    crate::task::irq_wait::irq_wait_object(slot),
                    crate::traits::scheduller::WaitModel::OneShot,
                );
                crate::irqsafe::irq_restore(flags);
                res::OK
            }
            Err(e) => {
                crate::irqsafe::irq_restore(flags);
                match e {
                    crate::task::irq_wait::IrqWaitError::RegistryFull => res::E_SLAB, // реестр переполнен — ближайшая семантика "нет ресурса"
                    crate::task::irq_wait::IrqWaitError::NoLines
                    | crate::task::irq_wait::IrqWaitError::ZeroMaskSlots => res::E_INVALID_ARG,
                    crate::task::irq_wait::IrqWaitError::BadMaskPointer => res::E_INVALID_ARG,
                }
            }
        }
    }
}
