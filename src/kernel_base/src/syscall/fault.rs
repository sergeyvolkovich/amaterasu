//! Домен фолт-сисколлов (seL4/KeyKOS-модель: см. ipc::fault).
//!
//! ABI:
//!   FAULT_SET_ENDPOINT(27): (ep_slot, target_slot)
//!     Привязка фолт-обработчика: `ep_slot` — слот cspace текущей
//!     задачи с FaultEndpoint-капабилити (зафиксированный обработчик),
//!     `target_slot` — слот с TaskTCB-капабилити ЦЕЛИ (право Send,
//!     как у IPC-адресации). Требует прав TASK_CREATE|FAULT_HANDLE у
//!     группы вызывающего; обработчик обязан быть жив (зигота
//!     FaultEndpoint инвалидируется его смертью). Повторная привязка
//!     ЗАМЕНЯЕТ прежнюю.
//!   FAULT_REPLY(30): (target_task_cap, new_rip, new_rsp)
//!     Ответ на фолт — аналог инвокации resume-ключа KeyKOS: будит
//!     упавшую задачу. `target_task_cap` — task_cap_id упавшей (из
//!     заголовка принятого фолт-сообщения: sender). Валиден ТОЛЬКО
//!     зарегистрированному обработчику и ТОЛЬКО после приёма
//!     сообщения. new_rip/new_rsp: 0 — оставить как было (повтор
//!     упавшей инструкции, классический пейджер); иначе — возобновить
//!     с нового адреса/стека (эмуляция инструкции, сигнальный
//!     трамплин). Требует FAULT_HANDLE у группы.

use core::marker::PhantomData;

use syscall_macros::SyscallArguments;

use crate::{
    KernelCTL,
    access::capability::DirectCapabilityRights,
    access::namespace::NamespaceRights,
    ipc::fault::{self, FaultError, FaultReplyError},
    traits::{ArchImplementation, syscall::SyscallDomain, syscall::syscall_result as res},
};

/// Привязка фолт-эндпоинта к задаче-цели.
#[derive(SyscallArguments)]
pub struct SyscallFaultSetEndpoint {
    /// Слот cspace текущей задачи с FaultEndpoint-капабилити.
    ep_slot: u64,
    /// Слот cspace с TaskTCB-капабилити цели (право Send).
    target_slot: u64,
}

/// Ответ на фолт (resume упавшей задачи).
#[derive(SyscallArguments)]
pub struct SyscallFaultReply {
    /// task_cap_id упавшей задачи (sender в заголовке фолт-сообщения).
    target_task_cap: u64,
    /// Новый RIP (0 — повторить упавшую инструкцию).
    new_rip: u64,
    /// Новый RSP (0 — прежний стек).
    new_rsp: u64,
}

pub struct DomainFault<A: ArchImplementation + 'static, Handler>(
    &'static KernelCTL<A>,
    PhantomData<Handler>,
);

impl<A: ArchImplementation, Handler> DomainFault<A, Handler> {
    pub const fn new(kernel: &'static KernelCTL<A>) -> Self {
        Self(kernel, PhantomData)
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainFault<A, SyscallFaultSetEndpoint> {
    const SYSCALL_ID: usize = 27;
    type Args = SyscallFaultSetEndpoint;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        let access = self.0.permission_backend.lock();

        // Групповой потолок: оперируем ЧУЖИМ TCB (управление задачами)
        // и входим в фолт-домен (FAULT_HANDLE).
        if access
            .check_task_rights(
                current,
                NamespaceRights::TASK_CREATE | NamespaceRights::FAULT_HANDLE,
            )
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }

        let Some(current_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let current_gtcb = unsafe { current_ptr.as_ref() };

        // 1. Эндпоинт: резолв записи слота → живой обработчик. Смерть
        //    обработчика тумбстоунит его зиготу — снимок поколения в
        //    объекте расходится, resolve_fault_endpoint -> None.
        let handler_task_cap = {
            let caps = current_gtcb.capspace().lock();
            let record = match caps.get(&args.ep_slot) {
                Some(r) => r,
                None => return res::E_SLOT_EMPTY,
            };
            let sendable = match record.check_send() {
                Ok(s) => s,
                Err(_) => return res::E_CAP_REVOKED,
            };
            if !sendable.contains(DirectCapabilityRights::Send) {
                return res::E_RIGHTS_DENIED;
            }
            let (object, _) = match record.resolve() {
                Ok(pair) => pair,
                Err(_) => return res::E_CAP_REVOKED,
            };
            match object.resolve_fault_endpoint() {
                Some(handler) => handler,
                None => return res::E_NOT_FOUND, // обработчик мёртв/отозван
            }
        };

        // 2. Цель: TaskTCB-слот (право Send — как адресация IPC_SEND).
        let target_task_cap = {
            let tasks = self.0.task_manager().lock();
            match crate::syscall::ipc::resolve_task_slot::<A>(&tasks, current_gtcb, args.target_slot)
            {
                Ok((task_cap, _)) => task_cap,
                Err(code) => return code,
            }
        };

        // Сам себе обработчик — вечный блок: упавшая спит, будить
        // некому (аналог запрета self-send в IPC_SEND).
        if target_task_cap == handler_task_cap {
            return res::E_INVALID_ARG;
        }

        // 3. Обработчик обязан быть живой задачей (двойная проверка —
        //    зигота TaskTCB резолвится: жива и не переиспользована).
        if access.get_task_tcb(handler_task_cap).is_none() {
            return res::E_NOT_FOUND;
        }

        // 4. Биндинг (реестр — листовой лок).
        match fault::set_fault_handler(target_task_cap, handler_task_cap) {
            Ok(()) => res::OK,
            Err(FaultError::BindingsFull) => res::E_SLAB,
        }
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for DomainFault<A, SyscallFaultReply> {
    const SYSCALL_ID: usize = 30;
    type Args = SyscallFaultReply;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };

        {
            let access = self.0.permission_backend.lock();
            // Групповой потолок фолт-домена.
            if access
                .check_task_rights(current, NamespaceRights::FAULT_HANDLE)
                .is_err()
            {
                return res::E_RIGHTS_DENIED;
            }
        }

        // Запись фолта изымается атомарно: валидна только зарегистри-
        // рованному обработчику и только после ПРИЁМА сообщения.
        let wait_object = match fault::finish_fault(args.target_task_cap, current) {
            Ok(object) => object,
            Err(FaultReplyError::NoFault) => return res::E_NOT_FOUND,
            Err(FaultReplyError::NotHandler) => return res::E_RIGHTS_DENIED,
            Err(FaultReplyError::NotDelivered) => return res::E_INVALID_ARG,
        };

        // Опциональная модификация контекста упавшей: эмуляция
        // инструкции (skip), сигнальный трамплин (новый стек). Патч —
        // ДО пробуждения (как wake_sender_error): к моменту запуска
        // кадр уже новый. Слова кадра — собственность порта.
        if args.new_rip != 0 || args.new_rsp != 0 {
            let tasks = self.0.task_manager().lock();
            if let Some(tcb) = tasks.get_tcb(args.target_task_cap) {
                if args.new_rip != 0 {
                    tcb.patch_resume_result(A::RESUME_RIP_WORD, args.new_rip);
                }
                if args.new_rsp != 0 {
                    tcb.patch_resume_result(A::RESUME_RSP_WORD, args.new_rsp);
                }
            }
        }

        // Resume-инвокация: упавшая задача — в готовые, продолжит с
        // сохранённого (и опционально запатченного) кадра.
        lctl.scheduler_release_object(wait_object);
        res::OK
    }
}
