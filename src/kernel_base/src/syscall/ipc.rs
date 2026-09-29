//! Домен IPC-сисколлов: синхронный транспорт сообщений (стиль Лидтке/L4).
//!
//! Ядро — ТОЛЬКО транспорт: payload непрозрачен (сериализация —
//! FlatBuffers в юзерспейсе, см. cintos_user::flatbuf), capability
//! пересылаются явными дескрипторами ([`CapItem`], аналог L4 map
//! items). Rendezvous-логика — ipc::endpoint.
//!
//! ABI:
//!   IPC_SEND(10): (slot, msg_ptr, msg_size, caps_ptr, caps_count)
//!     slot — слот cspace ОТПРАВИТЕЛЯ с TaskTCB-капабилити получателя
//!     (право Send); msg — непрозрачное тело; caps — #[repr(C)] массив
//!     {src_slot, dst_slot, rights} × caps_count (src — слот отправителя;
//!     dst_slot ИГНОРИРУЕТСЯ ядром — см. IPC_WAIT).
//!   IPC_WAIT(11): (from_slot, tgt_ptr, tgt_capacity, recv_base, recv_count)
//!     from_slot — слот с TaskTCB отправителя (closed wait) или
//!     IPC_WAIT_ANY (open wait); tgt — буфер приёма [заголовок|caps|msg];
//!     recv_base/recv_count — ПРИЁМНОЕ ОКНО capability получателя: ядро
//!     кладёт i-ю capability сообщения в слот recv_base + i (seL4-стиль:
//!     слот выбирает получатель, а не отправитель). recv_count = 0 —
//!     сообщения с map items отклоняются отправителю.
//!
//! Блокировка: send без ждущего получателя спит до доставки; wait без
//! ждущего отправителя спит до доставки. Ошибка доставки спящему
//! отправителю пишется перезаписью RAX его сохранённого кадра
//! (TCB::patch_resume_rax) ДО пробуждения.

use core::marker::PhantomData;

use heapless::Vec as HVec;
use syscall_macros::SyscallArguments;

use crate::kernel_log;
use crate::{
    KernelCTL,
    ipc::{
        cap_transfer::{CapTransferError, CapTransferSpec, transfer_capabilities},
        endpoint::{
            self, CapItem, ClaimResult, HEADER_WORDS, IPC_WAIT_ANY, MAILBOX_SLOTS, MAX_CAPS,
            MAX_MSG, PendingDelivery, ReadyEndpoint,
        },
    },
    task::tcb::GTcb,
    traits::{
        ArchImplementation,
        scheduller::WaitModel,
        syscall::{SyscallDomain, syscall_result as res},
    },
};

#[derive(SyscallArguments)]
pub struct SyscallIPCSend {
    /// Слот cspace текущей задачи с TaskTCB-капабилити получателя.
    slot: u64,
    /// ВА непрозрачного тела сообщения (FlatBuffers и т.п.).
    msg_ptr: u64,
    msg_size: u64,
    /// ВА массива дескрипторов пересылки (3×u64 на capability) или 0.
    caps_ptr: u64,
    caps_count: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallIPCWait {
    /// Слот с TaskTCB отправителя (closed wait) или IPC_WAIT_ANY.
    from_slot: u64,
    /// ВА буфера приёма: [заголовок 3 слова][слоты caps][payload].
    tgt_ptr: u64,
    /// Ёмкость буфера в байтах.
    tgt_capacity: u64,
    /// База приёмного окна capability (слоты получателя recv_base+i).
    recv_base: u64,
    /// Размер приёмного окна в слотах (0 — capability не принимать).
    recv_count: u64,
}

pub struct IPCSyscallDomain<A: ArchImplementation + 'static, D>(
    &'static KernelCTL<A>,
    PhantomData<D>,
);

impl<A: ArchImplementation, Handler> IPCSyscallDomain<A, Handler> {
    pub const fn new(hanlder: &'static KernelCTL<A>) -> Self {
        Self(hanlder, PhantomData)
    }
}

/// Код ошибки пересылки → код возврата сисколла (зеркало capability.rs).
fn transfer_code(e: CapTransferError) -> u64 {
    match e {
        CapTransferError::SenderTaskNotFound | CapTransferError::ReceiverTaskNotFound => {
            res::E_NOT_FOUND
        }
        CapTransferError::SenderRightsDenied | CapTransferError::ReceiverRightsDenied(_) => {
            res::E_RIGHTS_DENIED
        }
        CapTransferError::SenderSlotEmpty => res::E_SLOT_EMPTY,
        CapTransferError::CapRevoked => res::E_CAP_REVOKED,
        CapTransferError::RightsExceeded => res::E_RIGHTS_EXCEEDED,
        CapTransferError::ReceiverSlotOccupied => res::E_SLOT_OCCUPIED,
        CapTransferError::Quota => res::E_QUOTA,
        CapTransferError::Slab(_) => res::E_SLAB,
    }
}

/// Результат резолва слота cspace: глобальный id задачи-цели + её GTcb.
type ResolvedTask<Umap> = (u64, core::ptr::NonNull<GTcb<Umap>>);

/// Разрешение слота cspace текущей задачи в TaskTCB-цель.
/// pub(crate): используется и фолт-доменом (FAULT_SET_ENDPOINT адресует
/// цель тем же способом, что и IPC_SEND).
pub(crate) fn resolve_task_slot<A: ArchImplementation>(
    tasks: &crate::task::TaskManager<A::Umap>,
    current_gtcb: &GTcb<A::Umap>,
    slot: u64,
) -> Result<ResolvedTask<A::Umap>, u64> {
    // Право Send + резолв цели (эпохи мембран/поколения зигот — внутри).
    let target = {
        let caps = current_gtcb.capspace().lock();
        let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
        let sendable = record
            .check_send()
            .map_err(|_| res::E_CAP_REVOKED)?;
        if !sendable.contains(crate::access::capability::DirectCapabilityRights::Send) {
            return Err(res::E_RIGHTS_DENIED);
        }
        let (object, _) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
        object.resolve_task_tcb().ok_or(res::E_INVALID_ARG)?
    };
    // Обратный поиск глобального id задачи-цели.
    let task_cap = tasks
        .task_cap_id_by_gtcb(target)
        .ok_or(res::E_NOT_FOUND)?;
    Ok((task_cap, target))
}

/// Читает дескрипторы пересылки из userspace отправителя.
fn read_cap_items<A: ArchImplementation>(
    umap: &A::Umap,
    caps_ptr: u64,
    caps_count: usize,
) -> Result<HVec<CapItem, MAX_CAPS>, u64> {
    let mut items: HVec<CapItem, MAX_CAPS> = HVec::new();
    if caps_count == 0 {
        return Ok(items);
    }
    let mut raw = [0u8; MAX_CAPS * 24];
    if !endpoint::read_from_user(umap, caps_ptr as usize, &mut raw[..caps_count * 24]) {
        return Err(res::E_INVALID_ARG);
    }
    for i in 0..caps_count {
        let w = |k: usize| -> u64 {
            u64::from_le_bytes(raw[i * 24 + k * 8..i * 24 + k * 8 + 8].try_into().unwrap())
        };
        let rights = crate::access::capability::DirectCapabilityRights::from_bits_truncate(w(2) as u8);
        if rights.is_empty() {
            return Err(res::E_INVALID_ARG);
        }
        let _ = items.push(CapItem {
            src_slot: w(0),
            dst_slot: w(1),
            rights: w(2) as u8,
        });
    }
    Ok(items)
}

/// Назначает слоты ПОЛУЧАТЕЛЯ для capability сообщения: ПЕРВЫЙ СВОБОДНЫЙ
/// слот приёмного окна на каждый дескриптор (окно задал получатель в
/// IPC_WAIT — seL4-стиль; отправитель cspace получателя адресовать не
/// может). Слот свободен, если записи нет или она затумбстоунена
/// (рекайкл на месте); слот, уже назначенный другому дескриптору ТОГО ЖЕ
/// сообщения, пропускается (дубли исключены).
///
/// Возвращает Err(E_SLOT_OCCUPIED), если свободных слотов окна не хватает.
fn assign_recv_slots<A: ArchImplementation>(
    access: &crate::access::AccessManager<A::Umap>,
    receiver_task_cap: u64,
    caps_count: usize,
    recv_base: u64,
    recv_count: usize,
) -> Result<HVec<u64, MAX_CAPS>, u64> {
    let receiver_ptr = access
        .get_task_tcb(receiver_task_cap)
        .ok_or(res::E_NOT_FOUND)?;
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let receiver = unsafe { receiver_ptr.as_ref() };
    let caps = receiver.capspace().lock();
    let mut chosen: HVec<u64, MAX_CAPS> = HVec::new();
    for _ in 0..caps_count {
        let mut picked = Err(res::E_SLOT_OCCUPIED);
        for k in 0..recv_count {
            let Some(slot) = recv_base.checked_add(k as u64) else {
                break;
            };
            let live = caps
                .get(&slot)
                .map(|r| r.is_live())
                .unwrap_or(false);
            if !live && !chosen.contains(&slot) {
                picked = Ok(slot);
                break;
            }
        }
        let _ = chosen.push(picked?);
    }
    Ok(chosen)
}

/// Пересылает capability доставки; успех — слоты ПОЛУЧАТЕЛЯ (для
/// заголовка), ошибка — код сисколла.
///
/// Слоты получателя назначает ЯДРО из приёмного окна получателя
/// ([`assign_recv_slots`], «первый свободный»): поле dst_slot
/// дескриптора отправителя не адресует cspace получателя.
fn transfer_delivery_caps<A: ArchImplementation>(
    access: &crate::access::AccessManager<A::Umap>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    delivery: &PendingDelivery,
    recv_base: u64,
    recv_count: usize,
) -> Result<HVec<u64, MAX_CAPS>, u64> {
    let chosen = assign_recv_slots::<A>(
        access,
        receiver_task_cap,
        delivery.caps_count,
        recv_base,
        recv_count,
    )?;
    let mut specs: HVec<CapTransferSpec, MAX_CAPS> = HVec::new();
    for (i, c) in delivery.caps.iter().take(delivery.caps_count).enumerate() {
        let _ = specs.push(CapTransferSpec {
            src_slot: c.src_slot,
            dst_slot: chosen[i],
            rights: crate::access::capability::DirectCapabilityRights::from_bits_truncate(
                c.rights,
            ),
        });
    }

    match transfer_capabilities(access, sender_task_cap, receiver_task_cap, &specs) {
        Ok(()) => Ok(chosen),
        Err((_, e)) => Err(transfer_code(e)),
    }
}

/// Патчит RAX спящего отправителя и будит его (ошибка доставки).
fn wake_sender_error<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    sender_task_cap: u64,
    wait_object: usize,
    code: u64,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
) {
    let tasks = kctl.task_manager().lock();
    if let Some(tcb) = tasks.get_tcb(sender_task_cap) {
        tcb.patch_resume_result(A::RESUME_RESULT_WORD, code);
    }
    drop(tasks);
    lctl.scheduler_release_object(wait_object);
}

/// Будит отправителя успешной доставки (слово результата в его кадре
/// уже ОК) и учитывает статистику доставки. Для ФОЛТ-доставок не
/// звать: отправитель (упавшая задача) спит на fault-объекте (см.
/// fault::mark_fault_delivered).
fn wake_sender_ok<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    sender_task_cap: u64,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    wait_object: usize,
) {
    {
        let tasks = kctl.task_manager().lock();
        crate::task::stats::count_ipc_sent_id(&tasks, sender_task_cap);
    }
    lctl.scheduler_release_object(wait_object);
}

/// Обрабатывает отброшенные (негабарит/неотображаемые) сообщения:
/// авторам — ошибка в кадр и пробуждение.
fn handle_dropped<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    dropped: &HVec<(u64, usize), MAILBOX_SLOTS>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
) {
    for (sender, wait_object) in dropped.iter() {
        wake_sender_error(kctl, *sender, *wait_object, res::E_INVALID_ARG, lctl);
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for IPCSyscallDomain<A, SyscallIPCSend> {
    const SYSCALL_ID: usize = 10;
    type Args = SyscallIPCSend;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let msg_size = args.msg_size as usize;
        let caps_count = args.caps_count as usize;
        if msg_size > MAX_MSG || caps_count > MAX_CAPS {
            return res::E_INVALID_ARG;
        }

        let access = self.0.permission_backend.lock();

        // Групповой потолок отправителя: IPC_SEND (+CAP_TRANSFER при
        // наличии дескрипторов — сама transfer_capabilities проверит).
        let ns_rights = crate::access::namespace::NamespaceRights::IPC_SEND
            | crate::access::namespace::NamespaceRights::CAP_TRANSFER;
        if access.check_task_rights(current, ns_rights).is_err() {
            return res::E_RIGHTS_DENIED;
        }

        let Some(sender_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом уничтожение невозможно.
        let sender = unsafe { sender_ptr.as_ref() };

        // Тело сообщения и дескрипторы — из userspace отправителя.
        let mut msg = [0u8; MAX_MSG];
        if !endpoint::read_from_user(sender.userspace_map(), args.msg_ptr as usize, &mut msg[..msg_size])
        {
            return res::E_INVALID_ARG;
        }
        let cap_items = match read_cap_items::<A>(sender.userspace_map(), args.caps_ptr, caps_count)
        {
            Ok(items) => items,
            Err(code) => return code,
        };

        // Адресат: слот → TaskTCB → глобальный id + GTcb.
        let (receiver_task_cap, receiver_ptr) = {
            let tasks = self.0.task_manager().lock();
            match resolve_task_slot::<A>(&tasks, sender, args.slot) {
                Ok(pair) => pair,
                Err(code) => return code,
            }
        };
        if receiver_task_cap == current {
            return res::E_INVALID_ARG; // самому себе — вечный блок
        }
        // SAFETY: под permission_backend-локом.
        let receiver = unsafe { receiver_ptr.as_ref() };
        let need = endpoint::delivery_bytes(caps_count, msg_size);

        match endpoint::claim_ready(receiver_task_cap, current, need, caps_count) {
            ClaimResult::TooSmall => res::E_INVALID_ARG,
            // Приёмное окно получателя не вмещает capability сообщения:
            // слоты получателя выбирает получатель в IPC_WAIT (seL4-стиль),
            // навязать свои — нельзя. Получатель продолжает ждать.
            ClaimResult::CapsRejected => res::E_INVALID_ARG,
            ClaimResult::NotWaiting => {
                // Медленный путь: ящик + сон отправителя.
                match endpoint::enqueue_pending(
                    receiver_task_cap,
                    current,
                    &msg[..msg_size],
                    &cap_items,
                ) {
                    Ok(mailbox_idx) => {
                        let _ = lctl.scheduler_block_on_object(
                            endpoint::sender_wait_object(mailbox_idx),
                            WaitModel::OneShot,
                        );
                        res::OK
                        // Доставка произойдёт в IPC_WAIT получателя
                        // (или ошибка — патчем RAX до пробуждения).
                    }
                    Err(_) => res::E_SLAB,
                }
            }
            ClaimResult::Claimed(ep_idx, ep) => {
                // Быстрый путь: получатель спит в wait. Буфер обязан
                // отображаться ЦЕЛИКОМ до пересылки capability.
                if !endpoint::check_user_region(
                    receiver.userspace_map(),
                    ep.tgt_va,
                    need,
                ) {
                    endpoint::restore_ready(ep_idx, ep);
                    return res::E_INVALID_ARG;
                }
                // Слоты ПОЛУЧАТЕЛЯ назначает ядро из ЕГО приёмного окна
                // («первый свободный»): поле dst_slot дескриптора
                // отправителя не адресует cspace получателя (занятость
                // чужих слотов больше не прощупывается ошибками доставки,
                // дубли внутри сообщения исключены).
                let dst_slots = match assign_recv_slots::<A>(
                    &access,
                    receiver_task_cap,
                    caps_count,
                    ep.recv_base,
                    ep.recv_count,
                ) {
                    Ok(slots) => slots,
                    Err(code) => {
                        endpoint::restore_ready(ep_idx, ep);
                        return code;
                    }
                };
                let mut specs: HVec<CapTransferSpec, MAX_CAPS> = HVec::new();
                for (i, c) in cap_items.iter().enumerate() {
                    let _ = specs.push(CapTransferSpec {
                        src_slot: c.src_slot,
                        dst_slot: dst_slots[i],
                        rights: crate::access::capability::DirectCapabilityRights::from_bits_truncate(
                            c.rights,
                        ),
                    });
                }
                match transfer_capabilities(&access, current, receiver_task_cap, &specs) {
                    Ok(()) => {
                        if endpoint::deliver_to_claimed(
                            receiver.userspace_map(),
                            &ep,
                            current,
                            &msg[..msg_size],
                            &dst_slots,
                        ) {
                            // Слот израсходован, получатель просыпается
                            // с сообщением. Статистика: отправитель —
                            // текущая задача; получатель — по id.
                            crate::task::stats::count_ipc_sent(lctl);
                            {
                                let tasks = self.0.task_manager().lock();
                                crate::task::stats::count_ipc_recv_id(
                                    &tasks,
                                    receiver_task_cap,
                                );
                            }
                            endpoint::consume_ready(ep_idx);
                            lctl.scheduler_release_object(endpoint::endpoint_wait_object(ep_idx));
                            res::OK
                        } else {
                            // Отображение схлопнулось между проверкой и
                            // записью (кооперативная модель — почти
                            // невозможно); откатываемся,Capability уже
                            // доставлены — фиксируем в логе.
                            kernel_log!(
                                "ipc: доставка в буфер {:#x} не удалась после пересылки caps\n",
                                ep.tgt_va
                            );
                            endpoint::restore_ready(ep_idx, ep);
                            res::E_INTERNAL
                        }
                    }
                    Err((_, e)) => {
                        // Пересылка не состоялась (валидация — без
                        // мутаций). Эндпоинт: вернуть ЛИБО отдать
                        // ждущему отправителю из ящика.
                        let code = transfer_code(e);
                        recover_endpoint_after_failure(
                            self.0,
                            lctl,
                            &access,
                            ep_idx,
                            ep,
                            receiver_task_cap,
                            receiver.userspace_map(),
                            ep.recv_base,
                            ep.recv_count,
                        );
                        code
                    }
                }
            }
        }
    }
}

/// Откат неудачной пересылки на ЗАХВАЧЕННОМ эндпоинте: инвариант —
/// получатель либо снова готов (restore), либо просыпается с
/// сообщением из ящика (ждущий отправитель не должен зависнуть вместе
/// с ним).
fn recover_endpoint_after_failure<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    ep_idx: usize,
    ep: ReadyEndpoint,
    receiver_task_cap: u64,
    receiver_umap: &A::Umap,
    recv_base: u64,
    recv_count: usize,
) {
    loop {
        let mut dropped: HVec<(u64, usize), MAILBOX_SLOTS> = HVec::new();
        match endpoint::take_pending(
            receiver_task_cap,
            None,
            receiver_umap,
            ep.tgt_va,
            ep.tgt_capacity,
            recv_base,
            recv_count,
            &mut dropped,
        ) {
            Some(delivery) => {
                if delivery.is_fault {
                    // Фолт-ящик: отправитель спит до FAULT_REPLY —
                    // только пометить доставку (см. SyscallIPCWait).
                    crate::ipc::fault::mark_fault_delivered(delivery.sender_task_cap);
                    handle_dropped(kctl, &dropped, lctl);
                    {
                        let tasks = kctl.task_manager().lock();
                        crate::task::stats::count_ipc_recv_id(&tasks, receiver_task_cap);
                    }
                    endpoint::consume_ready(ep_idx);
                    lctl.scheduler_release_object(endpoint::endpoint_wait_object(ep_idx));
                    return;
                }
                match transfer_delivery_caps::<A>(
                    access,
                    delivery.sender_task_cap,
                    receiver_task_cap,
                    &delivery,
                    recv_base,
                    recv_count,
                ) {
                    Ok(chosen) => {
                        // Слова слотов в заголовке буфера: фактические
                        // слоты приёмного окна (назначены выше).
                        if !endpoint::write_cap_slot_headers(receiver_umap, ep.tgt_va, &chosen) {
                            kernel_log!(
                                "ipc: слоты заголовка не записаны ({:#x})\n",
                                ep.tgt_va
                            );
                        }
                        wake_sender_ok::<A>(
                            kctl,
                            delivery.sender_task_cap,
                            lctl,
                            endpoint::sender_wait_object(delivery.mailbox_idx),
                        );
                        handle_dropped(kctl, &dropped, lctl);
                        // Сообщение доставлено: получатель просыпается,
                        // эндпоинт израсходован.
                        {
                            let tasks = kctl.task_manager().lock();
                            crate::task::stats::count_ipc_recv_id(&tasks, receiver_task_cap);
                        }
                        endpoint::consume_ready(ep_idx);
                        lctl.scheduler_release_object(endpoint::endpoint_wait_object(ep_idx));
                        return;
                    }
                    Err(code) => {
                        // Этому отправителю не повезло — ошибка в кадр,
                        // пробуем следующее сообщение.
                        wake_sender_error(
                            kctl,
                            delivery.sender_task_cap,
                            endpoint::sender_wait_object(delivery.mailbox_idx),
                            code,
                            lctl,
                        );
                        handle_dropped(kctl, &dropped, lctl);
                        continue;
                    }
                }
            }
            None => {
                handle_dropped(kctl, &dropped, lctl);
                // Ждущих отправителей нет: получатель продолжает ждать.
                endpoint::restore_ready(ep_idx, ep);
                return;
            }
        }
    }
}

impl<A: ArchImplementation + 'static> SyscallDomain for IPCSyscallDomain<A, SyscallIPCWait> {
    const SYSCALL_ID: usize = 11;
    type Args = SyscallIPCWait;
    type Umap = A::Umap;

    fn handle(
        &'static self,
        lctl: &mut crate::lctl::LocalKernelCTL<Self::Umap>,
        args: Self::Args,
    ) -> u64 {
        let Some(current) = lctl.current_task_cap_id() else {
            return res::E_NO_CURRENT_TASK;
        };
        let tgt_va = args.tgt_ptr as usize;
        let tgt_capacity = args.tgt_capacity as usize;
        if tgt_capacity < HEADER_WORDS * 8 || !tgt_va.is_multiple_of(8) {
            return res::E_INVALID_ARG;
        }
        // Приёмное окно capability: recv_count > MAX_CAPS бессмысленно
        // (сообщение несёт максимум MAX_CAPS дескрипторов) — ограничиваем
        // для тigth-арифметики; recv_base+recv_count обязан не переполнять
        // u64 (слоты recv_base+i вычисляются сложением при доставке).
        let recv_count = args.recv_count as usize;
        if recv_count > MAX_CAPS || args.recv_base.checked_add(args.recv_count).is_none() {
            return res::E_INVALID_ARG;
        }
        let recv_base = args.recv_base;

        let access = self.0.permission_backend.lock();

        let Some(receiver_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let receiver = unsafe { receiver_ptr.as_ref() };
        let umap = receiver.userspace_map();

        // Буфер приёма обязан отображаться (заголовок — минимум).
        if !endpoint::check_user_region(umap, tgt_va, HEADER_WORDS * 8) {
            return res::E_INVALID_ARG;
        }

        // Closed-wait фильтр: слот отправителя → его task_cap_id.
        let from = if args.from_slot == IPC_WAIT_ANY {
            None
        } else {
            let tasks = self.0.task_manager().lock();
            match resolve_task_slot::<A>(&tasks, receiver, args.from_slot) {
                Ok((sender_task_cap, _)) => Some(sender_task_cap),
                Err(code) => return code,
            }
        };

        // Быстрый путь: забрать ждущее сообщение (циклом — неудачные
        // пересылки capability не должны съедать сообщение получателя).
        loop {
            let mut dropped: HVec<(u64, usize), MAILBOX_SLOTS> = HVec::new();
            match endpoint::take_pending(
                current,
                from,
                umap,
                tgt_va,
                tgt_capacity,
                recv_base,
                recv_count,
                &mut dropped,
            ) {
                Some(delivery) => {
                    if delivery.is_fault {
                        // Фолт-сообщение (отправитель — упавшая задача,
                        // см. ipc::fault): payload уже в буфере,
                        // capability в нём нет. Отправителя НЕ будим — он
                        // спит на fault-объекте до FAULT_REPLY; помечаем
                        // доставку (после этого REPLY валиден).
                        crate::ipc::fault::mark_fault_delivered(delivery.sender_task_cap);
                        handle_dropped(self.0, &dropped, lctl);
                        crate::task::stats::count_ipc_recv(lctl);
                        return res::OK;
                    }
                    match transfer_delivery_caps::<A>(
                        &access,
                        delivery.sender_task_cap,
                        current,
                        &delivery,
                        recv_base,
                        recv_count,
                    ) {
                        Ok(chosen) => {
                            // Слова слотов в заголовке буфера: фактические
                            // слоты приёмного окна (назначены выше).
                            if !endpoint::write_cap_slot_headers(umap, tgt_va, &chosen) {
                                kernel_log!(
                                    "ipc: слоты заголовка не записаны ({:#x})\n",
                                    tgt_va
                                );
                            }
                            wake_sender_ok::<A>(
                                self.0,
                                delivery.sender_task_cap,
                                lctl,
                                endpoint::sender_wait_object(delivery.mailbox_idx),
                            );
                            handle_dropped(self.0, &dropped, lctl);
                            // Сообщение уже в буфере получателя (он —
                            // текущая задача): статистика приёма здесь.
                            crate::task::stats::count_ipc_recv(lctl);
                            return res::OK;
                        }
                        Err(code) => {
                            kernel_log!(
                                "ipc: пересылка caps от {} не удалась ({:#x})\n",
                                delivery.sender_task_cap,
                                code
                            );
                            wake_sender_error(
                                self.0,
                                delivery.sender_task_cap,
                                endpoint::sender_wait_object(delivery.mailbox_idx),
                                code,
                                lctl,
                            );
                            handle_dropped(self.0, &dropped, lctl);
                            continue; // следующее сообщение
                        }
                    }
                }
                None => {
                    handle_dropped(self.0, &dropped, lctl);
                    // Медленный путь: готовность + сон получателя.
                    match endpoint::register_ready(
                        current,
                        umap,
                        tgt_va,
                        tgt_capacity,
                        from,
                        recv_base,
                        recv_count,
                    ) {
                        Ok(ep_idx) => {
                            let _ = lctl.scheduler_block_on_object(
                                endpoint::endpoint_wait_object(ep_idx),
                                WaitModel::OneShot,
                            );
                            return res::OK;
                            // Доставка — в IPC_SEND отправителя (быстрый
                            // путь): буфер заполнится, RAX уже OK.
                        }
                        Err(endpoint::IpcError::EndpointsFull) => return res::E_SLAB,
                        Err(endpoint::IpcError::BadBuffer) => return res::E_INVALID_ARG,
                        Err(endpoint::IpcError::MailboxFull) => return res::E_SLAB,
                    }
                }
            }
        }
    }
}
