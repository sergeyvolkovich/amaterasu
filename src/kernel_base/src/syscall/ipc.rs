//! Домен IPC-сисколлов: синхронный транспорт сообщений (стиль Лидтке/L4).
//!
//! Ядро — ТОЛЬКО транспорт: payload непрозрачен (сериализация —
//! юзерспейс: тело {label, payload_len, payload}, см. cintos_user::ipc),
//! capability пересылаются явными дескрипторами ([`CapItem`], аналог L4
//! map items). Rendezvous-состояние — в TCB участников (task::
//! ipc_state), оркестрация — ipc::transport. ПОЧТОВЫХ ЯЩИКОВ НЕТ:
//! заблокированный отправитель держит сообщение в СВОЁМ буфере,
//! получатель копирует напрямую через его умап (классический L4).
//!
//! ABI (v3):
//!   IPC_SEND(10): (slot, msg_ptr, msg_size, caps_ptr, caps_count,
//!                  deadline)
//!     slot — слот cspace ОТПРАВИТЕЛЯ с TaskTCB-капабилити получателя
//!     (право Send); msg — непрозрачное тело; caps — #[repr(C)] массив
//!     {src_slot, dst_slot, rights} × caps_count (dst_slot ИГНОРИРУЕТСЯ
//!     ядром — см. IPC_WAIT); deadline — абсолютный тик (0 — вечно),
//!     по истечении E_TIMEOUT с самоочисткой из очереди получателя.
//!   IPC_WAIT(11): (target, tgt_ptr, tgt_capacity, recv_base,
//!                  recv_count, deadline)
//!     target — IPC_WAIT_ANY (open wait) или слот cspace с TaskTCB
//!     отправителя (closed wait); tgt — буфер приёма
//!     [заголовок|слоты caps|тело]; recv_base/recv_count — ПРИЁМНОЕ
//!     ОКНО capability (seL4-стиль: слот выбирает получатель).
//!
//! Блокировка (lost-wakeup-free): сон — через lctl::
//! scheduler_block_on_object_if, предикат проверяется ПОД WAKE_LOCK —
//! доставка, случившаяся между проверкой и сном, не теряется (предикат
//! её видит и отменяет сон). Ошибка доставки спящему отправителю
//! пишется перезаписью RAX его сохранённого кадра (TCB::
//! patch_resume_result) ДО пробуждения; для гонки «не успел уснуть»
//! исход дублируется в ipc.send_rax (см. task::ipc_state).
//!
//! Таймауты: после НАСТОЯЩЕГО сна хендлер НЕ перезапускается — код
//! E_TIMEOUT ставит будильщик: тик дедлайна зовёт зарегистрированный
//! резолвер (deadline::set_timeout_resolver — см. kernel_limine),
//! который патчит кадр и делает самоочистку; доставка в тот же тик
//! старше таймаута (резолвер видит её по IPC-состоянию).

use core::marker::PhantomData;

use heapless::Vec as HVec;
use syscall_macros::SyscallArguments;

use crate::kernel_log;
use crate::{
    KernelCTL,
    ipc::{
        cap_transfer::{CapTransferError, CapTransferSpec, transfer_capabilities},
        endpoint::{
            self, CapItem, HEADER_WORDS, MAX_CAPS, MAX_MSG,
        },
        transport,
    },
    task::ipc_state::{GateQueueSide, GateRoute, RecvSpec, SendSpec},
    task::tcb::GTcb,
    traits::{
        ArchImplementation,
        memory::MemoryInterfaceUserspace,
        scheduller::WaitModel,
        syscall::{SyscallDomain, syscall_result as res},
    },
};

#[derive(SyscallArguments)]
pub struct SyscallIPCSend {
    /// Слот cspace текущей задачи с TaskTCB-капабилити получателя.
    slot: u64,
    /// ВА непрозрачного тела сообщения (label + payload + данные).
    msg_ptr: u64,
    msg_size: u64,
    /// ВА массива дескрипторов пересылки (3×u64 на capability) или 0.
    caps_ptr: u64,
    caps_count: u64,
    /// Абсолютный дедлайн в тиках stats::global_ticks (0 — ждать
    /// вечно). По истечении E_TIMEOUT; сообщение, доставленное в тот же
    /// тик, старше таймаута (доставка побеждает).
    deadline: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallIPCWait {
    /// Слот с TaskTCB отправителя (closed wait) или IPC_WAIT_ANY.
    target: u64,
    /// ВА буфера приёма: [заголовок 3 слова][слоты caps][тело].
    tgt_ptr: u64,
    /// Ёмкость буфера в байтах.
    tgt_capacity: u64,
    /// База приёмного окна capability (слоты получателя recv_base+i).
    recv_base: u64,
    /// Размер приёмного окна в слотах (0 — capability не принимать).
    recv_count: u64,
    /// Абсолютный дедлайн (0 — ждать вечно); E_TIMEOUT по истечении.
    deadline: u64,
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

/// Цель IPC-операции по слоту cspace: прямая отправка задаче (TaskTCB-
/// капа, право Send) или отправка в гейт (IpcGate-капа, право Send).
pub(crate) enum IpcTarget<Umap: MemoryInterfaceUserspace> {
    Task(u64, core::ptr::NonNull<GTcb<Umap>>),
    /// ABA-защищённый маршрут гейта (id + поколение из капы).
    Gate(GateRoute),
}

/// Разрешение слота cspace в цель SEND: TaskTCB (право Send) или
/// IpcGate (право Send). Гейт-вариант — seL4-стиль: клиент шлёт В
/// КАНАЛ, а не задаче.
pub(crate) fn resolve_send_target<A: ArchImplementation>(
    tasks: &crate::task::TaskManager<A::Umap>,
    current_gtcb: &GTcb<A::Umap>,
    slot: u64,
) -> Result<IpcTarget<A::Umap>, u64> {
    let resolved = {
        let caps = current_gtcb.capspace().lock();
        let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
        let sendable = record.check_send().map_err(|_| res::E_CAP_REVOKED)?;
        if !sendable.contains(crate::access::capability::DirectCapabilityRights::Send) {
            return Err(res::E_RIGHTS_DENIED);
        }
        let (object, _) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
        // Гейт: вернуть маршрут немедленно (Copy; валидность сверена со
        // слотом под локом шарда — мёртвый/переиспользованный слот не
        // резолвится: E_CAP_REVOKED ещё здесь).
        if let Some(route) = object.resolve_ipc_gate() {
            return Ok(IpcTarget::Gate(route));
        }
        object.resolve_task_tcb().ok_or(res::E_INVALID_ARG)?
    };
    let task_cap = tasks
        .task_cap_id_by_gtcb(resolved)
        .ok_or(res::E_NOT_FOUND)?;
    Ok(IpcTarget::Task(task_cap, resolved))
}

/// Разрешение слота cspace в цель WAIT: IPC_WAIT_ANY (уже отфильтровано
/// вызывающим), TaskTCB (closed wait; право Send — резолв пира) или
/// IpcGate (ожидание НА ГЕЙТЕ; право Recv — приём из канала).
pub(crate) fn resolve_wait_target<A: ArchImplementation>(
    tasks: &crate::task::TaskManager<A::Umap>,
    current_gtcb: &GTcb<A::Umap>,
    slot: u64,
) -> Result<(Option<u64>, Option<GateRoute>), u64> {
    // Возврат: (from-фильтр, гейт-маршрут).
    let caps = current_gtcb.capspace().lock();
    let record = caps.get(&slot).ok_or(res::E_SLOT_EMPTY)?;
    let (object, rights) = record.resolve().map_err(|_| res::E_CAP_REVOKED)?;
    if let Some(route) = object.resolve_ipc_gate() {
        if !rights.contains(crate::access::capability::DirectCapabilityRights::Recv) {
            return Err(res::E_RIGHTS_DENIED);
        }
        return Ok((None, Some(route)));
    }
    // TaskTCB — closed wait: право Send (как в resolve_task_slot).
    if !rights.contains(crate::access::capability::DirectCapabilityRights::Send) {
        return Err(res::E_RIGHTS_DENIED);
    }
    let gtcb = object.resolve_task_tcb().ok_or(res::E_INVALID_ARG)?;
    let task_cap = tasks.task_cap_id_by_gtcb(gtcb).ok_or(res::E_NOT_FOUND)?;
    Ok((Some(task_cap), None))
}

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
fn assign_recv_slots_window<A: ArchImplementation>(
    access: &crate::access::AccessManager<A::Umap>,
    receiver_task_cap: u64,
    caps_count: usize,
    recv_base: u64,
    recv_count: usize,
) -> Result<HVec<u64, MAX_CAPS>, u64> {
    if caps_count == 0 {
        return Ok(HVec::new());
    }
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
/// ([`assign_recv_slots_window`], «первый свободный»): поле dst_slot
/// дескриптора отправителя не адресует cspace получателя.
fn transfer_delivery_caps<A: ArchImplementation>(
    access: &crate::access::AccessManager<A::Umap>,
    sender_task_cap: u64,
    receiver_task_cap: u64,
    caps: &[CapItem],
    recv_base: u64,
    recv_count: usize,
) -> Result<HVec<u64, MAX_CAPS>, u64> {
    let chosen = assign_recv_slots_window::<A>(
        access,
        receiver_task_cap,
        caps.len(),
        recv_base,
        recv_count,
    )?;
    let mut specs: HVec<CapTransferSpec, MAX_CAPS> = HVec::new();
    for (i, c) in caps.iter().enumerate() {
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

/// Патчит RAX спящего отправителя, ставит отметку для гонки «не успел
/// уснуть» и будит его (ошибка доставки). Вызывать с УЖЕ захваченным
/// task_manager-локом (guard передаётся ссылкой — повторный захват
/// внутри означал бы дедлок).
fn wake_sender_error<A: ArchImplementation>(
    tasks: &crate::task::TaskManager<A::Umap>,
    sender_task_cap: u64,
    code: u64,
    resume_word: usize,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
) {
    if let Some(tcb) = tasks.get_tcb(sender_task_cap) {
        tcb.patch_resume_result(resume_word, code);
    }
    transport::fail_sender(tasks, sender_task_cap, code);
    lctl.scheduler_release_object(endpoint::sender_wait_object(sender_task_cap));
}

/// Будит отправителя успешной доставки (слово результата в его кадре
/// уже ОК — патчить нечего; для гонки «не успел уснуть» send_rax
/// остаётся None = успех) и учитывает статистику доставки. Для ФОЛТ-
/// доставок не звать: отправитель (упавшая задача) спит на fault-
/// объекте (см. fault::mark_fault_delivered).
fn wake_sender_ok<A: ArchImplementation>(
    tasks: &crate::task::TaskManager<A::Umap>,
    sender_task_cap: u64,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
) {
    crate::task::stats::count_ipc_sent_id(tasks, sender_task_cap);
    lctl.scheduler_release_object(endpoint::sender_wait_object(sender_task_cap));
}

/// Возврат гейт-ожидателя после НЕУДАЧНОЙ доставки (restore уже выполнен
/// deliver_claimed'ом): если маршрут ещё валиден — снова в ГОЛОВУ
/// очереди (FIFO-справедливость); если гейт уничтожен в окне
/// клейм/доставка — отзыв ожидания: recv → Idle, патч кадра
/// E_CAP_REVOKED + пробуждение. Без отзыва ожидатель спал бы вечно:
/// очередь мёртвого гейта никого не пустит, а дренаж его уже не видит
/// (узел отсоединён клейм-путём). Требует захваченного
/// task_manager-лока — берёт сам.
fn gate_reclaim_or_revoke<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    route: GateRoute,
    receiver: u64,
    resume_word: usize,
) {
    let requeued = {
        let tasks = kctl.task_manager().lock();
        // После restore узел вне очереди (detach после клейма) —
        // Ok означает «поставлен в голову»; Err — гейт мёртв/TCB нет.
        crate::ipc::gate::gate_push(&tasks, route, receiver, GateQueueSide::Receivers, true)
            .is_ok()
    };
    if requeued {
        return;
    }
    {
        let tasks = kctl.task_manager().lock();
        if let Some(tcb) = tasks.get_tcb(receiver) {
            let mut ipc = tcb.ipc().lock();
            if matches!(
                ipc.recv,
                crate::task::ipc_state::IpcRecv::Receiving(s) if s.gate == Some(route)
            ) {
                ipc.recv = crate::task::ipc_state::IpcRecv::Idle;
            }
            tcb.patch_resume_result(resume_word, res::E_CAP_REVOKED);
        }
    }
    lctl.scheduler_release_object(endpoint::endpoint_wait_object(receiver));
}

/// Исход изъятия кандидата из очереди (быстрый путь WAIT).
enum TakeOutcome {
    /// Обычное сообщение доставлено в буфер получателя.
    Delivered,
    /// Фолт-сообщение доставлено (отправителя не будить).
    DeliveredFault,
    /// Кандидатов (под фильтр) больше нет.
    Empty,
}

/// Быстрый путь WAIT: разбирает очередь отправителей текущей задачи-
/// получателя. Вызывать с УЖЕ захваченным task_manager-локом (tasks —
/// deref guard'а; wakeup-хелперы локов НЕ берут). Каждый кандидат:
/// изъятие SendSpec (или фолт-слота) → проверка вместимости →
/// пересылка capability → копия тела из буфера ОТПРАВИТЕЛЯ (его умап;
/// буфер стабильна, пока он спит) → wake. Негабарит/
/// неудачная пересылка — ошибка отправителю (патч RAX + wake), цикл
/// продолжается со следующим.
fn take_next<A: ArchImplementation>(
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    tasks: &crate::task::TaskManager<A::Umap>,
    me: u64,
    my_umap: &A::Umap,
    from: Option<u64>,
    gate: Option<GateRoute>,
    tgt_va: usize,
    tgt_capacity: usize,
    recv_base: u64,
    recv_count: usize,
    resume_word: usize,
) -> TakeOutcome {
    loop {
        // Кандидат — изъятие: гейт-очередь (waiting НА ГЕЙТЕ; O(1)
        // detach головы по его собственным ссылкам) или собственная
        // очередь отправителей (прямой эндпоинт).
        let candidate = if let Some(route) = gate {
            crate::ipc::gate::gate_pop_sender(tasks, route)
                .map(|id| (id, false))
                .or_else(|| transport::pop_next_candidate(tasks, me, from))
        } else {
            transport::pop_next_candidate(tasks, me, from)
        };
        let Some((sender_id, is_fault)) = candidate else {
            return TakeOutcome::Empty;
        };
        if is_fault {
            // Фолт-кандидат: тело — в слоте активного фолта (ядро),
            // НЕ в userspace упавшей задачи. Отправителя не будим —
            // он спит на fault-объекте до FAULT_REPLY.
            let Some(msg) = crate::ipc::fault::take_pending_fault(tasks, sender_id, me) else {
                // Слот уже нет (обработчик перезаписан/фолт снят) —
                // запись очереди протухла, кандидат пропускается.
                continue;
            };
            let need = endpoint::delivery_bytes(0, msg.len());
            if need > tgt_capacity
                || !endpoint::check_user_region(my_umap, tgt_va, need)
            {
                // Буфер мал: фолт НЕ отбрасывается никогда (потеря =
                // вечное зависание упавшей) — вернём кандидата в голову
                // очереди и выйдем: подойдёт следующий wait с большим
                // буфером (см. ipc::fault).
                crate::ipc::fault::untake_pending_fault(tasks, sender_id, me);
                if let Some(route) = gate {
                    // Гейт мог быть уничтожен в окне изъятия: push
                    // откажет (E_CAP_REVOKED-маршрут) — фолт остаётся в
                    // СВОЁМ слоте фолтов (не в очереди гейта) и будет
                    // доставлен через другой wait/маршрут; сам упавший
                    // спит на фолт-объекте и не зависит от гейта.
                    let _ = crate::ipc::gate::gate_push(
                        tasks,
                        route,
                        sender_id,
                        GateQueueSide::Senders,
                        true,
                    );
                } else {
                    transport::requeue_candidate(tasks, me, sender_id, true);
                }
                return TakeOutcome::Empty;
            }
            if !endpoint::write_delivery_header_and_body(
                my_umap,
                tgt_va,
                sender_id,
                &msg,
                &[],
            ) {
                // Отображение схлопнулось между проверкой и записью —
                // фолт возвращается в слот (см. выше — не теряем).
                crate::ipc::fault::untake_pending_fault(tasks, sender_id, me);
                if let Some(route) = gate {
                    // См. выше: отказ push при мёртвом гейте безопасен.
                    let _ = crate::ipc::gate::gate_push(
                        tasks,
                        route,
                        sender_id,
                        GateQueueSide::Senders,
                        true,
                    );
                } else {
                    transport::requeue_candidate(tasks, me, sender_id, true);
                }
                return TakeOutcome::Empty;
            }
            crate::ipc::fault::mark_fault_delivered(sender_id);
            crate::task::stats::count_ipc_recv_id(tasks, me);
            return TakeOutcome::DeliveredFault;
        }
        // Обычный отправитель: изъять его SendSpec (он спит — параметры
        // стабильны; изъятие делает его «в обработке»).
        let Some(spec) = transport::take_send_state(tasks, sender_id) else {
            // Защита: запись без SendSpec (уже изъят другим SMP-путём —
            // невозможно по построению, но не зависаем) — пропуск.
            continue;
        };
        let need = endpoint::delivery_bytes(spec.caps_count, spec.msg_len);
        if need > tgt_capacity || !endpoint::check_user_region(my_umap, tgt_va, need) {
            // Негабарит/неотображаемо — НЕ доставимо никогда (буфер не
            // вырастет в этом wait): отправителю ошибка, следующий
            // кандидат.
            wake_sender_error::<A>(tasks, sender_id, res::E_INVALID_ARG, resume_word, lctl);
            continue;
        }
        // Пересылка capability (слоты — из МОЕГО приёмного окна).
        let caps: &[CapItem] = &spec.caps[..spec.caps_count];
        let dst_slots = match transfer_delivery_caps::<A>(
            access,
            sender_id,
            me,
            caps,
            recv_base,
            recv_count,
        ) {
            Ok(slots) => slots,
            Err(code) => {
                kernel_log!(
                    "ipc: пересылка caps от {} не удалась ({:#x})\n",
                    sender_id,
                    code
                );
                wake_sender_error::<A>(tasks, sender_id, code, resume_word, lctl);
                continue;
            }
        };
        // Копия тела из буфера ОТПРАВИТЕЛЯ (его умап) → ядро → мой буфер.
        let sender_umap = match access.get_task_tcb(sender_id) {
            Some(ptr) => unsafe { ptr.as_ref().userspace_map() },
            // Отправитель исчез между изъятием и копией (уничтожение под
            // task_manager-локом невозможно; защита от иных путей).
            None => {
                wake_sender_error::<A>(tasks, sender_id, res::E_NOT_FOUND, resume_word, lctl);
                continue;
            }
        };
        let mut body = [0u8; MAX_MSG];
        if spec.msg_len > MAX_MSG
            || !endpoint::copy_body_from_sender(
                sender_umap,
                spec.msg_va,
                spec.msg_len,
                &mut body,
            )
        {
            // Буфер отправителя не читается (дыра в его умапе —
            // некорректный msg_va): ошибка отправителю.
            wake_sender_error::<A>(tasks, sender_id, res::E_INVALID_ARG, resume_word, lctl);
            continue;
        }
        if !endpoint::write_delivery_header_and_body(
            my_umap,
            tgt_va,
            sender_id,
            &body[..spec.msg_len],
            &dst_slots,
        ) {
            // Мой буфер схлопнулся между проверкой и записью
            // (многопоточный umap): capability уже в моём cspace —
            // фиксируем в логе; отправителю — ошибка.
            kernel_log!(
                "ipc: доставка в буфер {:#x} не удалась после пересылки caps\n",
                tgt_va
            );
            wake_sender_error::<A>(tasks, sender_id, res::E_INTERNAL, resume_word, lctl);
            continue;
        }
        // Доставка состоялась: rendezvous завершён.
        transport::finish_delivery(tasks, me, sender_id, false);
        wake_sender_ok::<A>(tasks, sender_id, lctl);
        crate::task::stats::count_ipc_recv_id(tasks, me);
        return TakeOutcome::Delivered;
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
        let sender_umap = sender.userspace_map();

        // Дескрипторы пересылки — валидируются СРАЗУ (права на слоты);
        // само тело остаётся в userspace отправителя (L4: без копии до
        // rendezvous).
        let cap_items = match read_cap_items::<A>(sender_umap, args.caps_ptr, caps_count) {
            Ok(items) => items,
            Err(code) => return code,
        };

        // Адресат: слот → TaskTCB (прямая отправка) | IpcGate (гейт).
        let target = {
            let tasks = self.0.task_manager().lock();
            match resolve_send_target::<A>(&tasks, sender, args.slot) {
                Ok(t) => t,
                Err(code) => return code,
            }
        };
        match target {
            IpcTarget::Gate(route) => {
                match send_to_gate::<A>(
                    self.0,
                    lctl,
                    &access,
                    current,
                    sender_umap,
                    route,
                    args.msg_ptr as usize,
                    msg_size,
                    &cap_items,
                    args.deadline,
                ) {
                    SendOutcome::Done(code) => code,
                    SendOutcome::AwaitReply => res::OK,
                }
            }
            IpcTarget::Task(receiver_task_cap, receiver_ptr) => {
                if receiver_task_cap == current {
                    return res::E_INVALID_ARG; // самому себе — вечный блок
                }
                // SAFETY: под permission_backend-локом.
                let receiver = unsafe { receiver_ptr.as_ref() };
                match send_to_task::<A>(
                    self.0,
                    lctl,
                    &access,
                    current,
                    sender_umap,
                    receiver_task_cap,
                    receiver.userspace_map(),
                    args.msg_ptr as usize,
                    msg_size,
                    &cap_items,
                    args.deadline,
                ) {
                    SendOutcome::Done(code) => code,
                    SendOutcome::AwaitReply => res::OK,
                }
            }
        }
    }
}

/// Доставка ЗАХВАЧЕННОМУ (клеймнутому) получателю: валидация буфера →
/// слоты из приёмного окна → пересылка capability → копия тела из
/// буфера отправителя → finish (reply_to) → wake получателя.
/// Общий механизм быстрого пути send_to_task и гейт-маршрута.
/// При неудаче получатель возвращается в Receiving (restore).
#[allow(clippy::too_many_arguments)]
fn deliver_claimed<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    sender_umap: &A::Umap,
    receiver_task_cap: u64,
    receiver_umap: &A::Umap,
    rspec: crate::task::ipc_state::RecvSpec,
    msg_va: usize,
    msg_len: usize,
    caps: &[CapItem],
) -> Result<(), u64> {
    let caps_count = caps.len();
    let need = endpoint::delivery_bytes(caps_count, msg_len);
    let tasks = kctl.task_manager().lock();
    if !endpoint::check_user_region(receiver_umap, rspec.tgt_va, need) {
        transport::restore_receiver(&tasks, receiver_task_cap, rspec);
        return Err(res::E_INVALID_ARG);
    }
    let dst_slots = match assign_recv_slots_window::<A>(
        access,
        receiver_task_cap,
        caps_count,
        rspec.recv_base,
        rspec.recv_count,
    ) {
        Ok(slots) => slots,
        Err(code) => {
            transport::restore_receiver(&tasks, receiver_task_cap, rspec);
            return Err(code);
        }
    };
    let specs: HVec<CapTransferSpec, MAX_CAPS> = {
        let mut s: HVec<CapTransferSpec, MAX_CAPS> = HVec::new();
        for (i, c) in caps.iter().enumerate() {
            let _ = s.push(CapTransferSpec {
                src_slot: c.src_slot,
                dst_slot: dst_slots[i],
                rights: crate::access::capability::DirectCapabilityRights::
                    from_bits_truncate(c.rights),
            });
        }
        s
    };
    match transfer_capabilities(access, current, receiver_task_cap, &specs) {
        Ok(()) => {}
        Err((_, e)) => {
            transport::restore_receiver(&tasks, receiver_task_cap, rspec);
            return Err(transfer_code(e));
        }
    }
    // Тело: буфер отправителя → ядро → буфер получателя.
    let mut body = [0u8; MAX_MSG];
    if msg_len > MAX_MSG
        || !endpoint::copy_body_from_sender(sender_umap, msg_va, msg_len, &mut body)
    {
        transport::restore_receiver(&tasks, receiver_task_cap, rspec);
        return Err(res::E_INVALID_ARG);
    }
    if !endpoint::write_delivery_header_and_body(
        receiver_umap,
        rspec.tgt_va,
        current,
        &body[..msg_len],
        &dst_slots,
    ) {
        kernel_log!(
            "ipc: доставка в буфер {:#x} не удалась после пересылки caps\n",
            rspec.tgt_va
        );
        transport::restore_receiver(&tasks, receiver_task_cap, rspec);
        return Err(res::E_INTERNAL);
    }
    transport::finish_delivery(&tasks, receiver_task_cap, current, false);
    drop(tasks);
    crate::task::stats::count_ipc_sent(lctl);
    {
        let tasks = kctl.task_manager().lock();
        crate::task::stats::count_ipc_recv_id(&tasks, receiver_task_cap);
    }
    lctl.scheduler_release_object(endpoint::endpoint_wait_object(receiver_task_cap));
    Ok(())
}

/// Результат фазы отправки (общий для SEND/CALL/REPLY-фаз).
enum SendOutcome {
    /// Отправка завершена с кодом (OK — доставлено; ошибка — иначе).
    Done(u64),
    /// CALL: сообщение доставлено/поставлено в очередь; клиент уже
    /// зарегистрировал Receiving — продолжает фазу ожидания ответа.
    AwaitReply,
}

/// Фаза отправки сообщения задаче `receiver_task_cap` (общий механизм
/// IPC_SEND и reply-фаз REPLY/REPLY_WAIT; CALL оркестрирует фазы сам —
/// см. await_reply_phase/call_via_gate). Тело сообщения живёт в
/// userspace ОТПРАВИТЕЛЯ (текущей задачи) по `msg_va` — быстрый путь
/// копирует через ядерный буфер, медленный оставляет до доставки
/// (классический L4: без буферизации в ядре).
///
/// Требует захваченного permission_backend-лока (кап-трансфер);
/// task_manager-лок берётся на атомарные секции внутри.
#[allow(clippy::too_many_arguments)]
fn send_to_task<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    sender_umap: &A::Umap,
    receiver_task_cap: u64,
    receiver_umap: &A::Umap,
    msg_va: usize,
    msg_len: usize,
    caps: &[CapItem],
    deadline: u64,
) -> SendOutcome {
    let caps_count = caps.len();
    let need = endpoint::delivery_bytes(caps_count, msg_len);

    // ── Быстрый путь: получатель ждёт — клейм. ──
    let claim = {
        let tasks = kctl.task_manager().lock();
        transport::claim_receiver(&tasks, receiver_task_cap, current, None, need, caps_count)
    };
    match claim {
        transport::ClaimResult::TooSmall | transport::ClaimResult::CapsRejected => {
            SendOutcome::Done(res::E_INVALID_ARG)
        }
        transport::ClaimResult::Claimed(rspec) => {
            // ── Быстрый путь: получатель спит в wait. ──
            if let Err(code) = deliver_claimed::<A>(
                kctl, lctl, access, current, sender_umap, receiver_task_cap,
                receiver_umap, rspec, msg_va, msg_len, caps,
            ) {
                return SendOutcome::Done(code);
            }
            SendOutcome::Done(res::OK)
        }
        transport::ClaimResult::NotWaiting => {
            // ── Медленный путь: SendSpec + очередь получателя. ──
            let spec = SendSpec {
                to: receiver_task_cap,
                gate: None,
                msg_va,
                msg_len,
                caps: {
                    let mut c = [CapItem { src_slot: 0, dst_slot: 0, rights: 0 }; MAX_CAPS];
                    for (d, s) in c.iter_mut().zip(caps.iter()) {
                        *d = *s;
                    }
                    c
                },
                caps_count,
                is_fault: false,
            };
            {
                let tasks = kctl.task_manager().lock();
                if let Some(tcb) = tasks.get_tcb(current) {
                    let mut ipc = tcb.ipc().lock();
                    ipc.send = Some(spec);
                    ipc.send_rax = None;
                }
                if transport::enqueue_sender(&tasks, receiver_task_cap, current, false).is_err() {
                    if let Some(tcb) = tasks.get_tcb(current) {
                        tcb.ipc().lock().send = None;
                    }
                    return SendOutcome::Done(res::E_SLAB);
                }
            }

            // ── Обычная SEND: сон на СВОЁМ объекте отправителя. ──
            let object = endpoint::sender_wait_object(current);
            let mut slept = true;
            if deadline > 0 {
                if crate::task::stats::global_ticks() >= deadline {
                    let tasks = kctl.task_manager().lock();
                    let _ = transport::sender_timeout_pending(&tasks, current);
                    return SendOutcome::Done(res::E_TIMEOUT);
                }
                if crate::task::deadline::register(current, object, deadline).is_err() {
                    let tasks = kctl.task_manager().lock();
                    let _ = transport::sender_timeout_pending(&tasks, current);
                    return SendOutcome::Done(res::E_SLAB);
                }
            }
            {
                let tasks = kctl.task_manager().lock();
                slept = lctl.scheduler_block_on_object_if(
                    object,
                    WaitModel::OneShot,
                    transport::sender_pred(&tasks, current),
                );
            }
            if deadline > 0 {
                let fired = crate::task::deadline::cancel(current);
                if fired && !slept {
                    let tasks = kctl.task_manager().lock();
                    let _ = transport::sender_timeout_pending(&tasks, current);
                    return SendOutcome::Done(res::E_TIMEOUT);
                }
            }
            if !slept {
                let tasks = kctl.task_manager().lock();
                return SendOutcome::Done(transport::take_send_result(&tasks, current).unwrap_or(res::OK));
            }
            // Истинный сон: кадр сохранён с RAX = OK; исход решит
            // будильщик (доставка — OK; таймаут — патч E_TIMEOUT
            // резолвером тика; смерть получателя — патч E_NOT_FOUND).
            SendOutcome::Done(res::OK)
        }
    }
}

/// Отправка В ГЕЙТ (seL4-эндпоинт): клейм FIFO-ожидателя (peek → claim
/// → detach — узел отсоединяется ТОЛЬКО после успешного клейма: при
/// отказе клейма он остаётся в очереди, а при уничтожении гейта в окне
/// клейм/доставка его отсоединяет дренаж — потерянных спящих нет);
/// никого — очередь гейта + сон на СВОЁМ объекте (data — в SendSpec с
/// gate=Some(маршрут); сервер-обработчик изымает через take_next/
/// gate_pop_sender). Результат изъятия ошибки — send_rax. Очередь БЕЗ
/// ёмкости — E_SLAB не бывает; отказ push — только мёртвый гейт
/// (E_CAP_REVOKED).
#[allow(clippy::too_many_arguments)]
fn send_to_gate<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    sender_umap: &A::Umap,
    route: GateRoute,
    msg_va: usize,
    msg_len: usize,
    caps: &[CapItem],
    deadline: u64,
) -> SendOutcome {
    let caps_count = caps.len();
    let need = endpoint::delivery_bytes(caps_count, msg_len);

    // ── Быстрый путь: peek → клейм → detach FIFO-ожидателя гейта. ──
    loop {
        let candidate = match crate::ipc::gate::gate_peek_receiver(route) {
            Some(c) => c,
            None => break, // очередь пуста или гейт мёртв — медленный путь
        };
        let claim = {
            let tasks = kctl.task_manager().lock();
            transport::claim_receiver(&tasks, candidate, current, Some(route), need, caps_count)
        };
        match claim {
            // Затухшая голова (уже не ждёт) — отсоединить (O(1)) и
            // попробовать следующую.
            transport::ClaimResult::NotWaiting => {
                let tasks = kctl.task_manager().lock();
                crate::ipc::gate::gate_detach_receiver(&tasks, route, candidate);
                continue;
            }
            // Буфер/окно получателя не вмещают: он ОСТАЁТСЯ в очереди
            // (detach не выполнялся — семантика прежнего unpop без
            // окна потери), отправителю — ошибка.
            transport::ClaimResult::TooSmall | transport::ClaimResult::CapsRejected => {
                return SendOutcome::Done(res::E_INVALID_ARG);
            }
            transport::ClaimResult::Claimed(rspec) => {
                // Клейм состоялся: изъятие из очереди. Гейт мог быть
                // уничтожен в окне peek/claim — дренаж уже отсоединил
                // узел (false); оба исхода оставляют узел вне очереди
                // и в руках доставляющего.
                {
                    let tasks = kctl.task_manager().lock();
                    crate::ipc::gate::gate_detach_receiver(&tasks, route, candidate);
                }
                let receiver_umap = {
                    let tasks = kctl.task_manager().lock();
                    match tasks.get_tcb(candidate) {
                        Some(tcb) => unsafe {
                            // SAFETY: под task_manager-локом TCB жив.
                            tcb.gtcb_owner().as_ref().userspace_map()
                        },
                        None => {
                            transport::restore_receiver(&tasks, candidate, rspec);
                            continue;
                        }
                    }
                };
                let result = deliver_claimed::<A>(
                    kctl, lctl, access, current, sender_umap, candidate,
                    receiver_umap, rspec, msg_va, msg_len, caps,
                );
                if let Err(code) = result {
                    // Restore выполнен; вернуть ожидателя живому гейту
                    // или отозвать его с E_CAP_REVOKED (мёртвый гейт).
                    gate_reclaim_or_revoke::<A>(
                        kctl,
                        lctl,
                        route,
                        candidate,
                        A::RESUME_RESULT_WORD,
                    );
                    return SendOutcome::Done(code);
                }
                return SendOutcome::Done(res::OK);
            }
        }
    }

    // ── Медленный путь: очередь гейта + сон на своём объекте. ──
    let spec = SendSpec {
        to: 0, // гейт-маршрут: адресат определяется сервером при изъятии
        gate: Some(route),
        msg_va,
        msg_len,
        caps: {
            let mut c = [CapItem { src_slot: 0, dst_slot: 0, rights: 0 }; MAX_CAPS];
            for (d, s) in c.iter_mut().zip(caps.iter()) {
                *d = *s;
            }
            c
        },
        caps_count,
        is_fault: false,
    };
    {
        let tasks = kctl.task_manager().lock();
        if let Some(tcb) = tasks.get_tcb(current) {
            let mut ipc = tcb.ipc().lock();
            ipc.send = Some(spec);
            ipc.send_rax = None;
        }
        // Очередь интрузивная — БЕЗ ёмкости: отказ = гейт уничтожен
        // между resolve и постановкой (маршрут невалиден). Честный
        // E_CAP_REVOKED вместо прежнего молчаливого `let _ =` с E_SLAB.
        if crate::ipc::gate::gate_push(&tasks, route, current, GateQueueSide::Senders, false)
            .is_err()
        {
            if let Some(tcb) = tasks.get_tcb(current) {
                tcb.ipc().lock().send = None;
            }
            return SendOutcome::Done(res::E_CAP_REVOKED);
        }
    }

    let object = endpoint::sender_wait_object(current);
    let mut slept = true;
    if deadline > 0 {
        if crate::task::stats::global_ticks() >= deadline {
            let tasks = kctl.task_manager().lock();
            let _ = transport::sender_timeout_pending(&tasks, current);
            return SendOutcome::Done(res::E_TIMEOUT);
        }
        if crate::task::deadline::register(current, object, deadline).is_err() {
            let tasks = kctl.task_manager().lock();
            let _ = transport::sender_timeout_pending(&tasks, current);
            return SendOutcome::Done(res::E_SLAB);
        }
    }
    {
        let tasks = kctl.task_manager().lock();
        slept = lctl.scheduler_block_on_object_if(
            object,
            WaitModel::OneShot,
            transport::sender_pred(&tasks, current),
        );
    }
    if deadline > 0 {
        let fired = crate::task::deadline::cancel(current);
        if fired && !slept {
            let tasks = kctl.task_manager().lock();
            let _ = transport::sender_timeout_pending(&tasks, current);
            return SendOutcome::Done(res::E_TIMEOUT);
        }
    }
    if !slept {
        let tasks = kctl.task_manager().lock();
        return SendOutcome::Done(transport::take_send_result(&tasks, current).unwrap_or(res::OK));
    }
    // Истинный сон: исход решит будильщик (сервер изымет сообщение и
    // разбудит / таймаут-резолвер патчит E_TIMEOUT с самоочисткой).
    SendOutcome::Done(res::OK)
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
        // (сообщение несёт максимум MAX_CAPS дескрипторов); recv_base+
        // recv_count обязан не переполнять u64.
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

        // Цель ожидания: ANY (open), TaskTCB (closed) или IpcGate
        // (ожидание НА ГЕЙТЕ, право Recv).
        let (from, gate) = if args.target == endpoint::IPC_WAIT_ANY {
            (None, None)
        } else {
            let tasks = self.0.task_manager().lock();
            match resolve_wait_target::<A>(&tasks, receiver, args.target) {
                Ok(pair) => pair,
                Err(code) => return code,
            }
        };

        wait_loop::<A>(
            self.0,
            lctl,
            &access,
            current,
            umap,
            from,
            gate,
            tgt_va,
            tgt_capacity,
            recv_base,
            recv_count,
            args.deadline,
        )
    }
}

/// Цикл ожидания WAIT (общий для IPC_WAIT и IPC_REPLY_WAIT): fast path
/// (очередь) → регистрация Receiving → сон под предикатом → перепроверка.
/// `gate` — ожидание на гейте (commit IPC-гейтов); None — собственный
/// эндпоинт. Блокировка/таймауты — см. модульный комментарий.
#[allow(clippy::too_many_arguments)]
fn wait_loop<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    umap: &A::Umap,
    from: Option<u64>,
    gate: Option<GateRoute>,
    tgt_va: usize,
    tgt_capacity: usize,
    recv_base: u64,
    recv_count: usize,
    deadline: u64,
) -> u64 {
    let spec = RecvSpec {
        from,
        gate,
        tgt_va,
        tgt_capacity,
        recv_base,
        recv_count,
    };

    // Цикл ожидания: fast path (очередь) → регистрация → сон →
    // перепроверка. См. модульный комментарий про lost-wakeup.
    loop {
        // task_manager-лок держится на весь шаг: take_next и wake-
        // хелперы локов НЕ берут (deref guard'а).
        let tasks = kctl.task_manager().lock();
        match take_next::<A>(
            lctl,
            access,
            &tasks,
            current,
            umap,
            from,
            gate,
            tgt_va,
            tgt_capacity,
            recv_base,
            recv_count,
            A::RESUME_RESULT_WORD,
        ) {
            TakeOutcome::Delivered | TakeOutcome::DeliveredFault => {
                crate::task::stats::count_ipc_recv(lctl);
                return res::OK;
            }
            TakeOutcome::Empty => {}
        }

        // Дедлайн уже прошёл (вернулись сюда после пробуждения по
        // таймауту, доставки нет) — спать больше нельзя.
        if deadline > 0 && crate::task::stats::global_ticks() >= deadline {
            if let Some(route) = gate {
                crate::ipc::gate::gate_remove_task(&tasks, route, current);
            }
            transport::unregister_wait(&tasks, current);
            return res::E_TIMEOUT;
        }

        // Регистрация ожидания (Claimed = доставка в полёте —
        // перепроверка циклом; завершение увидит seq/быстрый путь).
        // Для гейта — встать в очередь ожидателей гейта (отправители
        // клеймят FIFO-получателей оттуда). Очередь БЕЗ ёмкости;
        // отказ = гейт уничтожен/переиспользован (маршрут невалиден,
        // например проснулись по смерти канала) — честный E_CAP_REVOKED
        // вместо прежнего молчаливого `let _ =`, оставлявшего получателя
        // ждать мёртвый канал.
        let snap = match transport::register_wait(&tasks, current, spec) {
            Ok(snap) => snap,
            Err(()) => continue,
        };
        if let Some(route) = gate {
            if crate::ipc::gate::gate_push(&tasks, route, current, GateQueueSide::Receivers, false)
                .is_err()
            {
                transport::unregister_wait(&tasks, current);
                return res::E_CAP_REVOKED;
            }
        }

        // Дедлайн (абсолютный тик): регистрация до сна.
        let object = endpoint::endpoint_wait_object(current);
        if deadline > 0 && crate::task::deadline::register(current, object, deadline).is_err() {
            // Реестр дедлайнов полон: регистрацию снять (спать без
            // будильщика нельзя).
            if let Some(route) = gate {
                crate::ipc::gate::gate_remove_task(&tasks, route, current);
            }
            transport::unregister_wait(&tasks, current);
            return res::E_SLAB;
        }

        // Сон под предикатом (lost-wakeup guard): доставка, случившаяся
        // до постановки в очередь, отменяет сон.
        let slept = lctl.scheduler_block_on_object_if(
            object,
            WaitModel::OneShot,
            transport::receiver_pred(&tasks, current, snap, from),
        );
        // ВАЖНО: сисколл-хендлер выполняется ДО фактического
        // переключения (порт переключает после возврата dispatch, кадр
        // сохраняется с RAX = возврату хендлера). После УСПЕШНОГО сна
        // хендлер ОБЯЗАН вернуть OK: пробуждение решает исход — доставка
        // (буфер заполнен клеймом отправителя) даёт OK; таймаут —
        // резолвер тика патчит E_TIMEOUT; смерть — патч E_NOT_FOUND.
        // Повторный block без возврата ставил бы задачу в очередь
        // дважды и никогда не отдавал CPU.
        if slept {
            return res::OK;
        }
        // Предикат сработал ДО сна (событие уже случилось) — решаем
        // немедленно; tasks-лок всё ещё захвачен (шаг цикла).
        {
            let delivered = {
                let tcb = tasks.get_tcb(current).expect("собственный TCB жив");
                let ipc = tcb.ipc().lock();
                ipc.seq != snap || matches!(ipc.recv, crate::task::ipc_state::IpcRecv::Claimed(_))
            };
            if delivered {
                // Кандидат в очереди — изымаем; очередь пуста, но seq
                // изменился — доставка прошла КЛЕЙМОМ (буфер заполнен).
                match take_next::<A>(
                    lctl,
                    access,
                    &tasks,
                    current,
                    umap,
                    from,
                    gate,
                    tgt_va,
                    tgt_capacity,
                    recv_base,
                    recv_count,
                    A::RESUME_RESULT_WORD,
                ) {
                    TakeOutcome::Delivered | TakeOutcome::DeliveredFault => {
                        crate::task::stats::count_ipc_recv(lctl);
                        return res::OK;
                    }
                    TakeOutcome::Empty => {
                        crate::task::stats::count_ipc_recv(lctl);
                        return res::OK;
                    }
                }
            }
            // Таймаут: слот дедлайна выстрелил без доставки (гонка «тик
            // в окне [регистрация .. сон]»).
            let fired = deadline > 0 && crate::task::deadline::cancel(current);
            if fired {
                if let Some(route) = gate {
                    crate::ipc::gate::gate_remove_task(&tasks, route, current);
                }
                transport::unregister_wait(&tasks, current);
                return res::E_TIMEOUT;
            }
        }
        // Клейм в полёте (Claimed, доставка завершается на другом ядре):
        // цикл повторит блок — предикат увидит завершение по seq.
    }
}

// ─── RPC: IPC_REPLY / IPC_CALL / IPC_REPLY_WAIT ─────────────────────────────

#[derive(SyscallArguments)]
pub struct SyscallIPCReply {
    /// ВА тела ответа (уходит клиенту, от которого получен последний
    /// запрос).
    msg_ptr: u64,
    msg_size: u64,
    /// ВА массива дескрипторов пересылки (например, передача результата
    /// клиенту) или 0.
    caps_ptr: u64,
    caps_count: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallIPCCall {
    /// Слот cspace с TaskTCB-капабилити сервера (право Send).
    slot: u64,
    /// ВА тела запроса; ОТВЕТ доставляется В ТОТ ЖЕ БУФЕР (seL4-стиль:
    /// сообщение-буфер двунаправлен).
    msg_ptr: u64,
    msg_size: u64,
    caps_ptr: u64,
    caps_count: u64,
    /// ВА дескриптора приёма ответа (4×u64: capacity, recv_base,
    /// recv_count, deadline). 0 запрещён — CALL обязан ждать ответ с
    /// явными параметрами буфера.
    desc_ptr: u64,
}

#[derive(SyscallArguments)]
pub struct SyscallIPCReplyWait {
    /// ВА тела ответа (клиенту последнего запроса).
    msg_ptr: u64,
    msg_size: u64,
    caps_ptr: u64,
    caps_count: u64,
    /// Цель следующего ожидания: IPC_WAIT_ANY или слот TaskTCB
    /// (closed wait) — семантика IPC_WAIT (IpcGate добавит свой вариант).
    wait_target: u64,
    /// Дедлайн ожидания следующего запроса (0 — вечно).
    wait_deadline: u64,
}

/// IPC_REPLY(12): ответ клиенту, от которого получен последний запрос.
/// Адресат — неявный reply_to из TCB сервера (классический L4 reply):
/// TaskTCB-капа на клиента не нужна, адресат заверен ядром; namespace-
/// право IPC_SEND остаётся обязательным.
impl<A: ArchImplementation + 'static> SyscallDomain for IPCSyscallDomain<A, SyscallIPCReply> {
    const SYSCALL_ID: usize = 12;
    type Args = SyscallIPCReply;
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
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::IPC_SEND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(sender_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let sender = unsafe { sender_ptr.as_ref() };
        let sender_umap = sender.userspace_map();

        let cap_items = match read_cap_items::<A>(sender_umap, args.caps_ptr, caps_count) {
            Ok(items) => items,
            Err(code) => return code,
        };
        let reply_to = {
            let tasks = self.0.task_manager().lock();
            match transport::take_reply_to(&tasks, current) {
                Some(t) => t,
                None => return res::E_NOT_FOUND,
            }
        };
        let Some(receiver_ptr) = access.get_task_tcb(reply_to) else {
            // Адресат исчез после приёма запроса.
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let receiver = unsafe { receiver_ptr.as_ref() };

        match send_to_task::<A>(
            self.0,
            lctl,
            &access,
            current,
            sender_umap,
            reply_to,
            receiver.userspace_map(),
            args.msg_ptr as usize,
            msg_size,
            &cap_items,
            0,
        ) {
            SendOutcome::Done(code) => code,
            SendOutcome::AwaitReply => res::OK,
        }
    }
}

/// Фаза ожидания ответа CALL (клиент уже зарегистрировал Receiving —
/// `snap` её seq-снимок). Успешный сон → Done(OK): исход решит будильщик
/// (ответ = клейм+finish → кадр OK; отказ сервера → патч RAX; таймаут →
/// резолвер). Предикат сработал до сна → немедленный разбор исхода.
#[allow(clippy::too_many_arguments)]
fn await_reply_phase<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    current: u64,
    snap: u64,
    from: Option<u64>,
    deadline: u64,
) -> SendOutcome {
    let object = endpoint::endpoint_wait_object(current);
    if deadline > 0
        && crate::task::deadline::register(current, object, deadline).is_err()
    {
        let tasks = kctl.task_manager().lock();
        let _ = transport::receiver_timeout_pending(&tasks, current);
        return SendOutcome::Done(res::E_SLAB);
    }
    let slept = {
        let tasks = kctl.task_manager().lock();
        lctl.scheduler_block_on_object_if(
            object,
            WaitModel::OneShot,
            transport::call_pred(&tasks, current, snap, from),
        )
    };
    if slept {
        return SendOutcome::Done(res::OK);
    }
    // Предикат сработал ДО сна — событие уже случилось.
    loop {
        let tasks = kctl.task_manager().lock();
        if let Some(code) = transport::take_send_result(&tasks, current) {
            let _ = transport::receiver_timeout_pending(&tasks, current);
            return SendOutcome::Done(code);
        }
        let (seq_changed, claimed) = {
            let tcb = tasks.get_tcb(current).expect("собственный TCB жив");
            let ipc = tcb.ipc().lock();
            (
                ipc.seq != snap,
                matches!(ipc.recv, crate::task::ipc_state::IpcRecv::Claimed(_)),
            )
        };
        if !claimed && seq_changed {
            crate::task::stats::count_ipc_recv(lctl);
            return SendOutcome::Done(res::OK);
        }
        let fired = deadline > 0 && crate::task::deadline::cancel(current);
        if fired {
            let _ = transport::receiver_timeout_pending(&tasks, current);
            return SendOutcome::Done(res::E_TIMEOUT);
        }
        drop(tasks);
        // Claimed в полёте — короткий ре-блок; предикат увидит
        // завершение по seq и не уснёт.
        {
            let tasks = kctl.task_manager().lock();
            lctl.scheduler_block_on_object_if(
                object,
                WaitModel::OneShot,
                transport::call_pred(&tasks, current, snap, from),
            );
        }
    }
}

/// CALL через гейт: клейм FIFO-ожидателя гейта (peek → claim → detach,
/// как send_to_gate) — при неудаче клейма отправителю ошибка; никого —
/// очередь гейта БЕЗ сна (клиент далее ждёт ответ в await_reply_phase).
/// Отказ push (мёртвый гейт) — E_CAP_REVOKED: call_pred увидит
/// send_rax и хендлер раскрутит регистрацию ожидания ответа.
#[allow(clippy::too_many_arguments)]
fn call_via_gate<A: ArchImplementation>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut crate::lctl::LocalKernelCTL<A::Umap>,
    access: &crate::access::AccessManager<A::Umap>,
    current: u64,
    sender_umap: &A::Umap,
    route: GateRoute,
    msg_va: usize,
    msg_len: usize,
    caps: &[CapItem],
) -> Result<(), u64> {
    let caps_count = caps.len();
    let need = endpoint::delivery_bytes(caps_count, msg_len);
    loop {
        let candidate = match crate::ipc::gate::gate_peek_receiver(route) {
            Some(c) => c,
            None => break,
        };
        let claim = {
            let tasks = kctl.task_manager().lock();
            transport::claim_receiver(&tasks, candidate, current, Some(route), need, caps_count)
        };
        match claim {
            transport::ClaimResult::NotWaiting => {
                let tasks = kctl.task_manager().lock();
                crate::ipc::gate::gate_detach_receiver(&tasks, route, candidate);
                continue;
            }
            // Голова остаётся в очереди (detach после клейма — см.
            // send_to_gate); отправителю — ошибка.
            transport::ClaimResult::TooSmall | transport::ClaimResult::CapsRejected => {
                return Err(res::E_INVALID_ARG);
            }
            transport::ClaimResult::Claimed(rspec) => {
                {
                    let tasks = kctl.task_manager().lock();
                    crate::ipc::gate::gate_detach_receiver(&tasks, route, candidate);
                }
                let receiver_umap = {
                    let tasks = kctl.task_manager().lock();
                    match tasks.get_tcb(candidate) {
                        Some(tcb) => unsafe {
                            tcb.gtcb_owner().as_ref().userspace_map()
                        },
                        None => {
                            transport::restore_receiver(&tasks, candidate, rspec);
                            continue;
                        }
                    }
                };
                deliver_claimed::<A>(
                    kctl, lctl, access, current, sender_umap, candidate,
                    receiver_umap, rspec, msg_va, msg_len, caps,
                )?;
                return Ok(());
            }
        }
    }
    // Никого не ждёт: очередь гейта (без сна — клиент ждёт ОТВЕТ).
    let spec = SendSpec {
        to: 0,
        gate: Some(route),
        msg_va,
        msg_len,
        caps: {
            let mut c = [CapItem { src_slot: 0, dst_slot: 0, rights: 0 }; MAX_CAPS];
            for (d, s) in c.iter_mut().zip(caps.iter()) {
                *d = *s;
            }
            c
        },
        caps_count,
        is_fault: false,
    };
    {
        let tasks = kctl.task_manager().lock();
        if let Some(tcb) = tasks.get_tcb(current) {
            let mut ipc = tcb.ipc().lock();
            ipc.send = Some(spec);
            ipc.send_rax = None;
        }
        if crate::ipc::gate::gate_push(&tasks, route, current, GateQueueSide::Senders, false)
            .is_err()
        {
            if let Some(tcb) = tasks.get_tcb(current) {
                tcb.ipc().lock().send = None;
            }
            return Err(res::E_CAP_REVOKED);
        }
    }
    Ok(())
}

/// IPC_CALL(13): атомарные SEND+WAIT с неявным reply-путём (классический
/// L4 call; seL4 call). Ответ сервера доставляется В БУФЕР ЗАПРОСА
/// (двунаправленный буфер); сервер отвечает IPC_REPLY/IPC_REPLY_WAIT
/// без TaskTCB-капы клиента. Параметры приёма ответа — через
/// дескриптор в памяти вызывающего (лимит 6 арг-регистров ABI):
/// desc = {capacity u64, recv_base u64, recv_count u64, deadline u64}.
/// Цель — TaskTCB-капа сервера ИЛИ IpcGate (гейт-маршрут).
impl<A: ArchImplementation + 'static> SyscallDomain for IPCSyscallDomain<A, SyscallIPCCall> {
    const SYSCALL_ID: usize = 13;
    type Args = SyscallIPCCall;
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
        let tgt_va = args.msg_ptr as usize;
        if msg_size > MAX_MSG || caps_count > MAX_CAPS {
            return res::E_INVALID_ARG;
        }
        // Дескриптор приёма ответа (4×u64) — читается из userspace.
        if args.desc_ptr == 0 || !args.desc_ptr.is_multiple_of(8) {
            return res::E_INVALID_ARG;
        }
        let access = self.0.permission_backend.lock();
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::IPC_SEND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(sender_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let sender = unsafe { sender_ptr.as_ref() };
        let sender_umap = sender.userspace_map();

        let rd = |k: usize| -> Option<u64> {
            endpoint::read_user_u64(sender_umap, args.desc_ptr as usize + k * 8)
        };
        let (Some(capacity), Some(recv_base), Some(recv_count), Some(deadline)) =
            (rd(0), rd(1), rd(2), rd(3))
        else {
            return res::E_INVALID_ARG;
        };
        let capacity = capacity as usize;
        let recv_count = recv_count as usize;
        if capacity < HEADER_WORDS * 8
            || !tgt_va.is_multiple_of(8)
            || recv_count > MAX_CAPS
            || recv_base.checked_add(recv_count as u64).is_none()
        {
            return res::E_INVALID_ARG;
        }
        // Буфер запроса обязан быть R/W (в него же придёт ответ) и
        // вмещать хотя бы заголовок доставки.
        if !endpoint::check_user_region(
            sender_umap,
            tgt_va,
            capacity.min(msg_size + (3 + MAX_CAPS) * 8).max(HEADER_WORDS * 8),
        ) {
            return res::E_INVALID_ARG;
        }

        let cap_items = match read_cap_items::<A>(sender_umap, args.caps_ptr, caps_count) {
            Ok(items) => items,
            Err(code) => return code,
        };

        // Регистрация ожидания ответа ДО отправки: буфер приёма готов,
        // ответ сервера доставляется напрямую (клейм), не через очередь.
        // Для гейт-цели from=None (сервер клиенту не известен); для
        // прямой — from=Some(сервер).
        // (target_server, target_gate): гейт-маршрут — Some(маршрут);
        // прямой — Some(server). from-фильтр ответа = СЕРВЕР (не гейт!):
        // reply_to устанавливается при доставке запроса.
        let (target_server, target_gate) = {
            let tasks = self.0.task_manager().lock();
            match resolve_send_target::<A>(&tasks, sender, args.slot) {
                Ok(IpcTarget::Gate(route)) => (None, Some(route)),
                Ok(IpcTarget::Task(id, _)) => {
                    if id == current {
                        return res::E_INVALID_ARG;
                    }
                    (Some(id), None)
                }
                Err(code) => return code,
            }
        };
        let recv_spec = RecvSpec {
            from: target_server,
            gate: None,
            tgt_va,
            tgt_capacity: capacity,
            recv_base,
            recv_count,
        };
        let snap = {
            let tasks = self.0.task_manager().lock();
            match transport::register_wait(&tasks, current, recv_spec) {
                Ok(snap) => snap,
                Err(()) => return res::E_INTERNAL, // собственный TCB в Claimed?
            }
        };

        // ── Фаза отправки (без сна клиента как отправителя) ──
        let send_result = match (target_server, target_gate) {
            // Гейт-маршрут.
            (None, Some(route)) => call_via_gate::<A>(
                self.0,
                lctl,
                &access,
                current,
                sender_umap,
                route,
                tgt_va,
                msg_size,
                &cap_items,
            ),
            // Прямая отправка серверу.
            (Some(server), None) => {
                let claim = {
                    let tasks = self.0.task_manager().lock();
                    transport::claim_receiver(
                        &tasks,
                        server,
                        current,
                        None,
                        endpoint::delivery_bytes(caps_count, msg_size),
                        caps_count,
                    )
                };
                match claim {
                    transport::ClaimResult::Claimed(rspec) => {
                        let server_ptr = access.get_task_tcb(server).expect("жив под локом");
                        let server_umap =
                            unsafe { server_ptr.as_ref().userspace_map() };
                        deliver_claimed::<A>(
                            self.0,
                            lctl,
                            &access,
                            current,
                            sender_umap,
                            server,
                            server_umap,
                            rspec,
                            tgt_va,
                            msg_size,
                            &cap_items,
                        )
                    }
                    transport::ClaimResult::TooSmall
                    | transport::ClaimResult::CapsRejected => Err(res::E_INVALID_ARG),
                    transport::ClaimResult::NotWaiting => {
                        // В очередь сервера (БЕЗ сна — клиент ждёт ответ).
                        let spec = SendSpec {
                            to: server,
                            gate: None,
                            msg_va: tgt_va,
                            msg_len: msg_size,
                            caps: {
                                let mut c =
                                    [CapItem { src_slot: 0, dst_slot: 0, rights: 0 }; MAX_CAPS];
                                for (d, s) in c.iter_mut().zip(cap_items.iter()) {
                                    *d = *s;
                                }
                                c
                            },
                            caps_count,
                            is_fault: false,
                        };
                        let tasks = self.0.task_manager().lock();
                        if let Some(tcb) = tasks.get_tcb(current) {
                            let mut ipc = tcb.ipc().lock();
                            ipc.send = Some(spec);
                            ipc.send_rax = None;
                        }
                        match transport::enqueue_sender(&tasks, server, current, false) {
                            Ok(()) => Ok(()),
                            Err(()) => {
                                if let Some(tcb) = tasks.get_tcb(current) {
                                    tcb.ipc().lock().send = None;
                                }
                                Err(res::E_SLAB)
                            }
                        }
                    }
                }
            }
            _ => return res::E_INTERNAL,
        };
        if let Err(code) = send_result {
            // Откат регистрации (ответ не придёт) — отправка не состоялась.
            let tasks = self.0.task_manager().lock();
            let _ = transport::receiver_timeout_pending(&tasks, current);
            return code;
        }

        // ── Фаза ожидания ответа ──
        match await_reply_phase::<A>(
            self.0,
            lctl,
            current,
            snap,
            target_server,
            deadline,
        ) {
            SendOutcome::Done(code) => code,
            SendOutcome::AwaitReply => res::OK,
        }
    }
}

/// IPC_REPLY_WAIT(15): reply + следующий wait одним сисколлом (классика
/// L4 «reply and wait» — основной цикл RPC-сервера). Ответ доставляется
/// как в IPC_REPLY; при успехе — wait (open/closed; гейт-цель добавит
/// IpcGate-вариант). Ошибка reply прерывает операцию (явная семантика).
impl<A: ArchImplementation + 'static> SyscallDomain for IPCSyscallDomain<A, SyscallIPCReplyWait> {
    const SYSCALL_ID: usize = 15;
    type Args = SyscallIPCReplyWait;
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
        if access
            .check_task_rights(current, crate::access::namespace::NamespaceRights::IPC_SEND)
            .is_err()
        {
            return res::E_RIGHTS_DENIED;
        }
        let Some(sender_ptr) = access.get_task_tcb(current) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let sender = unsafe { sender_ptr.as_ref() };
        let sender_umap = sender.userspace_map();

        // ── Фаза 1: reply ──
        let cap_items = match read_cap_items::<A>(sender_umap, args.caps_ptr, caps_count) {
            Ok(items) => items,
            Err(code) => return code,
        };
        let reply_to = {
            let tasks = self.0.task_manager().lock();
            match transport::take_reply_to(&tasks, current) {
                Some(t) => t,
                None => return res::E_NOT_FOUND,
            }
        };
        let Some(receiver_ptr) = access.get_task_tcb(reply_to) else {
            return res::E_NOT_FOUND;
        };
        // SAFETY: под permission_backend-локом.
        let receiver = unsafe { receiver_ptr.as_ref() };

        let reply_code = match send_to_task::<A>(
            self.0,
            lctl,
            &access,
            current,
            sender_umap,
            reply_to,
            receiver.userspace_map(),
            args.msg_ptr as usize,
            msg_size,
            &cap_items,
            0,
        ) {
            SendOutcome::Done(code) => code,
            SendOutcome::AwaitReply => res::OK,
        };
        if reply_code != res::OK {
            return reply_code;
        }

        // ── Фаза 2: wait на следующий запрос ──
        let tgt_va = args.msg_ptr as usize; // сервер переиспользует буфер
        if !tgt_va.is_multiple_of(8) {
            return res::E_INVALID_ARG;
        }
        let recv_count = 0usize; // окно задаётся СЛЕДУЮЩИМ wait'ом явно:
        let _ = recv_count;      // REPLY_WAIT принимает без окна — caps-
        // сообщения отклоняются отправителям (совместимо с RECV_NONE).
        // Ёмкость буфера: та же, что у ответа — сервер знает размер
        // своего буфера только через аргумент msg_size; для приёма
        // используем минимально достаточный резерв заголовка+тела
        // лимита транспорта (ядро всё равно отклонит негабарит).
        let capacity = (HEADER_WORDS + MAX_CAPS) * 8 + MAX_MSG;

        let from = if args.wait_target == endpoint::IPC_WAIT_ANY {
            None
        } else {
            let tasks = self.0.task_manager().lock();
            match resolve_task_slot::<A>(&tasks, sender, args.wait_target) {
                Ok((sender_task_cap, _)) => Some(sender_task_cap),
                Err(code) => return code,
            }
        };

        wait_loop::<A>(
            self.0,
            lctl,
            &access,
            current,
            sender_umap,
            from,
            None,
            tgt_va,
            capacity,
            0,
            0,
            args.wait_deadline,
        )
    }
}

#[cfg(test)]
mod tests {
    /// Параметры валидации IPC-аргументов (чистые функции — без ядра).
    use super::*;

    #[test]
    fn delivery_bytes_matches_wire_format() {
        // Заголовок 3 слова + по слову на cap + тело.
        assert_eq!(endpoint::delivery_bytes(0, 0), 24);
        assert_eq!(endpoint::delivery_bytes(1, 16), 48);
        assert_eq!(endpoint::delivery_bytes(MAX_CAPS, MAX_MSG), (3 + MAX_CAPS) * 8 + MAX_MSG);
    }

    #[test]
    fn queue_capacity_is_reasonable() {
        // Очередь на задачу — замена глобального пула ящиков.
        assert!(crate::task::ipc_state::MAX_IPC_QUEUE >= 8);
        assert!(MAX_CAPS <= 8);
    }
}
