//! Оркестрация rendezvous поверх task::ipc_state (логика доставки).
//!
//! СОСТОЯНИЕ ЖИВЁТ В TCB (классический L4): заблокированный отправитель
//! держит сообщение в СВОЁМ буфере ([`SendSpec`]), получатель —
//! спецификацию приёма ([`RecvSpec`]); очередь отправителей — в TCB
//! ПОЛУЧАТЕЛЯ. Здесь — атомарные переходы состояний и учёт очередей;
//! копирование userspace и пересылка capability — у вызывающего
//! (syscall::ipc / ipc::fault), под permission_backend-локом.
//!
//! ПРЕДИКАТЫ СНА (lost-wakeup guard): засыпание — через lctl::
//! scheduler_block_on_object_if, предикат проверяется ПОД WAKE_LOCK.
//!   - отправитель: `send == None` (изъято доставкой/ошибкой) — тогда
//!     исход сисколла берётся из `send_rax`;
//!   - получатель: `seq != снимок || recv == Claimed || очередь
//!     содержит кандидата под фильтр || (гейт с отправителями)`.
//!
//! ПРАВИЛА БЛОКИРОВОК: всё в этом модуле зовётся под ЗАХВАЧЕННЫМ
//! task_manager-локом (жизнеспособность TCB); ipc-локи/гейт-локи —
//! листовые. WAKE_LOCK поверх ipc/гейт-локов берёт ТОЛЬКО предикат
//! (см. task::ipc_state — порядок WAKE_LOCK → ipc → gate не обращён
//! нигде).

use heapless::Vec as HVec;

use crate::task::ipc_state::{GateRoute, IpcRecv, RecvSpec, SendSpec};
use crate::task::tcb::TCB;
use crate::task::TaskManager;
use crate::traits::memory::MemoryInterfaceUserspace;

/// Результат захвата ждущего получателя.
pub enum ClaimResult {
    /// Получатель ждёт и захвачен (Receiving → Claimed): spec — его
    /// параметры приёма. Возврат в Receiving — [`restore_receiver`],
    /// завершение доставки — [`finish_delivery`].
    Claimed(RecvSpec),
    /// Никто не ждёт (или фильтры не совпали) — медленный путь.
    NotWaiting,
    /// Буфер получателя мал для сообщения.
    TooSmall,
    /// Приёмное окно не вмещает capability сообщения.
    CapsRejected,
}

/// Захват ждущего получателя (send, быстрый путь). `gate` — Some(маршрут)
/// для отправки через гейт (получатель обязан ждать ТОТ ЖЕ гейт —
/// сравнение маршрутов включает поколение: ожидатель протухшего гейта
/// не подходит), None для прямой отправки задаче (получатель с
/// гейт-ожиданием не подходит).
pub fn claim_receiver<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    sender: u64,
    gate: Option<GateRoute>,
    need_bytes: usize,
    caps_count: usize,
) -> ClaimResult {
    let Some(tcb) = tasks.get_tcb(receiver) else {
        return ClaimResult::NotWaiting;
    };
    let mut ipc = tcb.ipc().lock();
    let IpcRecv::Receiving(spec) = ipc.recv else {
        return ClaimResult::NotWaiting;
    };
    if spec.gate != gate {
        return ClaimResult::NotWaiting;
    }
    // Closed-wait фильтр: ждёт строго этого отправителя?
    if let Some(only_from) = spec.from
        && only_from != sender
    {
        return ClaimResult::NotWaiting;
    }
    if need_bytes > spec.tgt_capacity {
        return ClaimResult::TooSmall;
    }
    // Приёмное окно обязано вмещать все дескрипторы: приём capability
    // без согласия получателя запрещён (слоты выбирает получатель).
    if caps_count > spec.recv_count {
        return ClaimResult::CapsRejected;
    }
    ipc.recv = IpcRecv::Claimed(spec);
    ipc.seq = ipc.seq.wrapping_add(1);
    ClaimResult::Claimed(spec)
}

/// Откат захвата (неудачная доставка): получатель продолжает ждать.
pub fn restore_receiver<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    spec: RecvSpec,
) {
    if let Some(tcb) = tasks.get_tcb(receiver) {
        let mut ipc = tcb.ipc().lock();
        if matches!(ipc.recv, IpcRecv::Claimed(_)) {
            ipc.recv = IpcRecv::Receiving(spec);
        }
    }
}

/// Завершение доставки: получатель выходит из ожидания с сообщением.
/// `reply_to` ставится только для НЕ-фолтовых отправителей (фолт-ответ —
/// FAULT_REPLY, не IPC_REPLY).
pub fn finish_delivery<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    sender: u64,
    is_fault: bool,
) {
    if let Some(tcb) = tasks.get_tcb(receiver) {
        let mut ipc = tcb.ipc().lock();
        ipc.recv = IpcRecv::Idle;
        ipc.seq = ipc.seq.wrapping_add(1);
        if !is_fault {
            ipc.reply_to = Some(sender);
        }
    }
}

/// Ставит отправителя в очередь получателя (send, медленный путь).
/// НЕ будит получателя: очередь накапливается, только пока получатель НЕ
/// зарегистрирован (зарегистрированного отправитель захватывает клеймом),
/// поэтому будить некого — кандидат заберёт следующий IPC_WAIT.
pub fn enqueue_sender<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    sender: u64,
    is_fault: bool,
) -> Result<(), ()> {
    let Some(tcb) = tasks.get_tcb(receiver) else {
        return Err(());
    };
    let mut ipc = tcb.ipc().lock();
    // Пока получатель спит в Receiving, очередь пополняться не должна
    // (отправитель обязан был захватить его) — защитный инвариант.
    if matches!(ipc.recv, IpcRecv::Receiving(_) | IpcRecv::Claimed(_)) {
        return Err(());
    }
    ipc.queue
        .push((sender, is_fault))
        .map_err(|_| ())?;
    ipc.seq = ipc.seq.wrapping_add(1);
    Ok(())
}

/// Изымает параметры заблокированного отправителя (кандидат выбран
/// получателем). После изъятия отправитель больше не «в полёте»:
/// исход доставки пишется в `send_rax` (ошибка) или считается
/// успешным, а сам отправитель будится по объекту
/// endpoint::sender_wait_object(его id).
pub fn take_send_state<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
) -> Option<SendSpec> {
    let tcb = tasks.get_tcb(sender)?;
    let mut ipc = tcb.ipc().lock();
    ipc.send.take()
}

/// Ошибка доставки изъятому отправителю: код в его кадр (TCB::
/// patch_resume_result ДО пробуждения — механизм порта) + отметка
/// `send_rax` для гонки «не успел уснуть» (см. блокирующие хендлеры).
pub fn fail_sender<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
    code: u64,
) {
    if let Some(tcb) = tasks.get_tcb(sender) {
        let mut ipc = tcb.ipc().lock();
        ipc.send_rax = Some(code);
    }
}

/// Снимает отметку результата отправителя (хендлер SEND читает после
/// неудавшегося сна: Some(code) — ошибка доставки, None — успех).
pub fn take_send_result<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
) -> Option<u64> {
    let tcb = tasks.get_tcb(sender)?;
    let mut ipc = tcb.ipc().lock();
    ipc.send_rax.take()
}

/// Заблокирован ли отправитель ещё (не изъят доставкой).
pub fn sender_still_pending<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
) -> bool {
    tasks
        .get_tcb(sender)
        .map(|tcb| tcb.ipc().lock().send.is_some())
        .unwrap_or(false)
}

/// Извлекает ПЕРВОГО подходящего кандидата из очереди получателя (FIFO;
/// closed-wait фильтр `from` — как take_pending прежнего реестра).
/// Кандидат УДАЛЯЕТСЯ из очереди; данные сообщения читает вызывающий из
/// TCB/буфера отправителя (или фолт-слота для is_fault).
pub fn pop_next_candidate<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    from: Option<u64>,
) -> Option<(u64, bool)> {
    let tcb = tasks.get_tcb(receiver)?;
    let mut ipc = tcb.ipc().lock();
    let pos = ipc.queue.iter().position(|(id, _)| match from {
        None => true,
        Some(only) => *id == only,
    })?;
    Some(ipc.queue.remove(pos))
}

/// Регистрация ожидания получателя (wait, медленный путь). Повторная
/// регистрация той же задачи ЗАМЕНЯЕТ спецификацию. `Err(())` —
/// получатель уже захвачен доставляющим (Claimed): вызывающий
/// перепроверяет доставку (seq) и повторяет.
pub fn register_wait<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    spec: RecvSpec,
) -> Result<u64, ()> {
    let Some(tcb) = tasks.get_tcb(receiver) else {
        return Err(());
    };
    let mut ipc = tcb.ipc().lock();
    match ipc.recv {
        IpcRecv::Claimed(_) => Err(()),
        _ => {
            ipc.recv = IpcRecv::Receiving(spec);
            Ok(ipc.seq)
        }
    }
}

/// Снимает регистрацию ожидания (таймаут/отказ): Receiving → Idle.
/// Claimed не трогает — там доставка в полёте, решает доставляющий.
pub fn unregister_wait<Umap: MemoryInterfaceUserspace>(tasks: &TaskManager<Umap>, receiver: u64) {
    if let Some(tcb) = tasks.get_tcb(receiver) {
        let mut ipc = tcb.ipc().lock();
        if matches!(ipc.recv, IpcRecv::Receiving(_)) {
            ipc.recv = IpcRecv::Idle;
        }
    }
}

/// Самоочистка отправителя при ТАЙМАУТЕ SEND: убрать себя из очереди
/// получателя/гейта и снять SendSpec. Возврат true — запись найдена и
/// снята (сообщение не было изъято доставкой).
pub fn cancel_send<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
    queue_owner: u64,
    gate: Option<GateRoute>,
) -> bool {
    // 1. Своя SendSpec.
    if let Some(tcb) = tasks.get_tcb(sender) {
        let mut ipc = tcb.ipc().lock();
        ipc.send = None;
        ipc.send_rax = Some(crate::traits::syscall::syscall_result::E_TIMEOUT);
    }
    // 2. Запись в очереди получателя (прямая отправка).
    if gate.is_none()
        && let Some(tcb) = tasks.get_tcb(queue_owner)
    {
        let mut ipc = tcb.ipc().lock();
        ipc.queue.retain(|(id, _)| *id != sender);
    }
    // 3. Гейт-очередь (gateway-маршрут) — O(1) по собственным ссылкам.
    if let Some(route) = gate {
        crate::ipc::gate::gate_remove_task(tasks, route, sender);
    }
    true
}

// ─── Резолюция таймаутов (тик дедлайна; см. deadline::set_timeout_resolver)

/// Таймаут SEND: отправитель ещё не доставлен? Снимает SendSpec + запись
/// из очереди владельца/гейта (самочистка — хендлер НЕ перезапускается
/// после сна) и возвращает параметры маршрута для чистки. None —
/// доставка уже состоялась/в полёте (таймаут проигнорировать).
pub fn sender_timeout_pending<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
) -> Option<(u64, Option<GateRoute>)> {
    let tcb = tasks.get_tcb(sender)?;
    let spec = {
        let mut ipc = tcb.ipc().lock();
        let spec = ipc.send?;
        ipc.send = None;
        ipc.send_rax = Some(crate::traits::syscall::syscall_result::E_TIMEOUT);
        spec
    };
    // Самочистка очередей (гейт — O(1) по собственным ссылкам).
    if spec.gate.is_none()
        && let Some(owner) = tasks.get_tcb(spec.to)
    {
        let mut ipc = owner.ipc().lock();
        ipc.queue.retain(|(id, _)| *id != sender);
    }
    if let Some(route) = spec.gate {
        crate::ipc::gate::gate_remove_task(tasks, route, sender);
    }
    Some((spec.to, spec.gate))
}

/// Таймаут WAIT: получатель всё ещё ждёт (не доставлено/не клеймлено)?
/// Снимает регистрацию (Receiving → Idle) и для гейт-ожиданий — запись
/// из очереди гейта; сообщение, вставшее в очередь позже, заберёт
/// следующий WAIT. true — таймаут валиден (патчить кадр).
pub fn receiver_timeout_pending<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
) -> bool {
    let Some(tcb) = tasks.get_tcb(receiver) else {
        return false;
    };
    let gate = {
        let mut ipc = tcb.ipc().lock();
        match ipc.recv {
            IpcRecv::Receiving(spec) => {
                ipc.recv = IpcRecv::Idle;
                spec.gate
            }
            _ => return false,
        }
    };
    if let Some(route) = gate {
        // O(1) по собственным ссылкам; мёртвый гейт — дренаж уже всё снял.
        crate::ipc::gate::gate_remove_task(tasks, route, receiver);
    }
    true
}

/// Изымает неявный адресат ответа (RPC): IPC_REPLY/IPC_REPLY_WAIT
/// адресуются им, TaskTCB-капабилити на клиента не требуется (адресат
/// заверен ядром — он был реальным отправителем последнего принятого
/// НЕ-фолтового сообщения).
pub fn take_reply_to<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    me: u64,
) -> Option<u64> {
    let tcb = tasks.get_tcb(me)?;
    let mut ipc = tcb.ipc().lock();
    ipc.reply_to.take()
}

/// Возвращает кандидата В ГОЛОВУ очереди получателя (откат изъятия:
/// фолт-сообщение не поместилось в буфер — подойдёт следующий wait).
pub fn requeue_candidate<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    sender: u64,
    is_fault: bool,
) {
    if let Some(tcb) = tasks.get_tcb(receiver) {
        let mut ipc = tcb.ipc().lock();
        if !ipc.queue.contains(&(sender, is_fault)) {
            let _ = ipc.queue.insert(0, (sender, is_fault));
        }
    }
}

/// Предикат сна ВНУТРИ CALL (под WAKE_LOCK): событие ответа/ошибки —
/// как receiver_pred ПЛЮС отметка ошибки доставки нашего сообщения
/// (send_rax): сервер мог отклонить запрос (негабарит/пересылка caps) —
/// клиент обязан проснуться с этим кодом, а не ждать ответ вечно.
pub fn call_pred<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    me: u64,
    seq_snapshot: u64,
    from: Option<u64>,
) -> impl FnOnce() -> bool + '_ {
    move || {
        let Some(tcb) = tasks.get_tcb(me) else {
            return true;
        };
        let ipc = tcb.ipc().lock();
        if ipc.send_rax.is_some()
            || ipc.seq != seq_snapshot
            || matches!(ipc.recv, IpcRecv::Claimed(_))
        {
            return true;
        }
        if let IpcRecv::Receiving(spec) = ipc.recv
            && spec.gate.is_none()
            && ipc.queue.iter().any(|(id, _)| match from {
                None => true,
                Some(only) => *id == only,
            })
        {
            return true;
        }
        false
    }
}

/// Предикат сна ОТПРАВИТЕЛЯ (под WAKE_LOCK): «моё сообщение уже изъято».
pub fn sender_pred<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    sender: u64,
) -> impl FnOnce() -> bool + '_ {
    move || {
        tasks
            .get_tcb(sender)
            .map(|tcb: &TCB<Umap>| tcb.ipc().lock().send.is_none())
            .unwrap_or(true)
    }
}

/// Предикат сна ПОЛУЧАТЕЛЯ (под WAKE_LOCK): событие уже случилось —
/// захват (Claimed), запись в очередь под фильтр, или изменение seq
/// (завершение доставки после захвата).
pub fn receiver_pred<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    receiver: u64,
    seq_snapshot: u64,
    from: Option<u64>,
) -> impl FnOnce() -> bool + '_ {
    move || {
        let Some(tcb) = tasks.get_tcb(receiver) else {
            return true;
        };
        let ipc = tcb.ipc().lock();
        if ipc.seq != seq_snapshot || matches!(ipc.recv, IpcRecv::Claimed(_)) {
            return true;
        }
        if let IpcRecv::Receiving(spec) = ipc.recv {
            // Очередь (прямой эндпоинт): кандидат под фильтр?
            if spec.gate.is_none()
                && ipc.queue.iter().any(|(id, _)| match from {
                    None => true,
                    Some(only) => *id == only,
                })
            {
                return true;
            }
            // Гейт-ожидание: у гейта появились отправители — ИЛИ гейт
            // уже мёртв/переиспользован (маршрут невалиден). Предикат
            // обязан разбудить и на смерть канала: иначе ожидатель спал
            // бы на мёртвом гейте до дедлайна/вечно (wake от destroy
            // терялся бы в гонке «не успел уснуть»); проснувшийся wait
            // увидит невалидный маршрут и выйдет с E_CAP_REVOKED.
            if let Some(route) = spec.gate {
                let (valid, has_senders) = crate::ipc::gate::gate_status(route);
                if !valid || has_senders {
                    return true;
                }
            }
        }
        false
    }
}

/// Результат очистки умершей задачи (для syscall_task::destroy):
/// (task_cap_id спящего отправителя, его wait-объект) — вызывающий
/// патчит RAX (E_NOT_FOUND) и будит.
pub type Orphans = HVec<(u64, usize), 64>;

/// Чистит IPC-состояние ВСЕХ задач от следов умершей: очередь записей
/// `(мёртвый, _)`, отправителей, нацеленных на мёртвого (`send.to ==
/// dead`), и неявных ответов мёртвому (`reply_to == dead`).
///
/// Вызывать ПОСЛЕ удаления TCB умершей (destroy_task) под захваченным
/// task_manager-локом: попутно не будим — вызывающий патчит кадры и
/// дренит объекты (тот же контракт, что у прежнего endpoint::
/// on_task_destroyed).
pub fn on_task_destroyed<Umap: MemoryInterfaceUserspace>(
    tasks: &TaskManager<Umap>,
    dead: u64,
) -> Orphans {
    let mut orphans: Orphans = HVec::new();
    tasks.for_each_tcb(|id, tcb| {
        let mut ipc = tcb.ipc().lock();
        // Отправитель, нацеленный на умершего (в т.ч. стоящий в его
        // очереди — сама очередь умерла вместе с его TCB): ошибка
        // доставки, будим по его собственному объекту.
        if let Some(spec) = ipc.send
            && spec.to == dead
        {
            ipc.send = None;
            ipc.send_rax = Some(crate::traits::syscall::syscall_result::E_NOT_FOUND);
            let _ = orphans.push((id, crate::ipc::endpoint::sender_wait_object(id)));
        }
        // Мёртвый как кандидат в чужой очереди (защитно: стоящий в
        // очереди спит и не может умереть, но путь destroy чужих задач
        // асимметричен — чистим безусловно).
        if !ipc.queue.is_empty() {
            ipc.queue.retain(|(id, _)| *id != dead);
        }
        // Неявный ответ умершему (RPC): адресат исчез.
        if ipc.reply_to == Some(dead) {
            ipc.reply_to = None;
        }
    });
    orphans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AccessManager;
    use crate::ipc::endpoint::MAX_CAPS;
    use crate::ipc::endpoint::CapItem;
    use crate::task::ipc_state::{IpcRecv, IpcChan, RecvSpec, SendSpec};
    use crate::task::tcb::GTcb;
    use crate::traits::memory::PAGE_SIZE;
    use crate::traits::syscall::syscall_result as res;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // ── Тестовая инфраструктура (паттерн idalloc::tests) ────────────────

    struct TestFrames(AtomicUsize);
    static FRAMES: TestFrames = TestFrames(AtomicUsize::new(1));

    impl crate::traits::memory::FrameAllocator for TestFrames {
        fn allocate_pages(&self, count: usize) -> Option<crate::traits::memory::MemoryPTR> {
            let first = self.0.fetch_add(count, Ordering::SeqCst);
            crate::traits::memory::MemoryPTR::new(first * PAGE_SIZE, count)
        }
        fn deallocate_pages(&self, _ptr: crate::traits::memory::MemoryPTR) {}
    }

    static std_once: std::sync::Once = std::sync::Once::new();
    fn ensure_slab() {
        std_once.call_once(|| {
            let mem = unsafe {
                let layout = std::alloc::Layout::from_size_align(16 * 1024 * 1024, PAGE_SIZE)
                    .expect("layout");
                let ptr = std::alloc::alloc_zeroed(layout);
                assert!(!ptr.is_null(), "oom");
                core::slice::from_raw_parts_mut(ptr, 16 * 1024 * 1024 / PAGE_SIZE)
            };
            crate::traits::memory::set_hhdm_offset(mem.as_ptr() as usize);
            crate::traits::memory::init_hooks::init_allocator(&FRAMES);
        });
    }

    /// Фиктивный умап: VA = phys + DELTA, отображено [0, limit).
    #[derive(Clone, Copy)]
    struct FakeUmap {
        delta: usize,
    }

    impl MemoryInterfaceUserspace for FakeUmap {
        fn allocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _c: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn deallocate_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _r: crate::traits::memory::MemoryPTR,
            _c: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn map_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<crate::traits::memory::MemoryPTR, crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn unmap_memory_region(
            &self,
            _a: &dyn crate::traits::memory::FrameAllocator,
            _p: crate::traits::memory::MemoryPTR,
            _v: usize,
        ) -> Result<(), crate::traits::memory::ErrorCode> {
            unimplemented!()
        }
        fn translate(&self, virt: usize) -> Option<usize> {
            // Задачи живут в окне [delta, delta + limit): физика = VA - delta.
            let phys = virt.checked_sub(self.delta)?;
            (phys < 0x4000).then_some(phys)
        }
    }

    struct World {
        tasks: TaskManager<FakeUmap>,
        access: AccessManager<FakeUmap>,
    }

    fn spawn(world: &mut World) -> u64 {
        let gtcb = GTcb::new(FakeUmap { delta: 0x1_0000_0000 }, None);
        world
            .tasks
            .create_task(&mut world.access, 0, gtcb)
            .expect("create task")
    }

    fn spec_send(to: u64) -> SendSpec {
        SendSpec {
            to,
            gate: None,
            msg_va: 0x1_0000_1000,
            msg_len: 16,
            caps: [CapItem { src_slot: 0, dst_slot: 0, rights: 0 }; MAX_CAPS],
            caps_count: 0,
            is_fault: false,
        }
    }

    fn spec_recv() -> RecvSpec {
        RecvSpec {
            from: None,
            gate: None,
            tgt_va: 0x1_0000_2000,
            tgt_capacity: 4096,
            recv_base: 16,
            recv_count: 4,
        }
    }

    /// Полный цикл состояний: claim → finish, claim → restore, очередь,
    /// изъятие, ошибка отправителю, таймаут-очистка, destroyed-скан.
    #[test]
    fn transport_state_machine() {
        let _guard = crate::test_guard::GLOBAL.lock();
        ensure_slab();
        let mut world = World {
            tasks: TaskManager::new(),
            access: AccessManager::new().expect("access"),
        };
        // Namespace 0 не создан: create_task ожидает живой namespace —
        // создаём корневой.
        let ns = world.access.create_namespace(16, 1 << 20, 7, crate::access::namespace::NamespaceRights::all(), 256).expect("ns");
        let rx = {
            let gtcb = GTcb::new(FakeUmap { delta: 0x1_0000_0000 }, None);
            world.tasks.create_task(&mut world.access, ns, gtcb).expect("rx")
        };
        let tx = {
            let gtcb = GTcb::new(FakeUmap { delta: 0x1_0000_1000 }, None);
            world.tasks.create_task(&mut world.access, ns, gtcb).expect("tx")
        };

        // Никто не ждёт: NotWaiting.
        let tasks = &world.tasks;
        assert!(matches!(
            claim_receiver(tasks, rx, tx, None, 64, 0),
            ClaimResult::NotWaiting
        ));

        // Регистрация ожидания: seq-снимок.
        let snap = register_wait(tasks, rx, spec_recv()).expect("register");
        assert!(!receiver_pred(tasks, rx, snap, None)(), "пока без событий");

        // Захват: TooSmall / CapsRejected / успешный claim.
        assert!(matches!(
            claim_receiver(tasks, rx, tx, None, 4097, 0),
            ClaimResult::TooSmall
        ));
        assert!(matches!(
            claim_receiver(tasks, rx, tx, None, 64, 5),
            ClaimResult::CapsRejected
        ));
        let spec = match claim_receiver(tasks, rx, tx, None, 64, 1) {
            ClaimResult::Claimed(s) => s,
            _ => panic!("ожидался захват"),
        };
        // После клейма предикат получателя видит событие.
        assert!(receiver_pred(tasks, rx, snap, None)());
        // Повторный клейм невозможен (Claimed).
        assert!(matches!(
            claim_receiver(tasks, rx, tx, None, 64, 0),
            ClaimResult::NotWaiting
        ));

        // Откат клейма: получатель снова ждёт, seq НЕ меняется restore'ом
        // (но pred всё ещё видит снимок старым — recv вернулся в Receiving).
        restore_receiver(tasks, rx, spec);
        {
            let tcb = tasks.get_tcb(rx).unwrap();
            assert!(matches!(tcb.ipc().lock().recv, IpcRecv::Receiving(_)));
        }

        // Завершение доставки: Idle + reply_to + seq++.
        finish_delivery(tasks, rx, tx, false);
        {
            let tcb = tasks.get_tcb(rx).unwrap();
            let ipc = tcb.ipc().lock();
            assert_eq!(ipc.recv, IpcRecv::Idle);
            assert_eq!(ipc.reply_to, Some(tx));
            assert_ne!(ipc.seq, snap);
        }

        // Медленный путь: очередь. Пока Receiving — enqueue отклонён
        // (инвариант: зарегистрированный должен клеймиться, не копиться).
        register_wait(tasks, rx, spec_recv()).expect("re-register");
        unregister_wait(tasks, rx);
        enqueue_sender(tasks, rx, tx, false).expect("enqueue");
        // Предикат получателя видит кандидата — но только при
        // ЗАРЕГИСТРИРОВАННОМ ожидании (Idle-получатель разбирает очередь
        // быстрым путём wait, а не сном).
        let snap2 = register_wait(tasks, rx, spec_recv()).expect("re-register for pred");
        assert!(receiver_pred(tasks, rx, snap2, None)());
        // Closed-wait фильтр прячет кандидата.
        assert!(!receiver_pred(tasks, rx, snap2, Some(999))());
        // FIFO-изъятие + параметры отправителя.
        assert_eq!(pop_next_candidate(tasks, rx, None), Some((tx, false)));
        {
            let tcb = tasks.get_tcb(tx).unwrap();
            tcb.ipc().lock().send = Some(spec_send(rx));
        }
        assert!(sender_still_pending(tasks, tx));
        let taken = take_send_state(tasks, tx).expect("spec изъят");
        assert_eq!(taken.to, rx);
        assert!(!sender_still_pending(tasks, tx));
        // Предикат отправителя: изъято → не спать.
        assert!(sender_pred(tasks, tx)());

        // Ошибка доставки изъятому: send_rax читается хендлером.
        fail_sender(tasks, tx, res::E_INVALID_ARG);
        assert_eq!(take_send_result(tasks, tx), Some(res::E_INVALID_ARG));
        assert_eq!(take_send_result(tasks, tx), None);

        // Таймаут SEND: cancel_send снимает и spec, и запись в очереди.
        {
            let tcb = tasks.get_tcb(tx).unwrap();
            tcb.ipc().lock().send = Some(spec_send(rx));
        }
        // rx всё ещё зарегистрирован после pred-проверок — снимаем.
        unregister_wait(tasks, rx);
        enqueue_sender(tasks, rx, tx, false).expect("enqueue 2");
        cancel_send(tasks, tx, rx, None);
        {
            let tcb = tasks.get_tcb(tx).unwrap();
            let ipc = tcb.ipc().lock();
            assert!(ipc.send.is_none());
            assert_eq!(ipc.send_rax, Some(res::E_TIMEOUT));
        }
        assert!(pop_next_candidate(tasks, rx, None).is_none(), "очередь чиста");

        // Уничтожение получателя: отправитель-сирота → (id, wait-object).
        {
            let tcb = tasks.get_tcb(tx).unwrap();
            tcb.ipc().lock().send = Some(spec_send(rx));
        }
        // rx НЕ зарегистрирован (unregister_wait выше) → enqueue ok.
        enqueue_sender(tasks, rx, tx, false).ok();
        // «Умирает» rx: tx нацелен на него → сирота с его wait-объектом.
        let orphans = on_task_destroyed(tasks, rx);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, tx);
        assert_eq!(orphans[0].1, crate::ipc::endpoint::sender_wait_object(tx));
        assert!(!sender_still_pending(tasks, tx));
        // «Умирает» tx: его запись в очереди rx чистится.
        let _ = on_task_destroyed(tasks, tx);
        assert!(pop_next_candidate(tasks, rx, None).is_none());
        // reply_to на умершего чистится.
        {
            let tcb = tasks.get_tcb(rx).unwrap();
            tcb.ipc().lock().reply_to = Some(tx);
        }
        let _ = on_task_destroyed(tasks, tx);
        {
            let tcb = tasks.get_tcb(rx).unwrap();
            assert_eq!(tcb.ipc().lock().reply_to, None);
        }
        let _ = IpcChan::new();
    }

    /// Уничтожение ПОЛУЧАТЕЛЯ с ждущими отправителями: сироты получают
    /// (id, sender_wait_object(id)) для патча RAX + пробуждения.
    #[test]
    fn destroyed_receiver_orphans_senders() {
        let _guard = crate::test_guard::GLOBAL.lock();
        ensure_slab();
        let mut world = World {
            tasks: TaskManager::new(),
            access: AccessManager::new().expect("access"),
        };
        let ns = world.access.create_namespace(16, 1 << 20, 7, crate::access::namespace::NamespaceRights::all(), 256).expect("ns");
        let rx = {
            let gtcb = GTcb::new(FakeUmap { delta: 0x1_0000_0000 }, None);
            world.tasks.create_task(&mut world.access, ns, gtcb).expect("rx")
        };
        let tx = {
            let gtcb = GTcb::new(FakeUmap { delta: 0x1_0000_1000 }, None);
            world.tasks.create_task(&mut world.access, ns, gtcb).expect("tx")
        };
        {
            let tcb = world.tasks.get_tcb(tx).unwrap();
            tcb.ipc().lock().send = Some(spec_send(rx));
        }
        let orphans = on_task_destroyed(&world.tasks, rx);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, tx);
        assert_eq!(orphans[0].1, crate::ipc::endpoint::sender_wait_object(tx));
        // Отправитель очищен, код ошибки выставлен.
        assert!(!sender_still_pending(&world.tasks, tx));
        assert_eq!(take_send_result(&world.tasks, tx), Some(res::E_NOT_FOUND));
    }
}
