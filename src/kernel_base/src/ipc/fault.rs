//! Фолт-эндпоинты (стиль seL4 / KeyKOS): доставка фолтов ring3-задач
//! обработчику в юзерспейсе через обычный IPC-транспорт.
//!
//! МОДЕЛЬ (соответствие классике):
//!   - seL4: у TCB есть fault-эндпоинт (capability); при фолте ядро
//!     выполняет блокирующую отправку fault-IPC на этот эндпоинт;
//!     обработчик получает сообщение (fault IP, адрес, флаги), чинит
//!     причину (например, маппит страницу) и отвечает — упавшая задача
//!     повторяет упавшую инструкцию.
//!   - KeyKOS: у домена есть keeper; при фолте ядро передаёт keeper'у
//!     сообщение фолта вместе с resume-ключом; инвокация resume-ключа
//!     возобновляет домен (опционально с новым контекстом).
//!   - ЗДЕСЬ: оба механизма сведены к существующим идиомам ядра.
//!     Эндпоинт — capability-объект [`crate::access::capability::
//!     CapabilityObject::FaultEndpoint`] с фиксированным обработчиком
//!     (создатель). Привязка (FAULT_SET_ENDPOINT, слоты TaskTCB +
//!     FaultEndpoint) записывает «задача → обработчик» в реестр
//!     биндингов. При фолте ядро САМО выполняет отправку сообщения от
//!     имени упавшей задачи через rendezvous-транспорт ipc::endpoint —
//!     обработчик принимает его обычным IPC_WAIT. Resume-ключ — это
//!     ЗАПИСЬ об активном фолте: FAULT_REPLY проверяет, что зовёт
//!     именно зарегистрированный обработчик, и будит упавшую задачу
//!     (опционально с новым RIP/RSP).
//!
//! ПОТОК ФОЛТА (исключение в ring3,deliverable-вектор):
//!   1. Порт (idt-путь) проверяет: вектор доставляем, фолт из ring3,
//!      у текущей задачи есть биндинг → [`deliver_fault`].
//!   2. Выделяется слот активного фолта; собирается сообщение
//!      (тело проволочного формата ipc: label = FAULT_LABEL,
//!      payload = 5×u64 — см. [`FaultInfo::encode`]).
//!   3. Доставка: быстрый путь — обработчик уже спит в IPC_WAIT
//!      (claim эндпоинта, запись в его буфер, пробуждение); медленный
//!      путь — почтовый ящик (обработчик заберёт при следующем
//!      IPC_WAIT: [`endpoint::enqueue_pending_fault`]).
//!   4. Упавшая задача блокируется на `fault_wait_object(слот)` с
//!      СОХРАНЁННЫМ кадром (порт кладёт его в слот возобновления TCB).
//!   5. Обработчик читает фолт, зовёт FAULT_REPLY: ядро проверяет
//!      «обработчик + доставка состоялась», опционально патчит
//!      RIP/RSP сохранённого кадра и будит задачу. new_rip=0 —
//!      повторить упавшую инструкцию (классический пейджер);
//!      new_rip≠0 — продолжить с нового адреса (эмуляция/сигнал).
//!
//! ОТЛИЧИЕ от обычного IPC-отправителя: упавшая задача спит на СВОЁМ
//! fault-объекте (а не sender_wait_object ящика) и НЕ будится при
//! приёме сообщения обработчиком — только FAULT_REPLY'ем. Поэтому
//! фолт-ящики никогда не «отбрасываются с ошибкой» (take_pending их
//! пропускает вместо drop), а уничтожение обработчика будит упавших
//! (см. [`on_task_destroyed`]) — иначе они зависли бы навсегда.
//!
//! СМЕРТЬ УЧАСТНИКОВ:
//!   - умерла упавшая (невозможно для self-exit — она спит, но ядро
//!     защищено): слот освобождается молча;
//!   - умер обработчик: биндинги снимаются, упавшие БУДЯТСЯ — задача
//!     повторяет упавшую инструкцию, фолтится снова и попадает в
//!     фатальный путь уже без обработчика (громкая диагностика вместо
//!     тихого зависания). Сообщение из ящика отбрасывается молча
//!     (endpoint::on_task_destroyed).
//!
//! ОГРАНИЧЕНИЕ v1 (как у всего IPC): wake идёт через per-core
//! планировщик ТЕКУЩЕГО ядра — корректно, пока участники на одном ядре
//! (boot-серверы на BSP). Аналогично irq_wait.
//!
//! СИНХРОНИЗАЦИЯ: оба реестра — листовые локи IrqSafeSpinMutex (в
//! реестр нельзя войти, удерживая другой лок; путь исключения и так
//! бежит с погашенными IF). Порядок внешних локов при доставке:
//! permission_backend (AccessManager) → реестры endpoint/fault, как
//! во всех IPC-сисколлах.

use heapless::Vec as HVec;

use crate::{
    KernelCTL,
    ipc::endpoint::{self, ClaimResult},
    irqsafe::IrqSafeSpinMutex,
    kernel_log,
    lctl::LocalKernelCTL,
    traits::{ArchImplementation, scheduller::WaitModel},
};

/// База wait-объектов фолтов (не пересекается с IPC: 0x1_0000, IRQ:
/// 0x2_0000 и тестовыми идентификаторами mt_test: 0xAA).
pub const FAULT_OBJECT_BASE: usize = 0x3_0000;

/// Максимум ОДНОВРЕМЕННО активных фолтов (упавших задач).
pub const MAX_FAULT_SLOTS: usize = 16;

/// Максимум биндингов «задача → обработчик».
pub const MAX_FAULT_BINDINGS: usize = 32;

/// Label (тег тела) фолт-сообщений («FA17» = fault). Ядро и
/// юзерспейс обязаны соглашаться на это значение — зеркалится в
/// cintos_user::fault.
pub const FAULT_LABEL: u64 = 0xFA17_0000_0000_0001;

/// Слов payload в фолт-сообщении (kind, addr, ip, sp, err).
pub const FAULT_MSG_WORDS: usize = 5;

/// Полный размер тела фолт-сообщения (заголовок {label, payload_len}
/// + payload). Раскладка — см. [`FaultInfo::encode`].
pub const FAULT_MSG_LEN: usize = 16 + FAULT_MSG_WORDS * 8;

/// Объект ожидания упавшей задачи в слоте `slot`.
pub fn fault_wait_object(slot: usize) -> usize {
    FAULT_OBJECT_BASE + slot
}

/// Векторы, доставляемые обработчику (ключевое подмножество 0..31;
/// остальное — фатально для ядра: NMI/MC/DF и сегментные исключения
/// ядра не ретранслируются). Порты сверяются с собственным набором.
pub mod fault_kind {
    /// #DE: деление на ноль.
    pub const DIVIDE_ERROR: u64 = 0;
    /// #BP: int3 (юзерспейс-отладчики).
    pub const BREAKPOINT: u64 = 3;
    /// #OF: into.
    pub const OVERFLOW: u64 = 4;
    /// #UD: неверный опкод (в т.ч. ud2 — триггер тестов).
    pub const INVALID_OPCODE: u64 = 6;
    /// #GP: общая защита (привилегированная инструкция в ring3 и т.п.).
    pub const GENERAL_PROTECTION: u64 = 13;
    /// #PF: страничный фолт (addr = CR2, err = код CPU).
    pub const PAGE_FAULT: u64 = 14;
    /// #MF: x87 FPU.
    pub const X87_MATH: u64 = 16;
    /// #AC: выравнивание (нужен CR4.AM + EFLAGS.AC).
    pub const ALIGNMENT_CHECK: u64 = 17;
    /// #XF: SIMD.
    pub const SIMD_EXCEPTION: u64 = 19;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultError {
    /// Реестр биндингов переполнен.
    BindingsFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReplyError {
    /// Задача не находится в состоянии фолта (нет активной записи).
    NoFault,
    /// Отвечает не тот, кто зарегистрирован обработчиком.
    NotHandler,
    /// Сообщение ещё не принято обработчиком (ответ до приёма
    /// недопустим — как в seL4, reply валиден только после fault IPC).
    NotDelivered,
}

/// Данные фолта (payload сообщения; слово sender заголовка доставки —
/// task_cap_id упавшей задачи — обработчик видит в заголовке приёма).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultInfo {
    /// Вектор исключения ([`fault_kind`]).
    pub kind: u64,
    /// Адрес фолта: CR2 для #PF, 0 для остальных.
    pub addr: u64,
    /// RIP упавшей инструкции (точка повторного исполнения).
    pub ip: u64,
    /// RSP упавшей задачи (для эмуляции/смены стека в ответе).
    pub sp: u64,
    /// Код ошибки CPU (#PF: P/W/U/R-биты; 0 для остальных).
    pub err: u64,
}

impl FaultInfo {
    /// Payload-слова сообщения.
    pub fn payload_words(&self) -> [u64; FAULT_MSG_WORDS] {
        [self.kind, self.addr, self.ip, self.sp, self.err]
    }

    /// Кодирует тело фолт-сообщения в проволочном формате ipc
    /// (fixed-заголовок; формат — зеркало `cintos_user::ipc`::BODY_HDR,
    /// little-endian), чтобы обработчик разбирал фолт тем же
    /// `ipc::wait`/`parse_received`, что и обычные сообщения.
    ///
    /// Раскладка (56 байт, фиксированная — размер не зависит от данных):
    /// ```text
    /// [ 0.. 8) label       (u64) = FAULT_LABEL
    /// [ 8..16) payload_len (u64) = 5×8
    /// [16..56) payload           = 5×u64 (le)
    /// ```
    pub fn encode(&self) -> [u8; FAULT_MSG_LEN] {
        let mut m = [0u8; FAULT_MSG_LEN];
        m[0..8].copy_from_slice(&FAULT_LABEL.to_le_bytes());
        m[8..16].copy_from_slice(&((FAULT_MSG_WORDS * 8) as u64).to_le_bytes());
        for (i, w) in self.payload_words().iter().enumerate() {
            m[16 + i * 8..24 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
        m
    }
}

// ─── Реестр биндингов «задача → обработчик» ─────────────────────────────────

/// Биндинг: фолты задачи `task` доставляются задаче `handler`.
#[derive(Debug, Clone, Copy)]
struct FaultBinding {
    task: u64,
    handler: u64,
}

/// Слот активного фолта: упавшая задача спит на `fault_wait_object(i)`.
#[derive(Debug, Clone, Copy)]
struct FaultSlot {
    faulting: u64,
    handler: u64,
    /// Сообщение ПРИНЯТО обработчиком (быстрый путь доставки или
    /// take_pending в его IPC_WAIT). Только после этого FAULT_REPLY
    /// валиден — до приёма ответ означал бы дубликаты фолтов.
    delivered: bool,
}

static BINDINGS: IrqSafeSpinMutex<[Option<FaultBinding>; MAX_FAULT_BINDINGS]> =
    IrqSafeSpinMutex::new([None; MAX_FAULT_BINDINGS]);

static SLOTS: IrqSafeSpinMutex<[Option<FaultSlot>; MAX_FAULT_SLOTS]> =
    IrqSafeSpinMutex::new([None; MAX_FAULT_SLOTS]);

/// Привязывает/перепривязывает фолт-обработчик задачи. Повторная
/// привязка ЗАМЕНЯЕТ прежнюю (переназначение обработчика — легальная
/// операция менеджера задачи). Обработчик обязан быть живой задачей —
/// проверяет вызывающий сисколл (под permission_backend-локом).
pub fn set_fault_handler(task_cap_id: u64, handler_task_cap: u64) -> Result<(), FaultError> {
    let mut bindings = BINDINGS.lock();
    let mut free: Option<usize> = None;
    for (idx, slot) in bindings.iter_mut().enumerate() {
        match slot {
            Some(b) if b.task == task_cap_id => {
                b.handler = handler_task_cap;
                return Ok(());
            }
            None if free.is_none() => free = Some(idx),
            _ => {}
        }
    }
    let Some(idx) = free else {
        return Err(FaultError::BindingsFull);
    };
    bindings[idx] = Some(FaultBinding {
        task: task_cap_id,
        handler: handler_task_cap,
    });
    Ok(())
}

/// Обработчик задачи (None — фолт уйдёт в фатальный путь порта).
/// Вызывается из пути исключения (IF погашены) — листовой лок.
pub fn fault_handler_of(task_cap_id: u64) -> Option<u64> {
    let bindings = BINDINGS.lock();
    bindings
        .iter()
        .find_map(|s| s.filter(|b| b.task == task_cap_id).map(|b| b.handler))
}

/// Выделяет слот активного фолта (запись для упавшей задачи).
/// Повторный фолт той же задачи невозможен (она спит), но защитно
/// ПЕРЕЗАПИСЫВАЕТ прежнюю запись.
fn begin_fault(faulting: u64, handler: u64) -> Option<usize> {
    let mut slots = SLOTS.lock();
    let mut free: Option<usize> = None;
    for (idx, slot) in slots.iter_mut().enumerate() {
        match slot {
            Some(s) if s.faulting == faulting => {
                *slot = Some(FaultSlot {
                    faulting,
                    handler,
                    delivered: false,
                });
                return Some(idx);
            }
            None if free.is_none() => free = Some(idx),
            _ => {}
        }
    }
    let idx = free?;
    slots[idx] = Some(FaultSlot {
        faulting,
        handler,
        delivered: false,
    });
    Some(idx)
}

/// Освобождает слот активного фолта без побочных эффектов (откат
/// неудачной доставки — порт продолжит фатальным путём).
fn abort_fault(slot: usize) {
    let mut slots = SLOTS.lock();
    slots[slot] = None;
}

/// Помечает сообщение фолта доставленным (обработчик его ПРИНЯЛ):
/// быстрый путь доставки ИЛИ IPC_WAIT, забравший фолт-ящик
/// (см. syscall::ipc — ветка delivery.is_fault).
/// Возврат false — записи уже нет (обработчик умер после enqueue).
pub fn mark_fault_delivered(faulting: u64) -> bool {
    let mut slots = SLOTS.lock();
    for slot in slots.iter_mut() {
        if let Some(s) = slot
            && s.faulting == faulting {
                s.delivered = true;
                return true;
            }
    }
    false
}

/// Изымает фолт-запись для ответа (FAULT_REPLY): проверяет, что
/// отвечает зарегистрированный обработчик, и что сообщение было им
/// принято. Успех — wait-объект упавшей задачи для пробуждения
/// (слот освобождается здесь же; кадр упавшей остаётся в её TCB).
pub fn finish_fault(faulting: u64, handler: u64) -> Result<usize, FaultReplyError> {
    let mut slots = SLOTS.lock();
    for (idx, slot) in slots.iter_mut().enumerate() {
        let Some(s) = slot else { continue };
        if s.faulting != faulting {
            continue;
        }
        if s.handler != handler {
            return Err(FaultReplyError::NotHandler);
        }
        if !s.delivered {
            return Err(FaultReplyError::NotDelivered);
        }
        *slot = None;
        return Ok(fault_wait_object(idx));
    }
    Err(FaultReplyError::NoFault)
}

/// Чистит реестры от умершей задачи. Возвращает wait-объекты упавших,
/// чьим обработчиком она была — вызывающий (SCHED_DESTROY_TASK) их
/// освобождает: задача проснётся, повторит упавшую инструкцию и
/// сфолтит уже без биндинга (фатальный дамп с именованием причины).
///
/// Смерть самой упавшей (спит в фолте) для self-exit недостижима —
/// слот всё равно освобождается молча (защита от будущих путей
/// уничтожения чужих задач).
pub fn on_task_destroyed(task_cap_id: u64) -> HVec<usize, MAX_FAULT_SLOTS> {
    let mut to_release: HVec<usize, MAX_FAULT_SLOTS> = HVec::new();

    {
        let mut bindings = BINDINGS.lock();
        for slot in bindings.iter_mut() {
            if let Some(b) = slot
                && (b.task == task_cap_id || b.handler == task_cap_id) {
                    *slot = None;
                }
        }
    }

    {
        let mut slots = SLOTS.lock();
        for (idx, slot) in slots.iter_mut().enumerate() {
            let Some(s) = slot else { continue };
            if s.faulting == task_cap_id {
                *slot = None;
            } else if s.handler == task_cap_id {
                *slot = None;
                let _ = to_release.push(fault_wait_object(idx));
            }
        }
    }

    to_release
}

// ─── Доставка (путь исключения порта) ───────────────────────────────────────

/// Доставка фолта обработчику + блокировка упавшей. Вызывается ТОЛЬКО
/// из пути исключения ТЕКУЩЕЙ задачи (порт): подIF=0, CR3 упавшей
/// активна (запись в буфер обработчика — через translate+HHDM, без
/// смены CR3), после успеха порт сохраняет кадр упавшей в её TCB и
/// уходит в цикл планировщика.
///
/// `false` — обработчика нет / он мёртв / ресурсы исчерпаны: порт
/// продолжает фатальным путём (дамп + halt), как до фолт-эндпоинтов.
///
/// Порядок локов — как в IPC_SEND: permission_backend держится на
/// всю доставку (резолв обработчика + его буфер), реестры endpoint/
/// fault — листовые внутри.
pub fn deliver_fault<A: ArchImplementation + 'static>(
    kctl: &'static KernelCTL<A>,
    lctl: &mut LocalKernelCTL<A::Umap>,
    faulting_task_cap: u64,
    info: &FaultInfo,
) -> bool {
    let Some(handler) = fault_handler_of(faulting_task_cap) else {
        return false;
    };
    let msg = info.encode();
    let need = endpoint::delivery_bytes(0, msg.len());

    // Обработчик обязан существовать (защита от биндинга на мёртвую
    // задачу между привязкой и фолтом). Под permission_backend-локом
    // уничтожение невозможно.
    let access = kctl.permission_backend().lock();
    let Some(handler_gtcb) = access.get_task_tcb(handler) else {
        return false;
    };
    // SAFETY: под permission_backend-локом уничтожение невозможно.
    let handler_umap = unsafe { handler_gtcb.as_ref().userspace_map() };

    let Some(slot) = begin_fault(faulting_task_cap, handler) else {
        return false;
    };

    // Фолт-сообщение capability не несёт: caps_count = 0 — любое
    // приёмное окно обработчика (даже recv_count = 0) его принимает.
    match endpoint::claim_ready(handler, faulting_task_cap, need, 0) {
        // Быстрый путь: обработчик спит в IPC_WAIT — захват, запись в
        // его буфер, пробуждение. Фолт сразу «доставлен».
        ClaimResult::Claimed(ep_idx, ep) => {
            if endpoint::check_user_region(handler_umap, ep.tgt_va, need)
                && endpoint::deliver_to_claimed(
                    handler_umap,
                    &ep,
                    faulting_task_cap,
                    &msg,
                    &[],
                )
            {
                endpoint::consume_ready(ep_idx);
                mark_fault_delivered(faulting_task_cap);
                // Разбудить обработчика (его кадр: RAX уже OK с момента
                // блокировки в IPC_WAIT — буфер заполнен).
                lctl.scheduler_release_object(endpoint::endpoint_wait_object(ep_idx));
            } else {
                // Буфер обработчика мал/не отображён — ошибка КОНФИГУРАЦИИ
                // обработчика. Разбудить его нельзя (кадр без сообщения),
                // оставить спать — зависание пары. Фатально с диагностикой.
                endpoint::restore_ready(ep_idx, ep);
                kernel_log!(
                    "fault: буфер обработчика {} непригоден ({:#x}, need {})\n",
                    handler,
                    ep.tgt_va,
                    need
                );
                abort_fault(slot);
                return false;
            }
        }
        ClaimResult::TooSmall => {
            // Аналогично: ждущий обработчик с буфером меньше фолт-сообщения
            // (100 байт) — ошибка конфигурации; фолт-ящик не выйдет из
            // taker'а, пара зависнет. Фатально с диагностикой.
            kernel_log!(
                "fault: буфер ожидания обработчика {} меньше {} байт\n",
                handler,
                need
            );
            abort_fault(slot);
            return false;
        }
        ClaimResult::CapsRejected => {
            // CAPS-квота обработчика исчерпана — конфигурация обработчика
            // непригодна для доставки фолта (fail-closed, как TooSmall).
            kernel_log!("fault: caps-квота обработчика {} исчерпана\n", handler);
            abort_fault(slot);
            return false;
        }
        ClaimResult::NotWaiting => {
            // Медленный путь: ящик; обработчик заберёт фолт следующим
            // IPC_WAIT (take_pending, ветка is_fault — пометит доставку
            // и НЕ будет будить отправителя: упавшая спит до REPLY).
            match endpoint::enqueue_pending_fault(handler, faulting_task_cap, &msg) {
                Ok(_) => {}
                Err(_) => {
                    kernel_log!(
                        "fault: пул ящиков переполнен — фолт задачи {} потерян\n",
                        faulting_task_cap
                    );
                    abort_fault(slot);
                    return false;
                }
            }
        }
    }

    // Упавшая задача уходит в ожидание своего фолт-объекта. Порт после
    // возврата true сохранит её кадр в TCB и уйдёт в планировщик.
    let _ = lctl.scheduler_block_on_object(fault_wait_object(slot), WaitModel::OneShot);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Мини-верификатор проволочного формата ipc (зеркало
    /// cintos_user::ipc::parse_received для тела): label + payload_len
    /// + payload.
    fn parse_body(buf: &[u8]) -> Option<(u64, &[u8])> {
        if buf.len() < 16 {
            return None;
        }
        let label = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let plen = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
        let payload = buf.get(16..16 + plen)?;
        Some((label, payload))
    }

    #[test]
    fn fault_msg_is_fixed_layout() {
        let info = FaultInfo {
            kind: fault_kind::PAGE_FAULT,
            addr: 0x1234_5678,
            ip: 0xAAAA_0000,
            sp: 0xBBBB_1111,
            err: 0x3,
        };
        let msg = info.encode();
        assert_eq!(msg.len(), FAULT_MSG_LEN);
        assert_eq!(FAULT_MSG_LEN, 56);
        let (label, payload) = parse_body(&msg).expect("валидное тело");
        assert_eq!(label, FAULT_LABEL);
        assert_eq!(payload.len(), FAULT_MSG_WORDS * 8);
        let word = |i: usize| -> u64 {
            u64::from_le_bytes(payload[i * 8..(i + 1) * 8].try_into().unwrap())
        };
        assert_eq!(word(0), fault_kind::PAGE_FAULT);
        assert_eq!(word(1), 0x1234_5678);
        assert_eq!(word(2), 0xAAAA_0000);
        assert_eq!(word(3), 0xBBBB_1111);
        assert_eq!(word(4), 0x3);
    }

    /// Реестры — глобальные статики: один тест на всю
    /// последовательность (как в ipc::endpoint).
    #[test]
    fn fault_registry_lifecycle() {
        // Биндинги: установка, замена, чтение.
        set_fault_handler(10, 20).expect("биндинг 10→20");
        assert_eq!(fault_handler_of(10), Some(20));
        assert_eq!(fault_handler_of(11), None);
        set_fault_handler(10, 30).expect("замена обработчика");
        assert_eq!(fault_handler_of(10), Some(30));
        set_fault_handler(11, 30).expect("биндинг 11→30");

        // Слоты: begin → delivered → finish.
        let slot = begin_fault(10, 30).expect("слот фолта");
        assert_eq!(fault_wait_object(slot), FAULT_OBJECT_BASE + slot);
        // Ответ до доставки — отказ; чужой обработчик — отказ.
        assert_eq!(finish_fault(10, 30), Err(FaultReplyError::NotDelivered));
        assert_eq!(finish_fault(10, 20), Err(FaultReplyError::NotHandler));
        assert!(mark_fault_delivered(10));
        // После приёма — валиден только зарегистрированному.
        assert_eq!(finish_fault(10, 30), Ok(fault_wait_object(slot)));
        // Слот изъят: повторный ответ и пометка — мимо.
        assert_eq!(finish_fault(10, 30), Err(FaultReplyError::NoFault));
        assert!(!mark_fault_delivered(10));

        // Смерть обработчика: упавшие будятся, биндинги снимаются.
        let s1 = begin_fault(10, 30).expect("повторный фолт задачи 10");
        let s2 = begin_fault(11, 30).expect("фолт задачи 11 (обработчик 30)");
        let wake = on_task_destroyed(30);
        assert_eq!(wake.len(), 2);
        assert!(wake.contains(&fault_wait_object(s1)));
        assert!(wake.contains(&fault_wait_object(s2)));
        assert_eq!(fault_handler_of(10), None);
        assert_eq!(fault_handler_of(11), None);

        // Смерть упавшей: слот молча освобождается, будить некого.
        begin_fault(10, 99).expect("фолт задачи 10");
        assert!(on_task_destroyed(10).is_empty());
        assert_eq!(finish_fault(10, 99), Err(FaultReplyError::NoFault));

        // Переполнение биндингов: 32 слота, 33-я привязка — отказ.
        for i in 0..MAX_FAULT_BINDINGS as u64 {
            set_fault_handler(1000 + i, 2000 + i).expect("заполнение биндингов");
        }
        assert_eq!(
            set_fault_handler(9999, 2),
            Err(FaultError::BindingsFull)
        );
        // Замена существующего биндинга работает и при полном реестре.
        set_fault_handler(1000, 7).expect("замена при полном реестре");
        assert_eq!(fault_handler_of(1000), Some(7));
    }
}
