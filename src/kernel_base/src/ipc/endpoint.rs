//! IPC-эндпоинты: синхронный rendezvous-транспорт в стиле Лидтке/L4.
//!
//! МОДЕЛЬ (L4-минимализм, «ядро — только транспорт»):
//!   - Сообщение = НЕПРОЗРАЧНЫЕ байты (payload) + явные kernel-visible
//!     дескрипторы пересылки capability (аналог L4 map items). Ядро НЕ
//!     разбирает payload — сериализация (FlatBuffers и прочие) — задача
//!     юзерспейса.
//!   - Адресация: capability-слоты cspace. Отправитель адресует
//!     получателя слотом с TaskTCB-капабилити (право Send), получатель
//!     может ждать «от кого угодно» (open wait, [`IPC_WAIT_ANY`]) или
//!     «от конкретного отправителя» (closed wait, его TaskTCB-слот).
//!   - Rendezvous: send блокируется до приёма, wait — до отправки
//!     (классическая семантика Лидтке: IPC завершается в момент
//!     встречи, быстрая сторона не копирует в очередь).
//!
//! ПОТОКИ (кооперативная модель, задачи на одном ядре):
//!   SEND, быстрый путь: получатель уже ждёт (endpoint ready) →
//!     атомарный «захват» ожидания (claim), пересылка capability,
//!     копия [заголовок|payload] в буфер получателя (постранично,
//!     через translate), пробуждение получателя. Отправитель не спал.
//!   SEND, медленный путь: получателя нет → payload уходит в почтовый
//!     ящик (статический пул), отправитель блокируется на объекте
//!     `sender_wait_object(mailbox)`.
//!   WAIT, быстрый путь: есть ждущий отправитель → копия из ящика в
//!     буфер, пересылка capability, пробуждение отправителя (RAX
//!     отправителя уже OK — доставлено).
//!   WAIT, медленный путь: отправителей нет → регистрация готовности
//!     (endpoint), блокировка на `endpoint_wait_object(idx)`.
//!
//! ФОРМАТ доставки в буфер получателя (u64-слова, little-endian):
//!   [0] task_cap_id отправителя
//!   [1] размер payload в байтах
//!   [2] число доставленных capability (N)
//!   [3..3+N] слоты ПОЛУЧАТЕЛЯ, куда легли capability
//!   [3+N .. 3+N+size] payload (байты сообщения, для юзерспейса)
//!
//! ОТКАЗЫ: негабаритное для буфера получателя сообщение НЕ доставляется
//! (отправитель получает ошибку в свой кадр); уничтожение задачи чистит
//! реестр ([`on_task_destroyed`]): ждущие отправители умершего
//! получателя будятся с E_NOT_FOUND (RAX их сохранённых кадров
//! перезаписывается до пробуждения — см. TCB::patch_resume_rax), ящики
//! умершего отправителя отбрасываются.
//!
//! СИНХРОНИЗАЦИЯ: SpinMutex-реестр — ВНУТРЕННИЙ лок; внешний порядок —
//! permission_backend (AccessManager) → task_manager → реестр. Внутри
//! секции реестра чужих локов не берётся (копирование в userspace —
//! через HHDM по переведённым физическим адресам). Планировщик
//! (scheduler_release_object) зовётся ТОЛЬКО с отпущенным локом
//! реестра.
//!
//! ОГРАНИЧЕНИЕ v1 (как и весь планировщик): wake идёт через per-core
//! планировщик ТЕКУЩЕГО ядра — корректно, когда участники живут на
//! одном ядре (все boot-серверы на BSP). Межъядерный wake (IPI) —
//! отдельный этап SMP.

use heapless::Vec as HVec;
use spin::mutex::SpinMutex;

use crate::traits::memory::{
    is_user_range, MemoryInterfaceUserspace, phys_to_virt, PAGE_SIZE,
};

/// Максимум payload одного сообщения (байт). Совпадает с
/// cintos_user::flatbuf::MAX_MSG — юзерспейс-сериализация вмещается.
pub const MAX_MSG: usize = 512;

/// Максимум дескрипторов пересылки capability в одном сообщении.
pub const MAX_CAPS: usize = 8;

/// Максимум ОДНОВРЕМЕННО готовых получателей (endpoints).
pub const MAX_ENDPOINTS: usize = 32;

/// Пул почтовых ящиков ждущих отправителей.
pub const MAILBOX_SLOTS: usize = 16;

/// Слот «ждать от кого угодно» (open wait, семантика L4 from-any).
pub const IPC_WAIT_ANY: u64 = u64::MAX;

/// Слова заголовка ДО списка слотов capability: отправитель, размер,
/// число capability.
pub const HEADER_WORDS: usize = 3;

/// База пространства wait-объектов IPC для планировщика. Не пересекается
/// с IRQ-линиями (0..64) и тестовыми объектами (mt_test: 0xAA).
pub const IPC_OBJECT_BASE: usize = 0x1_0000;

/// Объект ожидания отправителя, спящего в ящике `mailbox_idx`.
pub fn sender_wait_object(mailbox_idx: usize) -> usize {
    IPC_OBJECT_BASE + mailbox_idx
}

/// Объект ожидания получателя, спящего на эндпоинте `endpoint_idx`.
pub fn endpoint_wait_object(endpoint_idx: usize) -> usize {
    IPC_OBJECT_BASE + 64 + endpoint_idx
}

/// Дескриптор пересылки одной capability (wire-формат userspace→ядро,
/// #[repr(C)] 3×u64: src_slot, dst_slot, права — DirectCapabilityRights).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapItem {
    pub src_slot: u64,
    pub dst_slot: u64,
    pub rights: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Пул почтовых ящиков переполнен (слишком много ждущих отправителей).
    MailboxFull,
    /// Все эндпоинты заняты (слишком много ждущих получателей).
    EndpointsFull,
    /// Буфер получателя не отображён (translate первой страницы None).
    BadBuffer,
}

/// Снимок готового получателя (участвует в claim/restore).
#[derive(Debug, Clone, Copy)]
pub struct ReadyEndpoint {
    pub receiver_task_cap: u64,
    /// ВА буфера, по которому ждущий получатель примет сообщение
    /// (переводится в физику ПОСТРАНИЧНО в момент доставки).
    pub tgt_va: usize,
    /// Ёмкость буфера получателя в байтах.
    pub tgt_capacity: usize,
    /// Closed-wait фильтр: Some(cap) — принимать только от него.
    pub from: Option<u64>,
    /// ПРИЁМНОЕ ОКНО capability (seL4-стиль): слоты получателя, куда
    /// ядро кладёт пересылаемые capability — recv_base + i для i-го
    /// дескриптора сообщения. Слот выбирает ЯДРО, а не отправитель:
    /// отправитель не может ни занять «пустые по соглашению» слоты
    /// получателя, ни прощупать их занятость. recv_count == 0 —
    /// получатель capability НЕ принимает (сообщение с map items
    /// отклоняется отправителю, не доходя до буфера).
    pub recv_base: u64,
    pub recv_count: usize,
}

impl ReadyEndpoint {
    /// Слот i-й capability сообщения внутри окна; None — окно меньше
    /// сообщения или переполнение адресного сложения.
    pub fn recv_slot(&self, index: usize) -> Option<u64> {
        if index >= self.recv_count {
            return None;
        }
        self.recv_base.checked_add(index as u64)
    }
}

/// Состояние эндпоинта. Claimed — захвачен отправителем на доставке:
/// слот НЕ считается свободным (нельзя переиспользовать под чужую
/// регистрацию — wait-объект ждущего получателя привязан к индексу),
/// но и не виден новым отправителям.
#[derive(Debug, Clone, Copy)]
enum EndpointState {
    Ready(ReadyEndpoint),
    Claimed(ReadyEndpoint),
}

/// Результат захвата ждущего получателя.
pub enum ClaimResult {
    /// Получатель ждёт и захвачен (эндпоинт снят до исхода пересылки).
    Claimed(usize, ReadyEndpoint),
    /// Никто не ждёт (или closed-wait на другого) — медленный путь.
    NotWaiting,
    /// Получатель ждёт, но его буфер мал для этого сообщения.
    TooSmall,
    /// Получатель ждёт, но его приёмное окно не вмещает capability
    /// сообщения (recv_count < caps_count) — сообщение неотдоставимо,
    /// отправитель получает ошибку, получатель продолжает ждать.
    CapsRejected,
}

/// Результат изъятия ждущего сообщения: данные для пересылки
/// capability (payload уже скопирован получателю).
#[derive(Debug, Clone, Copy)]
pub struct PendingDelivery {
    pub sender_task_cap: u64,
    /// Ящик, из которого изъято (для пробуждения отправителя).
    pub mailbox_idx: usize,
    pub caps_count: usize,
    pub caps: [CapItem; MAX_CAPS],
    /// Фолт-сообщение (отправитель — упавшая задача ipc::fault):
    /// отправителя НЕ будить — он спит на fault-объекте до FAULT_REPLY;
    /// вызывающий помечает доставку fault::mark_fault_delivered.
    pub is_fault: bool,
}

/// Ящик ждущего отправителя: сообщение скопировано из его userspace
/// в момент блокировки (дальше буфер отправителя мог бы исчезнуть).
/// `is_fault` — ящик фолта (ipc::fault): упавшая задача спит на
/// fault-объекте, обычные правила пробуждения/отбрасывания к ней
/// неприменимы.
struct Mailbox {
    used: bool,
    receiver_task_cap: u64,
    sender_task_cap: u64,
    msg_size: usize,
    msg: [u8; MAX_MSG],
    caps_count: usize,
    caps: [CapItem; MAX_CAPS],
    is_fault: bool,
}

struct Registry {
    mailboxes: [Mailbox; MAILBOX_SLOTS],
    /// Эндпоинт i: None — свободен; Some(Ready) — получатель ждёт;
    /// Some(Claimed) — доставка в полёте.
    endpoints: [Option<EndpointState>; MAX_ENDPOINTS],
}

const EMPTY_CAP: CapItem = CapItem {
    src_slot: 0,
    dst_slot: 0,
    rights: 0,
};

static REGISTRY: SpinMutex<Registry> = SpinMutex::new(Registry {
    mailboxes: [const {
        Mailbox {
            used: false,
            receiver_task_cap: 0,
            sender_task_cap: 0,
            msg_size: 0,
            msg: [0; MAX_MSG],
            caps_count: 0,
            caps: [EMPTY_CAP; MAX_CAPS],
            is_fault: false,
        }
    }; MAILBOX_SLOTS],
    endpoints: [None; MAX_ENDPOINTS],
});

// ─── Побайтовое копирование userspace↔kernel (постранично) ──────────────────

/// Копирует `buf.len()` байт из userspace-VA в ядерный буфер.
/// Постранично: буфер может пересекать границу страниц, а физика
/// соседних страниц НЕ обязана быть непрерывной. `false` — дыра.
pub fn read_from_user<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    buf: &mut [u8],
) -> bool {
    // COPYIN-ГЕЙТ: верхняя половина — ядерные отображения, разделяемые с
    // умапом задачи; translate() там успешен, а копирование ядром идёт в
    // обход U/S-бита. Без этого гейта ring3 читает память ядра.
    if !is_user_range(va, buf.len()) {
        return false;
    }
    let mut off = 0usize;
    while off < buf.len() {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, buf.len() - off);
        // USER-семантика copyin: нижняя половина + U/S (см. translate_user).
        let Some(phys) = umap.translate_user(va + off, false) else {
            return false;
        };
        // SAFETY: phys получен translate живого умапа; страница задачи
        // замаплена HHDM.
        let src = phys_to_virt(phys) as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(off), chunk);
        }
        off += chunk;
    }
    true
}

/// Копирует ядерный буфер в userspace-VA (постранично, как
/// read_from_user). Вызывать только после check_user_region.
pub fn write_to_user<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    buf: &[u8],
) -> bool {
    // COPYOUT-ГЕЙТ: симметрично read_from_user — без проверки ring3
    // получает ЗАПИСЬ в память ядра через tgt_ptr = ядерный VA.
    if !is_user_range(va, buf.len()) {
        return false;
    }
    let mut off = 0usize;
    while off < buf.len() {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, buf.len() - off);
        // USER-семантика copyout + WRITE: буфер обязан быть отображён с
        // R/W по всему пути (read-only страницы отклоняются).
        let Some(phys) = umap.translate_user(va + off, true) else {
            return false;
        };
        // SAFETY: как read_from_user.
        let dst = phys_to_virt(phys) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(off), dst, chunk);
        }
        off += chunk;
    }
    true
}

/// Полная проходимость диапазона [va, va+len) в пространстве задачи
/// (без записи). Проверка ДО доставки: частичная запись оставила бы
/// получателю полусообщение без возможности отката.
pub fn check_user_region<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    va: usize,
    len: usize,
) -> bool {
    // Проверка проходимости диапазона бессмысленна в верхней половине —
    // там translate() всегда успешен (ядерные отображения).
    if !is_user_range(va, len) {
        return false;
    }
    let mut off = 0usize;
    while off < len {
        let page_off = (va + off) & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, len - off);
        // USER-семантика + WRITE: диапазон — будущая цель записи ядра
        // (доставка сообщения), R/W обязателен по всему пути.
        if umap.translate_user(va + off, true).is_none() {
            return false;
        }
        off += chunk;
    }
    true
}

/// Пишет u64 в userspace-VA (выравнивание 8 проверяет вызывающий).
fn write_user_u64<Umap: MemoryInterfaceUserspace>(umap: &Umap, va: usize, value: u64) -> bool {
    write_to_user(umap, va, &value.to_le_bytes())
}

/// Общий заголовок + слоты capability + payload = байты буфера.
pub fn delivery_bytes(caps_count: usize, msg_len: usize) -> usize {
    (HEADER_WORDS + caps_count) * 8 + msg_len
}

// ─── SEND: быстрый путь ─────────────────────────────────────────────────────

/// Атомарный захват ждущего получателя (send, быстрый путь).
///
/// Эндпоинт переводится в Claimed В МОМЕНТ захвата: слот не переиспользуется (wait-объект получателя стабилен), но новые отправители его не видят — двойная доставка исключена. При неудачной пересылке
/// capability вызывающий обязан вернуть состояние через
/// [`restore_ready`], при успешной — освободить слот
/// [`consume_ready`].
pub fn claim_ready(
    receiver_task_cap: u64,
    sender_task_cap: u64,
    need_bytes: usize,
    caps_count: usize,
) -> ClaimResult {
    let mut reg = REGISTRY.lock();
    for (idx, slot) in reg.endpoints.iter_mut().enumerate() {
        // Копия снимка (EndpointState: Copy) — заём слота заканчивается
        // до присваивания Claimed.
        let Some(EndpointState::Ready(ep)) = *slot else {
            continue;
        };
        if ep.receiver_task_cap != receiver_task_cap {
            continue;
        }
        // Closed-wait фильтр: ждёт строго этого отправителя?
        if let Some(only_from) = ep.from
            && only_from != sender_task_cap {
                continue;
            }
        if need_bytes > ep.tgt_capacity {
            return ClaimResult::TooSmall;
        }
        // Приёмное окно обязано вмещать все дескрипторы сообщения:
        // приём capability без согласия получателя запрещён моделью
        // (слот выбирает получатель в IPC_WAIT, см. ReadyEndpoint).
        if caps_count > ep.recv_count {
            return ClaimResult::CapsRejected;
        }
        *slot = Some(EndpointState::Claimed(ep));
        return ClaimResult::Claimed(idx, ep);
    }
    ClaimResult::NotWaiting
}

/// Возвращает захваченный эндпоинт обратно в готовность (откат claim
/// после неудачной пересылки capability — получатель не должен терять
/// возможность принимать сообщения).
pub fn restore_ready(endpoint_idx: usize, ep: ReadyEndpoint) {
    let mut reg = REGISTRY.lock();
    if let Some(state) = reg.endpoints.get_mut(endpoint_idx)
        && matches!(state, Some(EndpointState::Claimed(_))) {
            *state = Some(EndpointState::Ready(ep));
        }
}

/// Освобождает эндпоинт ПОСЛЕ успешной доставки (быстрый путь send):
/// получатель разбужен, слот может принимать новую регистрацию.
pub fn consume_ready(endpoint_idx: usize) {
    let mut reg = REGISTRY.lock();
    if let Some(state) = reg.endpoints.get_mut(endpoint_idx)
        && matches!(state, Some(EndpointState::Claimed(_))) {
            *state = None;
        }
}

/// Снимает готовность получателя БЕЗ доставки (таймаут IPC_WAIT,
/// переполнение реестра дедлайнов): слот готовности не должен переживать
/// пробуждение — следующий отправитель доставил бы сообщение задаче,
/// которая уже не ждёт. Возвращает true, если слот был снят.
pub fn unregister_ready(receiver_task_cap: u64) -> bool {
    let mut reg = REGISTRY.lock();
    for slot in reg.endpoints.iter_mut() {
        if let Some(EndpointState::Ready(ep)) = *slot
            && ep.receiver_task_cap == receiver_task_cap
        {
            *slot = None;
            return true;
        }
    }
    false
}

// ─── SEND: медленный путь ───────────────────────────────────────────────────

/// Кладёт сообщение в почтовый ящик (получатель не ждёт). Отправителя
/// блокирует вызывающий — на `sender_wait_object(возвращённый idx)`.
pub fn enqueue_pending(
    receiver_task_cap: u64,
    sender_task_cap: u64,
    msg: &[u8],
    caps: &[CapItem],
) -> Result<usize, IpcError> {
    enqueue_impl(receiver_task_cap, sender_task_cap, msg, caps, false)
}

/// Фолт-вариант медленной отправки (ipc::fault::deliver_fault):
/// ящик помечается is_fault — его нельзя отбросить, а отправителя
/// нельзя будить при изъятии (он спит на fault-объекте до FAULT_REPLY).
pub fn enqueue_pending_fault(
    receiver_task_cap: u64,
    sender_task_cap: u64,
    msg: &[u8],
) -> Result<usize, IpcError> {
    enqueue_impl(receiver_task_cap, sender_task_cap, msg, &[], true)
}

fn enqueue_impl(
    receiver_task_cap: u64,
    sender_task_cap: u64,
    msg: &[u8],
    caps: &[CapItem],
    is_fault: bool,
) -> Result<usize, IpcError> {
    let mut reg = REGISTRY.lock();
    let idx = reg
        .mailboxes
        .iter()
        .position(|m| !m.used)
        .ok_or(IpcError::MailboxFull)?;
    let m = &mut reg.mailboxes[idx];
    m.used = true;
    m.receiver_task_cap = receiver_task_cap;
    m.sender_task_cap = sender_task_cap;
    m.msg_size = msg.len();
    m.msg[..msg.len()].copy_from_slice(msg);
    m.caps_count = caps.len();
    for (dst, src) in m.caps.iter_mut().zip(caps.iter()) {
        *dst = *src;
    }
    m.is_fault = is_fault;
    Ok(idx)
}

// ─── WAIT ───────────────────────────────────────────────────────────────────

/// Регистрирует готовность получателя (wait, медленный путь). Повторный
/// wait той же задачи ЗАМЕНЯЕТ прежний снимок (как irq_wait) и
/// возвращает индекс её эндпоинта.
pub fn register_ready<Umap: MemoryInterfaceUserspace>(
    receiver_task_cap: u64,
    umap: &Umap,
    tgt_va: usize,
    tgt_capacity: usize,
    from: Option<u64>,
    recv_base: u64,
    recv_count: usize,
) -> Result<usize, IpcError> {
    // Минимальная валидация буфера: первая страница заголовка доступна
    // и адрес выровнен на u64 (заголовок — сырые u64-слова).
    if tgt_capacity < HEADER_WORDS * 8 || !tgt_va.is_multiple_of(8) {
        return Err(IpcError::BadBuffer);
    }
    if !check_user_region(umap, tgt_va, HEADER_WORDS * 8) {
        return Err(IpcError::BadBuffer);
    }

    let mut reg = REGISTRY.lock();
    // Замена существующего ожидания той же задачи — слот тот же
    // (только Ready: Claimed — получатель спит в доставке, он не
    // может перевызвать wait).
    for (idx, slot) in reg.endpoints.iter_mut().enumerate() {
        if let Some(EndpointState::Ready(ep)) = slot
            && ep.receiver_task_cap == receiver_task_cap {
                *slot = Some(EndpointState::Ready(ReadyEndpoint {
                    receiver_task_cap,
                    tgt_va,
                    tgt_capacity,
                    from,
                    recv_base,
                    recv_count,
                }));
                return Ok(idx);
            }
    }
    let idx = reg
        .endpoints
        .iter()
        .position(|s| s.is_none())
        .ok_or(IpcError::EndpointsFull)?;
    reg.endpoints[idx] = Some(EndpointState::Ready(ReadyEndpoint {
        receiver_task_cap,
        tgt_va,
        tgt_capacity,
        from,
        recv_base,
        recv_count,
    }));
    Ok(idx)
}

/// Забирает ПЕРВОЕ подходящее ждущее сообщение (wait, быстрый путь):
/// получатель `receiver_task_cap`, фильтр `from` (None — от кого
/// угодно). Payload копируется в буфер получателя СРАЗУ (доставка
/// неделима), capability возвращает вызывающему для пересылки (под
/// permission_backend-локом).
///
/// СЛОВА СЛОТОВ в заголовке НЕ пишутся здесь: слоты назначает ядро из
/// приёмного окна получателя ПОСЛЕ успешной пересылки (нужно знание
/// занятости cspace) — вызывающий дописывает их
/// [`write_cap_slot_headers`]. Окно обязано вмещать дескрипторы
/// (recv_count): негабаритные сообщения отбрасываются, как и
/// негабаритный payload.
///
/// Сообщения, которые НЕ влезают в буфер получателя (или регион не
/// отображён), ОТБРАСЫВАЮТСЯ: их отправители попадают в `dropped` —
/// вызывающий патчит их RAX (E_INVALID_ARG) и будит.
pub fn take_pending<Umap: MemoryInterfaceUserspace>(
    receiver_task_cap: u64,
    from: Option<u64>,
    umap: &Umap,
    tgt_va: usize,
    tgt_capacity: usize,
    recv_base: u64,
    recv_count: usize,
    dropped: &mut HVec<(u64, usize), MAILBOX_SLOTS>,
) -> Option<PendingDelivery> {
    let mut reg = REGISTRY.lock();
    for (idx, m) in reg.mailboxes.iter_mut().enumerate() {
        if !m.used || m.receiver_task_cap != receiver_task_cap {
            continue;
        }
        if let Some(only_from) = from
            && m.sender_task_cap != only_from {
                continue;
            }
        // Приёмное окно получателя обязано вмещать capability сообщения.
        // Фолт-ящики капабилити не несут (enqueue_pending_fault — &[]),
        // поэтому фолты условие не задевают.
        if m.caps_count > recv_count {
            // Сообщение неотдоставимо НИКОГДА (окно не вырастет в этом
            // wait): отбрасываем, отправитель получит ошибку (фолты —
            // не трогаем, см. ниже общий принцип).
            if !m.is_fault {
                m.used = false;
                let _ = dropped.push((m.sender_task_cap, sender_wait_object(idx)));
            }
            continue;
        }
        let total = delivery_bytes(m.caps_count, m.msg_size);
        if total > tgt_capacity || !check_user_region(umap, tgt_va, total) {
            // Фолт-ящики НЕ отбрасываются НИКОГДА: упавшая задача спит на
            // fault-объекте, пробудить её может только FAULT_REPLY —
            // потерять единственное уведомление = вечное зависание.
            // Пропускаем: подойдёт к следующему wait с достаточным
            // буфером (см. ipc::fault).
            if m.is_fault {
                continue;
            }
            // Не доставится НИКОГДА (буфер не вырастет): отбрасываем,
            // отправитель получит ошибку.
            m.used = false;
            let _ = dropped.push((m.sender_task_cap, sender_wait_object(idx)));
            continue;
        }
        let mut ok = write_user_u64(umap, tgt_va, m.sender_task_cap);
        ok &= write_user_u64(umap, tgt_va + 8, m.msg_size as u64);
        ok &= write_user_u64(umap, tgt_va + 16, m.caps_count as u64);
        // Слова слотов (tgt_va + (3+i)*8) НЕ пишутся: слоты назначит
        // ядро из приёмного окна после успешной пересылки capability
        // (см. write_cap_slot_headers / ipc::assign_recv_slots).
        ok &= write_to_user(
            umap,
            tgt_va + (HEADER_WORDS + m.caps_count) * 8,
            &m.msg[..m.msg_size],
        );
        if !ok {
            // Отображение «схлопнулось» между проверкой и записью
            // (многопоточный umap) — считаем сообщение недоставимым.
            // Фолт-ящик не теряем (см. ветку выше) — попытка повторится.
            if m.is_fault {
                continue;
            }
            m.used = false;
            let _ = dropped.push((m.sender_task_cap, sender_wait_object(idx)));
            continue;
        }
        let delivery = PendingDelivery {
            sender_task_cap: m.sender_task_cap,
            mailbox_idx: idx,
            caps_count: m.caps_count,
            caps: m.caps,
            is_fault: m.is_fault,
        };
        m.used = false;
        return Some(delivery);
    }
    None
}

// ─── Доставка send→готовый получатель (после claim) ─────────────────────────

/// Копирует сообщение прямо в буфер ЗАХВАЧЕННОГО ждущего получателя
/// (send, быстрый путь; claim уже снят, конкурентных доставок нет).
/// `caps_dst_slots` — слоты ПОЛУЧАТЕЛЯ, куда легли capability (после
/// успешной transfer_capabilities).
pub fn deliver_to_claimed<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    ep: &ReadyEndpoint,
    sender_task_cap: u64,
    msg: &[u8],
    caps_dst_slots: &[u64],
) -> bool {
    let total = delivery_bytes(caps_dst_slots.len(), msg.len());
    if total > ep.tgt_capacity || !check_user_region(umap, ep.tgt_va, total) {
        return false;
    }
    let mut ok = write_user_u64(umap, ep.tgt_va, sender_task_cap);
    ok &= write_user_u64(umap, ep.tgt_va + 8, msg.len() as u64);
    ok &= write_user_u64(umap, ep.tgt_va + 16, caps_dst_slots.len() as u64);
    for (i, slot) in caps_dst_slots.iter().enumerate() {
        ok &= write_user_u64(umap, ep.tgt_va + (HEADER_WORDS + i) * 8, *slot);
    }
    ok &= write_to_user(umap, ep.tgt_va + (HEADER_WORDS + caps_dst_slots.len()) * 8, msg);
    ok
}

// ─── Уничтожение задачи ─────────────────────────────────────────────────────

/// Дописывает слова слотов ПОЛУЧАТЕЛЯ в заголовок доставки (медленный
/// путь wait): вызывается ПОСЛЕ успешной пересылки capability, когда
/// ядро уже назначило слоты из приёмного окна (см. take_pending —
/// почему слова не пишутся там). `slots` — фактические слоты.
pub fn write_cap_slot_headers<Umap: MemoryInterfaceUserspace>(
    umap: &Umap,
    tgt_va: usize,
    slots: &[u64],
) -> bool {
    let mut ok = true;
    for (i, slot) in slots.iter().enumerate() {
        ok &= write_user_u64(umap, tgt_va + (HEADER_WORDS + i) * 8, *slot);
    }
    ok
}

/// Чистит реестр от умершей задачи. Возвращает спящих отправителей,
/// чьи сообщения умерли вместе с получателем, — их RAX патчит
/// вызывающий (E_NOT_FOUND) и будит через планировщик.
///
/// Вызывать БЕЗ удержания лока реестра; сам лок берётся здесь.
pub fn on_task_destroyed(task_cap_id: u64) -> HVec<(u64, usize), MAILBOX_SLOTS> {
    let mut orphans: HVec<(u64, usize), MAILBOX_SLOTS> = HVec::new();
    let mut reg = REGISTRY.lock();
    // 1. Умер ГОТОВЫЙ получатель: эндпоинт снимается, будить некого.
    for slot in reg.endpoints.iter_mut() {
        if let Some(state) = slot {
            let receiver = match state {
                EndpointState::Ready(ep) | EndpointState::Claimed(ep) => ep.receiver_task_cap,
            };
            if receiver == task_cap_id {
                *slot = None;
            }
        }
    }
    // 2. Ящики: умер ОТПРАВИТЕЛЬ — сообщение отбрасывается; умер
    //    ПОЛУЧАТЕЛЬ — спящий отправитель становится сиротой.
    //    Фолт-ящик (is_fault) умершего получателя отбрасывается БЕЗ
    //    сироты: упавший спит на fault-объекте (не на ящике), его
    //    судьбу решает реестр фолтов (ipc::fault::on_task_destroyed).
    for (idx, m) in reg.mailboxes.iter_mut().enumerate() {
        if !m.used {
            continue;
        }
        if m.sender_task_cap == task_cap_id {
            m.used = false;
        } else if m.receiver_task_cap == task_cap_id {
            if !m.is_fault {
                let _ = orphans.push((m.sender_task_cap, sender_wait_object(idx)));
            }
            m.used = false;
        }
    }
    orphans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::memory::{is_user_range, set_hhdm_offset};

    /// COPYIN/COPYOUT-гейт: верхняя половина (ядерные отображения, общие
    /// с умапом задачи) обязана отсекаться ДО translate — translate там
    /// УСПЕШЕН, и без гейта ring3 получает примитивы чтения/записи памяти
    /// ядра (msg_ptr/tgt_ptr = 0xffff....).
    #[test]
    fn copy_gate_rejects_kernel_half() {
        let user = 0x0000_0001_0000_0000usize; // нижняя половина (окно задач)
        let kernel = 0xffff_ffff_8000_0000usize; // higher-half ядро

        assert!(is_user_range(user, 512));
        assert!(is_user_range(user, 0)); // пустой диапазон валиден
        assert!(!is_user_range(kernel, 512));
        // Старт в юзерспейсе, хвост ЗА границей (0x8000_0000_0000):
        let straddle = 0x0000_7fff_ffff_ff00usize;
        assert!(!is_user_range(straddle, 512), "диапазон, пересекающий границу, обязан отсекаться");
        assert!(is_user_range(straddle, 0x100)); // ещё до границы — ок
        let _ = kernel; // (наглядность)
    }

    /// Фиктивный умап: VA = phys + DELTA, отображено [0, limit).
    struct FakeUmap {
        delta: usize,
        limit: usize,
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
            let phys = virt.checked_sub(self.delta)?;
            (phys < self.limit).then_some(phys)
        }
    }

    fn umap() -> FakeUmap {
        FakeUmap {
            delta: 0x1_0000_0000,
            limit: 0x1_0000,
        }
    }

    /// Один тест на всю последовательность состояний реестра: реестр —
    /// глобальный static, параллельные тесты перемешали бы его.
    #[test]
    fn rendezvous_lifecycle() {
        let u = umap();
        // "Физическая память" приёмника: буфер на 4К по VA=delta+0x800.
        let mem = crate::traits::memory::test_alloc::page_aligned_leak(2);
        set_hhdm_offset(mem.as_ptr() as usize);

        // ── WAIT-медленный: получатель 100 ждёт от кого угодно, окно
        // приёма capability — слоты [16, 20). ──
        let tgt_va = u.delta + 0x800;
        let ep_idx = register_ready(100, &u, tgt_va, 4096, None, 16, 4)
            .expect("регистрация получателя");

        // ── SEND-быстрый: отправитель 200 захватывает эндпоинт. ──
        let need = delivery_bytes(1, 16);
        let (claimed_idx, ep) = match claim_ready(100, 200, need, 1) {
            ClaimResult::Claimed(idx, ep) => (idx, ep),
            _ => panic!("ожидался захват"),
        };
        assert_eq!(claimed_idx, ep_idx);
        assert_eq!(ep.receiver_task_cap, 100);
        // Повторный claim тем же отправителем — получателя больше нет.
        assert!(matches!(
            claim_ready(100, 200, need, 1),
            ClaimResult::NotWaiting
        ));

        // Closed-wait: получатель 300 ждёт ТОЛЬКО отправителя 400.
        let _ = register_ready(300, &u, tgt_va, 4096, Some(400), 0, 0)
            .expect("закрытый wait");
        assert!(matches!(
            claim_ready(300, 999, need, 1),
            ClaimResult::NotWaiting
        ));
        assert!(matches!(
            claim_ready(300, 400, need, 1),
            ClaimResult::Claimed(_, _)
        ));

        // Слишком маленький буфер: получатель 500 ждёт с 24 байтами
        // (минимум — голый заголовок), сообщение на 56 не влезает.
        let _ = register_ready(500, &u, tgt_va, HEADER_WORDS * 8, None, 0, 0)
            .expect("мелкий буфер");
        assert!(matches!(claim_ready(500, 200, 56, 0), ClaimResult::TooSmall));
        // Окно меньше дескрипторов: сообщение с cap отклоняется.
        assert!(matches!(
            claim_ready(500, 200, 4096, 1),
            ClaimResult::CapsRejected
        ));
        // Без дескрипторов — окно не важно (фолты так и ходят).
        assert!(matches!(
            claim_ready(500, 200, HEADER_WORDS * 8, 0),
            ClaimResult::TooSmall
        ));
        // restore откатывает прежний захват (TooSmall его не съел).
        restore_ready(claimed_idx, ep);
        assert!(matches!(
            claim_ready(100, 200, need, 1),
            ClaimResult::Claimed(_, _)
        ));

        // ── SEND-медленный: ящик для получателя 700. ──
        let msg = [0xABu8; 32];
        let caps = [CapItem {
            src_slot: 3,
            dst_slot: 5,
            rights: 1,
        }];
        let mb = enqueue_pending(700, 200, &msg, &caps).expect("ящик");
        let mb2 = enqueue_pending(700, 201, &msg, &caps).expect("ящик 2");

        // ── WAIT-быстрый: получатель 700 забирает первое сообщение. ──
        let mut dropped: HVec<(u64, usize), MAILBOX_SLOTS> = HVec::new();
        let delivery = take_pending(700, None, &u, tgt_va, 4096, 16, 2, &mut dropped)
            .expect("ожидалась доставка");
        assert_eq!(delivery.sender_task_cap, 200);
        assert_eq!(delivery.mailbox_idx, mb);
        assert_eq!(delivery.caps_count, 1);
        assert_eq!(delivery.caps[0].src_slot, 3);
        assert!(dropped.is_empty());
        // Заголовок в буфере получателя: отправитель, размер, 1 cap.
        // Слово слота (hdr[3]) НЕ пишется take_pending: слоты назначает
        // ядро ПОСЛЕ пересылки (write_cap_slot_headers) — здесь 0.
        let hdr = unsafe {
            core::slice::from_raw_parts(
                (mem.as_ptr() as usize + 0x800) as *const u64,
                HEADER_WORDS + 1,
            )
        };
        assert_eq!(hdr[0], 200);
        assert_eq!(hdr[1], 32);
        assert_eq!(hdr[2], 1);
        assert_eq!(hdr[3], 0);

        // Closed-wait фильтр: 700 ждёт только 201 — заберёт второе.
        let delivery2 = take_pending(700, Some(201), &u, tgt_va, 4096, 16, 2, &mut dropped)
            .expect("доставка по фильтру");
        assert_eq!(delivery2.sender_task_cap, 201);
        assert_eq!(delivery2.mailbox_idx, mb2);

        // Негабарит: получатель с буфером 16 байт + сообщение на 32 →
        // ящик отбрасывается, отправитель попадает в dropped.
        let mb3 = enqueue_pending(800, 200, &msg, &[]).expect("ящик 3");
        let _ = mb3;
        let before = dropped.len();
        assert!(take_pending(800, None, &u, tgt_va, 16, 0, 0, &mut dropped).is_none());
        assert_eq!(dropped.len(), before + 1);
        assert_eq!(dropped[dropped.len() - 1].0, 200);

        // ── Destroy: получатель 900 умер с ждущим отправителем. ──
        let mb4 = enqueue_pending(900, 200, &msg, &[]).expect("ящик 4");
        let orphans = on_task_destroyed(900);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, 200);
        assert_eq!(orphans[0].1, sender_wait_object(mb4));
        // Повторный destroy — чисто.
        assert!(on_task_destroyed(900).is_empty());

        // Умер отправитель: его ящики отбрасываются молча.
        let mb5 = enqueue_pending(950, 200, &msg, &[]).expect("ящик 5");
        let orphans = on_task_destroyed(200);
        assert!(orphans.is_empty());
        let mut d2: HVec<(u64, usize), MAILBOX_SLOTS> = HVec::new();
        assert!(take_pending(950, None, &u, tgt_va, 4096, 0, 0, &mut d2).is_none());
        let _ = mb5;
    }
}
