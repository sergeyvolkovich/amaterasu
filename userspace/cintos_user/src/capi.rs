//! capi — C-совместимый ABI юзерспейса NOMAD.
//!
//! Требование «коду юзерспейса нужна Си-совместимость»: вся
//! функциональность библиотеки (IPC-транспорт, разбор доставки,
//! сисколлы, auxv) доступна из C через стабильные `extern "C"`
//! символы с C-типами; сигнатуры зеркалятся заголовком
//! `cintos_user/include/nomad.h`. Ни одного Rust-типа в сигнатурах;
//! коды ошибок — те же биты SYSCALL_ERROR_FLAG, что и в ядре.
//!
//! C-демо (ipc_cdemo) компонуется с staticlib-сборкой этого крейта и
//! живёт в ISO рядом с Rust-серверами — бинарная доказательство
//! совместимости.
//!
//! LINT: сырые указатели в сигнатурах — сам СМЫСЛ C-ABI; валидность
//! памяти гарантирует вызывающий C-код (контракты в док-комментариях
//! каждой функции). clippy::not_unsafe_ptr_arg_deref отключён на модуль.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::abi;
use crate::cap::Rights;
use crate::handle::Slot;
use crate::ipc::{self, HEADER_WORDS, MAX_CAPS};

// ─── Общие ──────────────────────────────────────────────────────────────────

/// Размер буфера приёма IPC, рекомендованный C-коду (байт).
pub const NOMAD_IPC_BUF_LEN: usize = 1024;

/// Локальная ошибка «сообщение не влезает в транспорт».
pub const NOMAD_E_MSG_TOO_BIG: u64 = ipc::E_MSG_TOO_BIG;

/// Уступить квант планировщику.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_sched_yield() -> u64 {
    unsafe { crate::syscall::syscall0(abi::nr::SCHED_YIELD) }
}

/// Строка в лог ядра (serial + кольцо). Возврат — код сисколла.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_log_write(ptr: *const u8, len: u64) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::DBG_LOG_WRITE, ptr as u64, len) }
}

/// Значение auxv по тегу (0 — тег отсутствует).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_auxv_get(tag: u64) -> u64 {
    crate::crt0::auxv_get(tag).unwrap_or(0)
}

/// task_cap_id текущей задачи (AT_NOMAD_SELF_CAP; 0 — отсутствует).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_self_cap() -> u64 {
    nomad_auxv_get(abi::auxv_values::AT_NOMAD_SELF_CAP)
}

/// Self-exit: уничтожить текущую задачу (выходит из main по возврату;
/// C-код может позвать явно).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_exit() -> u64 {
    let self_cap = nomad_self_cap();
    unsafe { crate::syscall::syscall1(abi::nr::SCHED_DESTROY_TASK, self_cap) }
}

// ─── FUTEX (предикатный сон на слове разделяемой памяти; см. dekker.rs) ─────

/// Спать на ключе key, пока 4-байтовое слово по uaddr (shm-регион
/// ВЫЗЫВАЮЩЕЙ задачи) равно expected: проверка выполняется ядром ПОД
/// WAKE_LOCK атомарно с постановкой в очередь (syscall 53) — закрывает
/// lost-wakeup окно BLOCK_ON_OBJECT. 0 — возврат («спал и разбужен»
/// или «предикат сработал до сна»); спурийные пробуждения — контракт.
/// key обязан лежать вне резервов ядра (см. dekker::KEY_BASE).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_futex_wait(key: u64, uaddr: u64, expected: u32) -> u64 {
    unsafe { crate::syscall::syscall3(abi::nr::FUTEX_WAIT, key, uaddr, expected as u64) }
}

/// Разбудить до count ждущих ключа key (syscall 54; OneShot на вызов).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_futex_wake(key: u64, count: u32) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::FUTEX_WAKE, key, count as u64) }
}

// ─── Память ─────────────────────────────────────────────────────────────────

/// Выделить `pages` страниц; возврат — VA (старший бит = ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_alloc_pages(pages: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::ALLOC_PAGES, pages) }
}

/// Снять аллокацию по базовому VA.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_free_pages(vaddr: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::FREE_PAGES, vaddr) }
}

// ─── Capability ─────────────────────────────────────────────────────────────
// Возврат всех функций — код сисколла (старший бит = ошибка; у create_* —
// id созданной капы, у mount — VA). Права: NOMAD_CAP_* (прямые),
// NOMAD_NS_* (неймспейс). Mint/clone адресуют ОБЕ стороны TaskTCB-капами
// в cspace вызывающего — голые task_cap-id ядро отклоняет (E_RIGHTS_DENIED).

/// Создать неймспейс (группу задач) + корневую капу в dst_slot
/// вызывающего. rights_mask — NOMAD_NS_*; max_cap_objects — квота
/// cspace-записей/мембран (капы бессмертны — tombstone/recycle).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_create_namespace(
    dst_slot: u64,
    max_task_count: u64,
    max_memory_bytes: u64,
    persistency_badge: u64,
    rights_mask: u64,
    max_cap_objects: u64,
) -> u64 {
    unsafe {
        crate::syscall::syscall6(
            abi::nr::CAP_CREATE_NAMESPACE,
            dst_slot,
            max_task_count,
            max_memory_bytes,
            persistency_badge,
            rights_mask,
            max_cap_objects,
        )
    }
}

/// Капа на пул памяти IPC задачи owner_task_cap → её dst_slot.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_create_ipc_pool(owner_task_cap: u64, dst_slot: u64) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::CAP_CREATE_IPC_POOL, owner_task_cap, dst_slot) }
}

/// Капа на диапазон физики [phys_origin, phys_origin + page_count*PAGE)
/// → dst_slot owner'а; диапазон обязан быть в allow-list ядра. Монтаж —
/// nomad_mount_cap_region.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_create_mmio(
    owner_task_cap: u64,
    phys_origin: u64,
    page_count: u64,
    dst_slot: u64,
) -> u64 {
    unsafe {
        crate::syscall::syscall4(
            abi::nr::CAP_CREATE_MMIO,
            owner_task_cap,
            dst_slot,
            phys_origin,
            page_count,
        )
    }
}

/// Капа на логическую линию (GSI/MSI): trigger 0=edge, 1=level; линия
/// обязана быть свободна (иначе E_BUSY), до первого WaitIrq — маскирована.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_create_irq(
    owner_task_cap: u64,
    dst_slot: u64,
    line: u64,
    trigger: u64,
) -> u64 {
    unsafe {
        crate::syscall::syscall4(
            abi::nr::CAP_CREATE_IRQ,
            owner_task_cap,
            dst_slot,
            line,
            trigger,
        )
    }
}

/// Mint: производная копия (src_task_cap, src_slot) → (dst_task_cap,
/// dst_slot) с правами ⊆ источника (биты NOMAD_CAP_*).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_mint(
    src_task_cap: u64,
    src_slot: u64,
    dst_task_cap: u64,
    dst_slot: u64,
    rights: u64,
) -> u64 {
    unsafe {
        crate::syscall::syscall5(
            abi::nr::CAP_MINT,
            src_task_cap,
            src_slot,
            dst_task_cap,
            dst_slot,
            rights,
        )
    }
}

/// Clone: копия в той же мембране (право Clone у источника).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_clone(
    src_task_cap: u64,
    src_slot: u64,
    dst_task_cap: u64,
    dst_slot: u64,
) -> u64 {
    unsafe {
        crate::syscall::syscall4(abi::nr::CAP_CLONE, src_task_cap, src_slot, dst_task_cap, dst_slot)
    }
}

/// Ревок мембраны слота: протухают запись и все производные (слот
/// остаётся занятым).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_revoke(task_cap: u64, slot: u64) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::CAP_REVOKE, task_cap, slot) }
}

/// Ревок + tombstone записи НА МЕСТЕ (слот переиспользуется через
/// recycle при следующей установке).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_destroy(task_cap: u64, slot: u64) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::CAP_DESTROY, task_cap, slot) }
}

/// Снять отображение capability-региона по базовому VA (возврат
/// nomad_mount_cap_region).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_unmount_cap_region(vaddr: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::UNMOUNT_CAP_REGION, vaddr) }
}

// ─── IPC ────────────────────────────────────────────────────────────────────

/// Дескриптор пересылки capability для C (L4 map item): 24 байта,
/// раскладка синхронизирована с Rust `ipc::CapDesc` и ядром.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NomadCapDesc {
    pub src_slot: u64,
    pub dst_slot: u64,
    pub rights: u64,
}

const _: () = assert!(core::mem::size_of::<NomadCapDesc>() == 24);

/// Синхронная отправка (блокируется до приёма).
///
/// slot — слот cspace получателя; label/payload — тело собирается
/// как {label, payload_len, payload} (см. nomad.h); caps — массив
/// NomadCapDesc×caps_len (может быть NULL при caps_len=0).
/// Возврат: 0 — доставлено; иначе код ошибки (старший бит).
/// Разбор C-массива NomadCapDesc в Rust-дескрипторы (контракт C-ABI:
/// caps — валидный массив caps_len элементов или NULL при caps_len=0).
fn decode_caps(caps: *const NomadCapDesc, caps_len: u64) -> ([ipc::CapDesc; MAX_CAPS], usize) {
    let mut rust_caps = [ipc::CapDesc::new(Slot::new(0), Slot::new(0), Rights::from_bits(0)); MAX_CAPS];
    let n = (caps_len as usize).min(MAX_CAPS);
    if caps.is_null() || n == 0 {
        return (rust_caps, 0);
    }
    // SAFETY: caps — валидный массив (контракт C-ABI).
    let src = unsafe { core::slice::from_raw_parts(caps.cast::<NomadCapDesc>(), n) };
    for (dst, s) in rust_caps.iter_mut().zip(src.iter()) {
        *dst = ipc::CapDesc::new(
            Slot::new(s.src_slot),
            Slot::new(s.dst_slot),
            Rights::from_bits(s.rights),
        );
    }
    (rust_caps, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_send(
    slot: u64,
    label: u64,
    payload: *const u8,
    payload_len: u64,
    caps: *const NomadCapDesc,
    caps_len: u64,
) -> u64 {
    if payload_len as usize > crate::ipc::MAX_MSG {
        return ipc::E_MSG_TOO_BIG;
    }
    // SAFETY: payload — валидная память вызывающего на payload_len байт
    // (контракт C-ABI).
    let payload = unsafe {
        core::slice::from_raw_parts(payload, payload_len as usize)
    };
    let mut rust_caps = [ipc::CapDesc::new(
        Slot::new(0),
        Slot::new(0),
        Rights::from_bits(0),
    ); MAX_CAPS];
    let n = (caps_len as usize).min(MAX_CAPS);
    // SAFETY: caps — валидный массив NomadCapDesc×caps_len (контракт).
    let src = if caps.is_null() || n == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(caps.cast::<NomadCapDesc>(), n) }
    };
    for (dst, s) in rust_caps.iter_mut().zip(src.iter()) {
        *dst = ipc::CapDesc::new(
            Slot::new(s.src_slot),
            Slot::new(s.dst_slot),
            Rights::from_bits(s.rights),
        );
    }
    match ipc::send(Slot::new(slot), label, payload, &rust_caps[..n]) {
        Ok(()) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Ответ клиенту последнего запроса (IPC_REPLY; см. nomad.h).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_reply(
    label: u64,
    payload: *const u8,
    payload_len: u64,
    caps: *const NomadCapDesc,
    caps_len: u64,
) -> u64 {
    let ok = unsafe { payload.as_ref() }.is_some() || payload_len == 0;
    if !ok || payload_len as usize > crate::ipc::MAX_MSG {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: payload — валидная память вызывающего (контракт C-ABI).
    let payload = unsafe { core::slice::from_raw_parts(payload, payload_len as usize) };
    let (rust_caps, n) = decode_caps(caps, caps_len);
    match ipc::reply(label, payload, &rust_caps[..n]) {
        Ok(()) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Создать IPC-гейт (IPC_CREATE_GATE; см. nomad.h).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_create_gate(dst_slot: u64) -> u64 {
    match ipc::create_gate(Slot::new(dst_slot)) {
        Ok(id) => id,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Уничтожить IPC-гейт (IPC_DESTROY_GATE; см. nomad.h).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_destroy_gate(slot: u64) -> u64 {
    match ipc::destroy_gate(Slot::new(slot)) {
        Ok(id) => id,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Атомарный call (IPC_CALL; см. nomad.h) — буфер двунаправленный.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_call(
    slot: u64,
    buf: *mut u8,
    buf_len: u64,
    label: u64,
    request: *const u8,
    request_len: u64,
    caps: *const NomadCapDesc,
    caps_len: u64,
    recv_base: u64,
    recv_count: u64,
    deadline: u64,
) -> u64 {
    if buf.is_null()
        || buf_len < (crate::ipc::BODY_HDR + request_len as usize) as u64
        || request_len as usize > crate::ipc::MAX_MSG
    {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: buf/request — валидная память вызывающего (контракт C-ABI).
    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf, buf_len as usize) };
    let request_slice = unsafe { core::slice::from_raw_parts(request, request_len as usize) };
    let (rust_caps, n) = decode_caps(caps, caps_len);
    match ipc::call(
        Slot::new(slot),
        label,
        request_slice,
        &rust_caps[..n],
        ipc::recv_window(Slot::new(recv_base), recv_count),
        deadline,
        buf_slice,
    ) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Reply + следующий wait (IPC_REPLY_WAIT; см. nomad.h).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_reply_wait(
    label: u64,
    payload: *const u8,
    payload_len: u64,
    caps: *const NomadCapDesc,
    caps_len: u64,
    from: u64,
    deadline: u64,
    buf: *mut u8,
    buf_len: u64,
) -> u64 {
    if buf.is_null() || buf_len < (crate::ipc::HEADER_WORDS * 8) as u64 {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: payload — валидная память вызывающего (контракт C-ABI).
    let payload_slice = if payload_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(payload, payload_len as usize) }
    };
    let (rust_caps, n) = decode_caps(caps, caps_len);
    // SAFETY: buf — валидная память вызывающего (контракт C-ABI).
    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf, buf_len as usize) };
    match ipc::reply_wait(
        label,
        payload_slice,
        &rust_caps[..n],
        if from == u64::MAX {
            ipc::WaitFrom::Any
        } else {
            ipc::WaitFrom::Slot(Slot::new(from))
        },
        deadline,
        buf_slice,
    ) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Ожидание сообщения (блокируется до доставки). from — слот
/// отправителя или NOMAD_IPC_WAIT_ANY. recv_base/recv_count — приёмное
/// окно capability получателя (ядро кладёт i-ю capability в первый
/// свободный слот окна; 0/0 — не принимать: сообщение с map items
/// отклонит отправителю). buf — буфер приёма (>= 24 байт;
/// см. NOMAD_IPC_BUF_LEN). Возврат: 0 — сообщение в buf (разбор через
/// nomad_ipc_msg_*); иначе код ошибки.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_wait(
    from: u64,
    recv_base: u64,
    recv_count: u64,
    buf: *mut u8,
    buf_len: u64,
) -> u64 {
    if buf.is_null() || buf_len < (HEADER_WORDS * 8) as u64 {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: buf — валидная память вызывающего на buf_len байт.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, buf_len as usize) };
    let from = if from == u64::MAX {
        ipc::WaitFrom::Any
    } else {
        ipc::WaitFrom::Slot(Slot::new(from))
    };
    match ipc::wait(
        from,
        ipc::RecvWindow {
            base: Slot::new(recv_base),
            count: recv_count,
        },
        slice,
    ) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Слот «ждать от кого угодно» (open wait) — wire-значение u64::MAX.
pub const NOMAD_IPC_WAIT_ANY: u64 = u64::MAX;

// ─── Разбор принятого сообщения (нулевые копии: указатели в buf) ───────────

/// task_cap_id отправителя (0 — буфер не валиден).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_msg_sender(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.sender).unwrap_or(0)
}

/// Тег (label) тела сообщения.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_msg_label(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.label).unwrap_or(0)
}

/// Указатель на payload (NULL — буфер не валиден). Живёт в buf.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_msg_payload(
    buf: *const u8,
    buf_len: u64,
    out_len: *mut u64,
) -> *const u8 {
    match msg_view(buf, buf_len) {
        Some(v) => {
            if !out_len.is_null() {
                // SAFETY: out_len — валидный u64 вызывающего (контракт).
                unsafe { *out_len = v.payload.len() as u64 };
            }
            v.payload.as_ptr()
        }
        None => core::ptr::null(),
    }
}

/// Число доставленных capability.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_msg_caps_count(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.caps_len as u64).unwrap_or(0)
}

/// Слот ПОЛУЧАТЕЛЯ i-й capability (u64::MAX — вне диапазона).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_ipc_msg_cap_slot(buf: *const u8, buf_len: u64, i: u64) -> u64 {
    match msg_view(buf, buf_len) {
        Some(v) => v
            .cap_slots
            .get(i as usize)
            .copied()
            .unwrap_or(u64::MAX),
        None => u64::MAX,
    }
}

struct MsgView {
    sender: u64,
    label: u64,
    payload: &'static [u8],
    caps_len: usize,
    cap_slots: [u64; MAX_CAPS],
}

/// SAFETY-контракт: buf — память вызывающего на buf_len байт (только
/// читается). Возврат 'static — время жизни привязано к buf (C-контракт).
fn msg_view(buf: *const u8, buf_len: u64) -> Option<MsgView> {
    if buf.is_null() || buf_len == 0 || buf_len as usize > isize::MAX as usize {
        return None;
    }
    // SAFETY: контракт выше.
    let slice = unsafe { core::slice::from_raw_parts(buf, buf_len as usize) };
    let parsed = ipc::parse_received(slice)?;
    // payload заимствует buf — продлеваем до 'static по C-контракту
    // (указатель отдаётся вызывающему, время жизни — его буфер).
    let payload: &'static [u8] = unsafe { core::mem::transmute(parsed.payload) };
    Some(MsgView {
        sender: parsed.sender.raw(),
        label: parsed.label,
        payload,
        caps_len: parsed.caps_len,
        cap_slots: {
            let mut raw = [0u64; MAX_CAPS];
            for (r, s) in raw.iter_mut().zip(parsed.cap_slots.iter()) {
                *r = s.raw();
            }
            raw
        },
    })
}

// ─── Таймер (L4-модель v2: тик — капа IrqLine на GSI из TASK_STATS) ────────

/// Частота тика (зеркало kernel_limine/kernel_x86::timer). Линия тика —
/// динамика платформы (GSI из MADT): берите из TASK_STATS (слово [10]);
/// на legacy-платформе — timer::FALLBACK_TIMER_LINE (0).
pub const NOMAD_TICK_HZ: u64 = crate::timer::TICK_HZ;

/// Уснуть до ближайшего тика таймера. buf — массив 2×u64
/// [count][line] (см. nomad_timer_wait_buf). Возврат — код сисколла
/// (0 — буфер заполнен: [0]=1, [1]=номер линии).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_wait_tick(buf: *mut u64) -> u64 {
    if buf.is_null() {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: buf — валидная память на 2×u64 (контракт C-ABI).
    let arr = unsafe { &mut *(buf.cast::<[u64; 2]>()) };
    // v2: клеймят лениво при первом вызове (капа в TICK_CAP_SLOT);
    // линия — из TASK_STATS (u32::MAX/сбой — legacy-линия 0).
    match lazy_claim_tick() {
        Ok(()) => {}
        Err(crate::syscall::SyscallError::Kernel(code)) => return code,
    }
    let caps = crate::timer::tick_caps_buf();
    match crate::timer::wait_tick(arr, &caps) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Ленивый claim линии тика (один раз на процесс; атомарный флаг).
fn lazy_claim_tick() -> Result<(), crate::syscall::SyscallError> {
    use core::sync::atomic::{AtomicBool, Ordering};
    static CLAIMED: AtomicBool = AtomicBool::new(false);
    if CLAIMED.load(Ordering::Acquire) {
        return Ok(());
    }
    let self_cap = crate::crt0::auxv_get(crate::abi::auxv::AT_NOMAD_SELF_CAP)
        .map_or_else(
            || crate::handle::TaskCap::new(u64::MAX),
            crate::handle::TaskCap::new,
        );
    let mut sbuf = crate::stats::stats_buf();
    let line = crate::stats::task_stats(self_cap, &mut sbuf)
        .map(|s| s.timer_line)
        .unwrap_or(crate::timer::FALLBACK_TIMER_LINE);
    crate::timer::claim_tick_line(self_cap, line)?;
    CLAIMED.store(true, Ordering::Release);
    Ok(())
}

// ─── Статистика (перенос отчётности в юзерспейс) ───────────────────────────

/// Снапшот статистики задачи для C (зеркало kernel_base::task::stats;
/// wire-блок 16×u64 — совместим побайтово с TASK_STATS).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NomadTaskStats {
    pub magic: u64,
    pub version: u64,
    pub task_cap_id: u64,
    pub cpu_ticks: u64,
    pub yields: u64,
    pub ipc_sent: u64,
    pub ipc_recv: u64,
    pub blocks: u64,
    pub global_ticks: u64,
    pub tick_hz: u64,
    pub preempts: u64,
    pub reserved: [u64; 5],
}

const _: () = assert!(core::mem::size_of::<NomadTaskStats>() == crate::stats::STATS_WORDS * 8);

/// Снапшот статистики задачи (своей — без прав, чужой — STATS_READ).
/// out — валидная память под sizeof(NomadTaskStats). Возврат — код
/// сисколла (0 — out заполнен).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_task_stats(task_cap_id: u64, out: *mut NomadTaskStats) -> u64 {
    if out.is_null() {
        return abi::result::E_INVALID_ARG;
    }
    let mut buf = crate::stats::stats_buf();
    match crate::stats::task_stats(crate::handle::TaskCap::new(task_cap_id), &mut buf) {
        Ok(_) => {
            // SAFETY: out — валидная память на размер структуры; wire-
            // блок побайтово совместим (assert размера выше).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr().cast::<u8>(),
                    out as *mut u8,
                    crate::stats::STATS_WORDS * 8,
                );
            }
            0
        }
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

// ─── Разделяемая память (длинные IPC без ядра в датапути) ─────────────────

/// Создать capability на разделяемый регион СОБСТВЕННОЙ памяти
/// (ALLOC_PAGES → сюда → пересылка IPC map-item'ом; монтаж получателем
/// — nomad_mount_cap_region). Монтирование получателем — ПО СЛОТУ
/// (старший бит — ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_cap_create_shared(src_vaddr: u64, pages: u64, dst_slot: u64) -> u64 {
    unsafe { crate::syscall::syscall3(abi::nr::CAP_CREATE_SHARED, src_vaddr, pages, dst_slot) }
}

/// Смонтировать capability-регион в своё пространство (возврат — VA,
/// старший бит — ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn nomad_mount_cap_region(cap_slot: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::MOUNT_CAP_REGION, cap_slot) }
}

/// Волшебное слово SPSC-кольца (проверка смонтированных страниц).
pub const NOMAD_SHM_RING_MAGIC: u64 = crate::shm::SHM_RING_MAGIC;

/// Инициализировать кольцо в СОБСТВЕННЫХ страницах (производитель).
/// va — возврат ALLOC_PAGES, pages — его же размер. Возврат: 0 — ок,
/// 1 — неверные аргументы.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_shm_producer_init(va: u64, pages: u64) -> u64 {
    // SAFETY: va — живая собственная аллокация pages страниц (контракт).
    match unsafe { crate::shm::Producer::init(va as usize, pages as usize) } {
        Some(_) => 0,
        None => 1,
    }
}

/// Кладёт кадр в кольцо (производитель). va/pages — ТЕ ЖЕ, что в
/// nomad_shm_producer_init: кольцо ПЕРЕОТКРЫВАЕТСЯ по заголовку (индексы
/// в самих страницах — переоткрытие их не трогает). Возврат: 0 — ок,
/// 1 — переполнено/ошибка.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_shm_push(va: u64, pages: u64, data: *const u8, len: u64) -> u64 {
    // SAFETY: va — инициализированное кольцо (контракт).
    let Some(mut prod) = (unsafe { crate::shm::Producer::open(va as usize, pages as usize) })
    else {
        return 1;
    };
    // SAFETY: data — валидная память на len байт (контракт).
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    u64::from(!prod.push(bytes))
}

/// Достаёт кадр из кольца (потребитель). va — возврат nomad_mount_cap_region,
/// pages — размер региона. Возврат — длина кадра; u64::MAX — пусто/ошибка.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_shm_pop(va: u64, pages: u64, out: *mut u8, out_len: u64) -> u64 {
    // SAFETY: va — живой внешний маппинг pages страниц (контракт).
    let Some(mut cons) = (unsafe { crate::shm::Consumer::open(va as usize, pages as usize) })
    else {
        return u64::MAX;
    };
    // SAFETY: out — валидная память на out_len байт (контракт).
    let buf = unsafe { core::slice::from_raw_parts_mut(out, out_len as usize) };
    match cons.pop(buf) {
        Some(n) => n as u64,
        None => u64::MAX,
    }
}

// ─── Фолт-эндпоинты (seL4/KeyKOS: keeper-модель) ─────────────────────────────

/// Код ошибки Rust-обвязки → C-возврат.
fn code_of(e: crate::syscall::SyscallError) -> u64 {
    match e {
        crate::syscall::SyscallError::Kernel(code) => code,
    }
}

/// Данные фолта (payload сообщения; 5×u64 = 40 байт).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NomadFaultInfo {
    /// Вектор исключения (NOMAD_FAULT_DE..NOMAD_FAULT_XF).
    pub kind: u64,
    /// Адрес фолта (CR2 для #PF, 0 иначе).
    pub addr: u64,
    /// RIP упавшей инструкции.
    pub ip: u64,
    /// RSP упавшей задачи.
    pub sp: u64,
    /// Код ошибки CPU (биты P/W/U/R для #PF, 0 иначе).
    pub err: u64,
}

const _: () = assert!(core::mem::size_of::<NomadFaultInfo>() == 5 * 8);

/// Создать фолт-эндпоинт: ТЕКУЩАЯ задача становится обработчиком,
/// capability — в dst_slot её cspace. Требует CAP_MANAGE|FAULT_HANDLE.
/// 0 — ок; иначе NOMAD_E_*.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_fault_create_endpoint(dst_slot: u64) -> u64 {
    match crate::fault::create_endpoint(Slot::new(dst_slot)) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Привязать эндпоинт (ep_slot текущей задачи) к ЦЕЛИ (её TaskTCB-слот):
/// фолты цели пойдут обработчику через nomad_ipc_wait. Требует
/// TASK_CREATE|FAULT_HANDLE; повторная привязка заменяет прежнюю.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_fault_set_endpoint(ep_slot: u64, target_slot: u64) -> u64 {
    match crate::fault::set_endpoint(Slot::new(ep_slot), Slot::new(target_slot)) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Ответить на фолт (resume упавшей): new_rip/new_rsp = 0 — повторить
/// упавшую инструкцию; иначе — продолжить с нового адреса/стека.
/// Валиден только зарегистрированному обработчику ПОСЛЕ приёма
/// сообщения. 0 — ок; NOMAD_E_NOT_FOUND — задача не в фолте;
/// NOMAD_E_RIGHTS — зовёт не обработчик; NOMAD_E_INVALID_ARG —
/// сообщение ещё не принято.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_fault_reply(
    target_task_cap: u64,
    new_rip: u64,
    new_rsp: u64,
) -> u64 {
    match crate::fault::reply(crate::handle::TaskCap::new(target_task_cap), new_rip, new_rsp) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Это фолт-сообщение? (label == NOMAD_FAULT_LABEL). 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_fault_is(buf: *const u8, buf_len: u64) -> u64 {
    u64::from(msg_view(buf, buf_len).is_some_and(|v| v.label == crate::fault::FAULT_LABEL))
}

/// Разбор фолт-сообщения из буфера приёма. out_info — валидный
/// NomadFaultInfo вызывающего. 0 — заполнено; NOMAD_E_INVALID_ARG — не
/// фолт/плохой буфер. sender (task_cap_id упавшей) — как обычно,
/// nomad_ipc_msg_sender.
#[unsafe(no_mangle)]
pub extern "C" fn nomad_fault_parse(
    buf: *const u8,
    buf_len: u64,
    out_info: *mut NomadFaultInfo,
) -> u64 {
    let Some(view) = msg_view(buf, buf_len) else {
        return abi::result::E_INVALID_ARG;
    };
    if out_info.is_null() || view.label != crate::fault::FAULT_LABEL {
        return abi::result::E_INVALID_ARG;
    }
    if view.payload.len() != crate::fault::FAULT_MSG_WORDS * 8 {
        return abi::result::E_INVALID_ARG;
    }
    let word = |i: usize| -> u64 {
        u64::from_le_bytes(view.payload[i * 8..(i + 1) * 8].try_into().unwrap())
    };
    // SAFETY: out_info — валидная структура вызывающего (контракт).
    unsafe {
        *out_info = NomadFaultInfo {
            kind: word(0),
            addr: word(1),
            ip: word(2),
            sp: word(3),
            err: word(4),
        };
    }
    0
}
