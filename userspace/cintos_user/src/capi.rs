//! capi — C-совместимый ABI юзерспейса NOMAD.
//!
//! Требование «коду юзерспейса нужна Си-совместимость»: вся
//! функциональность библиотеки (IPC-транспорт, FlatBuffers-разбор,
//! сисколлы, auxv) доступна из C через стабильные `extern "C"`
//! символы с C-типами; сигнатуры зеркалятся заголовком
//! `cintos_user/include/cintos.h`. Ни одного Rust-типа в сигнатурах;
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

use core::ffi::c_void;

use crate::abi;
use crate::ipc::{self, HEADER_WORDS, MAX_CAPS};

// ─── Общие ──────────────────────────────────────────────────────────────────

/// Размер буфера приёма IPC, рекомендованный C-коду (байт).
pub const CINT_IPC_BUF_LEN: usize = 1024;

/// Локальная ошибка «сообщение не влезает в транспорт».
pub const CINT_E_MSG_TOO_BIG: u64 = ipc::E_MSG_TOO_BIG;

/// Уступить квант планировщику.
#[unsafe(no_mangle)]
pub extern "C" fn cint_sched_yield() -> u64 {
    unsafe { crate::syscall::syscall0(abi::nr::SCHED_YIELD) }
}

/// Строка в лог ядра (serial + кольцо). Возврат — код сисколла.
#[unsafe(no_mangle)]
pub extern "C" fn cint_log_write(ptr: *const u8, len: u64) -> u64 {
    unsafe { crate::syscall::syscall2(abi::nr::DBG_LOG_WRITE, ptr as u64, len) }
}

/// Значение auxv по тегу (0 — тег отсутствует).
#[unsafe(no_mangle)]
pub extern "C" fn cint_auxv_get(tag: u64) -> u64 {
    crate::crt0::auxv_get(tag).unwrap_or(0)
}

/// task_cap_id текущей задачи (AT_CINTOS_SELF_CAP; 0 — отсутствует).
#[unsafe(no_mangle)]
pub extern "C" fn cint_self_cap() -> u64 {
    cint_auxv_get(abi::auxv_values::AT_CINTOS_SELF_CAP)
}

/// Self-exit: уничтожить текущую задачу (выходит из main по возврату;
/// C-код может позвать явно).
#[unsafe(no_mangle)]
pub extern "C" fn cint_exit() -> u64 {
    let self_cap = cint_self_cap();
    unsafe { crate::syscall::syscall1(abi::nr::SCHED_DESTROY_TASK, self_cap) }
}

// ─── Память ─────────────────────────────────────────────────────────────────

/// Выделить `pages` страниц; возврат — VA (старший бит = ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn cint_alloc_pages(pages: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::ALLOC_PAGES, pages) }
}

/// Снять аллокацию по базовому VA.
#[unsafe(no_mangle)]
pub extern "C" fn cint_free_pages(vaddr: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::FREE_PAGES, vaddr) }
}

// ─── IPC ────────────────────────────────────────────────────────────────────

/// Дескриптор пересылки capability для C (L4 map item): 24 байта,
/// раскладка синхронизирована с Rust `ipc::CapDesc` и ядром.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CintCapDesc {
    pub src_slot: u64,
    pub dst_slot: u64,
    pub rights: u64,
}

const _: () = assert!(core::mem::size_of::<CintCapDesc>() == 24);

/// Синхронная отправка (блокируется до приёма).
///
/// slot — слот cspace получателя; label/payload — тело (FlatBuffers
/// соберёт ядро-независимый формат внутри); caps — массив
/// CintCapDesc×caps_len (может быть NULL при caps_len=0).
/// Возврат: 0 — доставлено; иначе код ошибки (старший бит).
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_send(
    slot: u64,
    label: u64,
    payload: *const u8,
    payload_len: u64,
    caps: *const CintCapDesc,
    caps_len: u64,
) -> u64 {
    if payload_len as usize > crate::flatbuf::MAX_MSG {
        return ipc::E_MSG_TOO_BIG;
    }
    // SAFETY: payload — валидная память вызывающего на payload_len байт
    // (контракт C-ABI).
    let payload = unsafe {
        core::slice::from_raw_parts(payload, payload_len as usize)
    };
    let mut rust_caps = [ipc::CapDesc::new(0, 0, 0); MAX_CAPS];
    let n = (caps_len as usize).min(MAX_CAPS);
    // SAFETY: caps — валидный массив CintCapDesc×caps_len (контракт).
    let src = if caps.is_null() || n == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(caps.cast::<CintCapDesc>(), n) }
    };
    for (dst, s) in rust_caps.iter_mut().zip(src.iter()) {
        *dst = ipc::CapDesc::new(s.src_slot, s.dst_slot, s.rights);
    }
    match ipc::send(slot, label, payload, &rust_caps[..n]) {
        Ok(()) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Ожидание сообщения (блокируется до доставки). from — слот
/// отправителя или CINT_IPC_WAIT_ANY. recv_base/recv_count — приёмное
/// окно capability получателя (ядро кладёт i-ю capability в первый
/// свободный слот окна; 0/0 — не принимать: сообщение с map items
/// отклонит отправителю). buf — буфер приёма (>= 24 байт;
/// см. CINT_IPC_BUF_LEN). Возврат: 0 — сообщение в buf (разбор через
/// cint_ipc_msg_*); иначе код ошибки.
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_wait(
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
    match ipc::wait(from, ipc::RecvWindow { base: recv_base, count: recv_count }, slice) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

/// Слот «ждать от кого угодно» (open wait).
pub const CINT_IPC_WAIT_ANY: u64 = ipc::WAIT_ANY;

// ─── Разбор принятого сообщения (нулевые копии: указатели в buf) ───────────

/// task_cap_id отправителя (0 — буфер не валиден).
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_msg_sender(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.sender).unwrap_or(0)
}

/// FlatBuffers-тег (label) тела сообщения.
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_msg_label(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.label).unwrap_or(0)
}

/// Указатель на payload (NULL — буфер не валиден). Живёт в buf.
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_msg_payload(
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
pub extern "C" fn cint_ipc_msg_caps_count(buf: *const u8, buf_len: u64) -> u64 {
    msg_view(buf, buf_len).map(|v| v.caps_len as u64).unwrap_or(0)
}

/// Слот ПОЛУЧАТЕЛЯ i-й capability (u64::MAX — вне диапазона).
#[unsafe(no_mangle)]
pub extern "C" fn cint_ipc_msg_cap_slot(buf: *const u8, buf_len: u64, i: u64) -> u64 {
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
        sender: parsed.sender,
        label: parsed.label,
        payload,
        caps_len: parsed.caps_len,
        cap_slots: parsed.cap_slots,
    })
}

// ─── FlatBuffers-сборка (для C без Rust-типов) ───────────────────────────────

/// КОНТЕКСТ: сборщик FlatBuffers-тела сообщения. Размер — CINT_FB_CTX_SIZE
/// (выделяйте CintFbCtx по значению; аллокаций нет).
#[repr(C)]
pub struct CintFbCtx {
    _private: [u8; 0],
}

/// Размер контекста сборщика (байт) — sizeof в C берётся из заголовка,
/// здесь — для статической проверки зеркала.
pub const CINT_FB_CTX_SIZE: usize = core::mem::size_of::<crate::flatbuf::Builder>();

/// Инициализация сборщика в ctx (обязан вмещать CINT_FB_CTX_SIZE байт).
#[unsafe(no_mangle)]
pub extern "C" fn cint_fb_init(ctx: *mut c_void) {
    // SAFETY: ctx — валидная память на CINT_FB_CTX_SIZE байт (контракт).
    unsafe { (ctx as *mut crate::flatbuf::Builder).write(crate::flatbuf::Builder::new()) };
}

/// Тег сообщения.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fb_label(ctx: *mut c_void, label: u64) {
    // SAFETY: ctx — инициализированный Builder.
    unsafe {
        (*(ctx as *mut crate::flatbuf::Builder)).label(label);
    }
}

/// Payload (байты копируются в контекст; повторный вызов перезаписывает).
#[unsafe(no_mangle)]
pub extern "C" fn cint_fb_payload(ctx: *mut c_void, ptr: *const u8, len: u64) {
    // SAFETY: ctx + ptr — контракты выше.
    unsafe {
        let b = &mut *(ctx as *mut crate::flatbuf::Builder);
        let bytes = core::slice::from_raw_parts(ptr, len as usize);
        b.payload(bytes);
    }
}

/// Финализация: в buf_len — размер, возврат — указатель на готовое
/// тело (живёт в ctx) или NULL (переполнение).
#[unsafe(no_mangle)]
pub extern "C" fn cint_fb_finish(ctx: *mut c_void, out_len: *mut u64) -> *const u8 {
    // SAFETY: контракты выше.
    unsafe {
        let b = &mut *(ctx as *mut crate::flatbuf::Builder);
        match b.finish() {
            Some(wire) => {
                if !out_len.is_null() {
                    *out_len = wire.len() as u64;
                }
                wire.as_ptr()
            }
            None => core::ptr::null(),
        }
    }
}

// ─── Таймер (L4-модель: тик — линия IRQ0) ──────────────────────────────────

/// Линия тика и частота (зеркала kernel_limine/kernel_x86::timer).
pub const CINT_TIMER_LINE: u32 = crate::timer::TIMER_IRQ_LINE;
pub const CINT_TICK_HZ: u64 = crate::timer::TICK_HZ;

/// Уснуть до ближайшего тика таймера. buf — массив 2×u64
/// [count][line] (см. cint_timer_wait_buf). Возврат — код сисколла
/// (0 — буфер заполнен: [0]=1, [1]=номер линии).
#[unsafe(no_mangle)]
pub extern "C" fn cint_wait_tick(buf: *mut u64) -> u64 {
    if buf.is_null() {
        return abi::result::E_INVALID_ARG;
    }
    // SAFETY: buf — валидная память на 2×u64 (контракт C-ABI).
    let arr = unsafe { &mut *(buf.cast::<[u64; 2]>()) };
    match crate::timer::wait_tick(arr) {
        Ok(_) => 0,
        Err(crate::syscall::SyscallError::Kernel(code)) => code,
    }
}

// ─── Статистика (перенос отчётности в юзерспейс) ───────────────────────────

/// Снапшот статистики задачи для C (зеркало kernel_base::task::stats;
/// wire-блок 16×u64 — совместим побайтово с TASK_STATS).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CintTaskStats {
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
    pub reserved: [u64; 6],
}

const _: () = assert!(core::mem::size_of::<CintTaskStats>() == crate::stats::STATS_WORDS * 8);

/// Снапшот статистики задачи (своей — без прав, чужой — STATS_READ).
/// out — валидная память под sizeof(CintTaskStats). Возврат — код
/// сисколла (0 — out заполнен).
#[unsafe(no_mangle)]
pub extern "C" fn cint_task_stats(task_cap_id: u64, out: *mut CintTaskStats) -> u64 {
    if out.is_null() {
        return abi::result::E_INVALID_ARG;
    }
    let mut buf = crate::stats::stats_buf();
    match crate::stats::task_stats(task_cap_id, &mut buf) {
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
/// — cint_mount_cap_region). Монтирование получателем — ПО СЛОТУ
/// (старший бит — ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn cint_cap_create_shared(src_vaddr: u64, pages: u64, dst_slot: u64) -> u64 {
    unsafe { crate::syscall::syscall3(abi::nr::CAP_CREATE_SHARED, src_vaddr, pages, dst_slot) }
}

/// Смонтировать capability-регион в своё пространство (возврат — VA,
/// старший бит — ошибка).
#[unsafe(no_mangle)]
pub extern "C" fn cint_mount_cap_region(cap_slot: u64) -> u64 {
    unsafe { crate::syscall::syscall1(abi::nr::MOUNT_CAP_REGION, cap_slot) }
}

/// Волшебное слово SPSC-кольца (проверка смонтированных страниц).
pub const CINT_SHM_RING_MAGIC: u64 = crate::shm::SHM_RING_MAGIC;

/// Инициализировать кольцо в СОБСТВЕННЫХ страницах (производитель).
/// va — возврат ALLOC_PAGES, pages — его же размер. Возврат: 0 — ок,
/// 1 — неверные аргументы.
#[unsafe(no_mangle)]
pub extern "C" fn cint_shm_producer_init(va: u64, pages: u64) -> u64 {
    // SAFETY: va — живая собственная аллокация pages страниц (контракт).
    match unsafe { crate::shm::Producer::init(va as usize, pages as usize) } {
        Some(_) => 0,
        None => 1,
    }
}

/// Кладёт кадр в кольцо (производитель). va/pages — ТЕ ЖЕ, что в
/// cint_shm_producer_init: кольцо ПЕРЕОТКРЫВАЕТСЯ по заголовку (индексы
/// в самих страницах — переоткрытие их не трогает). Возврат: 0 — ок,
/// 1 — переполнено/ошибка.
#[unsafe(no_mangle)]
pub extern "C" fn cint_shm_push(va: u64, pages: u64, data: *const u8, len: u64) -> u64 {
    // SAFETY: va — инициализированное кольцо (контракт).
    let Some(mut prod) = (unsafe { crate::shm::Producer::open(va as usize, pages as usize) })
    else {
        return 1;
    };
    // SAFETY: data — валидная память на len байт (контракт).
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    u64::from(!prod.push(bytes))
}

/// Достаёт кадр из кольца (потребитель). va — возврат cint_mount_cap_region,
/// pages — размер региона. Возврат — длина кадра; u64::MAX — пусто/ошибка.
#[unsafe(no_mangle)]
pub extern "C" fn cint_shm_pop(va: u64, pages: u64, out: *mut u8, out_len: u64) -> u64 {
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
pub struct CintFaultInfo {
    /// Вектор исключения (CINT_FAULT_DE..CINT_FAULT_XF).
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

const _: () = assert!(core::mem::size_of::<CintFaultInfo>() == 5 * 8);

/// Создать фолт-эндпоинт: ТЕКУЩАЯ задача становится обработчиком,
/// capability — в dst_slot её cspace. Требует CAP_MANAGE|FAULT_HANDLE.
/// 0 — ок; иначе CINT_E_*.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fault_create_endpoint(dst_slot: u64) -> u64 {
    match crate::fault::create_endpoint(dst_slot) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Привязать эндпоинт (ep_slot текущей задачи) к ЦЕЛИ (её TaskTCB-слот):
/// фолты цели пойдут обработчику через cint_ipc_wait. Требует
/// TASK_CREATE|FAULT_HANDLE; повторная привязка заменяет прежнюю.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fault_set_endpoint(ep_slot: u64, target_slot: u64) -> u64 {
    match crate::fault::set_endpoint(ep_slot, target_slot) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Ответить на фолт (resume упавшей): new_rip/new_rsp = 0 — повторить
/// упавшую инструкцию; иначе — продолжить с нового адреса/стека.
/// Валиден только зарегистрированному обработчику ПОСЛЕ приёма
/// сообщения. 0 — ок; CINT_E_NOT_FOUND — задача не в фолте;
/// CINT_E_RIGHTS — зовёт не обработчик; CINT_E_INVALID_ARG —
/// сообщение ещё не принято.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fault_reply(
    target_task_cap: u64,
    new_rip: u64,
    new_rsp: u64,
) -> u64 {
    match crate::fault::reply(target_task_cap, new_rip, new_rsp) {
        Ok(()) => 0,
        Err(e) => code_of(e),
    }
}

/// Это фолт-сообщение? (label == CINT_FAULT_LABEL). 1/0.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fault_is(buf: *const u8, buf_len: u64) -> u64 {
    u64::from(msg_view(buf, buf_len).is_some_and(|v| v.label == crate::fault::FAULT_LABEL))
}

/// Разбор фолт-сообщения из буфера приёма. out_info — валидный
/// CintFaultInfo вызывающего. 0 — заполнено; CINT_E_INVALID_ARG — не
/// фолт/плохой буфер. sender (task_cap_id упавшей) — как обычно,
/// cint_ipc_msg_sender.
#[unsafe(no_mangle)]
pub extern "C" fn cint_fault_parse(
    buf: *const u8,
    buf_len: u64,
    out_info: *mut CintFaultInfo,
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
        *out_info = CintFaultInfo {
            kind: word(0),
            addr: word(1),
            ip: word(2),
            sp: word(3),
            err: word(4),
        };
    }
    0
}
