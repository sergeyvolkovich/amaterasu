//! proto — типизированные прототипы IPC-сообщений NOMAD.
//!
//! Сериализация целиком в юзерспейсе: ядро — чистый L4-транспорт,
//! payload не разбирает (см. [`crate::flatbuf`]). Здесь — ПРИМЕР
//! протокола поверх generic-слоя [`crate::flatbuf`]: fb-сервис
//! «информация о задаче».
//!
//! ИЕРАРХИЯ сообщений:
//!
//! ```text
//! ipc::send(peer, label, payload)                     ← транспорт
//!   └─ конверт IpcMessage {0: label u64, 1: payload}  ← flatbuf::Builder
//!        └─ payload = таблица протокола               ← ЭТОТ МОДУЛЬ
//! ```
//!
//! Метка конверта (label) — тег типа сообщения (MR0 у Лидтке):
//! [`FB_INFO_REQ`] — запрос без тела (payload пуст), [`FB_INFO_RSP`] —
//! в payload таблица [`encode_info_rsp`]/[`InfoRspRef`].
//!
//! ПРАВИЛА ЭВОЛЮЦИИ СХЕМ (каноника FlatBuffers, обязательны):
//!   1. id поля ТОЛЬКО добавляется в конец; переиспользовать/удалять
//!      существующие id нельзя (старые клиенты прочитают новое поле
//!      старым типом — мусор, а не ошибка/паника);
//!   2. тип существующего id НЕ меняется;
//!   3. отсутствующее поле = значение по умолчанию (0 / "" / []);
//!   4. читатель обязан толерантно принимать буферы ЛЮБОЙ более старой
//!      И более новой версии схемы (vtable сам скрывает отсутствующие
//!      и лишние поля).
//!
//! Верификация: [`TableRef::parse`] проверяет структуру буфера
//! (буфер может прийти от чужой задачи), типизированные обёртки
//! ([`InfoRspRef`]) фиксируют соответствие геттеров схеме.

#![forbid(unsafe_code)]

use crate::flatbuf::{EncodeError, TableBuilder, TableRef};

/// Запрос «информация о задаче» (payload конверта пуст).
pub const FB_INFO_REQ: u64 = 0xFB10;

/// Ответ «информация о задаче» (payload — таблица InfoRsp).
pub const FB_INFO_RSP: u64 = 0xFB11;

// ─── InfoReq ────────────────────────────────────────────────────────────────

/// Схема InfoReq: `{0: req_id u32}` — сквозной номер запроса для
/// сопоставления ответов (сервер обязан эхом вернуть его в InfoRsp).
///
/// Эволюция: новые поля (например, маска запрашиваемого) добавлять
/// ТОЛЬКО новым id (1, 2, ...) — старые серверы их игнорируют.
pub fn encode_info_req(out: &mut [u8], req_id: u32) -> Result<usize, EncodeError> {
    let mut b = TableBuilder::<2>::new();
    b.set(0, req_id.into())?;
    b.encode(out)
}

// ─── InfoRsp ────────────────────────────────────────────────────────────────

/// Схема InfoRsp:
///
/// ```fbs
/// table InfoRsp {
///   req_id:   u32;   // id 0: эхо запроса
///   version:  string;// id 1: версия сервера (v1)
///   uptime_s: u64;   // id 2: аптайм в секундах (v2)
/// }
/// ```
///
/// v1-сервер пишет id 0..1, v2 — id 0..2; читатель любой версии
/// работает с любым буфером (см. тесты ниже).
pub fn encode_info_rsp(
    out: &mut [u8],
    req_id: u32,
    version: &str,
    uptime_s: u64, // поле v2; v1-сервер его не пишет
) -> Result<usize, EncodeError> {
    let mut b = TableBuilder::<4>::new();
    b.set(0, req_id.into())?;
    b.set_str(1, version)?;
    b.set(2, uptime_s.into())?;
    b.encode(out)
}

/// Типизированное представление таблицы InfoRsp поверх чужого буфера
/// (zero-copy). Геттеры фиксируют соответствие типов схеме: чтение
/// отсутствующего поля даёт дефолт, испорченного — дефолт-ответ
/// (`None` внутри приведено к безопасному значению).
#[derive(Debug, Clone, Copy)]
pub struct InfoRspRef<'a> {
    t: TableRef<'a>,
}

impl<'a> InfoRspRef<'a> {
    /// Верифицирует буфер как таблицу. `None` — структура нарушена
    /// (не InfoRsp / усечено / мусор).
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        TableRef::parse(buf).map(|t| Self { t })
    }

    /// Эхо req_id запроса (0 — поле отсутствует/испорчено).
    pub fn req_id(&self) -> u32 {
        self.t.get_u32(0, 0).unwrap_or(0)
    }

    /// Версия сервера ("" — поле отсутствует/испорчено).
    pub fn version(&self) -> &'a str {
        self.t.get_str(1).unwrap_or("")
    }

    /// Аптайм в секундах (0 — поле отсутствует: сервер v1).
    pub fn uptime_s(&self) -> u64 {
        self.t.get_u64(2, 0).unwrap_or(0)
    }
}

// ─── Тесты ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flatbuf::MAX_MSG;

    #[test]
    fn info_req_roundtrip() {
        let mut out = [0u8; MAX_MSG];
        let n = encode_info_req(&mut out, 0xABCD).expect("encode");
        let t = TableRef::parse(&out[..n]).expect("parse");
        assert_eq!(t.get_u32(0, 0), Some(0xABCD));
        // Запрос без тела: в конверте едёт только эта таблица.
        assert_eq!(t.get_bytes(1), Some(&[][..]));
    }

    #[test]
    fn info_rsp_roundtrip_full() {
        let mut out = [0u8; MAX_MSG];
        let n = encode_info_rsp(&mut out, 7, "nomad-0.9", 123_456).expect("encode");
        let rsp = InfoRspRef::parse(&out[..n]).expect("parse");
        assert_eq!(rsp.req_id(), 7);
        assert_eq!(rsp.version(), "nomad-0.9");
        assert_eq!(rsp.uptime_s(), 123_456);
    }

    #[test]
    fn info_rsp_evolution_v1_buffer_read_by_v2() {
        // Сервер v1: только req_id + version (uptime не знает).
        let version = "0.9";
        let mut b = TableBuilder::<4>::new();
        b.set(0, 9u32.into()).unwrap();
        b.set_str(1, version).unwrap();
        let mut out = [0u8; MAX_MSG];
        let n = b.encode(&mut out).expect("encode");

        // Клиент v2: видит свои поля, uptime — дефолт (не мусор, не паника).
        let old = InfoRspRef::parse(&out[..n]).expect("parse");
        assert_eq!(old.req_id(), 9);
        assert_eq!(old.version(), "0.9");
        assert_eq!(old.uptime_s(), 0);
    }

    #[test]
    fn info_rsp_evolution_v2_buffer_read_by_v1() {
        // Сервер v2: все три поля.
        let mut out = [0u8; MAX_MSG];
        let n = encode_info_rsp(&mut out, 11, "1.0.0", 7200).expect("encode");

        // Клиент v1: читает только id 0..1, лишнее игнорирует безвредно.
        let t = TableRef::parse(&out[..n]).expect("parse");
        assert_eq!(t.get_u32(0, 0), Some(11));
        assert_eq!(t.get_str(1), Some("1.0.0"));
    }

    #[test]
    fn labels_are_distinct_tags() {
        // Метки конверта — устойчивые теги типов сообщений (MR0).
        assert_ne!(FB_INFO_REQ, FB_INFO_RSP);
    }

    #[test]
    fn corrupted_payload_is_rejected_by_parse() {
        let mut out = [0u8; MAX_MSG];
        let n = encode_info_rsp(&mut out, 1, "x", 2).expect("encode");

        // Усечение любой длины ломает структуру или не даёт полей.
        for cut in 1..n {
            let r = InfoRspRef::parse(&out[..cut]);
            if let Some(rsp) = r {
                // Структура могла уцелеть (таблица рано) — поля обязаны
                // быть дефолтными, но не паниковать.
                let _ = rsp.req_id();
                let _ = rsp.version();
                let _ = rsp.uptime_s();
            }
        }
        // Полный буфер валиден.
        assert!(InfoRspRef::parse(&out[..n]).is_some());

        // Порча корня.
        let mut bad = out;
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(InfoRspRef::parse(&bad).is_none());
    }
}
