//! IPC-подсистема.
//!
//! [`endpoint`] — проволочный формат + побайтовые копии userspace
//! (стиль Лидтке/L4: ядро не разбирает payload; сериализация —
//! юзерспейс). [`transport`] — оркестрация rendezvous поверх
//! TCB-состояния (task::ipc_state; почтовых ящиков нет — классический
//! L4: сообщение остаётся в буфере заблокированного отправителя).
//! [`gate`] — гейты-мультиплексоры (seL4-эндпоинты). [`cap_transfer`] —
//! пересылка capability при доставке (аналог L4 map items). [`fault`] —
//! фолт-эндпоинты (стиль seL4/KeyKOS): доставка фолтов ring3-задач их
//! обработчикам тем же транспортом + resume-механика.
pub mod cap_transfer;
pub mod endpoint;
pub mod fault;
pub mod gate;
pub mod transport;
