//! init_system — каркас init-сервера NOMAD (workspace-заглушка).
#![no_std]
//!
//! Крейт держит место под будущий init-сервер: bootstrap userland
//! (спавн boot-модулей через TASK_CREATE, раздача capability,
//! консольный сервис поверх DBG_LOG_READ). Пока реализация пуста,
//! но крейт должен собираться, чтобы workspace оставался зелёным
//! (пустой Cargo.toml без src/ валит весь workspace: cargo не может
//! разобрать member без таргетов).
//!
//! План вехи 0.1-beta: забрать у kernel_limine регистрацию серверов
//! (spawn_boot_servers) в userspace — ядро спавнит только init,
//! остальное init раскатывает сам по роcтеру boot-модулей.
