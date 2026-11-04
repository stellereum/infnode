//! infnode — сетевой слой (протокол): QUIC + DHT + storage (чанки RF≤3) + rewards + proof-of-storage.
//! НЕ содержит бизнес-логики почты (она в крейте `infmail`). Годится и для почты, и для блокчейна.

pub mod config;
pub mod dht;
pub mod federation;
pub mod keyring;
pub mod log;
pub mod mailbox;
pub mod metrics;
pub mod migration;
pub mod node;
pub mod proto;
pub mod reputation;
pub mod rewards;
pub mod services;
pub mod totp;
