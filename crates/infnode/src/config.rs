use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const NODEID_PREFIX: &str = "inf1:";

fn default_allow() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_unknown_allow() -> Vec<String> {
    // TOFU-нодам — только discovery (read-only). Не store (запись в DHT),
    // не pubsub/сервисы. Полное доверие — после pin в конфиге.
    vec![
        "dht.lookup".to_string(),
        "dht.update".to_string(),
        "dht.find_node".to_string(),
        "dht.find_value".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PeerConfig {
    pub name: String,
    /// Pinned Ed25519 key (32 bytes hex). Retained for frozen handshake-auth
    /// (`PinnedVerifier`, signature `VerifyingKey` checks) and TLS SPKI pin.
    /// NOT identity in FULL-PQ (identity is PQ-only via `pq_pub`/`primary_id`).
    /// Auth/TLS policy is frozen (sibling owns); this pin stays until the
    /// Falcon-TLS/auth follow-up migrates those call sites.
    pub ed_pub: String,
    /// Falcon-512 long-term PQ public key (897 bytes, hex). MANDATORY in
    /// FULL-PQ (a peer without it is refused by `primary_id` /
    /// `dual_announce_ids`). `Option` in the in-memory shape only so
    /// dynamically discovered (DHT/TOFU) peers — constructed in code, never
    /// parsed — can exist without a pin (they fail closed at `primary_id`
    /// and at the KEM-only handshake); parsed operator configs MUST carry
    /// it (see manual `Deserialize` impl: missing/legacy fails LOUDLY).
    pub pq_pub: Option<String>,
    pub endpoints: Vec<String>,
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
    /// лимит запросов/сек от этого пира (0 = без лимита)
    #[serde(default)]
    pub rate_limit_per_sec: u32,
    /// роль (RBAC): раскрывается в allow-список через roles ноды
    #[serde(default)]
    pub role: Option<String>,
    /// роль хранения пира: ["mail"] / ["files"] / обе (пусто = все бакеты)
    #[serde(default)]
    pub storage_roles: Vec<String>,
}

// Manual `Deserialize` for FULL-PQ wipe (nodes wiped, no compat):
// - `node_id` / `x_pub` REMOVED (identity is PQ-only via `pq_pub`;
//   X3DH leg cut by sibling — no static X25519 remains).
//   Presence fails LOUDLY with a migration error (never silent, never
//   ignored via `deny_unknown_fields` generic message).
// - `pq_pub` MANDATORY for parsed configs: absent fails LOUDLY.
// - `ed_pub` REQUIRED (frozen auth/TLS pin, sibling owns).
impl<'de> serde::Deserialize<'de> for PeerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct Helper {
            name: String,
            #[serde(default)]
            node_id: Option<String>,
            ed_pub: Option<String>,
            #[serde(default)]
            x_pub: Option<String>,
            #[serde(default)]
            pq_pub: Option<String>,
            #[serde(default)]
            endpoints: Vec<String>,
            #[serde(default = "default_allow")]
            allow: Vec<String>,
            #[serde(default)]
            rate_limit_per_sec: u32,
            #[serde(default)]
            role: Option<String>,
            #[serde(default)]
            storage_roles: Vec<String>,
        }
        let h = Helper::deserialize(deserializer)?;
        if h.node_id.is_some() {
            return Err(serde::de::Error::custom(format!(
                "peer '{}' uses removed field `node-id`: FULL-PQ wipe — delete `node-id`/`ed-pub`/`x-pub` classical pins, set `pq-pub` (Falcon-512, 897 bytes hex); nodes wiped, no compat",
                h.name
            )));
        }
        if h.x_pub.is_some() {
            return Err(serde::de::Error::custom(format!(
                "peer '{}' uses removed field `x-pub`: FULL-PQ wipe (X3DH leg cut, no static X25519) — delete `node-id`/`x-pub`, keep `ed-pub` (frozen auth/TLS pin) + set mandatory `pq-pub`; nodes wiped, no compat",
                h.name
            )));
        }
        let ed_pub = h.ed_pub.ok_or_else(|| {
            serde::de::Error::custom(format!(
                "peer '{}' missing `ed-pub` (frozen auth/TLS pin, still required)",
                h.name
            ))
        })?;
        let pq_pub = h.pq_pub.filter(|s| !s.is_empty());
        let Some(pq_pub) = pq_pub else {
            return Err(serde::de::Error::custom(format!(
                "peer '{}' missing mandatory `pq-pub` (FULL-PQ wipe: classical-only peer refused; provide Falcon-512 pq_pub hex)",
                h.name
            )));
        };
        // Fail fast on malformed PQ pin (same rule as `pq_bytes`: 897 bytes hex).
        let pq_bytes = hex::decode(&pq_pub).map_err(|_| {
            serde::de::Error::custom(format!(
                "peer '{}' has malformed `pq-pub` (must be 897 bytes hex)",
                h.name
            ))
        })?;
        if pq_bytes.len() != crate::proto::PQ_FALCON_PK_LEN {
            return Err(serde::de::Error::custom(format!(
                "peer '{}' has malformed `pq-pub` (must be 897 bytes hex)",
                h.name
            )));
        }
        Ok(PeerConfig {
            name: h.name,
            ed_pub,
            pq_pub: Some(pq_pub),
            endpoints: h.endpoints,
            allow: h.allow,
            rate_limit_per_sec: h.rate_limit_per_sec,
            role: h.role,
            storage_roles: h.storage_roles,
        })
    }
}

impl PeerConfig {
    /// allow-список с учётом роли (role раскрывается через roles).
    pub fn effective_allow(&self, roles: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut out = self.allow.clone();
        if let Some(role) = &self.role {
            if let Some(list) = roles.get(role) {
                for a in list {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        out
    }

    pub fn ed_bytes(&self) -> Result<[u8; 32]> {
        let b = hex::decode(&self.ed_pub)?;
        b.try_into()
            .map_err(|_| anyhow!("ed_pub должен быть 32 байта"))
    }

    /// Raw Falcon-512 public key, or `None` when absent (absent = refused
    /// by `primary_id`/`dual_announce_ids`, never silently classical).
    /// A present-but-malformed value is a hard error (fail closed).
    /// `None` only occurs for code-constructed dynamic (DHT/TOFU) peers;
    /// parsed configs always carry `Some` (enforced at parse).
    pub fn pq_bytes(&self) -> Result<Option<[u8; crate::proto::PQ_FALCON_PK_LEN]>> {
        let Some(s) = self.pq_pub.as_deref() else {
            return Ok(None);
        };
        let b = hex::decode(s)?;
        b.try_into()
            .map_err(|_| anyhow!("pq_pub должен быть 897 байт"))
            .map(Some)
    }

    /// Primary identity for this peer under the PQ-only re-ceremony
    /// (`keyring::resolve_node_id` peer-side mirror): the PQ id derived via
    /// `proto::pq_id_from_pub`. PQ is MANDATORY — a peer without a pinned
    /// `pq_pub` is refused (FULL-PQ wipe, no classical fallback).
    pub fn primary_id(&self) -> Result<[u8; crate::proto::NODEID_LEN]> {
        let Some(pq) = self.pq_bytes()? else {
            return Err(anyhow!("pq_pub is mandatory (classical-only peer refused)"));
        };
        Ok(crate::proto::pq_id_from_pub(&pq))
    }

    /// PQ-only announce view: the single PQ id. A peer without a pinned
    /// PQ key is refused (no legacy alias).
    /// Same ordering rule as `keyring::dual_announce_ids` (recomputed from
    /// the pinned keys, never stored — pins stay the source of truth).
    pub fn dual_announce_ids(&self) -> Result<Vec<[u8; crate::proto::NODEID_LEN]>> {
        let Some(pq) = self.pq_bytes()? else {
            return Err(anyhow!("pq_pub is mandatory (classical-only peer refused)"));
        };
        Ok(vec![crate::proto::pq_id_from_pub(&pq)])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    pub name: String,
    pub listen: String,
    /// порт исходящего QUIC-сокета (для NAT hole punching — фиксированный = стабильный
    /// публичный адрес через NAT); пусто = эфемерный
    #[serde(default)]
    pub client_listen: Option<String>,
    #[serde(default)]
    pub advertise: Option<String>,
    pub peers: Vec<PeerConfig>,
    /// принимать неизвестные ноды (TOFU, как SSH): они получают ACL из unknown-allow
    #[serde(default)]
    pub allow_unknown: bool,
    /// ACL для неизвестных нод
    #[serde(default = "default_unknown_allow")]
    pub unknown_allow: Vec<String>,
    /// HTTP-эндпоинт Prometheus-метрик (напр. "127.0.0.1:9401"); пусто = выкл
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// уровень логов: 0=error, 1=warn, 2=info, 3=debug
    #[serde(default)]
    pub log_level: Option<u8>,
    /// роли (RBAC): имя роли -> allow-список
    #[serde(default)]
    pub roles: HashMap<String, Vec<String>>,
    /// TTL (сек) для сообщений в outbox (retention, GDPR)
    #[serde(default = "default_outbox_ttl")]
    pub outbox_ttl_secs: u64,
    /// роль хранения: ["mail"] / ["files"] / обе (пусто = все бакеты).
    /// Нода может быть только почтовым или только файловым хранилищем, или и тем и тем.
    #[serde(default)]
    pub storage_roles: Vec<String>,
    /// Доверенные валидаторы (для будущего консенсуса PoA): node_id каждой ноды-валидатора.
    /// Сейчас один валидатор (владелец); когда появится блокчейн-слой, эти ноды будут
    /// подписывать блоки (кворум). Пусто = консенсус не активен (текущий режим).
    #[serde(default)]
    pub validators: Vec<String>,
    /// Домен сети (федерация), напр. "infmail.org". Используется для подтверждения валидатора
    /// через DNS TXT: нода проверяет, что TXT-запись домена содержит node_id валидатора.
    /// Позволяет федерации: каждый владелец своего домена может поднять свою сеть.
    #[serde(default)]
    pub domain: Option<String>,
    /// HTTP-слушатель веб-API и webmail (напр. "0.0.0.0:3000"); пусто = выкл
    #[serde(default)]
    pub web_listen: Option<String>,
    /// TON-кошелёк владельца ноды (для выплат наград). Указывается при init ноды.
    #[serde(default)]
    pub wallet: Option<String>,
    /// каталог со статикой фронтенда (сборка Next.js); пусто = без статики
    #[serde(default)]
    pub web_static: Option<String>,
}

fn default_outbox_ttl() -> u64 {
    3600
}

pub fn load(path: &Path) -> Result<NodeConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow!("config: {e}"))?;
    serde_yaml::from_str(&raw).map_err(|e| anyhow!("yaml: {e}"))
}

pub fn save(path: &Path, cfg: &NodeConfig) -> Result<()> {
    std::fs::write(path, serde_yaml::to_string(cfg)?)?;
    Ok(())
}
