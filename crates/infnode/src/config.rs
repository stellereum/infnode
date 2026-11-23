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
    /// CONSENSUS-ONLY Ed25519 validator key (32 bytes, hex). This is NOT
    /// transport identity, auth or a TLS pin — infnode never reads it. It is
    /// retained because the frozen consensus validator set
    /// (`ValidatorId = [u8; 32]`) is Ed-keyed; the YAML key stays `ed-pub`
    /// for existing configs (`consensus-pub` is the new canonical name).
    /// A peer without it simply does not contribute a consensus key.
    #[serde(default)]
    pub consensus_pub: Option<String>,
    /// Falcon-512 long-term PQ public key (897 bytes, hex). MANDATORY in
    /// FULL-PQ (a peer without it is refused by `primary_id` /
    /// `dual_announce_ids`). `Option` in the in-memory shape only so
    /// dynamically discovered (DHT/TOFU) peers — constructed in code, never
    /// parsed — can exist without a pin until the CHALLENGE teaches it (they
    /// fail closed at `primary_id` and at the KEM-only handshake); parsed
    /// operator configs MUST carry it (see manual `Deserialize` impl:
    /// missing/legacy fails LOUDLY).
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
// - `node_id` / `x_pub` REMOVED (identity is PQ-only via `pq_pub`; the
//   classical Ed25519 identity, X3DH leg and Ed TLS pin are gone). Presence
//   fails LOUDLY with a migration error.
// - `ed-pub` is still accepted, but ONLY as the consensus validator key
//   (canonical name `consensus-pub`); it is never a transport identity.
// - `pq_pub` MANDATORY for parsed configs: absent fails LOUDLY.
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
            // `ed-pub` is the historical name of the CONSENSUS key field.
            #[serde(default)]
            ed_pub: Option<String>,
            #[serde(default)]
            consensus_pub: Option<String>,
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
                "peer '{}' uses removed field `x-pub`: FULL-PQ wipe (X3DH leg cut, no static X25519) — delete `node-id`/`x-pub`/`ed-pub`, set mandatory `pq-pub`; nodes wiped, no compat",
                h.name
            )));
        }
        // Ed25519 is accepted ONLY as the consensus validator key; it is
        // never a transport identity/TLS pin. `consensus-pub` is canonical,
        // `ed-pub` is the historical alias.
        let consensus_pub = h
            .consensus_pub
            .or(h.ed_pub)
            .filter(|s| !s.is_empty())
            .map(|s| {
                let b = hex::decode(&s).map_err(|_| {
                    serde::de::Error::custom(format!(
                        "peer '{}' has malformed `consensus-pub`/`ed-pub` (must be 32 bytes hex)",
                        h.name
                    ))
                })?;
                if b.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "peer '{}' has malformed `consensus-pub`/`ed-pub` (must be 32 bytes hex)",
                        h.name
                    )));
                }
                Ok(s)
            })
            .transpose()?;
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
            consensus_pub,
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

    /// Consensus-only Ed25519 validator key, if pinned. Never used by
    /// infnode transport/auth (the `ValidatorId` type is frozen at 32 bytes).
    pub fn consensus_bytes(&self) -> Result<Option<[u8; 32]>> {
        let Some(s) = self.consensus_pub.as_deref() else {
            return Ok(None);
        };
        let b = hex::decode(s)?;
        b.try_into()
            .map(Some)
            .map_err(|_| anyhow!("consensus_pub должен быть 32 байта"))
    }

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
