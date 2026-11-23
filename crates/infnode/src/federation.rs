//! federation.rs — подтверждение валидатора через DNS TXT (федерации).
//!
//! Идея: владелец домена (напр. infmail.org) добавляет TXT-запись вида:
//!   _infnode.infmail.org  TXT  "infnode-validator=inf1:{node_id}:{pq_pub}:{ip}"
//!
//! Это связывает три вещи:
//!   1. Домен (контроль владельца DNS)
//!   2. Криптоидентичность (node_id = blake3("infnode-pqid-v1"||falcon_pk)[..20])
//!   3. IP валидатора
//!
//! FULL-PQ: only the Falcon-512 PQ identity exists. A record carrying the
//! removed 32-byte Ed25519 pin (`...:{64 hex ed}:{ip}`) is REFUSED, and a
//! record without `pq_pub` cannot be self-consistent (node_id must derive
//! from it) — never trusted.
//!
//! Нода при подключении проверяет TXT через DNS-over-HTTPS (dns.google, без доп. зависимостей):
//! если запись содержит node_id валидатора — он подтверждён владельцем домена.
//!
//! Преимущества:
//!   - уменьшает шанс захвата (чужой не выдаст себя за валидатора домена)
//!   - федерации: каждый владелец своего домена может поднять свою сеть
//!   - подтверждение валидности валидатора для нод
//!
//! Валидатор: `infnode announce --domain infmail.org --advertise 109.107.155.67:9400`
//!   выводит TXT-значение и инструкцию по добавлению записи.
//! Нода: в node.yaml указать `domain: infmail.org` — при serve проверит валидатора.

use anyhow::{anyhow, Result};
use serde_json::json;

/// Формат TXT-записи для подтверждения валидатора.
pub const TXT_PREFIX: &str = "infnode-validator=";
/// Имя DNS-подзаписи.
pub fn txt_name(domain: &str) -> String {
    format!("_infnode.{}", domain.trim_end_matches('.'))
}

/// DoH-резолверы по порядку. Множество резолверов убирает единую точку отказа
/// и региональные блокировки (один сервис недоступен — пробуем следующий).
pub const DOH_RESOLVERS: &[&str] = &[
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net:5053/dns-query",
];

/// Запросить TXT-записи имени у нескольких DoH-резолверов (fallback).
/// Возвращает список строк-значений TXT (без кавычек). Ошибка — только если
/// ВСЕ резолверы недоступны.
pub fn query_txt(domain: &str) -> Result<Vec<String>> {
    let name = txt_name(domain);
    let mut last_err: Option<String> = None;
    for base in DOH_RESOLVERS {
        // Google/Cloudflare используют ?name=&type=TXT; Quad9 аналогично.
        let url = format!("{}?name={}&type=TXT", base, urlencoding(&name));
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout_read(std::time::Duration::from_secs(10))
            .build();
        // Google отдаёт JSON; Cloudflare/Quad9 при запросе с Accept: application/dns-json тоже JSON.
        match agent.get(&url).set("accept", "application/dns-json").call() {
            Ok(resp) => match resp.into_json::<serde_json::Value>() {
                Ok(j) => {
                    let empty = vec![];
                    let answers = j["Answer"].as_array().unwrap_or(&empty);
                    let mut out = Vec::new();
                    for a in answers {
                        let data = a["data"].as_str().unwrap_or("").trim_matches('"');
                        if !data.is_empty() {
                            out.push(data.to_string());
                        }
                    }
                    return Ok(out);
                }
                Err(e) => last_err = Some(format!("{base}: parse {e}")),
            },
            Err(e) => last_err = Some(format!("{base}: {e}")),
        }
    }
    Err(anyhow!(
        "все DoH-резолверы недоступны: {}",
        last_err.unwrap_or_default()
    ))
}

/// Разобранная запись валидатора.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub node_id: String,
    /// Hex of the Falcon-512 public key (897 bytes). Mandatory for a
    /// self-consistent FULL-PQ record.
    pub pq_pub: Option<String>,
    pub ip: String,
}

/// Проверить самосогласованность записи: node_id должен быть `inf1:` +
/// первые 20 байт blake3("infnode-pqid-v1"||pq_pub). This catches forged or
/// broken records where the claimed id does not match the key. A record
/// without `pq_pub` cannot be verified and is refused (fail closed).
pub fn record_self_consistent(rec: &ValidatorRecord) -> bool {
    let Some(pq) = &rec.pq_pub else {
        return false;
    };
    let Ok(pq_bytes) = hex::decode(pq) else {
        return false;
    };
    if pq_bytes.len() != crate::proto::PQ_FALCON_PK_LEN {
        return false;
    }
    let expected_id = format!(
        "inf1:{}",
        hex::encode(crate::proto::pq_id_from_pub(&pq_bytes))
    );
    expected_id == rec.node_id
}

/// Разобрать одну TXT-строку в запись валидатора.
/// Формат FULL-PQ: "infnode-validator=inf1:{node_id}:{pq_pub}:{ip}"
/// (pq_pub = 897-byte Falcon-512 key hex, 1794 chars).
/// Legacy classical records are REFUSED (None):
///   "infnode-validator=inf1:{node_id}:{ed_pub}:{ip}"  (64-hex Ed25519 pin)
///   "infnode-validator=inf1:{node_id}:{ip}"           (no key, unverifiable)
/// `ip` may include a port (`1.2.3.4:9400`) or be IPv6 — the whole remainder
/// after the key is taken.
pub fn parse_validator_record(data: &str) -> Option<ValidatorRecord> {
    const PQ_HEX: usize = crate::proto::PQ_FALCON_PK_LEN * 2;
    let data = data.trim_matches('"');
    let val = data.strip_prefix(TXT_PREFIX)?;
    let mut parts = val.splitn(3, ':');
    let proto = parts.next()?;
    let node_raw = parts.next()?;
    if proto != "inf1" || node_raw.is_empty() {
        return None;
    }
    let node_id = format!("inf1:{node_raw}");
    let rest = parts.next().unwrap_or("");
    // Legacy Ed25519 pin (exactly 64 hex chars followed by ':') — refused.
    if rest.len() >= 65
        && rest.as_bytes()[64] == b':'
        && hex::decode(&rest[..64])
            .map(|b| b.len() == 32)
            .unwrap_or(false)
    {
        return None;
    }
    if rest.len() < PQ_HEX + 1 || rest.as_bytes()[PQ_HEX] != b':' {
        // No PQ key: identity cannot be bound -> refuse (no legacy IP-only).
        return None;
    }
    let cand = &rest[..PQ_HEX];
    let pq = hex::decode(cand).ok()?;
    if pq.len() != crate::proto::PQ_FALCON_PK_LEN {
        return None;
    }
    let ip = rest[PQ_HEX + 1..].to_string();
    if ip.is_empty() {
        return None; // an endpoint is required
    }
    Some(ValidatorRecord {
        node_id,
        pq_pub: Some(cand.to_string()),
        ip,
    })
}

/// Сформировать TXT-значение для валидатора.
/// Формат: "infnode-validator=inf1:{node_id}:{pq_pub}:{ip}"
pub fn validator_txt(node_id: &str, pq_pub: &str, ip: &str) -> String {
    format!("{TXT_PREFIX}{node_id}:{pq_pub}:{ip}")
}

/// Проверить, что TXT-запись домена подтверждает валидатора (node_id).
/// SECURITY:
///   - запрос идёт к НЕСКОЛЬКИМ DoH-резолверам (fallback), а не к одному;
///   - запись обязана нести pq_pub, и node_id обязан выводиться из него.
pub async fn verify_domain_validator(domain: &str, expected_node_id: &str) -> Result<bool> {
    let dom = domain.to_string();
    let records = tokio::task::spawn_blocking(move || query_txt(&dom))
        .await
        .map_err(|e| anyhow!("DoH query task failed: {e}"))??;
    for data in &records {
        let Some(rec) = parse_validator_record(data) else {
            continue;
        };
        if rec.node_id != expected_node_id {
            continue;
        }
        if !record_self_consistent(&rec) {
            continue; // node_id не соответствует pq_pub — подделка/битая запись
        }
        return Ok(true);
    }
    Ok(false)
}

/// Найти валидатора сети по домену: вернуть (node_id, pq_pub, ip).
/// Несогласованные записи (node_id != pq_id_from_pub(pq_pub)) пропускаются.
pub async fn resolve_validator(domain: &str) -> Result<Option<(String, Option<String>, String)>> {
    let dom = domain.to_string();
    let records = tokio::task::spawn_blocking(move || query_txt(&dom))
        .await
        .map_err(|e| anyhow!("DoH query task failed: {e}"))??;
    for data in &records {
        let Some(rec) = parse_validator_record(data) else {
            continue;
        };
        if !record_self_consistent(&rec) {
            continue;
        }
        return Ok(Some((rec.node_id, rec.pq_pub, rec.ip)));
    }
    Ok(None)
}

/// Выбрать валидатора по домену с учётом TRUST ANCHOR: если `pinned` задан
/// (node_id/pq_pub из конфига), он имеет приоритет и DNS используется только
/// как источник IP (discovery), а не как источник истины. Подмена DNS тогда
/// безвредна: подключение всё равно проверяет владение pinned-ключом.
pub async fn resolve_with_trust_anchor(
    domain: &str,
    pinned: Option<(&str, &str)>,
) -> Result<Option<(String, Option<String>, String)>> {
    match pinned {
        Some((node_id, pq_pub)) => {
            // Пиннед: доверяем ключу из конфига, IP берём из DNS если получится.
            let dom = domain.to_string();
            let res = tokio::task::spawn_blocking(move || query_txt(&dom))
                .await
                .map_err(|e| anyhow!("DoH query task failed: {e}"))?;
            let ip = match res {
                Ok(records) => records
                    .iter()
                    .filter_map(|d| parse_validator_record(d))
                    .find(|r| r.node_id == node_id)
                    .map(|r| r.ip)
                    .unwrap_or_default(),
                Err(_) => String::new(),
            };
            Ok(Some((node_id.to_string(), Some(pq_pub.to_string()), ip)))
        }
        None => resolve_validator(domain).await,
    }
}

/// Простой URL-энкодер (без внешних зависимостей).
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Сгенерировать инструкцию для владельца (вывод команды announce).
pub fn announce_message(node_id: &str, pq_pub: &str, domain: &str, ip: &str) -> String {
    let name = txt_name(domain);
    let txt = validator_txt(node_id, pq_pub, ip);
    format!(
        "Добавь TXT-запись для подтверждения валидатора:\n\
         \x20 DNS-хост: {name}\n\
         \x20 TXT-значение: \"{txt}\"\n\
         \x20 (в панели DNS провайдера: Name={name}, Type=TXT, Value=\"{txt}\")\n\n\
         \x20 После добавления ноды смогут проверить валидатора через:\n\
         \x20   infnode verify-validator --domain {domain} --node-id {node_id}\n\
         \x20 И в node.yaml нод укажи: domain: {domain} — нода сама найдёт валидатора (IP + pq_pub из TXT)"
    )
}

// тихие use для json (может пригодиться позже)
#[allow(dead_code)]
fn _j(_x: serde_json::Value) -> serde_json::Value {
    json!({})
}
