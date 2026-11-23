use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
pub type Handler = for<'a> fn(Ctx<'a>, Vec<u8>) -> BoxFuture<'a, Result<Vec<u8>>>;

pub struct Ctx<'a> {
    pub node_id_hex: &'a str,
    pub node_name: &'a str,
    pub peer_name: &'a str,
    pub mail_dir: &'a Path,
    pub data_dir: &'a Path,
    pub peer_addr: std::net::SocketAddr,
    pub mail_key: [u8; 32],
}

pub const SERVICE_NAMES: &[&str] = &[
    "core.echo",
    "core.ping",
    "core.perf",
    "core.perf.up",
    "core.perf.down",
    "core.poke",
    "core.info",
    "core.health",
    "core.storage",
    "service.dht",
    "dht.lookup",
    "dht.update",
    "dht.find_node",
    "dht.store",
    "dht.find_value",
    "dht.sync",
    "storage.store",
    "storage.fetch",
    "storage.delete",
    "mail.list",
    "consensus.sign",
    "pubsub.subscribe",
    "pubsub.unsubscribe",
    "pubsub.publish",
    "pubsub.relay",
    "pubsub.msg",
];

pub fn handler_for(svc: u64) -> Option<Handler> {
    static HANDLERS: OnceLock<HashMap<u64, Handler>> = OnceLock::new();
    HANDLERS
        .get_or_init(|| {
            let mut m = HashMap::with_capacity(9);
            m.insert(crate::proto::svc_id("core.echo"), echo as Handler);
            m.insert(crate::proto::svc_id("core.ping"), ping as Handler);
            m.insert(crate::proto::svc_id("core.perf"), perf as Handler);
            m.insert(crate::proto::svc_id("core.perf.up"), perf_up as Handler);
            m.insert(crate::proto::svc_id("core.perf.down"), perf_down as Handler);
            m.insert(crate::proto::svc_id("core.poke"), poke as Handler);
            m.insert(crate::proto::svc_id("core.info"), info as Handler);
            m.insert(
                crate::proto::svc_id("core.storage"),
                storage_stats as Handler,
            );
            m.insert(crate::proto::svc_id("service.dht"), dht as Handler);
            m
        })
        .get(&svc)
        .copied()
}

pub fn is_allowed(allow: &[String], svc_name: &str) -> bool {
    // честный ACL: "*" = всё, точное имя, или префикс "core.*" → требует "core."
    // НЕТ хардкода core.*/pubsub.* — иначе TOFU-ограничение не работает.
    allow.iter().any(|a| {
        if a == "*" || a == svc_name {
            return true;
        }
        if let Some(prefix) = a.strip_suffix('*') {
            return svc_name.starts_with(prefix);
        }
        false
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[allow(dead_code)] // GATE: privilege guard for systemd hardening
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|u| u == "0")
        })
        .unwrap_or(false)
}

fn echo(_ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move { Ok(payload) })
}

fn ping(_ctx: Ctx<'_>, _payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        Ok(json!({ "pong": true, "at": now_ms() })
            .to_string()
            .into_bytes())
    })
}

fn perf(_ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move { Ok(payload) })
}

/// Однонаправленный upload: принимаем payload, отвечаем маленьким ack (не эхом).
fn perf_up(_ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        Ok(json!({ "ok": true, "received": payload.len() })
            .to_string()
            .into_bytes())
    })
}

/// Однонаправленный download: по запросу {size} возвращаем size байт (не эхо).
pub const MAX_PERF_DOWN_SIZE: usize = 4 * 1024 * 1024;

fn perf_down(_ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        let v: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|e| anyhow!("bad json: {e}"))?;
        let size = usize::try_from(v["size"].as_u64().unwrap_or(0))
            .map_err(|_| anyhow!("size too large"))?;
        if size > MAX_PERF_DOWN_SIZE {
            bail!("size too large");
        }
        Ok(vec![0xabu8; size])
    })
}

fn poke(ctx: Ctx<'_>, _payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        Ok(json!({ "observed": ctx.peer_addr.to_string() })
            .to_string()
            .into_bytes())
    })
}

fn info(ctx: Ctx<'_>, _payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        Ok(json!({
            "node": ctx.node_id_hex,
            "name": ctx.node_name,
            "peer": ctx.peer_name,
            "time": now_ms(),
        })
        .to_string()
        .into_bytes())
    })
}

/// Отчёт ноды о хранилище (для наград): размер kv.json + каталога chunks.
fn storage_stats(ctx: Ctx<'_>, _payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        // R2: dir_size рекурсивно гоняет stat по всему каталогу чанков — это
        // чистый блокирующий disk I/O, уводим его из воркера в spawn_blocking.
        let data_dir = ctx.data_dir.to_path_buf();
        let (kv_bytes, chunks_bytes) = tokio::task::spawn_blocking(move || {
            let kv = data_dir.join("kv.json");
            let kv_bytes = std::fs::metadata(&kv).map(|m| m.len()).unwrap_or(0);
            let chunks_bytes = dir_size(&data_dir.join("chunks"));
            (kv_bytes, chunks_bytes)
        })
        .await
        .unwrap_or((0, 0));
        Ok(json!({
            "ok": true,
            "node": ctx.node_name,
            "node_id": ctx.node_id_hex,
            "kv_bytes": kv_bytes,
            "chunks_bytes": chunks_bytes,
            "total_bytes": kv_bytes + chunks_bytes,
            "ts": now_ms(),
        })
        .to_string()
        .into_bytes())
    })
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                if md.is_dir() {
                    total += dir_size(&e.path());
                } else {
                    total += md.len();
                }
            }
        }
    }
    total
}

fn dht(_ctx: Ctx<'_>, _payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        Ok(json!({ "dht": "phase2-not-implemented" })
            .to_string()
            .into_bytes())
    })
}

pub fn invoke(handler: Handler, ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    handler(ctx, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_and_is_allowed_prefix_require_dot() {
        for name in [
            "dht.sync",
            "storage.store",
            "storage.fetch",
            "storage.delete",
            "mail.list",
            "consensus.sign",
        ] {
            assert!(
                SERVICE_NAMES.contains(&name),
                "SERVICE_NAMES must contain {name}"
            );
            assert_eq!(
                crate::proto::svc_name(crate::proto::svc_id(name)),
                Some(name)
            );
        }

        let acl = vec!["core.*".to_string()];
        assert!(is_allowed(&acl, "core.ping"));
        assert!(is_allowed(&acl, "core.perf.down"));
        assert!(
            !is_allowed(&acl, "core_evil"),
            "core.* must require the dot prefix, not match core_evil"
        );
        assert!(!is_allowed(&acl, "core"));
        assert!(handler_for(crate::proto::svc_id("core.ping")).is_some());
        assert!(handler_for(crate::proto::svc_id("unknown.svc")).is_none());
    }
}
