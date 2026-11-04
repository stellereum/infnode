use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::path::Path;
use std::pin::Pin;
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
    "pubsub.subscribe",
    "pubsub.unsubscribe",
    "pubsub.publish",
    "pubsub.relay",
    "pubsub.msg",
];

pub fn handler_for(svc: u64) -> Option<Handler> {
    match svc {
        s if s == crate::proto::svc_id("core.echo") => Some(echo),
        s if s == crate::proto::svc_id("core.ping") => Some(ping),
        s if s == crate::proto::svc_id("core.perf") => Some(perf),
        s if s == crate::proto::svc_id("core.perf.up") => Some(perf_up),
        s if s == crate::proto::svc_id("core.perf.down") => Some(perf_down),
        s if s == crate::proto::svc_id("core.poke") => Some(poke),
        s if s == crate::proto::svc_id("core.info") => Some(info),
        s if s == crate::proto::svc_id("core.storage") => Some(storage_stats),
        s if s == crate::proto::svc_id("service.dht") => Some(dht),
        _ => None,
    }
}

pub fn is_allowed(allow: &[String], svc_name: &str) -> bool {
    // честный ACL: "*" = всё, точное имя, или префикс "core.*" → core.ping и т.д.
    // НЕТ хардкода core.*/pubsub.* — иначе TOFU-ограничение не работает.
    allow.iter().any(|a| {
        if a == "*" || a == svc_name {
            return true;
        }
        if let Some(prefix) = a.strip_suffix(".*") {
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
fn perf_down(_ctx: Ctx<'_>, payload: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>>> {
    Box::pin(async move {
        let v: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|e| anyhow!("bad json: {e}"))?;
        let size = v["size"].as_u64().unwrap_or(0) as usize;
        if size > crate::proto::MAX_FRAME {
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
