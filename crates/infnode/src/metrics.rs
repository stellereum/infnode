//! Prometheus-метрики: минимальный HTTP-эндпоинт /metrics (без зависимостей).

use anyhow::Result;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct Metrics {
    pub frames_in: AtomicU64,
    pub frames_out: AtomicU64,
    pub reqs_total: AtomicU64,
    pub reqs_denied: AtomicU64,
    pub reqs_errors: AtomicU64,
    /// Frames accepted despite arriving out of order (max-gate is diagnostic
    /// only; see the anti-replay comment in node.rs).
    pub out_of_order_frames: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub conns_accepted: AtomicU64,
    pub conns_closed: AtomicU64,
    pub conns_active: AtomicU64,
    pub reconnects: AtomicU64,
    pub outbox_delivered: AtomicU64,
    pub outbox_dropped: AtomicU64,
    pub msgs_published: AtomicU64,
    pub msgs_delivered: AtomicU64,
    pub msgs_dropped_no_sub: AtomicU64,
    pub msgs_dropped_dead_rx: AtomicU64,
    /// Patch B: max задержка «стрим принят -> обработчик стартовал» (ms).
    pub dispatch_ms_max: AtomicU64,
    /// Patch B: max время обработки фрейма внутри handle_stream (ms).
    pub handler_ms_max: AtomicU64,
    /// R2/R3/R5: суммарное время блокирующего файлового вывода (ms) —
    /// write_file / persist_kv выполняются в spawn_blocking под гейтом.
    pub fs_write_ms_total: AtomicU64,
    /// R6: сколько раз kv.json реально перезаписывалось (после debounce).
    /// Считает эффективность dirty-флажка: N dht.store за окно => 1 persist.
    pub kv_persists_total: AtomicU64,
    /// F8 hardening: handshake initiations refused by the per-IP bucket.
    pub handshake_throttled: AtomicU64,
    /// F8 hardening: pre-auth connections closed on deadline without CHALLENGE.
    pub preauth_timeouts: AtomicU64,
    /// F8 hardening: handshakes refused while the source IP is strike-banned.
    pub auth_bans_hit: AtomicU64,
    /// F8 hardening: strike bans currently/ever imposed.
    pub auth_bans_total: AtomicU64,
    /// F8-rep: per-identity temp bans imposed (escalating, expiring).
    pub rep_bans: AtomicU64,
    /// F8-rep: handshakes/requests refused on identity reputation (ban hit
    /// or soft-throttle hit). Fail-closed counting, like `auth_bans_hit`.
    pub rep_refusals: AtomicU64,
    pub start_unix: std::sync::atomic::AtomicI64,
}

pub type ServiceCounters = Arc<std::sync::Mutex<HashMap<String, u64>>>;

fn fmt_metric(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    ));
}

pub fn render(
    m: &Metrics,
    svc: &ServiceCounters,
    uptime_s: u64,
    outbox_size: usize,
    subs_topics: usize,
    peer_count: usize,
) -> String {
    let mut out = String::new();
    fmt_metric(&mut out, "infnode_uptime_seconds", "uptime", uptime_s);
    fmt_metric(
        &mut out,
        "infnode_frames_in_total",
        "frames received",
        m.frames_in.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_frames_out_total",
        "frames sent",
        m.frames_out.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_requests_total",
        "service requests",
        m.reqs_total.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_requests_denied_total",
        "ACL-denied requests",
        m.reqs_denied.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_requests_errors_total",
        "request errors",
        m.reqs_errors.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_bytes_in_total",
        "payload bytes received",
        m.bytes_in.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_bytes_out_total",
        "payload bytes sent",
        m.bytes_out.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_connections_accepted_total",
        "connections accepted",
        m.conns_accepted.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_connections_closed_total",
        "connections closed",
        m.conns_closed.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_connections_active",
        "currently active connections",
        m.conns_active.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_reconnects_total",
        "reconnects",
        m.reconnects.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_outbox_delivered_total",
        "outbox messages delivered",
        m.outbox_delivered.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_outbox_dropped_total",
        "outbox messages dropped",
        m.outbox_dropped.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_messages_published_total",
        "pubsub publishes",
        m.msgs_published.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_messages_delivered_total",
        "pubsub deliveries",
        m.msgs_delivered.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_messages_dropped_no_sub_total",
        "pubsub.msg with no subscribers",
        m.msgs_dropped_no_sub.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_messages_dropped_dead_rx_total",
        "pubsub.msg to dropped receivers",
        m.msgs_dropped_dead_rx.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_dispatch_ms_max",
        "max stream-accept to handler-start delay (ms)",
        m.dispatch_ms_max.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_handler_ms_max",
        "max in-handler frame processing time (ms)",
        m.handler_ms_max.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_fs_write_ms_total",
        "time spent in blocking file writes (ms)",
        m.fs_write_ms_total.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_kv_persists_total",
        "kv.json full rewrites (after debounce)",
        m.kv_persists_total.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_handshake_throttled_total",
        "handshakes refused by per-IP bucket",
        m.handshake_throttled.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_preauth_timeouts_total",
        "pre-auth connections closed on deadline",
        m.preauth_timeouts.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_auth_bans_hit_total",
        "handshakes refused while IP strike-banned",
        m.auth_bans_hit.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_auth_bans_total",
        "strike bans imposed",
        m.auth_bans_total.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_rep_bans_total",
        "per-identity temp bans imposed",
        m.rep_bans.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_rep_refusals_total",
        "handshakes/requests refused on identity reputation",
        m.rep_refusals.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_log_dropped_total",
        "log lines dropped on full queue",
        crate::log::LOG_DROPPED.load(Ordering::Relaxed),
    );
    fmt_metric(
        &mut out,
        "infnode_log_write_ms_total",
        "time spent writing log lines (ms)",
        crate::log::LOG_WRITE_NS.load(Ordering::Relaxed) / 1_000_000,
    );
    fmt_metric(
        &mut out,
        "infnode_outbox_size",
        "pending outbox messages",
        outbox_size as u64,
    );
    fmt_metric(
        &mut out,
        "infnode_subscriptions_topics",
        "topics with subscribers",
        subs_topics as u64,
    );
    fmt_metric(
        &mut out,
        "infnode_peers_configured",
        "configured peers",
        peer_count as u64,
    );
    let svc = svc.lock().unwrap();
    for (name, count) in svc.iter() {
        let key = format!("infnode_service_requests_total{{service=\"{name}\"}} {count}\n");
        out.push_str(&key);
    }
    out
}

pub fn spawn(
    addr: &str,
    metrics: Arc<Metrics>,
    svc: Arc<std::sync::Mutex<HashMap<String, u64>>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let m = metrics.clone();
            let svc = svc.clone();
            std::thread::spawn(move || {
                let _ = handle(&mut s, &m, &svc);
            });
        }
    });
    Ok(())
}

fn handle(s: &mut TcpStream, m: &Metrics, svc: &ServiceCounters) -> Result<()> {
    let mut buf = [0u8; 2048];
    let n = s.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    if req.starts_with("GET /metrics") {
        let body = render(m, svc, 0, 0, 0, 0);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = s.write_all(resp.as_bytes());
    } else {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = s.write_all(resp.as_bytes());
    }
    Ok(())
}
