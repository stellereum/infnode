use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, VerifyingKey};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rand::RngCore;
use reed_solomon_erasure::galois_8::ReedSolomon;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Instant};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};
use x509_parser::parse_x509_certificate;

use crate::config::{NodeConfig, PeerConfig};
use crate::keyring::{NodeKeys, PqKeys};
use crate::proto::{self, now_ms, ts_ok, Frame, NODEID_LEN};
use crate::reputation::{RepConfig, RepEntry, REP_MAP_CAP, REP_MAP_HARD_CAP};

/// Токен-бакет для rate limiting запросов пира.
#[derive(Clone)]
pub struct RateBucket {
    tokens: f64,
    last: Instant,
}

impl RateBucket {
    /// Fresh bucket holds exactly one token: a new identity gets one
    /// immediate request, the rest is paced by `rate`.
    pub fn new() -> Self {
        Self {
            tokens: 1.0,
            last: Instant::now(),
        }
    }
    /// Fresh bucket pre-filled to burst capacity (`rate * 2`): for the
    /// per-IP handshake gate a short legit spike (reconnect storm, test
    /// redials) must pass while a sustained rain is still throttled.
    /// Request-level buckets keep `new()` (burst 1) on purpose.
    pub fn new_full(rate: u32) -> Self {
        Self {
            tokens: (f64::from(rate) * 2.0).max(1.0),
            last: Instant::now(),
        }
    }
    /// Idle time since the bucket was last touched (for reaping).
    pub fn idle(&self) -> Duration {
        self.last.elapsed()
    }
    /// rate req/sec (0 = unlimited)
    pub fn allow(&mut self, rate: u32) -> bool {
        if rate == 0 {
            return true;
        }
        let rate = rate as f64;
        let elapsed = self.last.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(rate * 2.0);
        self.last = Instant::now();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Default per-second request budget for DYNAMICALLY added peers: TOFU
/// unknowns accepted at the challenge gate and DHT-discovered nodes.
///
/// PENTEST F5 (P0): both dynamic-peer constructors used
/// `rate_limit_per_sec: 0`, and `RateBucket::allow(0)` is defined as
/// "unlimited" — so the LEAST-trusted peers (never pinned by the operator)
/// had the LARGEST budget: an unbounded `dht.lookup` / `find_node` /
/// `find_value` flood from a single ephemeral identity. Static peers keep
/// whatever the operator configured (including 0 = unlimited on purpose);
/// dynamic ones are born bounded. 20/s is generous for discovery heartbeats
/// and cheap enough that one identity cannot wedge a worker.
pub const DYNAMIC_PEER_RATE_LIMIT_PER_SEC: u32 = 20;

/// Backpressure caps (audit 2026-11-03). Every connection-adjacent
/// queue/table in this file is bounded by one of these. Shed policy is
/// uniform: fail-closed (drop/refuse the NEW item, keep serving the old),
/// mirroring the `MAX_OUTBOX_PER_PEER` + `outbox_dropped` idiom. Sheds bump
/// an existing `metrics` counter where one fits (`outbox_dropped`,
/// `msgs_dropped_dead_rx`); tables with no fitting counter shed silently and
/// are listed as follow-ups (no new metrics infra per task scope).
///
/// Fairness: per-peer caps isolate peers at enqueue time (one abusive peer
/// cannot evict honest peers' queues), and `MAX_OUTBOX_FLUSH_PER_PEER` makes
/// `flush_outbox_once` round-robin (one abusive peer cannot starve honest
/// peers at drain time).
/// Live QUIC connections tracked per peer (inner Vec of `conns`).
pub const MAX_CONNS_PER_PEER: usize = 8;
/// Distinct peers with tracked connections (outer `conns` map).
pub const MAX_CONN_PEERS_TOTAL: usize = 4096;
/// Total stored session keys (`sessions`, keyed by conn stable_id).
pub const MAX_SESSIONS_TOTAL: usize = 4096;
/// Distinct pubsub topics (`subs` outer map).
pub const MAX_SUBS_TOPICS: usize = 1024;
/// Distinct subscribers of one topic (`subs` inner map).
pub const MAX_SUBS_PEERS_PER_TOPIC: usize = 1024;
/// Live connections recorded per (topic, peer) (`SubState.conns`).
pub const MAX_SUB_CONNS_PER_PEER: usize = 8;
/// Distinct peers with a pending outbox queue (`outbox` outer map).
/// Per-queue depth stays `proto::MAX_OUTBOX_PER_PEER`.
pub const MAX_OUTBOX_PEERS_TOTAL: usize = 1024;
/// Fair-drain budget: messages processed for ONE peer per flush cycle.
/// Guarantees every queued peer is serviced each cycle.
pub const MAX_OUTBOX_FLUSH_PER_PEER: usize = 32;
/// Distinct (origin, topic) reorder buffers (`reorder` outer map).
pub const MAX_REORDER_KEYS: usize = 1024;
/// Buffered out-of-order messages per (origin, topic) (`reorder` inner map).
pub const MAX_REORDER_BUF_PER_KEY: usize = 128;
/// Decrypted mail bodies held in RAM (`mail_cache`).
pub const MAX_MAIL_CACHE_ENTRIES: usize = 256;
/// Distinct topics with local app subscribers (`app_subs` outer map).
pub const MAX_APP_SUB_TOPICS: usize = 1024;
/// Local subscribers of one topic (`app_subs` inner vec).
pub const MAX_APP_SUBS_PER_TOPIC: usize = 128;
/// Distinct topics with an allocated publish sequence (`topic_seq`).
pub const MAX_TOPIC_SEQ_TOPICS: usize = 1024;
/// Distinct node ids in the route table (`routes` total; per-update and
/// per-node caps stay in `proto`).
pub const MAX_ROUTES_TOTAL: usize = 4096;
/// Distinct peers with a tie-break fallback guard entry (`sessionless_guard`).
pub const MAX_SESSIONLESS_GUARD_PEERS: usize = 1024;

/// Reorder buffer: (origin, topic) -> (next_seq, {seq -> (data, src)}).
///
/// `src` (node id ОТПРАВИТЕЛЯ) едет вместе с `data`: буфер может отдать
/// сообщение ПОЗЖЕ, когда его уже отправил другой узел, и подставить
/// чужой `src` значило бы списать трафик с неверного peer-bucket.
type ReorderMap = HashMap<(String, String), (u64, BTreeMap<u64, (String, String)>)>;

/// Anti-replay window for ONE QUIC connection.
///
/// This used to live on `PeerLink`, i.e. one window shared by every connection to the
/// same peer. That is wrong whenever the sender has more than one live connection or
/// reconnects: the sender's `seq` is a single node-wide counter, so frames arrive on
/// each connection with numbers from one shared sequence, and a window keyed per peer
/// sees them as out of order. The result was a `replay/out-of-order` error that tore
/// down `frame_loop` immediately, so the node never completed authentication or
/// reached consensus — 7 to 20 `conn_closed` and zero `conn_open` in a real log.
///
/// A window belongs to the connection it protects: replays are a per-connection
/// concern, and QUIC already gives each connection a fresh, independent stream space.
#[derive(Default)]
pub struct ConnReplayWindow {
    pub last_seq: u32,
    pub last_ts: i64,
}

#[derive(Clone)]
pub struct PeerLink {
    pub cfg: PeerConfig,
    pub conn: Arc<RwLock<Option<Connection>>>,
    pub rtt: Arc<RwLock<Option<Duration>>>,
    pub learned: Arc<RwLock<Option<SocketAddr>>>,
    /// Last time a valid frame arrived from this peer. This is the LIVENESS signal
    /// (`peer_last_seen`, rewards for NAT peers) and is intentionally per-peer.
    pub last_seen: Arc<Mutex<i64>>,
    /// Per-CONNECTION anti-replay windows, keyed by `Connection::stable_id()`.
    /// See `ConnReplayWindow` for why one window per peer was wrong.
    pub replay_windows: Arc<tokio::sync::RwLock<HashMap<usize, Arc<Mutex<ConnReplayWindow>>>>>,
    pub client_cfg: quinn::ClientConfig,
    pub rate: Arc<Mutex<RateBucket>>,
}

/// Запись маршрута для discovery.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Route {
    pub endpoints: Vec<String>,
    pub ed_hex: String,
}

/// Подписка узла на топик: время + текущие живые соединения (может быть несколько).
#[derive(Clone)]
struct SubState {
    ts: i64,
    conns: HashMap<usize, Connection>,
}

/// Bookkeeping for the tie-break-exception dial in `conn_with_session`.
#[derive(Default)]
struct SessionlessGuard {
    /// Last time we dropped a session-less cached conn for this peer.
    last_drop: Option<std::time::Instant>,
    /// Last time we used the dial fallback for this peer.
    last_dial: Option<std::time::Instant>,
}

/// Minimum gap between two tie-break-exception dials to one peer.
const FALLBACK_DIAL_COOLDOWN_MS: u64 = 250;

/// Per-peer outbound-dial circuit breaker (redial-storm incident: a dead
/// peer was redialled on every endpoint every 20s forever, abuse-flagging a
/// host for "hammering ports").
///
/// Consecutive failed dial attempts are counted per peer in a LOCAL map
/// (deliberately NOT the reputation table: unreachable is not abusive, and
/// breaker state must never feed handshake-auth decisions). After
/// [`CIRCUIT_FAIL_THRESHOLD`] consecutive failures the peer is PARKED:
/// `reconnect_loop` skips it except for a single probe of the first
/// configured endpoint per backoff interval (no sweep, no NAT punch, no
/// `catch_up` spawn). Any successful connection (outbound dial or inbound
/// accept — both register via `add_conn`) resets the breaker to closed.
///
/// No env knobs (lead decision): the schedule is compiled in below.
/// In-zone counters live on `Node` (not `metrics.rs`).
pub const CIRCUIT_FAIL_THRESHOLD: u32 = 5;
/// First park backoff: matches the reconnect tick (one skipped sweep).
pub const CIRCUIT_BACKOFF_FIRST_SECS: u64 = 20;
/// Second consecutive park (first failed probe): 5 minutes.
pub const CIRCUIT_BACKOFF_SECOND_SECS: u64 = 300;
/// Steady-state park (second failed probe onward): 30 minutes (cap).
pub const CIRCUIT_BACKOFF_MAX_SECS: u64 = 1800;
/// Bound on tracked breaker entries (fail-closed eviction on the record path).
pub const MAX_CIRCUIT_PEERS: usize = 1024;
/// `reconnect_loop` tick (documents the existing 20s cadence; value unchanged).
pub const CIRCUIT_RECONNECT_INTERVAL_SECS: u64 = 20;

/// Breaker state for one peer.
#[derive(Clone, Copy, Debug)]
struct CircuitEntry {
    /// Consecutive failed dial attempts (entry is removed on any success).
    consecutive_failures: u32,
    /// Next time a single probe dial is allowed (`None` = closed, never open).
    next_probe_at: Option<std::time::Instant>,
    /// Backoff currently in force (test/monitor hook).
    backoff_secs: u64,
}

/// Backoff for the Nth consecutive failure (N >= threshold). Pure so the
/// storm-rate bound is provable without sleeping: 20s on first park, 5min
/// on the next failed probe, 30min steady-state (cap).
pub fn circuit_backoff_secs(consecutive_failures: u32) -> u64 {
    if consecutive_failures <= CIRCUIT_FAIL_THRESHOLD {
        CIRCUIT_BACKOFF_FIRST_SECS
    } else if consecutive_failures == CIRCUIT_FAIL_THRESHOLD + 1 {
        CIRCUIT_BACKOFF_SECOND_SECS
    } else {
        CIRCUIT_BACKOFF_MAX_SECS
    }
}

/// Whether N consecutive failures parks the peer. Pure (threshold test hook).
pub fn circuit_should_park(consecutive_failures: u32) -> bool {
    consecutive_failures >= CIRCUIT_FAIL_THRESHOLD
}

/// First configured endpoint for a parked probe (pure shape hook: a parked
/// peer dials this endpoint ONLY — no sweep, no gossip, no NAT punch).
/// `dial_parked_probe` (the sole parked dial path) uses exactly this.
pub fn circuit_probe_endpoint(endpoints: &[String]) -> Option<String> {
    endpoints.first().cloned()
}

/// Granularity of the simultaneous-open wait (the wait is a whole number of
/// these steps, so the peer is polled for an inbound connection every 50ms).
const SIMOPEN_WAIT_STEP_MS: u64 = 50;

/// Default simultaneous-open wait, in ms (`INFNODE_SIMOPEN_WAIT_MS`).
///
/// Was 750ms (15 x 50ms) for EVERY peer — a reconnect to a restarting or
/// loaded peer paid ~1s of sleep before the dial even started. 100ms is
/// enough for a LAN peer's inbound connection to land (a few ms) and keeps
/// the tie-break's original purpose (avoid the simultaneous-open abort
/// storm) intact. 0 disables the wait entirely.
const SIMOPEN_WAIT_MS_DEFAULT: u64 = 100;

/// Effective simultaneous-open wait in ms (`INFNODE_SIMOPEN_WAIT_MS`).
fn simopen_wait_ms() -> u64 {
    std::env::var("INFNODE_SIMOPEN_WAIT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(SIMOPEN_WAIT_MS_DEFAULT)
}

/// Whether the higher-id side must wait for the peer's inbound connection
/// before dialing itself.
///
/// Pure so the rule is testable without a live peer:
/// * the LOWER id always dials at once (exactly one side initiates, otherwise
///   QUIC's simultaneous-open abort storm starts);
/// * the HIGHER id waits only for a STATIC peer — one our config says dials
///   us back. A peer that is not in the config (TOFU/DHT-discovered) is not
///   obliged to dial us, and waiting for it delayed every reconnect by the
///   full tie-break window for nothing.
fn simopen_should_wait(
    self_id: &[u8; NODEID_LEN],
    peer_id: &[u8; NODEID_LEN],
    peer_is_static: bool,
) -> bool {
    self_id > peer_id && peer_is_static
}

/// F8 accept-path hardening: pre-auth deadline.
///
/// Connections with no valid CHALLENGE within N seconds are closed.
/// Env `STELL_INF_PREAUTH_DEADLINE_SECS`, default 15. Applies pre-auth only:
/// once `frame_loop` has `authed == Some`, the wait is indefinite again
/// (QUIC idle timeout 120s still bounds dead sessions). `0` disables.
pub const PREAUTH_DEADLINE_SECS_DEFAULT: u64 = 15;

/// Effective pre-auth deadline in seconds (`STELL_INF_PREAUTH_DEADLINE_SECS`).
pub fn preauth_deadline_secs() -> u64 {
    std::env::var("STELL_INF_PREAUTH_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(PREAUTH_DEADLINE_SECS_DEFAULT)
}

/// F8 accept-path hardening: per-IP handshake bucket.
///
/// Token-bucket rate for handshake initiations per source IP.
/// Env `STELL_INF_HANDSHAKE_PER_IP_PER_SEC`, default 30. `0` = unlimited
/// (matches `RateBucket::allow(0)`). Burst capacity is `rate * 2` via
/// `RateBucket`, so a short legit spike passes while a sustained rain is
/// throttled. Steady-state bound: `rate * preauth_deadline < MAX_INCOMING`
/// (30 * 15 = 450 < 512).
pub const HANDSHAKE_PER_IP_PER_SEC_DEFAULT: u32 = 30;

/// Effective per-IP handshake rate (`STELL_INF_HANDSHAKE_PER_IP_PER_SEC`).
pub fn handshake_per_ip_per_sec() -> u32 {
    std::env::var("STELL_INF_HANDSHAKE_PER_IP_PER_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(HANDSHAKE_PER_IP_PER_SEC_DEFAULT)
}

/// F8 accept-path hardening: failed-auth strikes with cooldown.
///
/// `STELL_INF_AUTH_FAIL_THRESHOLD` failed handshakes from one IP within
/// `STELL_INF_AUTH_FAIL_WINDOW_SECS` refuse new handshakes from that IP for
/// `STELL_INF_AUTH_BAN_COOLDOWN_SECS`. Any successful CHALLENGE from the IP
/// resets its strike count. All fail-closed: unparsable env falls back to
/// defaults below. `threshold == 0` disables banning.
pub const AUTH_FAIL_THRESHOLD_DEFAULT: u32 = 5;
pub const AUTH_FAIL_WINDOW_SECS_DEFAULT: u64 = 60;
pub const AUTH_BAN_COOLDOWN_SECS_DEFAULT: u64 = 300;

/// Effective strike threshold (`STELL_INF_AUTH_FAIL_THRESHOLD`).
pub fn auth_fail_threshold() -> u32 {
    std::env::var("STELL_INF_AUTH_FAIL_THRESHOLD")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(AUTH_FAIL_THRESHOLD_DEFAULT)
}

/// Effective strike window in seconds (`STELL_INF_AUTH_FAIL_WINDOW_SECS`).
pub fn auth_fail_window_secs() -> u64 {
    std::env::var("STELL_INF_AUTH_FAIL_WINDOW_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(AUTH_FAIL_WINDOW_SECS_DEFAULT)
}

/// Effective ban cooldown in seconds (`STELL_INF_AUTH_BAN_COOLDOWN_SECS`).
pub fn auth_ban_cooldown_secs() -> u64 {
    std::env::var("STELL_INF_AUTH_BAN_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(AUTH_BAN_COOLDOWN_SECS_DEFAULT)
}

/// Сообщение в persistent outbox (at-least-once доставка).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct QueuedMsg {
    topic: String,
    data: String,
    msg_id: u64,
    seq: u64,
    origin: String,
    attempts: u32,
    ts: i64,
}

pub struct Node {
    pub cfg: NodeConfig,
    pub keys: NodeKeys,
    pub id: [u8; NODEID_LEN],
    pub id_hex: String,
    pub peers: RwLock<HashMap<[u8; NODEID_LEN], PeerLink>>,
    /// Пиры из СТАТИЧЕСКОГО конфига (`cfg.peers`), т.е. те, кого мы сами
    /// настроили звонить НАМ. Только для них одновременное открытие (оба
    /// звоним одновременно) реально возможно, и только их стоит ждать при
    /// tie-break. Пир, которого нет в конфиге (TOFU/DHT), звонить нам не
    /// обязан — ждать его бессмысленно: валидатор получал ~750ms задержки на
    /// КАЖДЫЙ реконнект из-за пира, который так и не перезвонит.
    static_peers: std::collections::HashSet<[u8; NODEID_LEN]>,
    pub by_name: HashMap<String, [u8; NODEID_LEN]>,
    /// последнее время входящего запроса от пира (heartbeat) — для rewards/статуса,
    /// надёжнее чем PeerLink (пиры могут пересоздаваться при переподключении)
    pub last_req_from_peer: tokio::sync::RwLock<HashMap<[u8; NODEID_LEN], i64>>,
    seq: AtomicU32,
    client_ep: Endpoint,
    conns: Arc<RwLock<HashMap<[u8; NODEID_LEN], Vec<Connection>>>>,
    /// stable_id соединений, для которых уже запущен приёмный цикл (frame_loop).
    /// Нужен, чтобы не запустить второй цикл на том же соединении.
    looped: Arc<std::sync::Mutex<std::collections::HashSet<usize>>>,
    mail_dir: PathBuf,
    /// pubsub: топик -> (узел -> SubState{время, живые соединения}) — подписки persistent
    subs: RwLock<HashMap<String, HashMap<[u8; NODEID_LEN], SubState>>>,
    /// pubsub: dedup сообщений (msg_id -> ts), TTL для предотвращения петель
    seen: Mutex<HashMap<u64, i64>>,
    /// Anti-replay для CHALLENGE-рукопожатий (nonce -> ts): каждый nonce
    /// одноразовый внутри `TS_WINDOW_MS`. Занимается ПОСЛЕ проверки подписи,
    /// чтобы поддельные кадры не засоряли кэш.
    challenge_nonces: Mutex<HashMap<String, i64>>,
    /// pubsub: outbox ненадёжной доставки (узел -> очередь) — переживает рестарты
    outbox: RwLock<HashMap<[u8; NODEID_LEN], VecDeque<QueuedMsg>>>,
    /// pubsub: локальные прикладные подписчики (топик -> каналы)
    app_subs: RwLock<HashMap<String, Vec<mpsc::UnboundedSender<String>>>>,
    /// forward secrecy: session-ключи соединений (stable_id -> [u8;32])
    sessions: RwLock<HashMap<usize, [u8; 32]>>,
    /// KEX wiring: PQ transcript digest per connection (stable_id -> digest).
    /// Present IFF the session negotiated PQ (hybrid key); absent = classical.
    /// `frame_loop` seals/opens bodies with `kex_frame_*` (AAD-bound) when
    /// present, else the legacy `e2e_*` path byte-identical. Same cap as
    /// `sessions`; inserted/removed alongside it, never alone.
    pq_digests: RwLock<HashMap<usize, [u8; 32]>>,
    /// Guard for the tie-break-exception dial (see `conn_with_session`): per
    /// peer, when we last dropped a session-less cached conn + last fallback
    /// dial. Bounds direct dials so a dead peer cannot turn the exception
    /// into the dial storm the strict tie-break fixed.
    sessionless_guard: std::sync::Mutex<HashMap<[u8; NODEID_LEN], SessionlessGuard>>,
    /// Circuit breaker for outbound redials (redial-storm incident): per-peer
    /// consecutive dial failures with exponential park (20s → 5min → 30min).
    /// Local map on purpose (NOT reputation: unreachable ≠ abusive, and this
    /// state never feeds handshake-auth). Sync mutex: entries are tiny and
    /// the guard is never held across await.
    circuit: std::sync::Mutex<HashMap<[u8; NODEID_LEN], CircuitEntry>>,
    /// Breaker transitions (parks/unparks), in-zone counters (not metrics.rs).
    circuit_parks: AtomicU64,
    circuit_unparks: AtomicU64,
    /// маршруты для discovery (node_id -> Route)
    routes: RwLock<HashMap<[u8; NODEID_LEN], Route>>,
    /// каталог для персистентности (routes.json и пр.)
    pub data_dir: PathBuf,
    /// время старта (для core.health)
    started_at: Instant,
    /// ключ шифрования почты at rest
    mail_key: [u8; 32],
    /// Prometheus-метрики
    metrics: Arc<crate::metrics::Metrics>,
    svc_counters: crate::metrics::ServiceCounters,
    trace_seq: AtomicU64,
    /// TTL outbox (retention)
    outbox_ttl: u64,
    /// config path для live-reload (SIGHUP)
    config_path: PathBuf,
    /// live-reloadable unknown_allow (для TOFU-нод)
    unknown_allow_cfg: RwLock<Vec<String>>,
    /// Kademlia routing table
    routing: RwLock<crate::dht::RoutingTable>,
    /// KV-хранилище DHT
    kv: RwLock<crate::dht::KvStore>,
    /// per-topic счётчик seq (порядок сообщений одного origin)
    topic_seq: RwLock<HashMap<String, u64>>,
    /// reorder-буфер подписчика: (origin, topic) -> (next_seq, буфер)
    reorder: RwLock<ReorderMap>,
    /// кэш расшифрованных тел писем (mail name -> (blob, ts_ms)) — ускоряет повторное
    /// чтение Inbox при чистом валидаторе (чанки тянутся с нод по сети). TTL 60с.
    mail_cache: RwLock<HashMap<String, (Vec<u8>, i64)>>,
    /// R6: гейты сериализации фоновых записей состояния на диск — РАЗНЫЕ НА
    /// КАЖДЫЙ ФАЙЛ. Раньше все persist'ы (routes/subs/outbox/dht.json + хвост
    /// persist_kv) шли за ОДНИМ мьютексом, и медленная перезапись 48–85 МБ
    /// kv.json держала гейт секундами — за ним вставали любые другие
    /// persist'ы (на стенде: CHALLENGE/даже core.ping ждали чужой kv-записи).
    /// Теперь медленный kv не может заблокировать outbox/subs/routes/dht.json.
    gates: PersistGates,
    /// R6: kv изменился с последнего persist'а. Вместо ПОЛНОГО пересохранения
    /// kv.json на КАЖДЫЙ dht.store (на стенде ~6/мин × multi-МБ запись)
    /// dirty-флаг склеивает всплеск в ОДНО сохранение (паттерн outbox_dirty).
    kv_dirty: AtomicBool,
    /// R6: unix-ms завершения последнего persist'а kv (0 = ещё не было).
    /// От него же отсчитывается debounce-окно.
    kv_last_flush_ms: AtomicI64,
    /// R6: debounce-окно kv-флуша (мс). Поле, а не константа — тесты
    /// переопределяют, чтобы проверять окно без реальных пауз.
    kv_debounce_ms: AtomicU64,
    /// R3: outbox изменялся с последнего persist'а. 1-секундный flush-цикл
    /// пишет outbox.json ТОЛЬКО когда флаг поднят (swap), а не каждую секунду.
    outbox_dirty: AtomicBool,
    /// F8: per-IP handshake token-buckets (source IP -> bucket).
    handshake_buckets: Mutex<HashMap<IpAddr, RateBucket>>,
    /// F8: failed-handshake timestamps per source IP (for strike window).
    auth_failures: Mutex<HashMap<IpAddr, Vec<std::time::Instant>>>,
    /// F8: strike-ban expiry per source IP.
    auth_bans: Mutex<HashMap<IpAddr, std::time::Instant>>,
    /// F8-rep: per-identity reputation (node id -> entry). Extends the
    /// IP-level accept hardening (buckets/strikes): bans follow the offender
    /// identity across IPs and never hit well-behaved peers sharing an
    /// address. See `crate::reputation` for the score model.
    peer_rep: Mutex<HashMap<[u8; NODEID_LEN], RepEntry>>,
}

/// R6: гейт на КАЖДЫЙ персистимый файл. Держится только на время
/// spawn_blocking-записи этого файла (сериализация в гейт больше не входит).
struct PersistGates {
    kv: tokio::sync::Mutex<()>,
    outbox: tokio::sync::Mutex<()>,
    subs: tokio::sync::Mutex<()>,
    routes: tokio::sync::Mutex<()>,
    dht: tokio::sync::Mutex<()>,
    misc: tokio::sync::Mutex<()>,
}

impl PersistGates {
    fn new() -> Self {
        Self {
            kv: tokio::sync::Mutex::new(()),
            outbox: tokio::sync::Mutex::new(()),
            subs: tokio::sync::Mutex::new(()),
            routes: tokio::sync::Mutex::new(()),
            dht: tokio::sync::Mutex::new(()),
            misc: tokio::sync::Mutex::new(()),
        }
    }

    /// Гейт конкретного файла: одновременные писатели одного файла не могут
    /// сделать ему interleave (write не атомарен), но РАЗНЫЕ файлы не ждут
    /// друг друга. Неизвестное имя — общий «misc»-гейт.
    fn for_file(&self, name: &str) -> &tokio::sync::Mutex<()> {
        match name {
            "outbox.json" => &self.outbox,
            "subs.json" => &self.subs,
            "routes.json" => &self.routes,
            "dht.json" => &self.dht,
            _ => &self.misc,
        }
    }
}

/// Минимальный интервал между ротационными копиями kv.json (держим 1 свежую — сам kv.json пишется атомарно через tmp+rename, .bak лишь страховка оператора; audit 2026-10-06: 3×112М при диске 91%).
/// kv переписывается при каждом dht.store/синке (на стенде — каждые ~7с), и
/// раньше каждое сохранение означало полную копию файла: тысячи копий/сутки.
const KV_BACKUP_INTERVAL_MS: i64 = 5 * 60 * 1000;

/// R6: debounce-окно отложенного persist'а kv. Всплеск dht.store (на стенде
/// ~5–6/мин) склеивается в ОДНО сохранение вместо N; между сохранениями —
/// не меньше этого окна, считая от ЗАВЕРШЕНИЯ предыдущего (запись 48–85 МБ
/// занимает секунды — окно от конца гарантирует паузу, а не только паузу
/// между стартами). Тесты подменяют значение через `Node::kv_debounce_ms`.
const KV_FLUSH_DEBOUNCE_MS: u64 = 300_000;

/// Хвост `persist_kv`: ротация бэкапов + атомарная запись kv.json.
/// Вынесено из async-контекста: весь файловый I/O выполняется в
/// `spawn_blocking` под kv-гейтом (R2/R3/R5/R6) — на стенде kv.json
/// переписывается каждые ~7с, и раньше каждая такая запись блокировала
/// воркер рантайма прямо посреди обработки чужого запроса.
fn kv_persist_tail(data_dir: PathBuf, json: String) {
    let path = data_dir.join("kv.json");
    // Ротационная копия перед перезаписью: у kv.json (индексы ящиков,
    // манифесты) автоматических бэкапов не было вообще — только ручные
    // копии и один битый файл. Держим 3 самые свежие.
    // (c) Ротация не чаще KV_BACKUP_INTERVAL_MS: kv переписывается при
    // каждом dht.store/синке (на стенде — каждые ~7с), и раньше каждая
    // перезапись значила полную копию многомегабайтного файла (тысячи
    // копий/сутки write-amplification'а). Держим 1 свежую (см. выше),
    // просто не на каждом сохранении.
    if path.exists() {
        let mut baks: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&data_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Some(t) = n.strip_prefix("kv.json.bak-") {
                    if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
                        if let Ok(mt) = e.metadata().and_then(|m| m.modified()) {
                            baks.push((mt, e.path()));
                        }
                    }
                }
            }
        }
        baks.sort_by(|a, b| b.0.cmp(&a.0)); // свежие первыми
        let since_last = baks
            .first()
            .and_then(|(t, _)| t.elapsed().ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(i64::MAX);
        if since_last >= KV_BACKUP_INTERVAL_MS {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let bak = data_dir.join(format!("kv.json.bak-{ts}"));
            if std::fs::copy(&path, &bak).is_ok() {
                baks.insert(0, (std::time::SystemTime::now(), bak));
            }
        }
        while baks.len() > 1 {
            if let Some((_, old)) = baks.pop() {
                let _ = std::fs::remove_file(old);
            }
        }
    }
    // атомарно: крэш между write и rename оставляет старый целый файл
    // (раньше прямой write бился при крэше -> load_kv молча отдавал пустое)
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

impl Node {
    pub async fn new(
        cfg: NodeConfig,
        keys: NodeKeys,
        data_dir: PathBuf,
        config_path: PathBuf,
    ) -> Result<Arc<Self>> {
        let id = keys.id();
        let id_hex = keys.id_hex();
        // Re-ceremony mark: `Node::new` is classical-only today (no `PqKeys`
        // param — signature frozen; startup PQ enrolment via
        // `keyring::PqKeys::load_or_generate` is a follow-up outside this
        // change's zone). The local id is therefore the LEGACY alias —
        // say so in the log, never silently classical.
        crate::log::emit(
            2,
            "info",
            &cfg.name,
            0,
            "node_id_kind",
            json!({ "kind": crate::keyring::NodeIdKind::Legacy.label(), "id": id_hex }),
        );
        let client_bind = cfg
            .client_listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        let client_ep = Endpoint::client(
            client_bind
                .parse()
                .map_err(|e| anyhow!("client-listen: {e}"))?,
        )?;
        // NAT hole punching: client-сокет тоже принимает входящие (обратный пробой через NAT)
        let (certs, key) = build_tls(&keys)?;
        let mut sc = quinn::ServerConfig::with_single_cert(certs, key)?;
        sc.transport_config(Arc::new(transport_config()));
        client_ep.set_server_config(Some(sc));
        let mut peers = HashMap::new();
        let mut static_peers = std::collections::HashSet::new();
        let mut by_name = HashMap::new();
        let mut routes: HashMap<[u8; NODEID_LEN], Route> = HashMap::new();
        let roles = &cfg.roles;
        for p in &cfg.peers {
            let mut p = p.clone();
            // RBAC: раскрываем роль в allow
            p.allow = p.effective_allow(roles);
            let pid = p.node_id_raw()?;
            let ed = p.ed_bytes()?;
            let rc = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pinned: ed }))
            .with_no_client_auth();
            let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(rc))?;
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
            client_cfg.transport_config(Arc::new(transport_config()));
            peers.insert(
                pid,
                PeerLink {
                    cfg: p.clone(),
                    conn: Arc::new(RwLock::new(None)),
                    rtt: Arc::new(RwLock::new(None)),
                    learned: Arc::new(RwLock::new(None)),
                    last_seen: Arc::new(Mutex::new(0)),
                    replay_windows: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
                    client_cfg,
                    rate: Arc::new(Mutex::new(RateBucket::new())),
                },
            );
            by_name.insert(p.name.clone(), pid);
            // Static peer (from the config): it is configured to dial us back,
            // so the simultaneous-open tie-break applies to it.
            static_peers.insert(pid);
            routes.entry(pid).or_insert(Route {
                endpoints: p.endpoints.clone(),
                ed_hex: p.ed_pub.clone(),
            });
        }
        let mail_dir = std::env::var("INFNODE_MAIL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./infmail"));
        // загрузка персистентных маршрутов
        let routes_file = data_dir.join("routes.json");
        if let Ok(raw) = std::fs::read_to_string(&routes_file) {
            if let Ok(persisted) = serde_json::from_str::<HashMap<String, Route>>(&raw) {
                for (k, v) in &persisted {
                    if let Ok(b) = hex::decode(k.strip_prefix("inf1:").unwrap_or(k)) {
                        if b.len() == NODEID_LEN {
                            let mut pid = [0u8; NODEID_LEN];
                            pid.copy_from_slice(&b);
                            // Backpressure on load: persisted state is
                            // untrusted input — same total cap as live paths.
                            if !routes.contains_key(&pid) && routes.len() >= MAX_ROUTES_TOTAL {
                                continue;
                            }
                            routes.entry(pid).or_insert(v.clone());
                            // NAT hole punch: вспоминаем публичный client-адрес пира
                            if let Some(peer) = peers.get_mut(&pid) {
                                for ep in &v.endpoints {
                                    if let Ok(addr) = ep.parse::<SocketAddr>() {
                                        if !peer.cfg.endpoints.iter().any(|e| e == ep) {
                                            *peer.learned.write().await = Some(addr);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let outbox_ttl = cfg.outbox_ttl_secs.max(60);
        let unknown_allow_init = cfg.unknown_allow.clone();
        let node = Arc::new(Node {
            cfg,
            keys,
            id,
            id_hex,
            peers: RwLock::new(peers),
            static_peers,
            by_name,
            last_req_from_peer: tokio::sync::RwLock::new(HashMap::new()),
            seq: AtomicU32::new(1),
            client_ep,
            conns: Arc::new(RwLock::new(HashMap::new())),
            looped: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            mail_dir,
            subs: RwLock::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            challenge_nonces: Mutex::new(HashMap::new()),
            outbox: RwLock::new(HashMap::new()),
            app_subs: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            pq_digests: RwLock::new(HashMap::new()),
            sessionless_guard: std::sync::Mutex::new(HashMap::new()),
            circuit: std::sync::Mutex::new(HashMap::new()),
            circuit_parks: AtomicU64::new(0),
            circuit_unparks: AtomicU64::new(0),
            routes: RwLock::new(routes),
            data_dir: data_dir.clone(),
            started_at: Instant::now(),
            mail_key: load_or_create_mail_key(&data_dir),
            topic_seq: RwLock::new(HashMap::new()),
            reorder: RwLock::new(HashMap::new()),
            mail_cache: RwLock::new(HashMap::new()),
            metrics: Arc::new(crate::metrics::Metrics::default()),
            svc_counters: Arc::new(std::sync::Mutex::new(HashMap::new())),
            trace_seq: AtomicU64::new(1),
            outbox_ttl,
            config_path: config_path.clone(),
            unknown_allow_cfg: RwLock::new(unknown_allow_init),
            routing: RwLock::new(crate::dht::RoutingTable::new(id, crate::dht::K)),
            kv: RwLock::new(crate::dht::KvStore::default()),
            gates: PersistGates::new(),
            kv_dirty: AtomicBool::new(false),
            kv_last_flush_ms: AtomicI64::new(0),
            kv_debounce_ms: AtomicU64::new(
                std::env::var("INFNODE_KV_DEBOUNCE_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(KV_FLUSH_DEBOUNCE_MS),
            ),
            outbox_dirty: AtomicBool::new(false),
            handshake_buckets: Mutex::new(HashMap::new()),
            auth_failures: Mutex::new(HashMap::new()),
            auth_bans: Mutex::new(HashMap::new()),
            peer_rep: Mutex::new(HashMap::new()),
        });
        node.load_persistent().await;
        node.load_routing().await;
        node.load_kv().await;
        Ok(node)
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn next_trace(&self) -> u64 {
        self.trace_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// R2/R3/R5/R6: единая точка записи мелких JSON-файлов состояния
    /// (routes/subs/outbox/dht.json). Гейт — ПО ФАЙЛУ (`gates.for_file`), так
    /// что чужая медленная запись (в первую очередь kv.json) не может
    /// поставить этот persist в очередь на секунды. Сам std::fs::write — в
    /// spawn_blocking: блокирующий disk I/O не занимает воркер рантайма.
    /// Диагностика: ожидание гейта и запись логируются только при >=200мс
    /// (тот же порог, что у `dispatch`/`req_stages`).
    async fn write_file(&self, name: &str, json: String) {
        let path = self.data_dir.join(name);
        let t_gate = std::time::Instant::now();
        let _gate = self.gates.for_file(name).lock().await;
        let gate_ms = t_gate.elapsed().as_millis() as u64;
        let m = self.metrics.clone();
        let written = tokio::task::spawn_blocking(move || {
            let t0 = std::time::Instant::now();
            let r = std::fs::write(&path, json);
            (r, t0.elapsed().as_millis() as u64)
        })
        .await;
        let write_ms = match &written {
            Ok((_, ms)) => *ms,
            Err(_) => 0,
        };
        if let Ok((_, ms)) = written {
            m.fs_write_ms_total.fetch_add(ms, Ordering::Relaxed);
        }
        if gate_ms >= 200 || write_ms >= 200 {
            crate::log::emit(
                2,
                "info",
                &self.cfg.name,
                0,
                "persist_file_slow",
                json!({ "file": name, "gate_ms": gate_ms, "write_ms": write_ms }),
            );
        }
    }

    /// Fetch (or create) the anti-replay window for a specific connection.
    async fn replay_window(peer: &PeerLink, conn_id: usize) -> Arc<Mutex<ConnReplayWindow>> {
        if let Some(w) = peer.replay_windows.read().await.get(&conn_id) {
            return Arc::clone(w);
        }
        let mut w = peer.replay_windows.write().await;
        Arc::clone(
            w.entry(conn_id)
                .or_insert_with(|| Arc::new(Mutex::new(ConnReplayWindow::default()))),
        )
    }

    fn sign_frame(&self, f: &mut Frame) {
        let d = blake3::hash(&f.sign_data());
        let sig = self.keys.signing.sign(d.as_bytes());
        f.sig = sig.to_bytes();
    }

    /// F8: check whether `ip` is currently strike-banned. Expired bans are
    /// reaped lazily. Pure read path: never creates entries.
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        let mut bans = self.auth_bans.lock().await;
        if let Some(until) = bans.get(ip) {
            if std::time::Instant::now() < *until {
                return true;
            }
            bans.remove(ip);
        }
        false
    }

    /// F8: per-IP handshake admission: ban check + token-bucket.
    /// Returns true when the handshake may proceed. Fail-closed counting:
    /// banned or over-bucket handshakes bump `handshake_throttled` /
    /// `auth_bans_hit` and must be refused by the caller.
    pub async fn handshake_allowed(&self, ip: IpAddr) -> bool {
        if self.is_banned(&ip).await {
            self.metrics.auth_bans_hit.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let rate = handshake_per_ip_per_sec();
        if rate == 0 {
            return true;
        }
        let mut buckets = self.handshake_buckets.lock().await;
        // Bound memory: reap buckets idle >5min when the map grows.
        if buckets.len() > 4096 {
            buckets.retain(|_, b| b.idle() < Duration::from_secs(300));
        }
        let allowed = buckets
            .entry(ip)
            .or_insert_with(|| RateBucket::new_full(rate))
            .allow(rate);
        if !allowed {
            self.metrics
                .handshake_throttled
                .fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    /// F8: record a successful CHALLENGE from `ip`: strikes reset.
    pub async fn record_auth_success(&self, ip: &IpAddr) {
        self.auth_failures.lock().await.remove(ip);
    }

    /// F8: hardening counters for tests/monitoring (fail-closed, monotonic).
    pub fn handshake_throttled_total(&self) -> u64 {
        self.metrics.handshake_throttled.load(Ordering::Relaxed)
    }
    /// F8: pre-auth deadline closures so far.
    pub fn preauth_timeouts_total(&self) -> u64 {
        self.metrics.preauth_timeouts.load(Ordering::Relaxed)
    }
    /// F8: strike bans imposed so far.
    pub fn auth_bans_total(&self) -> u64 {
        self.metrics.auth_bans_total.load(Ordering::Relaxed)
    }
    /// F8: handshakes refused while strike-banned so far.
    pub fn auth_bans_hit_total(&self) -> u64 {
        self.metrics.auth_bans_hit.load(Ordering::Relaxed)
    }
    /// F8: currently active (post-handshake) connections.
    pub fn conns_active_total(&self) -> u64 {
        self.metrics.conns_active.load(Ordering::Relaxed)
    }

    /// F8: record a failed pre-auth handshake from `ip`. When failures within
    /// the window reach the threshold, impose a cooldown ban. Success resets
    /// (see `record_auth_success`). Threshold 0 disables banning.
    pub async fn record_auth_failure(&self, ip: IpAddr) {
        let threshold = auth_fail_threshold();
        if threshold == 0 {
            return;
        }
        let window = Duration::from_secs(auth_fail_window_secs().max(1));
        let cooldown = Duration::from_secs(auth_ban_cooldown_secs().max(1));
        let now = std::time::Instant::now();
        let mut failures = self.auth_failures.lock().await;
        // Bound memory: drop whole map if it grows unbounded (DDoS with
        // spoofed IPs still cannot grow it without bound).
        if failures.len() > 8192 {
            failures.clear();
        }
        let entry = failures.entry(ip).or_default();
        entry.push(now);
        let cutoff = now.checked_sub(window);
        match cutoff {
            Some(c) => entry.retain(|t| *t >= c),
            None => entry.clear(),
        }
        // Re-check length after pruning: only ban on in-window count.
        if entry.len() as u32 >= threshold {
            entry.clear();
            drop(failures);
            let mut bans = self.auth_bans.lock().await;
            if bans.len() > 8192 {
                let t = std::time::Instant::now();
                bans.retain(|_, until| *until > t);
            }
            bans.insert(ip, now + cooldown);
            self.metrics.auth_bans_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// F8-rep: core identity-score update. Positive `delta` rewards, negative
    /// penalises (see `crate::reputation` for the event mapping). On crossing
    /// at/below the ban score with no ban active, imposes an escalating temp
    /// ban (`base * 2^(bans-1)`, capped). Fail-closed: scores clamp, bans are
    /// time-gated and always forgive (no permanent ban).
    async fn rep_apply(&self, pid: [u8; NODEID_LEN], delta: i64) {
        let cfg = RepConfig::load();
        let now = std::time::Instant::now();
        let mut map = self.peer_rep.lock().await;
        if !map.contains_key(&pid) && map.len() >= REP_MAP_CAP {
            // Memory bound: evict neutral entries first, then everything but
            // active bans. The IP layer still binds the sender's address.
            map.retain(|_, e| e.banned_at(now) || e.score != 0);
            if map.len() >= REP_MAP_HARD_CAP {
                map.retain(|_, e| e.banned_at(now));
            }
        }
        let e = map.entry(pid).or_insert_with(|| RepEntry::fresh(now));
        e.touch(&cfg, now);
        e.score = e
            .score
            .saturating_add(delta)
            .clamp(crate::reputation::REP_SCORE_MIN, crate::reputation::REP_SCORE_MAX);
        e.updated = now;
        if delta < 0 && e.score <= cfg.ban_score && !e.banned_at(now) {
            e.bans = e.bans.saturating_add(1);
            let secs = crate::reputation::ban_duration_secs(e.bans, cfg.ban_secs, cfg.max_ban_secs);
            if let Some(until) = now.checked_add(Duration::from_secs(secs)) {
                e.ban_until = Some(until);
            }
            self.metrics.rep_bans.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// F8-rep: decayed score for an identity (0 = neutral or unknown).
    pub async fn rep_score(&self, pid: &[u8; NODEID_LEN]) -> i64 {
        let cfg = RepConfig::load();
        let now = std::time::Instant::now();
        let mut map = self.peer_rep.lock().await;
        match map.get_mut(pid) {
            Some(e) => {
                e.touch(&cfg, now);
                e.score
            }
            None => 0,
        }
    }

    /// F8-rep: true while the identity holds an unexpired temp ban. Expired
    /// bans are reaped lazily with forgiveness (see `RepEntry::touch`).
    pub async fn rep_is_banned(&self, pid: &[u8; NODEID_LEN]) -> bool {
        let cfg = RepConfig::load();
        let now = std::time::Instant::now();
        let mut map = self.peer_rep.lock().await;
        match map.get_mut(pid) {
            Some(e) => {
                e.touch(&cfg, now);
                e.banned_at(now)
            }
            None => false,
        }
    }

    /// F8-rep: true while the decayed score sits at/below the soft threshold
    /// AND no ban is active (a banned identity reports via `rep_is_banned`).
    /// Soft throttle refuses handshakes but imposes no ban — decay alone
    /// lifts the identity out.
    pub async fn rep_is_throttled(&self, pid: &[u8; NODEID_LEN]) -> bool {
        let cfg = RepConfig::load();
        let now = std::time::Instant::now();
        let mut map = self.peer_rep.lock().await;
        match map.get_mut(pid) {
            Some(e) => {
                e.touch(&cfg, now);
                !e.banned_at(now) && e.score <= cfg.soft_score
            }
            None => false,
        }
    }

    /// F8-rep: escalation memory — bans imposed on this identity so far
    /// (reset on full recovery). Test/monitoring accessor.
    pub async fn rep_ban_count(&self, pid: &[u8; NODEID_LEN]) -> u32 {
        let cfg = RepConfig::load();
        let now = std::time::Instant::now();
        let mut map = self.peer_rep.lock().await;
        match map.get_mut(pid) {
            Some(e) => {
                e.touch(&cfg, now);
                e.bans
            }
            None => 0,
        }
    }

    /// F8-rep: credit a valid handshake / accepted message.
    pub async fn rep_record_valid(&self, pid: &[u8; NODEID_LEN]) {
        let d = RepConfig::load().reward_valid;
        self.rep_apply(*pid, d).await;
    }

    /// F8-rep: debit a failed authentication by the PROVEN (post-handshake)
    /// identity. Pre-auth failures never reach this: the claimed id is
    /// unproven, so the connection is dropped with no identity debit.
    pub async fn rep_record_auth_failure(&self, pid: &[u8; NODEID_LEN]) {
        let d = RepConfig::load().pen_auth;
        self.rep_apply(*pid, -d).await;
    }

    /// F8-rep: debit an oversize transport frame (envelope over the caps).
    /// App-layer policy refusals (oversized DHT value, bad TTL, ACL deny)
    /// are NOT abuse signals and never call this.
    pub async fn rep_record_oversize(&self, pid: &[u8; NODEID_LEN]) {
        let d = RepConfig::load().pen_oversize;
        self.rep_apply(*pid, -d).await;
    }

    /// F8-rep: debit a per-peer rate-limit violation.
    pub async fn rep_record_rate_violation(&self, pid: &[u8; NODEID_LEN]) {
        let d = RepConfig::load().pen_rate;
        self.rep_apply(*pid, -d).await;
    }

    /// F8-rep: debit a protocol violation by the PROVEN (post-handshake)
    /// identity (bad signature, stale frame, src mismatch, decrypt
    /// failure). Pre-auth sources are unproven: unauthenticated frames drop
    /// the connection with no identity debit.
    pub async fn rep_record_protocol_violation(&self, pid: &[u8; NODEID_LEN]) {
        let d = RepConfig::load().pen_proto;
        self.rep_apply(*pid, -d).await;
    }

    /// F8-rep: identity temp bans imposed so far.
    pub fn rep_bans_total(&self) -> u64 {
        self.metrics.rep_bans.load(Ordering::Relaxed)
    }

    /// F8-rep: handshakes/requests refused on identity reputation so far.
    pub fn rep_refusals_total(&self) -> u64 {
        self.metrics.rep_refusals.load(Ordering::Relaxed)
    }

    /// Outbox shed counter (per-peer overflow, outer peer-queue overflow,
    /// expiry/TTL drops, overloaded persist-load trims). Mirrors the other
    /// `*_total()` fail-closed accessors.
    pub fn outbox_dropped_total(&self) -> u64 {
        self.metrics.outbox_dropped.load(Ordering::Relaxed)
    }

    // ============ Backpressure introspection / test hooks ============
    //
    // Thin wrappers over the REAL enqueue/drain/table paths above (no logic
    // duplication): integration tests drive these to assert cap enforcement,
    // per-peer isolation, and fair draining without a live network. Read-only
    // observers return table sizes; `bp_*` injectors call the same private
    // methods the production paths call.

    /// Enqueue one outbox message via the real `enqueue` path (caps, shed
    /// counter, dirty flag, persist).
    pub async fn bp_enqueue_outbox(
        &self,
        pid: [u8; NODEID_LEN],
        topic: String,
        data: String,
        msg_id: u64,
        seq: u64,
        origin: String,
    ) {
        self.enqueue(
            pid,
            QueuedMsg {
                topic,
                data,
                msg_id,
                seq,
                origin,
                attempts: 0,
                ts: now_ms(),
            },
        )
        .await;
    }

    /// Pending messages queued for one peer.
    pub async fn bp_outbox_len(&self, pid: [u8; NODEID_LEN]) -> usize {
        self.outbox.read().await.get(&pid).map(|q| q.len()).unwrap_or(0)
    }

    /// Distinct peers with a pending outbox queue.
    pub async fn bp_outbox_peer_count(&self) -> usize {
        self.outbox.read().await.len()
    }

    /// Per-message attempt counters for one peer's queue (drain progress).
    pub async fn bp_outbox_attempts(&self, pid: [u8; NODEID_LEN]) -> Vec<u32> {
        self.outbox
            .read()
            .await
            .get(&pid)
            .map(|q| q.iter().map(|m| m.attempts).collect())
            .unwrap_or_default()
    }

    /// Run one real `flush_outbox_once` drain cycle.
    pub async fn bp_flush_outbox_once(self: &Arc<Self>) {
        self.flush_outbox_once().await;
    }

    /// Insert into the real `subs_book` path (topic/peer caps). Returns false
    /// on shed. Does NOT attach a live conn (no network in tests).
    pub async fn bp_sub_book(&self, topic: &str, pid: [u8; NODEID_LEN]) -> bool {
        self.subs_book(topic, pid).await
    }

    /// (topics with subscribers, max subscribers of one topic).
    pub async fn bp_subs_sizes(&self) -> (usize, usize) {
        let s = self.subs.read().await;
        let max_peers = s.values().map(|m| m.len()).max().unwrap_or(0);
        (s.len(), max_peers)
    }

    /// Offer to the real `reorder_offer` path. Returns messages to deliver
    /// now as `(data, src, seq)`.
    pub async fn bp_reorder_offer(
        &self,
        origin: String,
        topic: String,
        seq: u64,
        data: String,
        src: String,
    ) -> Vec<(String, String, u64)> {
        self.reorder_offer(&origin, &topic, seq, data, src).await
    }

    /// (distinct reorder keys, largest single buffer).
    pub async fn bp_reorder_sizes(&self) -> (usize, usize) {
        let r = self.reorder.read().await;
        let max_buf = r.values().map(|(_, b)| b.len()).max().unwrap_or(0);
        (r.len(), max_buf)
    }

    /// Insert via the real `mail_cache_insert` path (cap + eviction).
    pub async fn bp_mail_cache_insert(&self, name: String, blob: Vec<u8>) {
        self.mail_cache_insert(name, blob).await;
    }

    /// Decrypted bodies currently cached.
    pub async fn bp_mail_cache_len(&self) -> usize {
        self.mail_cache.read().await.len()
    }

    /// Allocate via the real `next_topic_seq` path (saturates to 0 at cap).
    pub async fn bp_next_topic_seq(&self, topic: &str) -> u64 {
        self.next_topic_seq(topic).await
    }

    /// Distinct topics with an allocated sequence.
    pub async fn bp_topic_seq_len(&self) -> usize {
        self.topic_seq.read().await.len()
    }

    /// Live local subscribers of one topic (after dead-prune on register).
    pub async fn bp_app_subs_len(&self, topic: &str) -> usize {
        self.app_subs.read().await.get(topic).map(|v| v.len()).unwrap_or(0)
    }

    /// Insert via the real `session_insert` path. Returns false on shed.
    pub async fn bp_session_insert(&self, sid: usize, key: [u8; 32]) -> bool {
        self.session_insert(sid, key).await
    }

    /// Stored session keys.
    pub async fn bp_sessions_len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Insert via the real `add_conn` path (per-peer + total caps, eviction).
    pub async fn bp_conn_insert(&self, pid: [u8; NODEID_LEN], conn: Connection) {
        self.add_conn(pid, conn).await;
    }

    /// Tracked connections for one peer.
    pub async fn bp_conns_len(&self, pid: [u8; NODEID_LEN]) -> usize {
        self.conns.read().await.get(&pid).map(|v| v.len()).unwrap_or(0)
    }

    /// Distinct peers with tracked connections.
    pub async fn bp_conns_peers(&self) -> usize {
        self.conns.read().await.len()
    }

    /// Admit via the real sessionless-guard path (fail-closed at cap).
    /// On admit, ensures a guard entry exists like the production path.
    pub async fn bp_guard_admit(&self, pid: [u8; NODEID_LEN]) -> bool {
        let mut g = self
            .sessionless_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&pid) && g.len() >= MAX_SESSIONLESS_GUARD_PEERS {
            return false;
        }
        g.entry(pid).or_default();
        true
    }

    /// Stored routes.
    pub async fn bp_routes_len(&self) -> usize {
        self.routes.read().await.len()
    }

    /// Feed a `dht.update`-style payload through the REAL gossip-merge path
    /// (per-update + total caps). Returns the response bytes.
    pub async fn bp_handle_dht_update(self: &Arc<Self>, v: serde_json::Value) -> Option<Vec<u8>> {
        self.handle_dht_update(&v).await
    }

    pub fn resolve(&self, sel: &str) -> Result<[u8; NODEID_LEN]> {
        if let Some(pid) = self.by_name.get(sel) {
            return Ok(*pid);
        }
        let s = sel.strip_prefix("inf1:").unwrap_or(sel);
        let b = hex::decode(s)?;
        if b.len() != NODEID_LEN {
            bail!("node id must be 20 bytes");
        }
        let mut pid = [0u8; NODEID_LEN];
        pid.copy_from_slice(&b);
        Ok(pid)
    }

    /// Backpressure admission for the session table. Returns false (fail-closed:
    /// caller must abort the connection) when the table is full and this is a
    /// new entry. No fitting metrics counter exists (follow-up).
    async fn session_insert(&self, sid: usize, key: [u8; 32]) -> bool {
        let mut s = self.sessions.write().await;
        if !s.contains_key(&sid) && s.len() >= MAX_SESSIONS_TOTAL {
            return false;
        }
        s.insert(sid, key);
        true
    }

    /// KEX wiring: remember the PQ transcript digest for a PQ-negotiated
    /// connection. Same fail-closed cap as `session_insert`; caller drops the
    /// session + conn when full so the two maps never disagree on PQ-ness.
    async fn pq_digest_insert(&self, sid: usize, digest: [u8; 32]) -> bool {
        let mut m = self.pq_digests.write().await;
        if !m.contains_key(&sid) && m.len() >= MAX_SESSIONS_TOTAL {
            return false;
        }
        m.insert(sid, digest);
        true
    }

    async fn add_conn(&self, pid: [u8; NODEID_LEN], conn: Connection) {
        // Circuit breaker: any registered connection — outbound dial success
        // or inbound accept — proves reachability and closes the breaker.
        // Silent for healthy peers (no entry: no log, no counter). Auth,
        // reputation, and session logic below are untouched.
        self.circuit_record_success(pid);
        let sid = conn.stable_id();
        // Backpressure admission (fail-closed): dedup first, then caps. The
        // checks run under a read guard; the insert re-checks under the
        // write guard so a race can only refuse, never exceed the cap.
        // No fitting metrics counter exists for conn-table sheds (follow-up).
        let need_evict: Option<usize> = {
            let conns = self.conns.read().await;
            match conns.get(&pid) {
                Some(v) if v.iter().any(|c| c.stable_id() == sid) => return,
                Some(v) if v.len() >= MAX_CONNS_PER_PEER => v.first().map(|c| c.stable_id()),
                None if conns.len() >= MAX_CONN_PEERS_TOTAL => {
                    conn.close(quinn::VarInt::from(0u32), b"conn table full");
                    return;
                }
                _ => None,
            }
        };
        if let Some(old) = need_evict {
            // Evict the oldest conn of this peer (close + repoint + sub
            // cleanup via remove_conn), then store the new one below.
            self.remove_conn(pid, old).await;
        }
        let mut conns = self.conns.write().await;
        let v = conns.entry(pid).or_default();
        if v.iter().any(|c| c.stable_id() == sid) {
            return;
        }
        if v.len() >= MAX_CONNS_PER_PEER {
            drop(conns);
            conn.close(quinn::VarInt::from(0u32), b"conn table full");
            return;
        }
        v.push(conn);
    }

    async fn remove_conn(&self, pid: [u8; NODEID_LEN], sid: usize) {
        let removed: Option<Connection> = {
            let mut conns = self.conns.write().await;
            let mut removed = None;
            if let Some(v) = conns.get_mut(&pid) {
                if let Some(i) = v.iter().position(|c| c.stable_id() == sid) {
                    removed = Some(v.remove(i));
                }
                if v.is_empty() {
                    conns.remove(&pid);
                }
            }
            removed
        };
        // CLOSE the connection, never merely forget its handle. A forgotten
        // Connection keeps running on QUIC keepalive (max_idle 120s), which
        // holds the peer's accept permit (MAX_INCOMING) and local resources.
        // With evict-on-timeout every stalled request spawned a fresh conn
        // while the old ones lingered, so the peer's accept slots filled and
        // it started refusing outright -- "aborted by peer: the server
        // refused to accept a new connection" plus handshake timeouts in BOTH
        // directions, i.e. a total consensus blackout that only a restart
        // cleared.
        if let Some(c) = removed {
            c.close(quinn::VarInt::from(0u32), b"dropped by node");
        }
        let peer = self.peers.read().await.get(&pid).cloned();
        if let Some(peer) = peer {
            // guard от read() обязан умереть ДО write() — tokio RwLock нереентерабельный
            let matches = {
                let guard = peer.conn.read().await;
                matches!(guard.as_ref(), Some(c) if c.stable_id() == sid)
            };
            if matches {
                // если осталось живое соединение к этому пиру — переуказываем на него,
                // иначе None (reconnect_loop переподключится)
                let survivor = {
                    let conns = self.conns.read().await;
                    conns.get(&pid).and_then(|v| v.last().cloned())
                };
                match survivor {
                    Some(c) => *peer.conn.write().await = Some(c),
                    None => *peer.conn.write().await = None,
                }
            }
        }
        for by_node in self.subs.write().await.values_mut() {
            if let Some(st) = by_node.get_mut(&pid) {
                st.conns.remove(&sid);
            }
        }
    }

    async fn pick_conn(
        &self,
        peer: Option<&PeerLink>,
        pid: [u8; NODEID_LEN],
    ) -> Option<Connection> {
        // R18: `peer` читается ВЫЗЫВАЮЩИМ (поиск по peers здесь не нужен) — на
        // горячем пути запроса peers.read() делается ровно один раз в request_to,
        // а не три (request_to + connect_or_get + pick_conn). `None` = вызывающему
        // лень читать самому: тогда читаем здесь, ровно как раньше.
        let owned = match peer {
            Some(_) => None,
            None => self.peers.read().await.get(&pid).cloned(),
        };
        if let Some(peer) = peer.or(owned.as_ref()) {
            if let Some(c) = peer.conn.read().await.as_ref() {
                return Some(c.clone());
            }
        }
        let conns = self.conns.read().await;
        conns.get(&pid).and_then(|v| v.first().cloned())
    }

    async fn drop_conn(&self, pid: [u8; NODEID_LEN], conn_id: Option<usize>) {
        match conn_id {
            Some(sid) => self.remove_conn(pid, sid).await,
            None => {
                // Same rule as remove_conn: closing is what frees the PEER's
                // accept slot, not just our map entry (see there).
                let stale: Vec<Connection> = {
                    let mut conns = self.conns.write().await;
                    conns.remove(&pid).unwrap_or_default()
                };
                let peer = self.peers.read().await.get(&pid).cloned();
                if let Some(peer) = peer {
                    *peer.conn.write().await = None;
                }
                for c in stale {
                    c.close(quinn::VarInt::from(0u32), b"dropped by node");
                }
            }
        }
    }

    /// Drop all cached connections to a peer, forcing a fresh dial on next use.
    /// For callers whose own (shorter) timeout preempts `request_to`'s inner
    /// retry: the inner self-heal only fires on inner network errors, so a
    /// caller that times out first would otherwise reuse the dead connection
    /// forever (observed: one-directional consensus blackouts lasting until a
    /// process restart). Additive only; existing paths untouched.
    pub async fn invalidate_peer_conn(&self, pid: [u8; NODEID_LEN]) {
        self.drop_conn(pid, None).await;
    }

    /// Record a peer address we could DIAL, but never overwrite a good one
    /// with a bad one.
    ///
    /// On an INBOUND connection `conn.remote_address()` is the peer's
    /// *ephemeral client port* (something like 127.0.0.1:55169). Writing that
    /// into `learned` poisoned the NAT-punch fallback: every later dial first
    /// tried the configured endpoint, then burned its whole request budget on
    /// a port nobody listens on, and the caller's 2s timeout cancelled the
    /// attempt -- observed on the stand as handshake/"connection lost" storms
    /// plus reconnect churn that exhausted the peer's accept permits. Only
    /// fill `learned` when we do not have an address yet; our own outbound
    /// dials (which end at the peer's LISTENER) and DHT endpoint records
    /// remain the authoritative sources.
    ///
    /// R11: read-first. `learned` почти всегда уже заполнен, а раньше КАЖДЫЙ
    /// входящий кадр брал write-lock на эту ячейку — конкуренция с dial-путём,
    /// который тоже пишет learned.
    async fn remember_peer_addr(&self, peer: &PeerLink, addr: SocketAddr) {
        if peer.learned.read().await.is_some() {
            return;
        }
        let mut g = peer.learned.write().await;
        if g.is_none() {
            *g = Some(addr);
        }
    }

    async fn connect_with_auth(&self, peer: &PeerLink, addr: SocketAddr) -> Result<Connection> {
        let pid = peer.cfg.node_id_raw()?;
        let connecting =
            self.client_ep
                .connect_with(peer.client_cfg.clone(), addr, &peer.cfg.name)?;
        let conn = timeout(Duration::from_secs(8), connecting)
            .await
            .map_err(|_| anyhow!("handshake timeout"))??;

        // forward secrecy: свежий эфемерный X25519 на каждое соединение
        let eph_sec = XSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = XPub::from(&eph_sec);
        // PQ handshake offer (default-ON since PQ 9.1; explicit opt-out
        // `STELL_INF_PQ_HANDSHAKE=0`, honored pre-H only): ephemeral
        // ML-KEM-768 ek alongside the classical fields. Opted-out => None and
        // the classical payload below is byte-identical to before.
        let pq_offer = if proto::pq_handshake_active() {
            Some(pq_initiator_offer()?)
        } else {
            None
        };
        let payload = if let Some(offer) = &pq_offer {
            json!({
                "nonce": rand_hex(16),
                "at": now_ms(),
                "eph": hex::encode(eph_pub.as_bytes()),
                "ed": hex::encode(self.keys.verifying.as_bytes()),
                "x": hex::encode(self.keys.e2e_pub.as_bytes()),
                "pq_ver": proto::PQ_TRANSCRIPT_VERSION,
                "pq_suite": proto::PQ_SUITE_MLKEM768_HYBRID,
                "pq_ek": hex::encode(&offer.ek),
            })
            .to_string()
            .into_bytes()
        } else {
            json!({
                "nonce": rand_hex(16),
                "at": now_ms(),
                "eph": hex::encode(eph_pub.as_bytes()),
                "ed": hex::encode(self.keys.verifying.as_bytes()),
                "x": hex::encode(self.keys.e2e_pub.as_bytes()),
            })
            .to_string()
            .into_bytes()
        };
        let mut f = Frame {
            kind: proto::kind::CHALLENGE,
            seq: self.next_seq(),
            ts: now_ms(),
            src: self.id,
            dst: pid,
            svc: 0,
            payload,
            nonce: vec![],
            sig: [0; 64],
        };
        self.sign_frame(&mut f);
        // open_bi with no timeout hangs forever against a half-dead peer
        // (conn looks alive, streams never open): the caller then burns its
        // whole timeout budget doing nothing, and since no error surfaces the
        // cached conn is reused forever. Fail fast so retry/evict can engage.
        let (mut send, mut recv) =
            tokio::time::timeout(std::time::Duration::from_secs(8), conn.open_bi())
                .await
                .map_err(|_| anyhow!("open stream timeout"))??;
        send.write_all(&f.encode()).await?;
        let _ = send.finish();
        let bytes = timeout(
            Duration::from_secs(8),
            recv.read_to_end(proto::MAX_AUTH_FRAME),
        )
        .await
        .map_err(|_| anyhow!("AUTH timeout"))??;
        let auth = Frame::decode(&bytes)?;
        let vk = VerifyingKey::from_bytes(&peer.cfg.ed_bytes()?)?;
        if auth.kind != proto::kind::AUTH || auth.src != pid || !auth.verify(&vk) || !ts_ok(auth.ts)
        {
            bail!("auth failed");
        }
        // AUTH-payload тоже проверяем строго (fail-closed): свежесть `at` и
        // привязка `node` к src. Раньше содержимое payload не смотрелось
        // вообще — проходил любой подписанный фрейм с теми же полями.
        {
            let av: serde_json::Value = serde_json::from_slice(&auth.payload)?;
            let at = av["at"]
                .as_i64()
                .ok_or_else(|| anyhow!("auth without at"))?;
            if !ts_ok(at) {
                bail!("stale auth");
            }
            let node_field = av["node"]
                .as_str()
                .ok_or_else(|| anyhow!("auth without node"))?;
            if node_field != format!("inf1:{}", hex::encode(pid)) {
                bail!("auth node mismatch");
            }
            if hex_fixed_32(av["eph"].as_str(), "eph").is_err() {
                bail!("auth without eph");
            }
        }
        // PQ handshake answer (default-ON): verify the transcript tag BEFORE
        // session derivation; absent PQ fields => classical fallback (window,
        // plan §5) with a loud WARN + counter while pre-H. Refusals carry
        // clear errors, never silent downgrade.
        let pq_agreed = if proto::pq_handshake_active() {
            pq_initiator_answer(&pq_offer, &f.sign_data(), eph_pub.as_bytes(), &auth)?
        } else {
            None
        };
        if proto::pq_handshake_active() && pq_agreed.is_none() {
            // PQ was attempted first (default-ON) but the responder answered
            // classical: pre-H window fallback — loud, counted, explicit.
            proto::pq_warn_classical_fallback("dial");
        }
        // forward secrecy: сессионный ключ из static+эфемерных ECDH
        let classical = derive_session_key(&self.keys, &peer.cfg, &eph_sec, &auth.payload)?;
        // PQ-hybrid: breaks only if BOTH classical X3DH and ML-KEM break.
        let key = match &pq_agreed {
            Some(a) => proto::pq_hybrid_session_key(&classical, &a.shared, &a.digest),
            None => classical,
        };
        // Backpressure: fail-closed when the session table is full (the dial
        // fails here instead of growing memory without bound).
        if !self.session_insert(conn.stable_id(), key).await {
            self.drop_conn(pid, Some(conn.stable_id())).await;
            bail!("sessions full");
        }
        // KEX wiring: PQ-negotiated sessions carry their transcript digest so
        // frame seal/open binds the AAD; classical sessions store nothing and
        // stay on the legacy path. Digest-table-full drops the just-stored
        // session + conn (fail-closed, never a half-PQ session).
        if let Some(a) = &pq_agreed {
            if !self.pq_digest_insert(conn.stable_id(), a.digest).await {
                self.sessions.write().await.remove(&conn.stable_id());
                self.drop_conn(pid, Some(conn.stable_id())).await;
                bail!("pq digests full");
            }
        }
        self.add_route(pid, addr.to_string(), &peer.cfg.ed_pub)
            .await;
        self.routing_insert(pid, &peer.cfg.endpoints, &peer.cfg.ed_pub, &peer.cfg.x_pub)
            .await;
        // No replay reset needed: the anti-replay window is per CONNECTION now
        // (`ConnReplayWindow`, created lazily by `replay_window`), so a new
        // connection starts with an empty window and cannot inherit a sequence
        // position from a previous one. Resetting a shared per-peer window here was
        // the bug: it let an old connection's position suppress a new one's frames.
        Ok(conn)
    }

    /// Гарантировать, что на соединении работает приёмный цикл (frame_loop).
    ///
    /// QUIC-соединение двунаправленно, поэтому дозвонившаяся сторона тоже
    /// обязана принимать потоки. Раньше цикл запускался только на принятых
    /// соединениях (и в start_listener/reconnect_loop), из-за чего нода, которая
    /// только дозванивалась, могла отправлять запросы, но не могла принимать их
    /// обратно: pubsub-доставка молча работала в одну сторону. Идемпотентно по
    /// stable_id — второй цикл на том же соединении не поднимается.
    fn ensure_frame_loop(self: &Arc<Self>, conn: Connection, pid: Option<[u8; NODEID_LEN]>) {
        let sid = conn.stable_id();
        {
            let mut looped = self.looped.lock().unwrap_or_else(|e| e.into_inner());
            if !looped.insert(sid) {
                return;
            }
        }
        let node = self.clone();
        // Цикл сам снимет отметку по завершении (см. конец frame_loop).
        tokio::spawn(async move {
            frame_loop(conn, node, pid).await;
        });
    }

    /// R18: `peer` передаётся вызывающим (один peers.read на весь запрос вместо
    /// двух-трёх); все прочие вызовы читают peers сами и приходят сюда с готовым
    /// PeerLink.
    async fn connect_or_get(
        self: &Arc<Self>,
        peer: &PeerLink,
        pid: [u8; NODEID_LEN],
    ) -> Result<Connection> {
        if let Some(c) = self.pick_conn(Some(peer), pid).await {
            return Ok(c);
        }
        // Simultaneous-open tie-break. When BOTH sides dial each other at the
        // same moment QUIC resolves the collision badly for us: one handshake
        // is aborted by the other ("aborted by peer ... during the handshake")
        // and both ends retry in lockstep, producing a self-sustaining dial
        // storm -- 478 such aborts in ~7 minutes on the live stand, after
        // which neither direction could complete a handshake and consensus
        // stopped dead. Exactly one side initiates: the LOWER node id dials
        // at once, the higher one waits briefly for the peer's inbound
        // connection (the peer is configured to dial us for the same reason).
        // Falls through to dialing anyway after the wait, so a peer that
        // cannot dial us still gets connected.
        //
        // The wait is SHORT (100ms by default, `INFNODE_SIMOPEN_WAIT_MS`) and
        // only applies to a STATIC peer — one that our config says dials us
        // back. It used to be 15 x 50ms = 750ms for EVERY peer, so a
        // reconnect to a restarting/loaded peer cost ~1s of pure sleep, and a
        // peer that never dials back (TOFU/DHT-discovered, or a validator
        // behind NAT) delayed us for nothing on every single attempt.
        if simopen_should_wait(&self.id, &pid, self.static_peers.contains(&pid)) {
            let wait_ms = simopen_wait_ms();
            let step = SIMOPEN_WAIT_STEP_MS;
            let mut waited = 0u64;
            while waited < wait_ms {
                tokio::time::sleep(Duration::from_millis(step)).await;
                waited += step;
                if let Some(c) = self.pick_conn(Some(peer), pid).await {
                    return Ok(c);
                }
            }
            // If the lower node id did NOT dial within the window, we must fall
            // through to dial_peer. Otherwise, if the higher node is behind
            // NAT, NAT mappings expire and the node is permanently isolated
            // from the cluster.
        }
        self.dial_peer(peer, pid).await
    }
}

/// Endpoint hygiene: hard cap on dial attempts per peer per reconnect
/// cycle. Bounds the sweep so a peer with many configured/gossip endpoints
/// (or a fast-growing route table) can never look like a port scan.
pub const MAX_DIAL_ENDPOINTS_PER_CYCLE: usize = 3;

/// Endpoint hygiene: gossip-learned route endpoints per reconnect cycle.
/// A separate small budget inside [`MAX_DIAL_ENDPOINTS_PER_CYCLE`] — gossip
/// is tried only after every configured endpoint failed.
pub const MAX_GOSSIP_DIAL_PER_CYCLE: usize = 1;

/// Where one entry of a dial plan came from (test/monitoring accessor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialKind {
    /// Listed in the operator config, in listed order.
    Configured,
    /// Learned via route gossip, tried only after configured failed.
    Gossip,
    /// Public observed address (NAT hole punch), unparked peers only.
    Punch,
}

/// One endpoint to attempt in a reconnect cycle, in attempt order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialPlanEntry {
    pub endpoint: String,
    pub kind: DialKind,
}

/// Build the ordered dial plan for one reconnect cycle (pure, no I/O).
///
/// Order: configured first (listed order, exact dupes collapsed), then
/// gossip-learned route endpoints (skipping any already covered, at most
/// [`MAX_GOSSIP_DIAL_PER_CYCLE`]), then the NAT-punch fallback (only when
/// it adds an address not already covered). Total length never exceeds
/// [`MAX_DIAL_ENDPOINTS_PER_CYCLE`]; every entry counts toward the same
/// budget (no extra tries). A parked peer (sibling breaker signal) gets a
/// single probe of its first configured endpoint: no gossip, no punch.
///
/// Unparseable strings are kept (the dial loop logs them exactly as before
/// without spending budget); only actual `connect_with_auth` calls count
/// as attempts, so attempts `<= plan.len() <= MAX_DIAL_ENDPOINTS_PER_CYCLE`.
pub fn build_dial_plan(
    configured: &[String],
    gossip: &[String],
    punch: Option<SocketAddr>,
    parked: bool,
) -> Vec<DialPlanEntry> {
    if parked {
        // Single probe: first listed endpoint only, whatever it parses to.
        return configured
            .first()
            .map(|ep| DialPlanEntry {
                endpoint: ep.clone(),
                kind: DialKind::Configured,
            })
            .into_iter()
            .collect();
    }
    let mut out: Vec<DialPlanEntry> = Vec::new();
    for ep in configured {
        if out.len() >= MAX_DIAL_ENDPOINTS_PER_CYCLE {
            break;
        }
        if out.iter().any(|e| e.endpoint == *ep) {
            continue;
        }
        out.push(DialPlanEntry {
            endpoint: ep.clone(),
            kind: DialKind::Configured,
        });
    }
    let mut gossip_used = 0usize;
    for ep in gossip {
        if out.len() >= MAX_DIAL_ENDPOINTS_PER_CYCLE || gossip_used >= MAX_GOSSIP_DIAL_PER_CYCLE {
            break;
        }
        if out.iter().any(|e| e.endpoint == *ep) {
            continue;
        }
        out.push(DialPlanEntry {
            endpoint: ep.clone(),
            kind: DialKind::Gossip,
        });
        gossip_used += 1;
    }
    if out.len() < MAX_DIAL_ENDPOINTS_PER_CYCLE {
        if let Some(addr) = punch {
            let ep_str = addr.to_string();
            if !out.iter().any(|e| e.endpoint == ep_str) {
                out.push(DialPlanEntry {
                    endpoint: ep_str,
                    kind: DialKind::Punch,
                });
            }
        }
    }
    out
}

impl Node {
    /// Record one failed outbound dial attempt for a peer.
    ///
    /// Granularity is per ATTEMPT, not per endpoint: a full sweep that fails
    /// everywhere (or a single parked probe that fails) counts once, so the
    /// sibling width cap and this time-domain park compose instead of
    /// double-counting. At [`CIRCUIT_FAIL_THRESHOLD`] the peer parks with
    /// [`CIRCUIT_BACKOFF_FIRST_SECS`]; each failed probe while parked extends
    /// the park to the next backoff step (5min, then 30min cap). Success
    /// resets via [`Node::circuit_record_success`] (called from `add_conn`).
    pub fn circuit_record_failure(&self, pid: [u8; NODEID_LEN]) {
        let now = std::time::Instant::now();
        let mut map = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(&pid) && map.len() >= MAX_CIRCUIT_PEERS {
            // Fail-closed bound: evict one CLOSED entry first so a flood of
            // fresh dead peers cannot grow memory without bound; never evict
            // a parked peer (that would silently unpark it). If every entry
            // is parked, skip tracking (the peer stays unparked this cycle).
            if let Some(victim) = map
                .iter()
                .find_map(|(k, e)| (!circuit_should_park(e.consecutive_failures)).then_some(*k))
            {
                map.remove(&victim);
            } else {
                return;
            }
        }
        let e = map.entry(pid).or_insert(CircuitEntry {
            consecutive_failures: 0,
            next_probe_at: None,
            backoff_secs: 0,
        });
        e.consecutive_failures = e.consecutive_failures.saturating_add(1);
        if circuit_should_park(e.consecutive_failures) {
            let backoff = circuit_backoff_secs(e.consecutive_failures);
            e.backoff_secs = backoff;
            e.next_probe_at = now.checked_add(Duration::from_secs(backoff));
            if e.consecutive_failures == CIRCUIT_FAIL_THRESHOLD {
                let total = self.circuit_parks.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "[{}] CIRCUIT PARK peer={} fails={} backoff_s={} total_parks={}",
                    self.cfg.name,
                    hex::encode(pid),
                    e.consecutive_failures,
                    backoff,
                    total
                );
            } else {
                // Failed probe while parked: loud, but the park counter counts
                // closed→parked transitions only (escalations stay countable
                // via consecutive_failures/backoff_secs).
                eprintln!(
                    "[{}] CIRCUIT PARK-EXTEND peer={} fails={} backoff_s={}",
                    self.cfg.name,
                    hex::encode(pid),
                    e.consecutive_failures,
                    backoff
                );
            }
        }
    }

    /// Reset the breaker to closed. Called on every registered connection
    /// (`add_conn`: outbound dial success AND inbound accept prove
    /// reachability) and when `reconnect_loop` observes a live connection.
    /// Silent for healthy peers (unknown/closed entry: no log, no counter).
    pub fn circuit_record_success(&self, pid: [u8; NODEID_LEN]) {
        let was_parked = {
            let mut map = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
            match map.remove(&pid) {
                Some(e) => circuit_should_park(e.consecutive_failures),
                None => return,
            }
        };
        if was_parked {
            let total = self.circuit_unparks.fetch_add(1, Ordering::Relaxed) + 1;
            eprintln!(
                "[{}] CIRCUIT UNPARK peer={} total_unparks={}",
                self.cfg.name,
                hex::encode(pid),
                total
            );
        }
    }

    /// Breaker open (parked): threshold consecutive failures reached.
    /// Closed peers dial the normal path; only open peers are gated.
    pub fn circuit_is_parked(&self, pid: &[u8; NODEID_LEN]) -> bool {
        self.circuit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pid)
            .is_some_and(|e| circuit_should_park(e.consecutive_failures))
    }

    /// A parked peer may be probed once its backoff interval has elapsed.
    /// Closed peers are never "due" (the normal dial path owns them).
    pub fn circuit_probe_due(&self, pid: &[u8; NODEID_LEN]) -> bool {
        let map = self.circuit.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(pid) {
            Some(e) => {
                circuit_should_park(e.consecutive_failures)
                    && e.next_probe_at
                        .is_some_and(|u| std::time::Instant::now() >= u)
            }
            None => false,
        }
    }

    /// Consecutive failures currently counted for a peer (0 = closed/unknown).
    pub fn circuit_consecutive_failures(&self, pid: &[u8; NODEID_LEN]) -> u32 {
        self.circuit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pid)
            .map(|e| e.consecutive_failures)
            .unwrap_or(0)
    }

    /// Backoff in force for a parked peer (0 when closed). Test/monitor hook.
    pub fn circuit_current_backoff_secs(&self, pid: &[u8; NODEID_LEN]) -> u64 {
        self.circuit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pid)
            .map(|e| e.backoff_secs)
            .unwrap_or(0)
    }

    /// Breaker transitions so far (in-zone counters, not metrics.rs).
    pub fn circuit_parks_total(&self) -> u64 {
        self.circuit_parks.load(Ordering::Relaxed)
    }

    /// Breaker closes so far (in-zone counters, not metrics.rs).
    pub fn circuit_unparks_total(&self) -> u64 {
        self.circuit_unparks.load(Ordering::Relaxed)
    }

    /// Tracked breaker entries (cap test hook).
    pub fn circuit_len(&self) -> usize {
        self.circuit.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Node {
    /// Dial a peer directly, bypassing the simultaneous-open tie-break.
    ///
    /// This is the dial half of `connect_or_get`, split out so the guarded
    /// fallback in `conn_with_session` can use it. A successful dial always
    /// registers a session (`connect_with_auth`), so the returned conn is
    /// immediately usable for requests.
    ///
    /// Endpoint hygiene (port-scan incident): one reconnect cycle sweeps at
    /// most [`MAX_DIAL_ENDPOINTS_PER_CYCLE`] endpoints per peer — configured
    /// endpoints first (in listed order), gossip-learned route endpoints
    /// last within [`MAX_GOSSIP_DIAL_PER_CYCLE`], and the NAT-punch fallback
    /// only when unparked and inside the same budget (no extra tries). The
    /// gossip input is a bounded snapshot cloned once per cycle, never the
    /// live-growing route vec. A reputation-parked peer (banned or
    /// soft-throttled — sibling breaker signal, read-only here) gets a
    /// single probe of its first configured endpoint.
    async fn dial_peer(
        self: &Arc<Self>,
        peer: &PeerLink,
        pid: [u8; NODEID_LEN],
    ) -> Result<Connection> {
        // Bounded snapshots: cloned once so a concurrently growing route
        // table cannot widen this cycle's sweep.
        let configured: Vec<String> = peer.cfg.endpoints.clone();
        let gossip_snapshot: Vec<String> = self
            .routes
            .read()
            .await
            .get(&pid)
            .map(|r| r.endpoints.clone())
            .unwrap_or_default();
        let punch: Option<SocketAddr> = *peer.learned.read().await;
        // Sibling breaker signals (read-only observation, no state touched):
        // a reputation-parked OR circuit-parked peer gets a single probe of
        // its first configured endpoint, never a sweep.
        let parked = self.rep_is_banned(&pid).await
            || self.rep_is_throttled(&pid).await
            || self.circuit_is_parked(&pid);
        let plan = build_dial_plan(&configured, &gossip_snapshot, punch, parked);
        let mut last_err = anyhow!("no endpoints");
        let mut attempts = 0usize;
        for entry in &plan {
            // Defense in depth: the plan is already bounded; never exceed it.
            if attempts >= MAX_DIAL_ENDPOINTS_PER_CYCLE {
                break;
            }
            let addr: SocketAddr = match entry.endpoint.parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("[{}] bad endpoint '{}'", self.cfg.name, entry.endpoint);
                    continue;
                }
            };
            attempts += 1;
            let tag = match entry.kind {
                DialKind::Configured => String::new(),
                DialKind::Gossip => " (gossip)".to_string(),
                DialKind::Punch => " (NAT punch)".to_string(),
            };
            match self.connect_with_auth(peer, addr).await {
                Ok(c) => {
                    *peer.conn.write().await = Some(c.clone());
                    *peer.learned.write().await = Some(c.remote_address());
                    self.add_conn(pid, c.clone()).await;
                    self.ensure_frame_loop(c.clone(), Some(pid));
                    return Ok(c);
                }
                Err(e) => {
                    last_err = anyhow!("{} @ {}{tag}: {e}", peer.cfg.name, entry.endpoint);
                    eprintln!(
                        "[{}] connect {} @ {}{tag}: {e}",
                        self.cfg.name, peer.cfg.name, entry.endpoint
                    );
                }
            }
        }
        // Circuit breaker: a fully failed sweep counts ONE consecutive failure
        // (per-attempt, not per-endpoint — `build_dial_plan` above already
        // bounds the width). Success resets via `add_conn`.
        self.circuit_record_failure(pid);
        Err(last_err)
    }

    /// Single probe dial for a circuit-parked peer whose backoff has elapsed.
    ///
    /// Parked discipline: FIRST configured endpoint only (no endpoint sweep,
    /// no gossip, no NAT punch), and the caller (`reconnect_loop`) spawns no
    /// `catch_up` for it. Success closes the breaker (via `add_conn`); a
    /// failed probe extends the park to the next backoff step.
    async fn dial_parked_probe(
        self: &Arc<Self>,
        peer: &PeerLink,
        pid: [u8; NODEID_LEN],
    ) -> Result<Connection> {
        // The sole parked dial path: `circuit_probe_endpoint` returns the
        // FIRST configured endpoint only (no sweep, no gossip, no punch).
        let Some(ep) = circuit_probe_endpoint(&peer.cfg.endpoints) else {
            self.circuit_record_failure(pid);
            bail!("parked probe: no configured endpoints");
        };
        let addr: SocketAddr = match ep.parse() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("[{}] bad probe endpoint '{ep}'", self.cfg.name);
                self.circuit_record_failure(pid);
                bail!("parked probe: bad endpoint '{ep}'");
            }
        };
        match self.connect_with_auth(peer, addr).await {
            Ok(c) => {
                *peer.conn.write().await = Some(c.clone());
                *peer.learned.write().await = Some(c.remote_address());
                self.add_conn(pid, c.clone()).await;
                self.ensure_frame_loop(c.clone(), Some(pid));
                Ok(c)
            }
            Err(e) => {
                eprintln!(
                    "[{}] connect {} @ {ep} (parked probe): {e}",
                    self.cfg.name, peer.cfg.name
                );
                self.circuit_record_failure(pid);
                Err(anyhow!("{} @ {ep} (parked probe): {e}", peer.cfg.name))
            }
        }
    }

    /// A connection that is guaranteed to carry a session key, self-healing.
    ///
    /// A cached conn can lose its session (its frame_loop tore down and took
    /// the session entry with it while the object stayed cached). Such a conn
    /// can NEVER serve a request, yet the old code returned it as-is and every
    /// later request failed in ~10µs with "no session key for conn" until a
    /// process restart (observed live: one-directional consensus blackout,
    /// height 71587 stalled 4.5h, nodeB broadcasting nothing while receiving
    /// everything). This heals it:
    ///   1. fast path: cached conn + live session, returned as-is;
    ///   2. a cached conn without a session is dropped (exactly that object),
    ///      then the normal reconnect runs (strict tie-break preserved);
    ///   3. last resort: dial directly even as the higher-id side. Allowed
    ///      ONLY after we proved the cache unusable this call (dropped a
    ///      session-less conn) or recently (evict may have cleared it since),
    ///      and gated by a per-peer cooldown, so a dead peer cannot turn this
    ///      into the dial storm the strict tie-break fixed. The peer is alive
    ///      (it keeps sending to us), so one direct dial resolves the
    ///      blackout; a simultaneous-open abort just fails this attempt.
    async fn conn_with_session(
        self: &Arc<Self>,
        peer: &PeerLink,
        pid: [u8; NODEID_LEN],
    ) -> Result<(Connection, [u8; 32])> {
        let mut dropped_sessionless = false;
        // Fast path + scrub: a cached conn without a session is checked with brief wait (100ms)
        // before declaring it dead weight, so concurrent handshakes are not prematurely dropped.
        if let Some(conn) = self.pick_conn(Some(peer), pid).await {
            if let Some(key) = wait_session_key(self, &conn, 100).await {
                return Ok((conn, key));
            }
            self.drop_conn(pid, Some(conn.stable_id())).await;
            dropped_sessionless = true;
        }
        // Normal reconnect (strict tie-break preserved).
        if let Ok(conn) = self.connect_or_get(peer, pid).await {
            if let Some(key) = wait_session_key(self, &conn, 100).await {
                return Ok((conn, key));
            }
            self.drop_conn(pid, Some(conn.stable_id())).await;
            dropped_sessionless = true;
        }
        // Guarded fallback
        let now = std::time::Instant::now();
        {
            let mut g = self
                .sessionless_guard
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Backpressure: fail-closed when the guard table is full (no new
            // entry for an unknown peer; the fallback dial is skipped).
            // No fitting metrics counter exists (follow-up).
            if !g.contains_key(&pid) && g.len() >= MAX_SESSIONLESS_GUARD_PEERS {
                return Err(anyhow!("no session key for conn"));
            }
            let e = g.entry(pid).or_default();
            if dropped_sessionless {
                e.last_drop = Some(now);
            }
            if matches!(e.last_dial, Some(t) if now.duration_since(t).as_millis() < FALLBACK_DIAL_COOLDOWN_MS as u128)
            {
                return Err(anyhow!("no session key for conn"));
            }
            e.last_dial = Some(now);
        }
        match self.dial_peer(peer, pid).await {
            Ok(conn) => match wait_session_key(self, &conn, 150).await {
                Some(key) => Ok((conn, key)),
                None => {
                    self.drop_conn(pid, Some(conn.stable_id())).await;
                    Err(anyhow!("no session key for conn"))
                }
            },
            Err(e) => Err(anyhow!("fallback dial: {e}")),
        }
    }

    pub async fn request(
        self: &Arc<Self>,
        sel: &str,
        svc: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let pid = self.resolve(sel)?;
        self.request_to(pid, svc, payload).await
    }

    /// Запрос к пиру по его raw node_id.
    pub async fn request_to(
        self: &Arc<Self>,
        pid: [u8; NODEID_LEN],
        svc: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // R18: РОВНО ОДИН peers.read на весь запрос (дальше peer раздаётся в
        // connect_or_get/pick_conn — раньше каждый из них читал peers заново).
        let peer = self
            .peers
            .read()
            .await
            .get(&pid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown peer"))?;
        let t_dial = std::time::Instant::now();
        // Self-healing conn acquisition: a cached conn that lost its session
        // is dropped and reconnected (with a guarded dial fallback) instead of
        // failing every request until restart.
        let (conn, key) = self.conn_with_session(&peer, pid).await?;
        let dial_ms = t_dial.elapsed().as_millis();
        let t_resp = std::time::Instant::now();
        // R19: payload не клонируется «на всякий случай» — обе попытки читают
        // один и тот же Vec; clone остаётся только там, где владение реально
        // нужно (spawned-доставка в deliver_local).
        let req_timeout_secs: u64 = if svc == "mail.send" { 30 } else { 5 };
        let first = self
            .request_on(&conn, &pid, &key, &peer, svc, &payload, req_timeout_secs)
            .await;
        let resp_ms = t_resp.elapsed().as_millis();
        if dial_ms >= 200 || resp_ms >= 200 {
            eprintln!(
                "[{}] request_to {} dial={dial_ms}ms resp={resp_ms}ms",
                self.cfg.name,
                hex::encode(&pid[..4])
            );
        }
        match first {
            Ok(r) => Ok(r),
            Err(e) => {
                // повторяем ТОЛЬКО при сетевой ошибке (соединение умерло до ответа).
                // Если сервис уже выполнился (publish/mail), повторный retry задублирует side-эффект.
                let msg = e.to_string();
                let is_network = msg.contains("connection lost")
                    || msg.contains("response timeout")
                    || msg.contains("write timeout")
                    || msg.contains("closed")
                    || msg.contains("handshake")
                    || msg.contains("open stream");
                if !is_network {
                    return Err(e);
                }
                // Anti-re-flood: the single retry used to fire IMMEDIATELY on a
                // fresh connection. When the first attempt died to a receiver
                // drop (`too many concurrent streams`, 256 cap) every sender
                // re-dialed on the same tick and re-tripped the cap —
                // timeout+retry self-excitation (stellereum 2026-10-13:
                // `request_to dial=0ms resp=2500-3500ms`). A 50-150ms jittered
                // pause de-synchronizes the retries; still exactly one retry,
                // still off any consensus critical path (callers time out).
                let jitter_ms = 50u64 + rand::random::<u64>() % 101;
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                self.drop_conn(pid, Some(conn.stable_id())).await;
                let (conn, key) = self.conn_with_session(&peer, pid).await?;
                self.request_on(&conn, &pid, &key, &peer, svc, &payload, req_timeout_secs)
                    .await
            }
        }
    }

    /// Fire-and-forget send: write the request frame and RETURN without
    /// waiting for the peer's `RESP`.
    ///
    /// Why: `request_to` is a full request/response round trip. The peer's
    /// `RESP` is produced by its handler AFTER the handler is scheduled — on a
    /// WAN link that is 300-1200 ms, and the caller pays it on EVERY message.
    /// For a vote/proposal the response carries no information the sender
    /// needs (the peer's app-level answer is a fixed `{"ok":true,...}`), so
    /// the round trip is pure latency on the quorum-critical path.
    ///
    /// What this waits for: ONLY the local write (stream open + frame write +
    /// finish). The peer's response is drained by a detached background task,
    /// so the peer never sees a stream reset (which would log a "stream task
    /// error" on its side) and the caller's budget bounds the LOCAL spend.
    ///
    /// Retry discipline mirrors `request_to`: exactly one retry, on a network
    /// error only, after a jittered pause, on a fresh connection.
    pub async fn send_to(
        self: &Arc<Self>,
        pid: [u8; NODEID_LEN],
        svc: &str,
        payload: Vec<u8>,
    ) -> Result<()> {
        let peer = self
            .peers
            .read()
            .await
            .get(&pid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown peer"))?;
        let (conn, key) = self.conn_with_session(&peer, pid).await?;
        match self.send_frame_on(&conn, &pid, &key, svc, &payload).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                let is_network = msg.contains("connection lost")
                    || msg.contains("write timeout")
                    || msg.contains("closed")
                    || msg.contains("handshake")
                    || msg.contains("open stream");
                if !is_network {
                    return Err(e);
                }
                let jitter_ms = 50u64 + rand::random::<u64>() % 101;
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                self.drop_conn(pid, Some(conn.stable_id())).await;
                let (conn, key) = self.conn_with_session(&peer, pid).await?;
                self.send_frame_on(&conn, &pid, &key, svc, &payload).await
            }
        }
    }

    /// Write ONE request frame on `conn` and finish the send side. Does NOT
    /// read the response: the caller either does not care (fire-and-forget) or
    /// reads it itself.
    ///
    /// Returns the send stream's peer-side half in `recv` so the caller can
    /// decide; the fire-and-forget path hands it to a detached drain task.
    async fn send_frame_on(
        &self,
        conn: &Connection,
        pid: &[u8; NODEID_LEN],
        key: &[u8; 32],
        svc: &str,
        payload: &[u8],
    ) -> Result<()> {
        let (mut send, mut recv) =
            tokio::time::timeout(std::time::Duration::from_secs(8), conn.open_bi())
                .await
                .map_err(|_| anyhow!("open stream timeout"))??;
        // Same priority rule as `request_on`: consensus traffic must never
        // queue behind bulk DHT/chunk transfers.
        if svc == "pubsub.msg" || svc == "consensus.sign" {
            let _ = send.set_priority(1000);
        } else {
            let _ = send.set_priority(0);
        }
        let seq = self.next_seq();
        let ts = now_ms();
        let svc_id = proto::svc_id(svc);
        // KEX seal site: PQ sessions bind header+digest AAD, classical None.
        let pq_digest = self.pq_digests.read().await.get(&conn.stable_id()).copied();
        let (ct, nonce) = frame_seal_body(
            key,
            pq_digest,
            proto::kind::REQ,
            seq,
            ts,
            &self.id,
            pid,
            svc_id,
            payload,
        );
        let mut f = Frame {
            kind: proto::kind::REQ,
            seq,
            ts,
            src: self.id,
            dst: *pid,
            svc: svc_id,
            payload: ct,
            nonce,
            sig: [0; 64],
        };
        self.sign_frame(&mut f);
        self.metrics.frames_out.fetch_add(1, Ordering::Relaxed);
        let wire = f.encode();
        self.metrics
            .bytes_out
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        match tokio::time::timeout(Duration::from_secs(8), send.write_all(&wire)).await {
            Err(_) => return Err(anyhow!("write timeout")),
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(())) => {}
        }
        let _ = send.finish();
        // Drain the response in the background: the peer writes its `RESP`
        // after handling the service, and a half-read stream would make the
        // peer see a RESET (logged there as a stream error). The drain is
        // fire-and-forget and its result is ignored on purpose.
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(2), recv.read_to_end(proto::MAX_FRAME)).await;
        });
        Ok(())
    }

    /// Запрос по конкретному соединению (для pubsub-доставки подписчику).
    #[allow(clippy::too_many_arguments)] // GATE: replication plumbing needs full peer context
    async fn request_on(
        &self,
        conn: &Connection,
        pid: &[u8; NODEID_LEN],
        key: &[u8; 32],
        peer: &PeerLink,
        svc: &str,
        payload: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>> {
        // open_bi can block on the peer's stream credit or a half-dead
        // connection; connect_with_auth guards this same call with 8s. Bound it
        // so a stalled open surfaces as a retryable network error instead of
        // silently eating the caller's whole budget before the response timer
        // even starts.
        let t_open = std::time::Instant::now();
        let (mut send, mut recv) =
            tokio::time::timeout(std::time::Duration::from_secs(8), conn.open_bi())
                .await
                .map_err(|_| anyhow!("open stream timeout"))??;
        let open_ms = t_open.elapsed();
        // Priority scheduling: consensus traffic (pubsub.msg) must NEVER queue
        // behind bulk DHT/chunk storage transfers over WAN.
        if svc == "pubsub.msg" || svc == "consensus.sign" {
            let _ = send.set_priority(1000);
        } else {
            let _ = send.set_priority(0);
        }
        let seq = self.next_seq();
        let ts = now_ms();
        let svc_id = proto::svc_id(svc);
        // KEX seal site: PQ sessions bind header+digest AAD, classical None.
        let pq_digest = self.pq_digests.read().await.get(&conn.stable_id()).copied();
        let (ct, nonce) = frame_seal_body(
            key,
            pq_digest,
            proto::kind::REQ,
            seq,
            ts,
            &self.id,
            pid,
            svc_id,
            payload,
        );
        let mut f = Frame {
            kind: proto::kind::REQ,
            seq,
            ts,
            src: self.id,
            dst: *pid,
            svc: svc_id,
            payload: ct,
            nonce,
            sig: [0; 64],
        };
        self.sign_frame(&mut f);
        self.metrics.frames_out.fetch_add(1, Ordering::Relaxed);
        // R20: кодируем РОВНО ОДИН раз — раньше encode() считался дважды
        // (один раз в bytes_out, второй раз в write_all), т.е. каждый запрос
        // платил за полную сериализацию фрейма дважды.
        let wire = f.encode();
        self.metrics
            .bytes_out
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        // R21: write_all ограничен 8с (симметрично open_bi с коммита 449f4c5).
        // Зависший write раньше ждал бесконечно и съедал весь бюджет вызывающего
        // без единой ошибки сверху; теперь это "write timeout" — сетевая ошибка,
        // при которой request_to делает один повтор на свежем соединении.
        let t_write = std::time::Instant::now();
        match tokio::time::timeout(Duration::from_secs(8), send.write_all(&wire)).await {
            Err(_) => return Err(anyhow!("write timeout")),
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(())) => {}
        }
        let write_ms = t_write.elapsed();
        let _ = send.finish();
        let t_wait = std::time::Instant::now();
        let bytes = timeout(
            Duration::from_secs(timeout_secs),
            recv.read_to_end(proto::MAX_FRAME),
        )
        .await
        .map_err(|_| anyhow!("response timeout"))??;
        let wait_ms = t_wait.elapsed();
        // Patch B: стадии запроса (open/write/wait) с join-ключом (f.seq, f.ts) —
        // приёмник логирует ТЕ ЖЕ seq/ts в "dispatch", обе ноды сидят на одних
        // и тех же часах и строки джойнятся напрямую.
        let max_ms = open_ms.max(write_ms).max(wait_ms);
        if max_ms >= Duration::from_millis(200) {
            crate::log::emit(
                2,
                "info",
                &self.cfg.name,
                0,
                "req_stages",
                json!({
                    "seq": f.seq,
                    "ts": f.ts,
                    "svc": svc,
                    "open_ms": open_ms.as_millis() as u64,
                    "write_ms": write_ms.as_millis() as u64,
                    "wait_ms": wait_ms.as_millis() as u64,
                }),
            );
        }
        let resp = Frame::decode(&bytes)?;
        let vk = VerifyingKey::from_bytes(&peer.cfg.ed_bytes()?)?;
        if resp.kind != proto::kind::RESP || !resp.verify(&vk) {
            bail!("bad response");
        }
        // KEX open site: PQ sessions verify the AAD-bound tag, classical None.
        let pq_digest = self.pq_digests.read().await.get(&conn.stable_id()).copied();
        frame_open_body(key, pq_digest, &resp)
    }

    pub async fn ping(self: &Arc<Self>, sel: &str, count: u32) -> Result<String> {
        let pid = self.resolve(sel)?;
        let peer = self
            .peers
            .read()
            .await
            .get(&pid)
            .cloned()
            .ok_or_else(|| anyhow!("peer {sel} not found"))?;
        let mut times = Vec::new();
        for _ in 0..count {
            let t = Instant::now();
            let resp = self.request(sel, "core.ping", vec![]).await?;
            let dt = t.elapsed();
            times.push(dt);
            *peer.rtt.write().await = Some(dt);
            let txt = String::from_utf8_lossy(&resp);
            eprintln!(
                "  reply seq={} rtt={:.2}ms {}",
                times.len(),
                dt.as_secs_f64() * 1000.0,
                txt
            );
        }
        let min = times.iter().cloned().min().unwrap_or(Duration::ZERO);
        let max = times.iter().cloned().max().unwrap_or(Duration::ZERO);
        let avg: Duration = times.iter().sum::<Duration>() / times.len() as u32;
        let jitter = times
            .windows(2)
            .map(|w| {
                let d = w[1].saturating_sub(w[0]);
                d.as_secs_f64() * 1000.0
            })
            .fold(0.0_f64, |a, b| a + b)
            / times.len().max(2) as f64;
        Ok(format!(
            "min={:.2}ms avg={:.2}ms max={:.2}ms jitter={:.2}ms n={}",
            min.as_secs_f64() * 1000.0,
            avg.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0,
            jitter,
            times.len()
        ))
    }

    pub async fn perf(
        self: &Arc<Self>,
        sel: &str,
        size: usize,
        count: u32,
        direction: &str,
    ) -> Result<String> {
        let t = Instant::now();
        let mut ok = 0u32;
        match direction {
            // однонаправленный upload: шлём большой payload, получаем маленький ack
            "upload" => {
                let mut payload = vec![0u8; size];
                rand::thread_rng().fill_bytes(&mut payload);
                for _ in 0..count {
                    let resp = self.request(sel, "core.perf.up", payload.clone()).await?;
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                        if v["received"].as_u64().unwrap_or(0) as usize == size {
                            ok += 1;
                        }
                    }
                }
            }
            // однонаправленный download: шлём маленький запрос, получаем большой ответ
            "download" => {
                let req = json!({ "size": size }).to_string().into_bytes();
                for _ in 0..count {
                    let resp = self.request(sel, "core.perf.down", req.clone()).await?;
                    if resp.len() == size {
                        ok += 1;
                    }
                }
            }
            // эхо (по умолчанию): payload туда и обратно
            _ => {
                let mut payload = vec![0u8; size];
                rand::thread_rng().fill_bytes(&mut payload);
                for _ in 0..count {
                    let resp = self.request(sel, "core.perf", payload.clone()).await?;
                    if resp.len() == size {
                        ok += 1;
                    }
                }
            }
        }
        let dt = t.elapsed();
        let total_mb = (size * count as usize) as f64 / (1024.0 * 1024.0);
        let mbps = total_mb / dt.as_secs_f64();
        Ok(format!(
            "direction={direction} transferred={}MB in {:.3}s -> {:.2} MB/s (encrypted e2e+sign, {ok}/{count} verified)",
            total_mb, dt.as_secs_f64(), mbps
        ))
    }

    pub async fn poke(self: &Arc<Self>, sel: &str) -> Result<String> {
        let resp = self.request(sel, "core.poke", vec![]).await?;
        let v: serde_json::Value = serde_json::from_slice(&resp)?;
        let observed = v["observed"].as_str().unwrap_or("?");
        Ok(format!(
            "remote observed our endpoint: {observed} (NAT hole punch ok)"
        ))
    }

    pub async fn status(&self) -> Result<String> {
        let mut out = json!({
            "node": self.id_hex,
            "name": self.cfg.name,
            "listen": self.cfg.listen,
            "advertise": self.cfg.advertise,
        });
        let mut plist = Vec::new();
        for (pid, peer) in self.peers.read().await.iter() {
            let conn = peer.conn.read().await.is_some();
            let rtt = peer.rtt.read().await.map(|d| d.as_secs_f64() * 1000.0);
            let learned = peer.learned.read().await.map(|a| a.to_string());
            plist.push(json!({
                "name": peer.cfg.name,
                "node_id": format!("inf1:{}", hex::encode(pid)),
                "connected": conn,
                "rtt_ms": rtt,
                "learned_endpoint": learned,
                "acl": peer.cfg.allow,
            }));
        }
        out["peers"] = serde_json::Value::Array(plist);
        Ok(serde_json::to_string_pretty(&out)?)
    }

    // ============ Pub/Sub ============

    /// Локальная подписка приложения (CLI/MCP) на топик.
    pub async fn register_app_sub(&self, topic: &str) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut subs = self.app_subs.write().await;
            // Backpressure: fail-closed caps on the local subscriber table.
            // Dead receivers are pruned first (a dropped rx otherwise stays
            // in the vec forever and every publish pays for it); only when
            // all slots hold LIVE receivers is the new subscription shed
            // (the rx is still returned, but nothing is delivered to it).
            // No fitting metrics counter exists (follow-up).
            if !subs.contains_key(topic) && subs.len() >= MAX_APP_SUB_TOPICS {
                return rx;
            }
            let v = subs.entry(topic.to_string()).or_default();
            v.retain(|s| !s.is_closed());
            if v.len() >= MAX_APP_SUBS_PER_TOPIC {
                return rx;
            }
            v.push(tx);
        }
        rx
    }

    /// Подключиться к пиру и запустить обработку входящих фреймов (для подписчика).
    pub async fn start_listener(self: &Arc<Self>, sel: &str) -> Result<()> {
        let pid = self.resolve(sel)?;
        // R18: один peers.read здесь, дальше peer уходит в connect_or_get.
        let peer = self
            .peers
            .read()
            .await
            .get(&pid)
            .cloned()
            .ok_or_else(|| anyhow!("unknown peer"))?;
        let conn = self.connect_or_get(&peer, pid).await?;
        // connect_or_get уже поднял цикл; ensure_frame_loop идемпотентен.
        self.ensure_frame_loop(conn, Some(pid));
        Ok(())
    }

    /// Учёт известного эндпоинта пира + персистентность.
    async fn add_route(&self, pid: [u8; NODEID_LEN], endpoint: String, ed_hex: &str) {
        let mut write_now = false;
        {
            let mut routes = self.routes.write().await;
            // Backpressure: fail-closed total cap on the route table (per
            // update and per-node caps stay in `proto`). Unknown nodes beyond
            // the cap are ignored. No fitting metrics counter (follow-up).
            if !routes.contains_key(&pid) && routes.len() >= MAX_ROUTES_TOTAL {
                return;
            }
            let route = routes.entry(pid).or_insert(Route {
                endpoints: Vec::new(),
                ed_hex: ed_hex.to_string(),
            });
            if !route.endpoints.contains(&endpoint) {
                route.endpoints.push(endpoint);
                write_now = true;
            }
        }
        // запись на диск ВНЕ блокировки — иначе блокируем всех ждущих routes
        if write_now {
            let map: HashMap<String, Route> = {
                let routes = self.routes.read().await;
                routes
                    .iter()
                    .map(|(k, v)| (format!("inf1:{}", hex::encode(k)), v.clone()))
                    .collect()
            };
            if let Ok(json) = serde_json::to_string(&map) {
                // R2: std::fs::write убран из async-путя (write_file -> spawn_blocking).
                self.write_file("routes.json", json).await;
            }
        }
    }

    /// Динамическая регистрация неизвестной ноды (TOFU): строит pinned client_cfg и PeerLink.
    async fn add_dynamic_peer(&self, pid: [u8; NODEID_LEN], pcfg: PeerConfig) -> Result<()> {
        let ed = pcfg.ed_bytes()?;
        let rc = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pinned: ed }))
        .with_no_client_auth();
        let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(rc))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
        client_cfg.transport_config(Arc::new(transport_config()));
        let link = PeerLink {
            cfg: pcfg,
            conn: Arc::new(RwLock::new(None)),
            rtt: Arc::new(RwLock::new(None)),
            learned: Arc::new(RwLock::new(None)),
            last_seen: Arc::new(Mutex::new(0)),
            replay_windows: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            client_cfg,
            rate: Arc::new(Mutex::new(RateBucket::new())),
        };
        self.peers.write().await.insert(pid, link);
        Ok(())
    }

    /// Backpressure booking for the subscription table. Returns false
    /// (fail-closed: caller must refuse the subscription) when a new topic
    /// or a new subscriber would exceed the caps. Refreshes `ts` on the
    /// existing entry. Connection slots are capped separately at insert time.
    /// No fitting metrics counter exists (follow-up).
    async fn subs_book(&self, topic: &str, pid: [u8; NODEID_LEN]) -> bool {
        let mut subs = self.subs.write().await;
        if !subs.contains_key(topic) && subs.len() >= MAX_SUBS_TOPICS {
            return false;
        }
        let by_node = subs.entry(topic.to_string()).or_default();
        if !by_node.contains_key(&pid) && by_node.len() >= MAX_SUBS_PEERS_PER_TOPIC {
            return false;
        }
        let st = by_node.entry(pid).or_insert(SubState {
            ts: now_ms(),
            conns: HashMap::new(),
        });
        st.ts = now_ms();
        true
    }

    /// Обработка pubsub/dht-сервисов. Возвращает plaintext-ответ, если сервис распознан.
    async fn handle_node_svc(
        self: &Arc<Self>,
        svc: u64,
        conn: &Connection,
        from: [u8; NODEID_LEN],
        plain: &[u8],
    ) -> Option<Vec<u8>> {
        use crate::proto::svc_id;
        let v: serde_json::Value = serde_json::from_slice(plain).ok()?;
        let topic = v["topic"].as_str().unwrap_or("default").to_string();

        if svc == svc_id("dht.lookup") {
            return self.handle_dht_lookup(&v, from).await;
        }
        if svc == svc_id("dht.update") {
            return self.handle_dht_update(&v).await;
        }
        if svc == svc_id("dht.find_node") {
            return self.handle_dht_find_node(&v).await;
        }
        if svc == svc_id("dht.store") {
            return self.handle_dht_store(&v, from).await;
        }
        if svc == svc_id("dht.find_value") {
            return self.handle_dht_find_value(&v, from).await;
        }
        if svc == svc_id("dht.sync") {
            return self.handle_dht_sync(&v, from).await;
        }
        if svc == svc_id("storage.store") {
            return self.handle_storage_store(&v).await;
        }
        if svc == svc_id("storage.fetch") {
            return self.handle_storage_fetch(&v).await;
        }
        if svc == svc_id("storage.delete") {
            return self.handle_storage_delete(&v).await;
        }
        if svc == svc_id("mail.list") {
            return self.handle_mail_list(&v).await;
        }
        if svc == svc_id("core.health") {
            return self.handle_health().await;
        }
        // консенсус: суб-валидатор подписывает хэш состояния своим Ed25519 ключом.
        // Доступ разрешён только пирам из cfg.validators (и самому себе).
        if svc == svc_id("consensus.sign") {
            if !self.is_consensus_signer(&from).await {
                return Some(
                    json!({ "ok": false, "err": "not a consensus signer" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let v: serde_json::Value = serde_json::from_slice(plain).ok()?;
            let state_hash = v["state_hash"].as_str().unwrap_or("").to_string();
            if state_hash.len() != 64 {
                return Some(
                    json!({ "ok": false, "err": "bad state_hash" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let sig = ed25519_dalek::Signer::sign(&self.keys.signing, state_hash.as_bytes());
            return Some(
                json!({
                    "ok": true,
                    "node_id": self.id_hex,
                    "signature": hex::encode(sig.to_bytes()),
                })
                .to_string()
                .into_bytes(),
            );
        }

        if svc == svc_id("pubsub.subscribe") {
            if !crate::proto::topic_ok(&topic) {
                return Some(
                    json!({ "ok": false, "err": "bad topic" })
                        .to_string()
                        .into_bytes(),
                );
            }
            if !self.subs_book(&topic, from).await {
                return Some(
                    json!({ "ok": false, "err": "too many subscriptions" })
                        .to_string()
                        .into_bytes(),
                );
            }
            {
                // Fail-closed per-(topic, peer) connection slots: beyond the
                // cap the subscription stays (outbox covers delivery) but no
                // further live conn is tracked.
                let mut subs = self.subs.write().await;
                if let Some(st) = subs.get_mut(&topic).and_then(|m| m.get_mut(&from)) {
                    if st.conns.contains_key(&conn.stable_id())
                        || st.conns.len() < MAX_SUB_CONNS_PER_PEER
                    {
                        st.conns.insert(conn.stable_id(), conn.clone());
                    }
                }
            }
            self.persist_subs().await;
            Some(
                json!({ "ok": true, "op": "subscribed", "topic": topic })
                    .to_string()
                    .into_bytes(),
            )
        } else if svc == svc_id("pubsub.unsubscribe") {
            if !crate::proto::topic_ok(&topic) {
                return Some(
                    json!({ "ok": false, "err": "bad topic" })
                        .to_string()
                        .into_bytes(),
                );
            }
            if let Some(t) = self.subs.write().await.get_mut(&topic) {
                t.remove(&from);
            }
            self.persist_subs().await;
            Some(
                json!({ "ok": true, "op": "unsubscribed", "topic": topic })
                    .to_string()
                    .into_bytes(),
            )
        } else if svc == svc_id("pubsub.publish") {
            // Fail-closed: топик/данные/TTL ограничены ДО любых side-эффектов
            // (seq/mark_seen/deliver/forward). Раньше данные принимались вплоть
            // до 32 МиБ фрейма, а ttl=u64::MAX давал бесконечный веер по mesh.
            if !crate::proto::topic_ok(&topic) {
                return Some(
                    json!({ "ok": false, "err": "bad topic" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let data = v["data"].as_str().unwrap_or("").to_string();
            if !crate::proto::pubsub_data_ok(&data) {
                return Some(
                    json!({ "ok": false, "err": "data too large" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let msg_id = v["msg_id"].as_u64().unwrap_or_else(rand_u64);
            let ttl = v["ttl"]
                .as_u64()
                .unwrap_or(3)
                .min(crate::proto::MAX_PUBSUB_TTL);
            // порядок: origin присваивает seq из своего per-topic счётчика
            let seq = self.next_topic_seq(&topic).await;
            let origin = self.id_hex.clone();
            // помечаем на origin, чтобы вернувшийся по mesh relay не доставил дубликат
            self.mark_seen(msg_id).await;
            self.metrics.msgs_published.fetch_add(1, Ordering::Relaxed);
            let exclude_conn = conn.stable_id();
            let n = self
                .deliver_local(&topic, &data, msg_id, seq, &origin, Some(exclude_conn))
                .await;
            self.metrics
                .msgs_delivered
                .fetch_add(n as u64, Ordering::Relaxed);
            self.forward(&topic, &data, msg_id, seq, &origin, ttl, Some(from))
                .await;
            Some(
                json!({ "ok": true, "op": "published", "topic": topic, "delivered": n, "msg_id": msg_id, "seq": seq })
                    .to_string()
                    .into_bytes(),
            )
        } else if svc == svc_id("pubsub.relay") {
            // Тот же fail-closed гейт, что у publish: битый relay дропается
            // молча (без forward/deliver), иначе чужой веер качает через нас
            // гигабайты.
            if !crate::proto::topic_ok(&topic) {
                return Some(
                    json!({ "ok": false, "err": "bad topic" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let data = v["data"].as_str().unwrap_or("").to_string();
            if !crate::proto::pubsub_data_ok(&data) {
                return Some(
                    json!({ "ok": false, "err": "data too large" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let msg_id = v["msg_id"].as_u64().unwrap_or_else(rand_u64);
            let ttl = v["ttl"]
                .as_u64()
                .unwrap_or(0)
                .min(crate::proto::MAX_PUBSUB_TTL);
            let seq = v["seq"].as_u64().unwrap_or(0);
            let origin = v["origin"].as_str().unwrap_or("").to_string();
            if self.mark_seen(msg_id).await {
                return Some(
                    json!({ "ok": true, "op": "relayed", "dup": true, "msg_id": msg_id })
                        .to_string()
                        .into_bytes(),
                );
            }
            let exclude_conn = conn.stable_id();
            let n = self
                .deliver_local(&topic, &data, msg_id, seq, &origin, Some(exclude_conn))
                .await;
            self.forward(&topic, &data, msg_id, seq, &origin, ttl, Some(from))
                .await;
            Some(
                json!({ "ok": true, "op": "relayed", "topic": topic, "delivered": n, "msg_id": msg_id })
                    .to_string()
                    .into_bytes(),
            )
        } else if svc == svc_id("pubsub.msg") {
            // терминальная доставка приложению (с per-origin упорядочиванием)
            //
            // `src` = node id ОТПРАВИТЕЛЯ. Без него у получателя нет обратного
            // адреса: приложение (stellereum) выводит ключ ограничителя из
            // конверта, и без `src`/`from` все входящие сообщения попадали в
            // ОДИН общий token bucket ("broadcast") — любой пир мог исчерпать
            // бюджет ВСЕХ остальных. Теперь у каждого отправителя свой bucket.
            let src = hex::encode(from);
            let vv: serde_json::Value = match serde_json::from_slice(plain) {
                Ok(v) => v,
                Err(_) => {
                    // legacy (до seq/origin) — отдаём как есть. Не-JSON payload
                    // приложение всё равно не разберёт, поэтому `src` сюда
                    // положить некуда: конверт не является объектом.
                    let senders = {
                        let s = self.app_subs.read().await;
                        s.get(&topic).cloned().unwrap_or_default()
                    };
                    for tx in senders {
                        let _ = tx.send(String::from_utf8_lossy(plain).to_string());
                    }
                    return Some(
                        json!({ "ok": true, "op": "msg", "topic": topic })
                            .to_string()
                            .into_bytes(),
                    );
                }
            };
            let origin = vv["origin"].as_str().unwrap_or("").to_string();
            let seq = vv["seq"].as_u64().unwrap_or(0);
            let data = vv["data"].as_str().unwrap_or("").to_string();
            let mut ordered: Vec<String> = Vec::new();
            if origin.is_empty() || seq == 0 {
                ordered.push(
                    json!({ "topic": topic, "data": data, "msg_id": vv["msg_id"], "src": src })
                        .to_string(),
                );
            } else {
                // reorder: выдаём в порядке seq по (origin, topic)
                // (per-origin ordering; `src` travels with `data` so the
                // per-sender token bucket is charged to the real sender).
                // Backpressure sheds deliver immediately instead of buffering
                // (no loss, no stall; ordering best-effort under overflow).
                for (d, d_src, d_seq) in self.reorder_offer(&origin, &topic, seq, data, src).await
                {
                    ordered.push(
                        json!({ "topic": topic, "data": d, "seq": d_seq, "origin": origin, "src": d_src })
                            .to_string(),
                    );
                }
            }
            let senders = {
                let s = self.app_subs.read().await;
                s.get(&topic).cloned().unwrap_or_default()
            };
            // Delivery accounting: count receipts with no local subscriber
            // (topic mismatch / late subscribe). Counter only — the former
            // throttled [diag] eprintlns were removed after the blackhole
            // root cause (unsharded-vs-sharded topic mismatch) was found.
            if senders.is_empty() {
                self.metrics.msgs_dropped_no_sub.fetch_add(
                    1,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            for msg in &ordered {
                for tx in &senders {
                    if tx.send(msg.clone()).is_err() {
                        self.metrics
                            .msgs_dropped_dead_rx
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            Some(
                json!({ "ok": true, "op": "msg", "topic": topic })
                    .to_string()
                    .into_bytes(),
            )
        } else {
            None
        }
    }

    /// Per-origin reorder buffer insert. Returns the messages to deliver NOW,
    /// in order, as `(data, src, seq)`. Contiguous arrivals drain the buffer;
    /// duplicates (`seq < next`) return empty. Backpressure sheds (unknown
    /// key beyond `MAX_REORDER_KEYS`, or a full buffer beyond
    /// `MAX_REORDER_BUF_PER_KEY`) return the message for IMMEDIATE delivery
    /// instead of buffering: memory stays bounded, nothing is lost, no gap
    /// can stall the stream; ordering is best-effort under overflow.
    /// No fitting metrics counter exists (follow-up).
    async fn reorder_offer(
        &self,
        origin: &str,
        topic: &str,
        seq: u64,
        data: String,
        src: String,
    ) -> Vec<(String, String, u64)> {
        let mut out = Vec::new();
        let mut reorder = self.reorder.write().await;
        let key = (origin.to_string(), topic.to_string());
        if !reorder.contains_key(&key) && reorder.len() >= MAX_REORDER_KEYS {
            out.push((data, src, seq));
            return out;
        }
        let entry = reorder.entry(key).or_insert((1, BTreeMap::new()));
        let (next, buf) = entry;
        if seq == *next {
            out.push((data, src, seq));
            *next += 1;
            while let Some((d, d_src)) = buf.remove(next) {
                out.push((d, d_src, *next));
                *next += 1;
            }
        } else if seq > *next {
            if buf.len() >= MAX_REORDER_BUF_PER_KEY {
                out.push((data, src, seq));
            } else {
                buf.entry(seq).or_insert((data, src));
            }
        }
        // seq < next => дубликат/позднее — игнорируем
        out
    }

    /// Доставка подписчикам. Живые соединения — напрямую; оффлайн/ошибки — в persistent outbox.
    /// exclude = stable_id соединения-отправителя (не слать на тот же стрим).
    async fn deliver_local(
        self: &Arc<Self>,
        topic: &str,
        data: &str,
        msg_id: u64,
        seq: u64,
        origin: &str,
        exclude: Option<usize>,
    ) -> usize {
        let subs = self
            .subs
            .read()
            .await
            .get(topic)
            .cloned()
            .unwrap_or_default();
        let payload =
            json!({ "topic": topic, "data": data, "msg_id": msg_id, "seq": seq, "origin": origin })
                .to_string()
                .into_bytes();
        let mut n = 0usize;
        for (sub_pid, st) in &subs {
            let eligible: Vec<(usize, Connection)> = st
                .conns
                .iter()
                .filter(|(sid, _)| Some(**sid) != exclude)
                .map(|(sid, c)| (*sid, c.clone()))
                .collect();
            if !eligible.is_empty() {
                for (sid, sub_conn) in eligible {
                    let key = self.sessions.read().await.get(&sid).copied();
                    // R16: пира ВЫНИМАЕМ из-под read-guard ДО любого await.
                    // Раньше `if let (... , self.peers.read().await.get(..))`
                    // держал временный peers.read() до конца всего выражения
                    // (включая ветку else с enqueue(..) -> persist -> диск):
                    // каждый peers.write() (TOFU/reload) вставал за этот guard,
                    // а за ним вставало и первое await в request_to. Теперь
                    // guard живёт три строки и нигде не пересекается с await'ом.
                    let peer = {
                        let peers = self.peers.read().await;
                        peers.get(sub_pid).cloned()
                    };
                    if let (Some(key), Some(peer)) = (key, peer) {
                        let node = self.clone();
                        let payload = payload.clone();
                        let pid = *sub_pid;
                        let msg = QueuedMsg {
                            topic: topic.to_string(),
                            data: data.to_string(),
                            msg_id,
                            seq,
                            origin: origin.to_string(),
                            attempts: 0,
                            ts: now_ms(),
                        };
                        tokio::spawn(async move {
                            if node
                                .request_on(&sub_conn, &pid, &key, &peer, "pubsub.msg", &payload, 8)
                                .await
                                .is_err()
                            {
                                // соединение умерло/флап — убираем из подписок и кладём в outbox
                                node.remove_sub_conn(&msg.topic, pid, sid).await;
                                node.enqueue(pid, msg).await;
                            }
                        });
                        n += 1;
                    }
                }
            } else {
                // подписка жива, но соединений нет (узел оффлайн) — в outbox
                self.enqueue(
                    *sub_pid,
                    QueuedMsg {
                        topic: topic.to_string(),
                        data: data.to_string(),
                        msg_id,
                        seq,
                        origin: origin.to_string(),
                        attempts: 0,
                        ts: now_ms(),
                    },
                )
                .await;
                n += 1;
            }
        }
        n
    }

    /// Убрать конкретное соединение подписчика (мёртвое).
    async fn remove_sub_conn(&self, topic: &str, pid: [u8; NODEID_LEN], sid: usize) {
        let mut subs = self.subs.write().await;
        if let Some(by_node) = subs.get_mut(topic) {
            if let Some(st) = by_node.get_mut(&pid) {
                st.conns.remove(&sid);
            }
        }
    }

    /// Положить сообщение в outbox узла (dedup по msg_id) + персистентность.
    async fn enqueue(&self, pid: [u8; NODEID_LEN], msg: QueuedMsg) {
        let mut outbox = self.outbox.write().await;
        // Fairness (enqueue side): per-peer queues are independent AND the
        // number of peer queues is capped, so one abusive peer flooding its
        // own queue (or conjuring many peer ids) cannot evict honest peers'
        // queues. Shed drops the NEW message and reuses `outbox_dropped`.
        if !outbox.contains_key(&pid) && outbox.len() >= MAX_OUTBOX_PEERS_TOTAL {
            self.metrics.outbox_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let q = outbox.entry(pid).or_default();
        if q.iter().any(|m| m.msg_id == msg.msg_id) {
            return;
        }
        // Fail-closed: очередь на пира ограничена — иначе флуд публикаций
        // оффлайновому подписчику растит outbox (и outbox.json) без меры.
        // Старое вытесняется новым; счётчик — в существующую метрику дропов.
        if q.len() >= crate::proto::MAX_OUTBOX_PER_PEER {
            q.pop_front();
            self.metrics.outbox_dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(msg);
        // R3: мутация помечается dirty ПОД write-lock'ом — persist очищает флаг
        // до снапшота, поэтому мутация не может «потеряться» между флагом и записью.
        self.outbox_dirty.store(true, Ordering::SeqCst);
        drop(outbox);
        self.persist_outbox().await;
    }

    /// Дренит outbox: живые соединения подписчика или reconnect; ретраи/сроки.
    async fn flush_outbox_once(self: &Arc<Self>) {
        let nodes: Vec<[u8; NODEID_LEN]> = self.outbox.read().await.keys().copied().collect();
        for pid in nodes {
            // Fairness (drain side): round-robin budget per peer per cycle.
            // Without it one abusive peer with a full failing queue consumes
            // the whole flush cycle (1024 dial attempts) before honest peers
            // are serviced; with it every queued peer is touched each cycle.
            let mut budget = MAX_OUTBOX_FLUSH_PER_PEER;
            loop {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let front = {
                    let o = self.outbox.read().await;
                    match o.get(&pid) {
                        Some(q) => q.front().cloned(),
                        None => None,
                    }
                };
                let msg = match front {
                    Some(m) => m,
                    None => break,
                };
                let now = now_ms();
                if msg.attempts >= 5 || now - msg.ts > (self.outbox_ttl * 1000) as i64 {
                    let mut o = self.outbox.write().await;
                    if let Some(q) = o.get_mut(&pid) {
                        q.pop_front();
                        // R3: каждая мутация outbox поднимает dirty.
                        self.outbox_dirty.store(true, Ordering::SeqCst);
                    }
                    self.metrics.outbox_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let payload = json!({
                    "topic": msg.topic,
                    "data": msg.data,
                    "msg_id": msg.msg_id,
                    "seq": msg.seq,
                    "origin": msg.origin,
                })
                .to_string()
                .into_bytes();
                // живые соединения подписчика на этот топик
                let live_conns: Vec<Connection> = self
                    .subs
                    .read()
                    .await
                    .get(&msg.topic)
                    .and_then(|m| m.get(&pid))
                    .map(|st| st.conns.values().cloned().collect())
                    .unwrap_or_default();
                let sent = if let Some(conn) = live_conns.first() {
                    let sid = conn.stable_id();
                    let key = self.sessions.read().await.get(&sid).copied();
                    // R18: ровно один peers.read на итерацию (peer нужен и для
                    // connect_or_get ниже — он берётся тут же, один раз).
                    let peer = self.peers.read().await.get(&pid).cloned();
                    if let (Some(k), Some(p)) = (key, peer) {
                        let ok = self
                            .request_on(conn, &pid, &k, &p, "pubsub.msg", &payload, 8)
                            .await
                            .is_ok();
                        if !ok {
                            // мёртвое соединение — убираем, дальше пойдёт через reconnect
                            self.remove_sub_conn(&msg.topic, pid, sid).await;
                        }
                        ok
                    } else {
                        false
                    }
                } else {
                    // нет живого соединения — пробуем reconnect (известный пир).
                    // R18: один peers.read на итерацию — peer уходит и в
                    // connect_or_get, и в request_on (раньше читался дважды).
                    let peer = self.peers.read().await.get(&pid).cloned();
                    match peer {
                        Some(p) => match self.connect_or_get(&p, pid).await {
                            Ok(conn) => {
                                let sid = conn.stable_id();
                                let key = self.sessions.read().await.get(&sid).copied();
                                match key {
                                    Some(k) => self
                                        .request_on(&conn, &pid, &k, &p, "pubsub.msg", &payload, 8)
                                        .await
                                        .is_ok(),
                                    None => false,
                                }
                            }
                            Err(_) => false,
                        },
                        None => false,
                    }
                };
                let mut o = self.outbox.write().await;
                if let Some(q) = o.get_mut(&pid) {
                    if let Some(front) = q.front_mut() {
                        if sent {
                            q.pop_front();
                            self.metrics
                                .outbox_delivered
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            front.attempts += 1;
                        }
                        // R3: доставка/ретрай меняют outbox — dirty.
                        self.outbox_dirty.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        // чистка просроченных
        {
            let now = now_ms();
            let mut o = self.outbox.write().await;
            let before: usize = o.values().map(|q| q.len()).sum();
            o.retain(|_, q| {
                q.retain(|m| m.attempts < 5 && now - m.ts <= 3_600_000);
                !q.is_empty()
            });
            let after: usize = o.values().map(|q| q.len()).sum();
            if after != before {
                self.outbox_dirty.store(true, Ordering::SeqCst);
            }
        }
        // R3: flush-цикл пишет outbox.json ТОЛЬКО при dirty — раньше каждую
        // секунду ровно один и тот же (часто неизменившийся) файл переписывался
        // синхронно, т.е. один гарантированный disk write(2) в секунду на воркере.
        if self.outbox_dirty.swap(false, Ordering::SeqCst) {
            self.persist_outbox().await;
        }
    }

    async fn persist_subs(&self) {
        let map: HashMap<String, HashMap<String, i64>> = self
            .subs
            .read()
            .await
            .iter()
            .map(|(t, by_node)| {
                (
                    t.clone(),
                    by_node
                        .iter()
                        .map(|(k, v)| (format!("inf1:{}", hex::encode(k)), v.ts))
                        .collect(),
                )
            })
            .collect();
        if let Ok(json) = serde_json::to_string(&map) {
            // R2: write(2) убран из async-путя (write_file -> spawn_blocking под гейтом).
            self.write_file("subs.json", json).await;
        }
    }

    /// Чистка подписок старше 24ч (persistent-подписки не должны жить вечно).
    async fn prune_subs(&self) {
        let cutoff = now_ms() - 24 * 3600 * 1000;
        {
            let mut subs = self.subs.write().await;
            subs.retain(|_, by_node| {
                by_node.retain(|_, st| st.ts >= cutoff);
                !by_node.is_empty()
            });
        }
        self.persist_subs().await;
    }

    async fn persist_outbox(&self) {
        // R3: очищаем dirty ДО снапшота. Мутация, пришедшая после этого
        // момента, снова поднимет флаг (она ставит его под write-lock'ом, а
        // снапшот берётся не раньше, чем write-lock отпущен), так что её запись
        // не теряется: её либо уже видит этот снапшот, либо поймает следующий flush.
        self.outbox_dirty.store(false, Ordering::SeqCst);
        let map: HashMap<String, Vec<QueuedMsg>> = self
            .outbox
            .read()
            .await
            .iter()
            .map(|(k, v)| {
                (
                    format!("inf1:{}", hex::encode(k)),
                    v.iter().cloned().collect(),
                )
            })
            .collect();
        if let Ok(json) = serde_json::to_string(&map) {
            self.write_file("outbox.json", json).await;
        }
    }

    async fn load_persistent(&self) {
        let subs_file = self.data_dir.join("subs.json");
        if let Ok(raw) = std::fs::read_to_string(&subs_file) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, HashMap<String, i64>>>(&raw) {
                let mut subs = self.subs.write().await;
                for (t, by_node) in map {
                    let entry = subs.entry(t).or_default();
                    for (k, ts) in by_node {
                        if let Ok(b) = hex::decode(k.strip_prefix("inf1:").unwrap_or(&k)) {
                            if b.len() == NODEID_LEN {
                                let mut pid = [0u8; NODEID_LEN];
                                pid.copy_from_slice(&b);
                                entry.entry(pid).or_insert(SubState {
                                    ts,
                                    conns: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
        let outbox_file = self.data_dir.join("outbox.json");
                if let Ok(raw) = std::fs::read_to_string(&outbox_file) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, Vec<QueuedMsg>>>(&raw) {
                let mut outbox = self.outbox.write().await;
                for (k, v) in map {
                    if let Ok(b) = hex::decode(k.strip_prefix("inf1:").unwrap_or(&k)) {
                        if b.len() == NODEID_LEN {
                            let mut pid = [0u8; NODEID_LEN];
                            pid.copy_from_slice(&b);
                            // Backpressure on load: persisted state is
                            // untrusted input — enforce the same caps as the
                            // live path (per-queue trim keeps newest, outer
                            // cap sheds whole peer queues).
                            if !outbox.contains_key(&pid)
                                && outbox.len() >= MAX_OUTBOX_PEERS_TOTAL
                            {
                                self.metrics.outbox_dropped.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let mut dq: VecDeque<QueuedMsg> = v.into();
                            while dq.len() > crate::proto::MAX_OUTBOX_PER_PEER {
                                dq.pop_front();
                                self.metrics.outbox_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            outbox.insert(pid, dq);
                        }
                    }
                }
            }
        }
    }

    /// Флуд сообщения по mesh (кроме отправителя), с TTL.
    #[allow(clippy::too_many_arguments)] // GATE: forwarding needs full route context
    async fn forward(
        self: &Arc<Self>,
        topic: &str,
        data: &str,
        msg_id: u64,
        seq: u64,
        origin: &str,
        ttl: u64,
        exclude: Option<[u8; NODEID_LEN]>,
    ) {
        if ttl == 0 {
            return;
        }
        let peers: Vec<[u8; NODEID_LEN]> = self.peers.read().await.keys().copied().collect();
        let payload = json!({
            "topic": topic, "data": data, "msg_id": msg_id, "seq": seq, "origin": origin, "ttl": ttl - 1
        })
        .to_string()
        .into_bytes();
        for pid in peers {
            if Some(pid) == exclude {
                continue;
            }
            let node = self.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let _ = node.request_to(pid, "pubsub.relay", payload).await;
            });
        }
    }

    /// Монотонный seq на топик (порядок сообщений одного origin).
    /// Backpressure: the table is capped at `MAX_TOPIC_SEQ_TOPICS`. Beyond
    /// the cap an unknown topic gets seq 0 (legacy unordered path: the
    /// receiver delivers it immediately instead of reorder-buffering), so
    /// memory stays bounded while delivery keeps working. No fitting metrics
    /// counter exists (follow-up).
    async fn next_topic_seq(&self, topic: &str) -> u64 {
        let mut m = self.topic_seq.write().await;
        if let Some(s) = m.get_mut(topic) {
            *s += 1;
            return *s;
        }
        if m.len() >= MAX_TOPIC_SEQ_TOPICS {
            return 0;
        }
        m.insert(topic.to_string(), 1);
        1
    }

    /// Dedup: возвращает true, если сообщение уже видели.
    /// Окно 5 минут — то же `crate::dht::DEDUP_TTL_MS`, что и у KV-ключей `dedup:*`.
    async fn mark_seen(&self, msg_id: u64) -> bool {
        let mut seen = self.seen.lock().await;
        let now = now_ms();
        let expire = now - crate::dht::DEDUP_TTL_MS;
        seen.retain(|_, ts| *ts > expire);
        if seen.contains_key(&msg_id) {
            return true;
        }
        // Fail-closed для памяти: флуд уникальными msg_id не может растить
        // карту без меры. Сброс лишнего допускает повторную доставку (дубликат
        // безопасен — прикладной слой идемпотентен), но не потерю памяти.
        if seen.len() >= crate::proto::MAX_SEEN_IDS {
            seen.retain(|_, ts| *ts > now - 60_000);
            if seen.len() >= crate::proto::MAX_SEEN_IDS {
                let drop_n = seen.len() - crate::proto::MAX_SEEN_IDS + 1;
                let keys: Vec<u64> = seen.keys().take(drop_n).copied().collect();
                for k in keys {
                    seen.remove(&k);
                }
            }
        }
        seen.insert(msg_id, now);
        false
    }

    /// Discovery: ищем node_id в локальной таблице маршрутов, иначе спрашиваем пиров (TTL).
    async fn handle_dht_lookup(
        self: &Arc<Self>,
        v: &serde_json::Value,
        from: [u8; NODEID_LEN],
    ) -> Option<Vec<u8>> {
        let target_hex = v["node"].as_str().unwrap_or("").to_string();
        // Fail-closed: TTL из сети ограничен — без этого ttl=u64::MAX давал
        // глубокую рекурсию с веером задач на каждом уровне (усиление флуда).
        let ttl = v["ttl"]
            .as_u64()
            .unwrap_or(3)
            .min(crate::proto::MAX_DHT_LOOKUP_TTL);
        let s = target_hex.strip_prefix("inf1:").unwrap_or(&target_hex);
        let b = match hex::decode(s) {
            Ok(b) if b.len() == NODEID_LEN => b,
            _ => {
                return Some(
                    json!({ "ok": false, "err": "bad node id" })
                        .to_string()
                        .into_bytes(),
                );
            }
        };
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&b);

        let known = self.routes.read().await.get(&target).cloned();
        if let Some(route) = known {
            return Some(
                json!({ "ok": true, "found": true, "node": target_hex, "endpoints": route.endpoints, "ed_pub": route.ed_hex, "via": self.id_hex })
                    .to_string()
                    .into_bytes(),
            );
        }
        if ttl == 0 {
            return Some(
                json!({ "ok": true, "found": false, "node": target_hex })
                    .to_string()
                    .into_bytes(),
            );
        }
        // рекурсивный опрос пиров
        let peers: Vec<[u8; NODEID_LEN]> = self
            .peers
            .read()
            .await
            .keys()
            .copied()
            .filter(|p| *p != from)
            .collect();
        let payload = json!({ "node": target_hex, "ttl": ttl - 1 })
            .to_string()
            .into_bytes();
        let mut merged: Vec<String> = Vec::new();
        let mut found_ed: Option<String> = None;
        let mut handles = Vec::new();
        for pid in peers {
            let node = self.clone();
            let payload = payload.clone();
            handles.push(tokio::spawn(async move {
                node.request_to(pid, "dht.lookup", payload).await.ok()
            }));
        }
        for h in handles {
            if let Ok(Ok(Some(s))) = timeout(Duration::from_millis(1000), h).await {
                if let Ok(rv) = serde_json::from_slice::<serde_json::Value>(&s) {
                    if rv["found"].as_bool().unwrap_or(false) {
                        if let Some(eps) = rv["endpoints"].as_array() {
                            for e in eps {
                                if let Some(e) = e.as_str() {
                                    merged.push(e.to_string());
                                }
                            }
                        }
                        if let Some(ed) = rv["ed_pub"].as_str() {
                            found_ed = Some(ed.to_string());
                        }
                    }
                }
            }
        }
        merged.sort();
        merged.dedup();
        if merged.is_empty() {
            Some(
                json!({ "ok": true, "found": false, "node": target_hex })
                    .to_string()
                    .into_bytes(),
            )
        } else {
            Some(
                json!({ "ok": true, "found": true, "node": target_hex, "endpoints": merged, "ed_pub": found_ed, "via": self.id_hex })
                    .to_string()
                    .into_bytes(),
            )
        }
    }

    /// Обмен маршрутами (route gossip): сливаем маршруты, полученные от пира.
    async fn handle_dht_update(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let mut changed = false;
        if let Some(routes) = v["routes"].as_object() {
            // Fail-closed: сплетня ограничена по числу записей — без этого
            // один пир раздувал таблицу маршрутов и файл routes.json без меры.
            if routes.len() > crate::proto::MAX_ROUTES_PER_UPDATE {
                return Some(
                    json!({ "ok": false, "err": "routes too large" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let mut mine = self.routes.write().await;
            for (node_hex, rv) in routes {
                if let Ok(b) = hex::decode(node_hex.strip_prefix("inf1:").unwrap_or(node_hex)) {
                    if b.len() != NODEID_LEN {
                        continue;
                    }
                    let mut pid = [0u8; NODEID_LEN];
                    pid.copy_from_slice(&b);
                    // Backpressure: fail-closed total cap (unknown nodes
                    // beyond it are ignored; existing entries still merge).
                    if !mine.contains_key(&pid) && mine.len() >= MAX_ROUTES_TOTAL {
                        continue;
                    }
                    let ed_hex = rv["ed_pub"].as_str().unwrap_or("").to_string();
                    // Отравление таблицы: запись с чужим/битым ключом
                    // пропускается (иначе честный node_id привязывался к ключу
                    // атакующего и discovery уводил к нему).
                    if !ed_hex.is_empty() {
                        let Ok(ed) = hex::decode(&ed_hex) else {
                            continue;
                        };
                        if ed.len() != 32 {
                            continue;
                        }
                        if blake3::hash(&ed).as_bytes()[..NODEID_LEN] != pid[..] {
                            continue;
                        }
                    }
                    let endpoints: Vec<String> = rv["endpoints"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|e| e.as_str())
                                .filter(|e| crate::dht::endpoint_ok(e))
                                .take(crate::proto::MAX_ENDPOINTS_PER_NODE)
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default();
                    let route = Route {
                        endpoints,
                        ed_hex,
                    };
                    let entry = mine.entry(pid).or_insert_with(|| route.clone());
                    for e in &route.endpoints {
                        if entry.endpoints.len() >= crate::proto::MAX_ENDPOINTS_PER_NODE {
                            break;
                        }
                        if !entry.endpoints.contains(e) {
                            entry.endpoints.push(e.clone());
                            changed = true;
                        }
                    }
                    if entry.ed_hex.is_empty() {
                        entry.ed_hex = route.ed_hex.clone();
                        changed = true;
                    }
                }
            }
            drop(mine);
        }
        if changed {
            let map: HashMap<String, Route> = {
                let routes = self.routes.read().await;
                routes
                    .iter()
                    .map(|(k, v)| (format!("inf1:{}", hex::encode(k)), v.clone()))
                    .collect()
            };
            if let Ok(json) = serde_json::to_string(&map) {
                // R5: write(2) убран из обработчика dht.update (spawn_blocking).
                self.write_file("routes.json", json).await;
            }
        }
        Some(
            json!({ "ok": true, "op": "dht.update" })
                .to_string()
                .into_bytes(),
        )
    }

    /// Рассылает свои маршруты пирам (самообучение сети).
    async fn gossip_routes(self: &Arc<Self>) {
        let routes = self.routes.read().await;
        let map: HashMap<String, Route> = routes
            .iter()
            .map(|(k, v)| (format!("inf1:{}", hex::encode(k)), v.clone()))
            .collect();
        drop(routes);
        if map.is_empty() {
            return;
        }
        let peers: Vec<[u8; NODEID_LEN]> = self.peers.read().await.keys().copied().collect();
        let payload = json!({ "routes": map }).to_string().into_bytes();
        for pid in peers {
            let node = self.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let _ = node.request_to(pid, "dht.update", payload).await;
            });
        }
    }

    /// core.health: мониторинг ноды.
    async fn handle_health(self: &Arc<Self>) -> Option<Vec<u8>> {
        let peers = self.peers.read().await;
        let mut plist = Vec::new();
        for (pid, peer) in peers.iter() {
            let conn = peer.conn.read().await.is_some();
            let rtt = peer.rtt.read().await.map(|d| d.as_secs_f64() * 1000.0);
            plist.push(json!({
                "name": peer.cfg.name,
                "node_id": format!("inf1:{}", hex::encode(pid)),
                "connected": conn,
                "rtt_ms": rtt,
            }));
        }
        drop(peers);
        let outbox_sizes: HashMap<String, usize> = self
            .outbox
            .read()
            .await
            .iter()
            .map(|(k, v)| (format!("inf1:{}", hex::encode(k)), v.len()))
            .collect();
        let subs_count: HashMap<String, usize> = self
            .subs
            .read()
            .await
            .iter()
            .map(|(t, m)| (t.clone(), m.len()))
            .collect();
        Some(
            json!({
                "node": self.id_hex,
                "name": self.cfg.name,
                "uptime_s": self.started_at.elapsed().as_secs(),
                "peers": plist,
                "outbox": outbox_sizes,
                "subscribers": subs_count,
            })
            .to_string()
            .into_bytes(),
        )
    }

    // ============ Kademlia DHT ============

    /// Периодический refresh: пере-пинг ближайших узлов (поддержание бакетов живыми).
    async fn dht_refresh(self: &Arc<Self>) {
        let mut target = self.id;
        target[19] ^= 0x01; // чуть-чуть другой ID, чтобы покрыть ближний бакет
        let nodes = self
            .routing
            .read()
            .await
            .closest(&target, crate::dht::ALPHA);
        for n in nodes {
            if self.ensure_dht_peer(&n).await.is_err() {
                continue;
            }
            let _ = self.request_to(n.id, "core.ping", vec![]).await;
        }
        // чистим просроченные KV
        self.kv.write().await.prune();
        // Stale-eviction routing health (`dht::ROUTING_STALE_AFTER_MS`, 24 h —
        // тот же горизонт, что у `prune_subs`): сутки без refresh = мёртвый
        // вес, а не discovery-память. Пишем dht.json только если реально
        // что-то выселили.
        let stale = self
            .routing
            .write()
            .await
            .prune_stale(crate::dht::now_ms(), crate::dht::ROUTING_STALE_AFTER_MS);
        if stale > 0 {
            self.persist_routing().await;
        }
        // republish: переиздаём стареющие значения на k-ближайших к ключу
        let to_republish = self.kv.read().await.keys_to_republish(crate::dht::now_ms());
        for (key, value, ttl_ms, origin, stored_at) in to_republish {
            let h = blake3::hash(key.as_bytes());
            let mut target = [0u8; NODEID_LEN];
            target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
            let closest = self.routing.read().await.closest(&target, crate::dht::K);
            // stored_at rides along: the replica keeps the ORIGINAL age, so
            // TTL actually fires instead of resetting on every hop (audit
            // 2026-10-06 — mutual republish made entries immortal).
            let payload = json!({ "key": key, "value": value, "ttl": ttl_ms / 1000, "origin": format!("inf1:{}", hex::encode(origin)), "stored_at": stored_at })
                .to_string()
                .into_bytes();
            for n in closest {
                if self.ensure_dht_peer(&n).await.is_ok() {
                    let _ = self.request_to(n.id, "dht.store", payload.clone()).await;
                }
            }
        }
        // R6: refresh только помечает kv dirty — фактическое сохранение
        // (одно на все накопленные изменения) делает debounced flush-цикл.
        self.mark_kv_dirty();
    }

    /// R6: kv изменился — планируем ОДИН отложенный persist. Сами мутации
    /// (dht.store/синк/refresh) больше не ждут многомегабайтную запись.
    fn mark_kv_dirty(&self) {
        self.kv_dirty.store(true, Ordering::SeqCst);
    }

    /// R6: 1-секундный flush-цикл (паттерн outbox_dirty): пишет kv.json
    /// ТОЛЬКО когда dirty И когда прошло debounce-окно с последнего
    /// ЗАВЕРШЁННОГО сохранения. Всплеск из N dht.store => ровно одно
    /// сохранение; между сохранениями — пауза (запись 48–85 МБ дорогая).
    async fn kv_flush_if_due(&self) {
        if !self.kv_dirty.load(Ordering::SeqCst) {
            return;
        }
        let last = self.kv_last_flush_ms.load(Ordering::SeqCst);
        let debounce = self.kv_debounce_ms.load(Ordering::SeqCst) as i64;
        if last != 0 && now_ms().saturating_sub(last) < debounce {
            // dirty остаётся поднятым — догоним следующим тиком цикла
            return;
        }
        self.persist_kv_inner("debounced").await;
    }

    /// Принудительный persist (тесты/ручные вызовы) — мимо debounce-окна.
    #[allow(dead_code)] // GATE: manual snapshot hook for operator recovery
    async fn persist_kv(&self) {
        self.persist_kv_inner("direct").await;
    }

    /// Хвост persist_kv. R6 (см. также `kv_persist_tail`):
    ///  * dirty очищается ДО снапшота — мутация после этого момента снова
    ///    поднимет флаг (паттерн outbox_dirty), ничего не теряется;
    ///  * снапшот — один `Arc::clone` под read-локом (ранее здесь клонировалась
    ///    ВСЯ карта, 48–85 МБ, прямо на async-воркере);
    ///  * сериализация (≈1+ с CPU на 85 МБ) и запись едут ВНУТРИ
    ///    spawn_blocking под kv-гейтом: воркер не сжигает секунды на serde,
    ///    а из-за per-file гейтов outbox/subs/routes/dht.json за НИМ не ждут;
    ///  * стадии (gate/serialize/write) логируются только при >=200мс —
    ///    тот же порог, что у receiver-лога `dispatch`.
    async fn persist_kv_inner(&self, cause: &'static str) {
        let t0 = std::time::Instant::now();
        self.kv_dirty.store(false, Ordering::SeqCst);
        // (a) Мёртвое выкидываем ДО снапшота, а не только при чтении:
        // просроченные записи + dedup:* старше DEDUP_TTL_MS (см. KvStore::sweep).
        let (swept, swept_dedup, swept_out) = self.kv.write().await.sweep(crate::dht::now_ms());
        if swept > 0 {
            crate::log::emit(
                2,
                "info",
                &self.cfg.name,
                0,
                "kv_swept",
                json!({ "removed": swept, "dedup": swept_dedup }),
            );
        }
        // Sweep orphan chunks: an expired manifest whose chunk files stay on
        // disk leaks forever (audit 2026-10-06: chunks/ 658M vs kv 113M).
        // Only manifest-shaped values (JSON object with a "chunks" array)
        // trigger deletes; plain kv/dedup entries never match the prefilter.
        // Best-effort: a missing file or unparsable value just skips.
        let mut swept_files: Vec<std::path::PathBuf> = Vec::new();
        for (k, v) in &swept_out {
            if !v.contains("\"chunks\"") {
                continue;
            }
            let Ok(manifest) = serde_json::from_str::<serde_json::Value>(v) else {
                continue;
            };
            let Some(chunks) = manifest.get("chunks").and_then(|c| c.as_array()) else {
                continue;
            };
            let Some((bucket, _)) = k.split_once(':') else {
                continue;
            };
            let dir = self.chunks_dir(bucket);
            for c in chunks {
                if let Some(cid) = c.get("id").and_then(|i| i.as_str()) {
                    swept_files.push(dir.join(cid));
                }
            }
        }
        let swept_chunks = swept_files.len();
        if !swept_files.is_empty() {
            tokio::task::spawn_blocking(move || {
                for path in swept_files {
                    let _ = std::fs::remove_file(path);
                }
            });
        }
        if swept_chunks > 0 {
            crate::log::emit(
                2,
                "info",
                &self.cfg.name,
                0,
                "kv_swept_chunks",
                json!({ "deleted": swept_chunks }),
            );
        }
        let t_snap = std::time::Instant::now();
        let map = self.kv.read().await.entries_snapshot();
        let snap_us = t_snap.elapsed().as_micros() as u64;
        let entries = map.len();
        let t_gate = std::time::Instant::now();
        let _gate = self.gates.kv.lock().await;
        let gate_ms = t_gate.elapsed().as_millis() as u64;
        let data_dir = self.data_dir.clone();
        let m = self.metrics.clone();
        let t_block = std::time::Instant::now();
        let written = tokio::task::spawn_blocking(move || {
            // сериализация ЗДЕСЬ: вне async-воркера, вне какого-либо лока
            let t_ser = std::time::Instant::now();
            let json = serde_json::to_string(map.as_ref());
            let ser_ms = t_ser.elapsed().as_millis() as u64;
            let t_wr = std::time::Instant::now();
            let bytes = match json {
                Ok(j) => {
                    let n = j.len();
                    kv_persist_tail(data_dir, j);
                    n
                }
                Err(_) => 0,
            };
            (ser_ms, t_wr.elapsed().as_millis() as u64, bytes)
        })
        .await;
        let block_ms = t_block.elapsed().as_millis() as u64;
        let (ser_ms, write_ms, bytes) = written.unwrap_or((0, 0, 0));
        m.fs_write_ms_total.fetch_add(write_ms, Ordering::Relaxed);
        m.kv_persists_total.fetch_add(1, Ordering::Relaxed);
        // debounce-окно отсчитывается от ЗАВЕРШЕНИЯ: запись долгая,
        // иначе старты соседних сохранений слипались бы в непрерывный поток.
        self.kv_last_flush_ms.store(now_ms(), Ordering::SeqCst);
        if gate_ms >= 200 || block_ms >= 200 {
            crate::log::emit(
                2,
                "info",
                &self.cfg.name,
                0,
                "persist_kv_slow",
                json!({
                    "cause": cause,
                    "entries": entries,
                    "bytes": bytes,
                    "gate_ms": gate_ms,
                    "ser_ms": ser_ms,
                    "write_ms": write_ms,
                    "block_ms": block_ms,
                    "snap_us": snap_us,
                    "total_ms": t0.elapsed().as_millis() as u64,
                }),
            );
        }
    }

    async fn load_kv(&self) {
        let path = self.data_dir.join("kv.json");
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, crate::dht::StoredValue>>(&raw)
            {
                let mut kv = self.kv.write().await;
                for (k, v) in map {
                    kv.restore(k, v);
                }
            }
        }
    }

    /// Вставка/обновление узла в routing table + персистентность.
    async fn routing_insert(
        &self,
        pid: [u8; NODEID_LEN],
        endpoints: &[String],
        ed_hex: &str,
        x_hex: &str,
    ) {
        let mut routing = self.routing.write().await;
        routing.insert(crate::dht::NodeInfo {
            id: pid,
            endpoints: endpoints.to_vec(),
            ed_hex: ed_hex.to_string(),
            x_hex: x_hex.to_string(),
            last_seen: crate::dht::now_ms(),
        });
        drop(routing);
        self.persist_routing().await;
    }

    async fn persist_routing(&self) {
        let nodes = self.routing.read().await.all();
        if let Ok(json) = serde_json::to_string(&nodes) {
            self.write_file("dht.json", json).await;
        }
    }

    async fn load_routing(&self) {
        let path = self.data_dir.join("dht.json");
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(nodes) = serde_json::from_str::<Vec<crate::dht::NodeInfo>>(&raw) {
                let mut routing = self.routing.write().await;
                for n in nodes {
                    if n.id != self.id {
                        routing.insert(n);
                    }
                }
            }
        }
    }

    async fn routing_remove(&self, pid: [u8; NODEID_LEN]) {
        self.routing.write().await.remove(&pid);
        self.persist_routing().await;
    }

    /// Добавить обнаруженный узел как пира (для запросов к нему).
    pub async fn ensure_dht_peer(&self, info: &crate::dht::NodeInfo) -> Result<()> {
        if self.peers.read().await.contains_key(&info.id) {
            return Ok(());
        }
        // Fail-closed: запись из чужой таблицы маршрутов проверяется ДО
        // создания PeerLink — иначе отравленная запись давала pin на ключ
        // атакующего вместе с dial-бюджетом под его управлением.
        if !crate::dht::node_info_valid(&info.id, &info.ed_hex, &info.x_hex, &info.endpoints) {
            bail!("invalid dht node info");
        }
        let endpoints: Vec<String> = info
            .endpoints
            .iter()
            .filter(|e| crate::dht::endpoint_ok(e))
            .take(crate::proto::MAX_ENDPOINTS_PER_NODE)
            .cloned()
            .collect();
        let pcfg = PeerConfig {
            name: format!("dht-{}", hex::encode(&info.id[..4])),
            node_id: format!("inf1:{}", hex::encode(info.id)),
            ed_pub: info.ed_hex.clone(),
            x_pub: info.x_hex.clone(),
            // DHT-discovered peers are classical by construction (explicit):
            // PQ binding happens only via pinned pq_pub + verified tag.
            pq_pub: None,
            endpoints: endpoints.clone(),
            // DHT-обнаруженные ноды: только discovery (lookup/update/find_node).
            // БЕЗ dht.store (запись фейковых манифестов/реестра), dht.sync (слепок KV),
            // dht.find_value (чтение данных) — злонамеренная нода не может захватить
            // реестр/манифесты или выкачать KV.
            // PENTEST F5: born rate-limited (0 = unlimited is for operator-pinned
            // static peers only, never for identities we learned from the network).
            allow: vec![
                "dht.lookup".into(),
                "dht.update".into(),
                "dht.find_node".into(),
            ],
            rate_limit_per_sec: DYNAMIC_PEER_RATE_LIMIT_PER_SEC,
            role: None,
            storage_roles: vec![],
        };
        self.add_dynamic_peer(info.id, pcfg).await?;
        self.routing_insert(info.id, &endpoints, &info.ed_hex, &info.x_hex)
            .await;
        Ok(())
    }

    /// Итеративный Kademlia lookup: k ближайших к target.
    pub async fn dht_find_node(
        self: &Arc<Self>,
        target: &[u8; NODEID_LEN],
    ) -> Vec<crate::dht::NodeInfo> {
        // начальные кандидаты: routing table + конфигурированные пиры (bootstrap)
        let mut candidates = self.routing.read().await.closest(target, crate::dht::K);
        {
            let peers = self.peers.read().await;
            for (pid, p) in peers.iter() {
                if *pid == self.id {
                    continue;
                }
                let info = crate::dht::NodeInfo {
                    id: *pid,
                    endpoints: p.cfg.endpoints.clone(),
                    ed_hex: p.cfg.ed_pub.clone(),
                    x_hex: p.cfg.x_pub.clone(),
                    last_seen: crate::dht::now_ms(),
                };
                if !candidates.iter().any(|c| c.id == *pid) {
                    candidates.push(info);
                }
            }
        }
        candidates.sort_by(|a, b| {
            crate::dht::xor_distance(&a.id, target).cmp(&crate::dht::xor_distance(&b.id, target))
        });
        // Fast-path: in a small/static cluster (<= K nodes), all candidates are already known
        // locally from configured peers and routing table. Bypassing iterative network RPCs
        // eliminates 20+ redundant WAN round-trips per second.
        if candidates.len() <= crate::dht::K {
            return candidates;
        }
        let mut queried: std::collections::HashSet<[u8; NODEID_LEN]> =
            std::collections::HashSet::new();
        let mut no_progress = 0usize;
        let target_hex = format!("inf1:{}", hex::encode(target));
        loop {
            let to_query: Vec<crate::dht::NodeInfo> = candidates
                .iter()
                .filter(|n| !queried.contains(&n.id) && n.id != self.id)
                .take(crate::dht::ALPHA)
                .cloned()
                .collect();
            if to_query.is_empty() {
                break;
            }
            for n in &to_query {
                queried.insert(n.id);
            }
            let mut results: Vec<crate::dht::NodeInfo> = Vec::new();
            for n in to_query {
                if self.ensure_dht_peer(&n).await.is_err() {
                    // не смогли даже подключиться — узел мёртв, чистим
                    self.routing_remove(n.id).await;
                    continue;
                }
                let req = json!({ "target": target_hex }).to_string().into_bytes();
                match self.request_to(n.id, "dht.find_node", req).await {
                    Ok(resp) => {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if let Some(nodes) = v["nodes"].as_array() {
                                for nd in nodes {
                                    if let Some(info) = parse_dht_node(nd) {
                                        self.routing.write().await.insert(info.clone());
                                        results.push(info);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // сетевой сбой — узел скорее всего мёртв, убираем из таблицы
                        let msg = e.to_string();
                        if msg.contains("connection lost")
                            || msg.contains("handshake")
                            || msg.contains("timeout")
                            || msg.contains("closed")
                        {
                            self.routing_remove(n.id).await;
                        }
                    }
                }
            }
            if results.is_empty() {
                no_progress += 1;
            }
            let mut merged = candidates.clone();
            for n in results {
                if !merged.iter().any(|m| m.id == n.id) {
                    merged.push(n);
                }
            }
            merged.sort_by(|a, b| {
                crate::dht::xor_distance(&a.id, target)
                    .cmp(&crate::dht::xor_distance(&b.id, target))
            });
            merged.truncate(crate::dht::K);
            let same = merged
                .iter()
                .zip(candidates.iter())
                .all(|(a, b)| a.id == b.id);
            candidates = merged;
            if same {
                no_progress += 1;
            } else {
                no_progress = 0;
            }
            if no_progress >= 2 {
                break;
            }
        }
        candidates.into_iter().filter(|n| n.id != self.id).collect()
    }

    /// Локальный взгляд на ближайшие к target ноды (без сетевых запросов).
    /// Используется для отчёта о распределении данных по нодам.
    pub async fn dht_closest_local(&self, target: &[u8; NODEID_LEN]) -> Vec<crate::dht::NodeInfo> {
        let mut candidates = self.routing.read().await.closest(target, crate::dht::K);
        {
            let peers = self.peers.read().await;
            for (pid, p) in peers.iter() {
                if *pid == self.id {
                    continue;
                }
                let info = crate::dht::NodeInfo {
                    id: *pid,
                    endpoints: p.cfg.endpoints.clone(),
                    ed_hex: p.cfg.ed_pub.clone(),
                    x_hex: p.cfg.x_pub.clone(),
                    last_seen: crate::dht::now_ms(),
                };
                if !candidates.iter().any(|c| c.id == *pid) {
                    candidates.push(info);
                }
            }
        }
        candidates.sort_by(|a, b| {
            crate::dht::xor_distance(&a.id, target).cmp(&crate::dht::xor_distance(&b.id, target))
        });
        candidates.into_iter().filter(|n| n.id != self.id).collect()
    }

    async fn handle_dht_find_node(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let target_hex = v["target"].as_str().unwrap_or("").to_string();
        let s = target_hex.strip_prefix("inf1:").unwrap_or(&target_hex);
        let b = match hex::decode(s) {
            Ok(b) if b.len() == NODEID_LEN => b,
            _ => {
                return Some(
                    json!({ "ok": false, "err": "bad target" })
                        .to_string()
                        .into_bytes(),
                )
            }
        };
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&b);
        let nodes = self.routing.read().await.closest(&target, crate::dht::K);
        let list: Vec<serde_json::Value> = nodes
            .iter()
            .map(|n| {
                json!({
                    "node_id": format!("inf1:{}", hex::encode(n.id)),
                    "endpoints": n.endpoints,
                    "ed_pub": n.ed_hex,
                    "x_pub": n.x_hex,
                })
            })
            .collect();
        Some(
            json!({ "ok": true, "nodes": list })
                .to_string()
                .into_bytes(),
        )
    }

    async fn handle_dht_store(
        self: &Arc<Self>,
        v: &serde_json::Value,
        from: [u8; NODEID_LEN],
    ) -> Option<Vec<u8>> {
        let key = v["key"].as_str().unwrap_or("").to_string();
        let value = v["value"].as_str().unwrap_or("").to_string();
        // Fail-closed: ключ/значение/TTL из сети ограничены. Раньше значение
        // принималось вплоть до 32 МиБ фрейма (аллокация на каждый store), а
        // ttl=u64::MAX через `as i64` заворачивался в отрицательный.
        if !crate::proto::dht_key_ok(&key) {
            return Some(
                json!({ "ok": false, "err": "bad key" })
                    .to_string()
                    .into_bytes(),
            );
        }
        if !crate::proto::dht_value_ok(&value) {
            return Some(
                json!({ "ok": false, "err": "value too large" })
                    .to_string()
                    .into_bytes(),
            );
        }
        // Strict: a present-but-malformed ttl (negative, float, 0, huge)
        // is refused rather than defaulted — silent defaults mint storage
        // the sender never asked for.
        let ttl_secs: u64 = match v.get("ttl") {
            None => 3600,
            Some(t) => match t.as_u64() {
                Some(s) if (1..=crate::proto::MAX_REMOTE_TTL_SECS).contains(&s) => s,
                _ => {
                    return Some(
                        json!({ "ok": false, "err": "bad ttl" })
                            .to_string()
                            .into_bytes(),
                    );
                }
            },
        };
        let ttl = ttl_secs as i64;
        // Валидатор-авторитетные ключи web-слоя: recovery-коды и чёрные списки строго локальны
        // (утечка/подмена = захват аккаунта). Индексы ящиков (mail:) и файлов (files:) можно
        // реплицировать ТОЛЬКО пирам с соответствующей role хранения — ноды становятся
        // реальными держателями «каталога» писем/файлов для восстановления после потери kv.
        if key.starts_with("recovery:")
            || key.starts_with("blacklist:")
            || key.starts_with("share:")
        {
            return Some(
                json!({ "ok": false, "err": "key is local-authoritative" })
                    .to_string()
                    .into_bytes(),
            );
        }
        if key.starts_with("mail:") && !self.peer_allows(&from, "mail").await {
            return Some(
                json!({ "ok": false, "err": "peer role denies mail" })
                    .to_string()
                    .into_bytes(),
            );
        }
        if key.starts_with("files:") && !self.peer_allows(&from, "files").await {
            return Some(
                json!({ "ok": false, "err": "peer role denies files" })
                    .to_string()
                    .into_bytes(),
            );
        }
        // LWW по stored_at (если отправитель прислал): не затирать свежую локальную запись
        // устаревшей репликацией. Если stored_at не прислан — сохраняем текущее поведение.
        // R6: читаем РОВНО stored_at одного ключа (раньше здесь клонировалась вся
        // карта KV — 48–85 МБ копии на КАЖДЫЙ dht.store прямо на воркере).
        let sa = v["stored_at"].as_i64().unwrap_or(0);
        if sa > 0 {
            // Skew guard (audit follow-up): a FAR-FUTURE stored_at from a
            // skewed peer must not win LWW and mint a fresh TTL — keep local.
            // Only the ancient side is clamped (in store_replica).
            const SKEW_ALLOWANCE_MS: i64 = 5 * 60 * 1000;
            if sa > crate::dht::now_ms() + SKEW_ALLOWANCE_MS {
                return Some(
                    json!({ "ok": true, "stored": key, "lww": "skew" })
                        .to_string()
                        .into_bytes(),
                );
            }
            let local_sa = self.kv.read().await.stored_at(&key);
            if sa <= local_sa {
                return Some(
                    json!({ "ok": true, "stored": key, "lww": "local" })
                        .to_string()
                        .into_bytes(),
                );
            }
            // Replica with original age (audit 2026-10-06): preserve the
            // sender's clock so TTL fires on the original schedule instead of
            // resetting at every republish hop (immortal entries).
            self.kv
                .write()
                .await
                .store_replica(&key, value, ttl * 1000, self.id, sa);
            self.mark_kv_dirty();
            return Some(
                json!({ "ok": true, "stored": key, "replica": true })
                    .to_string()
                    .into_bytes(),
            );
        }
        // No clock on the sender: keep a present local value (audit follow-up
        // — legacy peers used to clobber newer locals AND reset their age).
        if self.kv.read().await.stored_at(&key) > 0 {
            return Some(
                json!({ "ok": true, "stored": key, "lww": "local-present" })
                    .to_string()
                    .into_bytes(),
            );
        }
        self.kv
            .write()
            .await
            .store(&key, value, ttl * 1000, self.id);
        // R6: всплеск dht.store => ОДНО отложенное сохранение, а не N полных
        // перезаписей kv.json ( response клиенту не меняется ).
        self.mark_kv_dirty();
        Some(
            json!({ "ok": true, "stored": key })
                .to_string()
                .into_bytes(),
        )
    }

    async fn handle_dht_find_value(
        self: &Arc<Self>,
        v: &serde_json::Value,
        from: [u8; NODEID_LEN],
    ) -> Option<Vec<u8>> {
        let key = v["key"].as_str().unwrap_or("").to_string();
        // Жёсткий отказ по сети для ключей захвата аккаунта: recovery-коды и чёрные списки.
        // (user:* — публичный реестр E2E-ключей, остаётся доступным для репликации.)
        // Индексы mail:/files: отдаём ТОЛЬКО пирам с соответствующей ролью хранения —
        // это позволяет валидатору восстановить «каталог» ящика/файлов с нод при потере kv,
        // не открывая его неизвестным/бесролевым пирам.
        if key.starts_with("recovery:")
            || key.starts_with("blacklist:")
            || key.starts_with("share:")
        {
            return Some(
                json!({ "ok": true, "found": false })
                    .to_string()
                    .into_bytes(),
            );
        }
        if key.starts_with("mail:") && !self.peer_allows(&from, "mail").await {
            return Some(
                json!({ "ok": true, "found": false })
                    .to_string()
                    .into_bytes(),
            );
        }
        if key.starts_with("files:") && !self.peer_allows(&from, "files").await {
            return Some(
                json!({ "ok": true, "found": false })
                    .to_string()
                    .into_bytes(),
            );
        }
        if let Some(value) = self.kv.write().await.get(&key) {
            return Some(
                json!({ "ok": true, "found": true, "value": value })
                    .to_string()
                    .into_bytes(),
            );
        }
        // не храним — возвращаем ближайших (для итеративного поиска значения)
        let h = blake3::hash(key.as_bytes());
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        let nodes = self.routing.read().await.closest(&target, crate::dht::K);
        let list: Vec<serde_json::Value> = nodes
            .iter()
            .map(|n| {
                json!({
                    "node_id": format!("inf1:{}", hex::encode(n.id)),
                    "endpoints": n.endpoints,
                    "ed_pub": n.ed_hex,
                    "x_pub": n.x_hex,
                })
            })
            .collect();
        Some(
            json!({ "ok": true, "found": false, "nodes": list })
                .to_string()
                .into_bytes(),
        )
    }

    /// dht.sync: отдать полный слепок KV (для догоняющей репликации при переподключении).
    /// Доступен только доверенным пирам (ACL), не TOFU-нодам.
    async fn handle_dht_sync(
        self: &Arc<Self>,
        v: &serde_json::Value,
        from: [u8; NODEID_LEN],
    ) -> Option<Vec<u8>> {
        // Fail-closed: лимит ограничен сверху (иначе пир просит сериализовать
        // сколь угодно много), а переросшие кап значения не отдаются вовсе.
        let limit = (v["limit"].as_u64().unwrap_or(10000) as usize)
            .min(crate::proto::MAX_DHT_SYNC_LIMIT);
        let now = crate::dht::now_ms();
        let mail_ok = self.peer_allows(&from, "mail").await;
        let files_ok = self.peer_allows(&from, "files").await;
        // R6: O(1)-снапшот вместо клона всей карты (слепок уезжает в ответ
        // уже без лока на kv).
        let map = self.kv.read().await.entries_snapshot();
        let mut out = serde_json::Map::new();
        for (k, st) in map.iter().take(limit) {
            if st.expires > now && st.value.len() <= crate::proto::MAX_DHT_VALUE_LEN {
                // recovery-коды и чёрные списки — локально-авторитетные, не реплицируются
                // (иначе код восстановления утечёт на другую ноду).
                // Индексы mail:/files: отдаём только пирам с соответствующей ролью хранения
                // (приёмщик фильтрует по своей роли в catch_up_with — симметрично).
                if k.starts_with("recovery:")
                    || k.starts_with("blacklist:")
                    || k.starts_with("share:")
                {
                    continue;
                }
                if k.starts_with("mail:") && !mail_ok {
                    continue;
                }
                if k.starts_with("files:") && !files_ok {
                    continue;
                }
                out.insert(
                    k.clone(),
                    json!({ "value": st.value, "ttl": st.ttl_ms / 1000, "stored_at": st.stored_at }),
                );
            }
        }
        Some(
            json!({ "ok": true, "count": out.len(), "entries": out })
                .to_string()
                .into_bytes(),
        )
    }

    /// Догоняющая репликация: после (пере)подключения к пиру тянем KV-слепок и
    /// недостающие чанки писем. Сеть малая — оба узла в k-ближайших ко всем ключам,
    /// поэтому берём всё (KV-репликация RF=2).
    pub async fn catch_up_with(self: &Arc<Self>, pid: [u8; NODEID_LEN]) {
        let resp = self
            .request_to(pid, "dht.sync", json!({}).to_string().into_bytes())
            .await;
        if let Ok(resp) = resp {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                if let Some(entries) = v["entries"].as_object() {
                    let allow_mail = self.role_allows("mail");
                    let allow_files = self.role_allows("files");
                    for (k, e) in entries {
                        // нода хранит только бакеты своей роли
                        if !allow_mail && (k.starts_with("m:") || k.starts_with("mail:")) {
                            continue;
                        }
                        if !allow_files && (k.starts_with("f:") || k.starts_with("files:")) {
                            continue;
                        }
                        // локально-авторитетные ключи не принимаем от пиров (share-токены,
                        // recovery-коды, чёрные списки) — даже если пир их пришлёт старым слепком
                        if k.starts_with("share:")
                            || k.starts_with("recovery:")
                            || k.starts_with("blacklist:")
                        {
                            continue;
                        }
                        if let Some(val) = e["value"].as_str() {
                            // LWW: не затирать свежие локальные записи старым слепком пира.
                            // (иначе индекс/манифест, только что обновлённый валидатором,
                            // перезаписывается устаревшей репликой при догоняющей репликации)
                            let sa = e["stored_at"].as_i64().unwrap_or(0);
                            let ttl = e["ttl"].as_i64().unwrap_or(0) * 1000;
                            self.kv.write().await.merge_replica(
                                k,
                                val.to_string(),
                                ttl,
                                self.id,
                                sa,
                            );
                        }
                    }
                    // R6: отложенное сохранение — синк не должен ждать
                    // многомегабайтную запись kv.json перед ответом.
                    self.mark_kv_dirty();
                }
            }
        }
        self.repair_chunks_from(pid).await;
    }

    /// Карта «blake3(контент) -> имя локального чанка» для бакета.
    /// Нужна, чтобы восстановить «дырку» манифеста, если тот же блоб лежит под
    /// другим chunk_id (дедуп по контенту): данные есть, имя другое.
    fn local_chunk_content_map(&self, bucket: &str) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        let dir = self.chunks_dir(bucket);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return map;
        };
        for e in rd.flatten() {
            let path = e.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(data) = std::fs::read(&path) {
                let h = hex::encode(blake3::hash(&data).as_bytes());
                map.entry(h)
                    .or_insert_with(|| e.file_name().to_string_lossy().to_string());
            }
        }
        map
    }

    /// Ремонт чанков: для локальных манифестов писем/файлов тянем недостающие чанки с пира
    /// (только для бакетов, входящих в роль ноды).
    /// ПРОГРЕВ УЗЛА: трогаем заранее всё, что иначе оплачивает первый запрос клиента
    /// (хэш-карта чанков — самая дорогая часть, чтение KV-базы, появление пиров).
    /// Наблюдалось: сразу после перезапуска первый запрос к почте (черновик) вис
    /// с HTTP 000 десятки секунд, потом всё работало — запрос попадал в окно сходимости.
    pub async fn warmup(self: &Arc<Self>) {
        let t0 = std::time::Instant::now();
        let me = self.clone();
        let _ = tokio::task::spawn_blocking(move || me.local_chunk_content_map("mail")).await;
        let me = self.clone();
        let _ = tokio::task::spawn_blocking(move || me.local_chunk_content_map("files")).await;
        let _ = self.get_local_kv("warmup").await;
        // R6: только длина (прогрев лока), без клона всей карты.
        let _ = self.kv.read().await.len();
        // ждём появления хотя бы одного пира, но не дольше 20 секунд
        for _ in 0..40 {
            let n = { self.routing.read().await.closest(&self.id, 1).len() };
            if n > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        eprintln!("[node] warmup завершён за {:?}", t0.elapsed());
    }

    async fn repair_chunks_from(self: &Arc<Self>, pid: [u8; NODEID_LEN]) {
        // Бюджет сетевых попыток на один вызов: проход должен быть коротким,
        // чтобы ремонт не занимал соединения и не мешал работе с почтой.
        let mut fetch_budget: usize = 12;
        // (ключ, бакет, ЗНАЧЕНИЕ) — значение берём прямо из перебора, без повторного
        // чтения: повторное чтение могло молча вернуть None и обрывать ремонт.
        let keys: Vec<(String, String, String)> = {
            let kv = self.kv.read().await;
            kv.entries_snapshot()
                .iter()
                .filter_map(|(k, v)| {
                    // МАНИФЕСТЫ В ПАМЯТИ ИМЕЮТ ПРЕФИКС "mail:"/"files:" (веб-слой кладёт их
                    // через kv_store_local), а не "m:" — из-за этого ремонт видел 0 ключей
                    // и никогда ничего не восстанавливал. Принимаем оба варианта.
                    let bucket = if k.starts_with("m:") || k.starts_with("mail:") {
                        Some("mail")
                    } else if k.starts_with("f:") || k.starts_with("files:") {
                        Some("files")
                    } else {
                        None
                    };
                    bucket.map(|b| (k.clone(), b.to_string(), v.value.clone()))
                })
                .collect()
        };
        // счётчики прохода: сколько разобрали, сколько чанков увидели, сколько не хватает
        let mut n_keys = keys.len();
        let mut n_parsed = 0usize;
        let mut n_chunks = 0usize;
        let mut n_missing = 0usize;
        // Карту «контент -> локальный файл» строим ОДИН раз на проход (раньше строилась
        // внутри цикла по манифестам: при 40 манифестах с дырками это хэшировало весь
        // чанк-каталог 40 раз синхронно и блокировало async-рантайм — веб-запросы висли).
        let mut content_map: Option<std::collections::HashMap<String, String>> = None;
        let mut map_built_for: Option<String> = None;
        for (_mkey, bucket, ms) in keys {
            if !self.role_allows(&bucket) {
                n_keys -= 1;
                continue;
            }
            let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&ms) else {
                continue;
            };
            let Some(chunks) = manifest["chunks"].as_array() else {
                continue;
            };
            n_parsed += 1;
            for c in chunks {
                n_chunks += 1;
                let cid = c["id"].as_str().unwrap_or("");
                if self.local_chunk_get(&bucket, cid).is_some() {
                    continue;
                }
                n_missing += 1;
                // БЮДЖЕТ прохода: не больше 12 сетевых попыток за раз, чтобы ремонт
                // не занимал соединения и не мешал обычной работе с почтой.
                if fetch_budget == 0 {
                    continue;
                }
                fetch_budget -= 1;
                // 1) локальный контент-матч (дедуп положил тот же блоб под другим id)
                if let Some(expected) = c["hash"].as_str() {
                    if map_built_for.as_deref() != Some(bucket.as_str()) {
                        // строим в blocking-пуле: файловый ввод-вывод не должен занимать
                        // поток асинхронного рантайма
                        let me = self.clone();
                        let b = bucket.clone();
                        content_map =
                            tokio::task::spawn_blocking(move || me.local_chunk_content_map(&b))
                                .await
                                .ok();
                        map_built_for = Some(bucket.clone());
                    }
                    if let Some(fname) = content_map.as_ref().and_then(|m| m.get(expected)).cloned()
                    {
                        let src = self.chunks_dir(&bucket).join(&fname);
                        if let Ok(data) = std::fs::read(&src) {
                            let dir = self.chunks_dir(&bucket);
                            let _ = std::fs::create_dir_all(&dir);
                            if write_chunk_atomic(&dir, cid, &data).is_ok() {
                                eprintln!("[node] repair: {cid} восстановлен локально по контенту");
                                continue;
                            }
                        }
                    }
                }
                let req = json!({ "bucket": bucket, "chunk_id": cid })
                    .to_string()
                    .into_bytes();
                let fetched = self.request_to(pid, "storage.fetch", req).await;
                if let Err(e) = &fetched {
                    eprintln!(
                        "[node] repair: запрос чанка {cid} к пиру {} НЕ УДАЛСЯ: {e}",
                        hex::encode(&pid[..4])
                    );
                    continue;
                }
                if let Ok(resp) = fetched {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                        if v["ok"].as_bool().unwrap_or(false) {
                            if let Some(b64) = v["data"].as_str() {
                                if let Ok(data) = base64::Engine::decode(
                                    &base64::engine::general_purpose::STANDARD,
                                    b64,
                                ) {
                                    // ПРОВЕРКА ЦЕЛОСТНОСТИ: не пишем чанк, если хэш не совпал
                                    // с манифестом (иначе пир подсунул бы мусор/подмену).
                                    if let Some(expected) = c["hash"].as_str() {
                                        let actual = hex::encode(blake3::hash(&data).as_bytes());
                                        if !actual.eq_ignore_ascii_case(expected) {
                                            eprintln!("[node] repair: chunk {cid} from peer mismatches manifest hash — skipped");
                                            continue;
                                        }
                                    }
                                    let dir = self.chunks_dir(&bucket);
                                    let _ = std::fs::create_dir_all(&dir);
                                    let _ = write_chunk_atomic(&dir, cid, &data);
                                    eprintln!(
                                        "[node] repair: {cid} получен от пира {}",
                                        hex::encode(&pid[..4])
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        eprintln!(
            "[node] repair: ключей={n_keys} разобрано={n_parsed} чанков={n_chunks} нет_локально={n_missing} (пир {})",
            hex::encode(&pid[..4])
        );
    }

    // ============ конец DHT ============

    // ============ Хранилище (storage.*) ============

    /// Валидация chunk_id (только hex, защита от path traversal).
    fn valid_chunk_id(&self, id: &str) -> bool {
        id.len() <= 80 && id.bytes().all(|b| b.is_ascii_hexdigit())
    }

    fn chunks_dir(&self, bucket: &str) -> PathBuf {
        // bucket: "mail" или "files" (только буквы)
        let safe: String = bucket
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        self.data_dir.join("chunks").join(safe)
    }

    /// Ключ манифеста блоба: ПОЛНЫЙ бакет ("{bucket}:{name}").
    /// Раньше использовался первый символ бакета ("{prefix}:{name}", m:/f:) —
    /// бакеты с общей первой буквой ("mail" vs "mybucket") коллидировали,
    /// fetch читал чужой манифест и отдавал байты с несовпадающим хэшем
    /// ("chunk tamper"). Централизовано: store/fetch/delete обязаны использовать это.
    pub fn blob_manifest_key(bucket: &str, name: &str) -> String {
        format!("{bucket}:{name}")
    }

    /// Роль хранения: разрешён ли бакет этой ноде (пустой список = все бакеты).
    pub fn role_allows(&self, bucket: &str) -> bool {
        if self.cfg.storage_roles.is_empty() {
            return true;
        }
        // Роль может называться ИМЕНЕМ БАКЕТА ("mail"/"files") либо задавать роль узла
        // ("validator"). Раньше роль "validator" не совпадала с именем бакета, поэтому
        // role_allows("mail") давал false и ремонт чанков молча обходил 0 манифестов
        // (дырки накапливались годами, хотя данные лежали на пирах).
        if self.cfg.storage_roles.iter().any(|r| r == bucket) {
            return true;
        }
        self.cfg
            .storage_roles
            .iter()
            .any(|r| r != "mail" && r != "files")
    }

    /// Может ли нода подписывать состояние консенсуса: сам валидатор или пир из cfg.validators.
    pub async fn is_consensus_signer(&self, from: &[u8; NODEID_LEN]) -> bool {
        if *from == self.id {
            return true;
        }
        if self.cfg.validators.is_empty() {
            return false;
        }
        let hex_id = format!("inf1:{}", hex::encode(from));
        self.cfg.validators.contains(&hex_id)
    }

    /// Роль пира: хранит ли он этот бакет (неизвестный пир/TOFU = оба бакета).
    pub async fn peer_allows(&self, pid: &[u8; NODEID_LEN], bucket: &str) -> bool {
        let Some(peer) = self.peers.read().await.get(pid).cloned() else {
            return true;
        };
        if peer.cfg.storage_roles.is_empty() {
            return true;
        }
        peer.cfg.storage_roles.iter().any(|r| r == bucket)
    }

    /// Сколько конфигурированных пиров имеют установленное QUIC-соединение.
    pub async fn peers_ready(&self) -> usize {
        let peers = self.peers.read().await;
        let mut n = 0usize;
        for p in peers.values() {
            if p.conn.read().await.is_some() {
                n += 1;
            }
        }
        n
    }

    /// Возвращает время последнего валидного фрейма от пира (входящий heartbeat) —
    /// признак живости для NAT-пиров. Это LIVENESS, отдельно от per-connection
    /// anti-replay окна (`ConnReplayWindow`).
    pub async fn peer_last_seen(&self, pid: &[u8; NODEID_LEN]) -> Option<i64> {
        // приоритет: отдельная карта входящих запросов (не зависит от пересоздания PeerLink)
        let map = self.last_req_from_peer.read().await;
        if let Some(ts) = map.get(pid) {
            return Some(*ts);
        }
        let arc: Option<std::sync::Arc<tokio::sync::Mutex<i64>>> = {
            let peers = self.peers.read().await;
            peers.get(pid).map(|p| p.last_seen.clone())
        };
        Some(*arc?.lock().await)
    }

    /// Все известные ноды сети (routing + конфигурированные пиры). Каждая запись содержит
    /// id/endpoints/ed_pub/x_pub — это позволяет rewards начислять награду нодам, которые
    /// прислали dht.update (автодобавление) без ручного внесения в конфиг валидатора.
    pub async fn known_peers(&self) -> Vec<crate::dht::NodeInfo> {
        let mut out: Vec<crate::dht::NodeInfo> = self.routing.read().await.all();
        // добавить конфигурированных пиров (могут отсутствовать в routing до первого контакта)
        let peers = self.peers.read().await;
        for (pid, p) in peers.iter() {
            if !out.iter().any(|n| n.id == *pid) {
                out.push(crate::dht::NodeInfo {
                    id: *pid,
                    endpoints: p.cfg.endpoints.clone(),
                    ed_hex: p.cfg.ed_pub.clone(),
                    x_hex: p.cfg.x_pub.clone(),
                    last_seen: crate::dht::now_ms(),
                });
            }
        }
        out
    }

    /// Сохранить чанк локально с dedup-проверкой по содержимому (П.3.5).
    /// Возвращает (ok, dedup_hit, written_bytes).
    /// Используется и в handle_storage_store (по сети), и в store_mail_boxed (локально).
    async fn write_chunk_with_dedup(
        self: &Arc<Self>,
        bucket: &str,
        chunk_id: &str,
        data: &[u8],
    ) -> (bool, bool, usize) {
        if !self.role_allows(bucket) {
            return (false, false, 0);
        }
        let dir = self.chunks_dir(bucket);
        if std::fs::create_dir_all(&dir).is_err() {
            return (false, false, 0);
        }
        let content_hash = blake3::hash(data);
        let dedup_key = format!("dedup:{}", hex::encode(content_hash.as_bytes()));
        // пропускаем запись, если этот же content_hash УЖЕ хранится на этой ноде
        // (т.е. файл уже локально). Безопасно: при удалении обновляем dedup-индекс.
        let mut dedup_hit = false;
        {
            let mut kv = self.kv.write().await;
            if let Some(v) = kv.get(&dedup_key) {
                if let Ok(d) = serde_json::from_str::<serde_json::Value>(&v) {
                    if let Some(nodes) = d["nodes"].as_array() {
                        if nodes
                            .iter()
                            .any(|x| x.as_str() == Some(&hex::encode(self.id)))
                        {
                            dedup_hit = true;
                        }
                    }
                }
            }
        }
        if dedup_hit {
            // ВАЖНО: dedup по КОНТЕНТУ мог сказать «уже храним», а файл лежит под
            // другим chunk_id. Тогда манифест ссылается на несуществующий чанк и
            // ремонт не находит его ни у нас, ни у пиров (на проде такие «дырки»
            // не восстанавливались). Гарантируем файл под ЗАПРОШЕННЫМ id.
            let p = dir.join(chunk_id);
            if !p.exists() {
                let _ = write_chunk_atomic(&dir, chunk_id, data);
            }
            return (true, true, data.len());
        }
        if write_chunk_atomic(&dir, chunk_id, data).is_err() {
            return (false, false, 0);
        }
        {
            let mut nodes: Vec<String> = {
                let mut kv = self.kv.write().await;
                kv.get(&dedup_key)
                    .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
                    .and_then(|d| d["nodes"].as_array().cloned())
                    .map(|arr| {
                        arr.into_iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let me = hex::encode(self.id);
            if !nodes.iter().any(|x| x == &me) {
                nodes.push(me);
            }
            let entry = serde_json::json!({
                "size": data.len(),
                "ts": crate::dht::now_ms(),
                "nodes": nodes,
            });
            let payload = serde_json::to_string(&entry).unwrap_or("{}".into());
            // dedup:* живёт только DEDUP_TTL_MS (5 мин) — иначе ключ копится
            // в kv.json месяцами (см. dht::DEDUP_TTL_MS).
            self.kv
                .write()
                .await
                .store(&dedup_key, payload, crate::dht::DEDUP_TTL_MS, self.id);
        }
        (true, false, data.len())
    }

    async fn handle_storage_store(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let id = v["chunk_id"].as_str().unwrap_or("").to_string();
        if !self.valid_chunk_id(&id) {
            return Some(
                json!({ "ok": false, "err": "bad chunk_id" })
                    .to_string()
                    .into_bytes(),
            );
        }
        let bucket = v["bucket"].as_str().unwrap_or("files");
        if !self.role_allows(bucket) {
            return Some(
                json!({ "ok": false, "err": format!("bucket '{bucket}' is not in this node's role") })
                    .to_string()
                    .into_bytes(),
            );
        }
        let data_b64 = v["data"].as_str().unwrap_or("").to_string();
        let data = match base64::engine::general_purpose::STANDARD.decode(&data_b64) {
            Ok(d) => d,
            Err(_) => {
                return Some(
                    json!({ "ok": false, "err": "bad data" })
                        .to_string()
                        .into_bytes(),
                )
            }
        };
        // Fail-closed: чанк ограничен (легитимные — 1 МиБ). Раньше принималось
        // вплоть до 32 МиБ фрейма на каждый storage.store.
        if data.len() > crate::proto::MAX_STORAGE_CHUNK_LEN {
            return Some(
                json!({ "ok": false, "err": "chunk too large" })
                    .to_string()
                    .into_bytes(),
            );
        }
        // Сверка с известными манифестами: если локально есть манифест с этим
        // chunk id и хэшем содержимого — несовпадение отклоняем (раньше приём
        // перезаписывал чанк безусловно: злонамеренная нода могла затереть чужой
        // чанк мусором — чтение потом падало. Незаметная подмена и раньше была
        // невозможна, теперь закрыта и порча). Неизвестный id принимаем: проверит читатель.
        {
            let got = hex::encode(blake3::hash(&data).as_bytes());
            // R6: O(1)-снапшот (без клона 48–85 МБ на КАЖДЫЙ storage.store)
            // + дешёвый префильтр значений перед JSON-парсом (см. ниже).
            let map = self.kv.read().await.entries_snapshot();
            let now = crate::dht::now_ms();
            let mut bad = false;
            for (k, st) in map.iter() {
                // Манифесты теперь лежат под ПОЛНЫМ бакетом ("{bucket}:{name}":
                // "mail:..", "files:..", плюс произвольные бакеты), старые — под
                // коротким ("m:.."/"f:.."). Принимаем оба формата + любой ключ
                // с манифестоподобным значением (есть массив "chunks"), чтобы
                // кастомные бакеты тоже проверялись.
                let known_prefix = k.starts_with("m:")
                    || k.starts_with("mail:")
                    || k.starts_with("f:")
                    || k.starts_with("files:")
                    || k.contains(':');
                if !known_prefix || st.expires <= now {
                    continue;
                }
                // R6: раньше здесь парсился КАЖДОЙ_VALUE карты (на стенде — все
                // 127 тыс. ключей, включая stell_*), т.е. сотни мс JSON-парса
                // на каждый storage.store. Манифест — JSON-объект с ключом
                // chunks; такой объект обязан содержать подстроку chunks, а
                // не-объекты/объекты без chunks в проверку не попадали и
                // раньше (m["chunks"] на них = null). Префильтр сохраняет
                // семантику дословно и отсекает почти всю карту strncmp'ом.
                if !(st.value.trim_start().starts_with('{') && st.value.contains("chunks")) {
                    continue;
                }
                if let Ok(m) = serde_json::from_str::<serde_json::Value>(&st.value) {
                    if let Some(cs) = m["chunks"].as_array() {
                        for c in cs {
                            if c["id"].as_str() == Some(id.as_str()) {
                                if let Some(exp) = c["hash"].as_str() {
                                    if !exp.eq_ignore_ascii_case(&got) {
                                        bad = true;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                if bad {
                    break;
                }
            }
            if bad {
                return Some(
                    json!({ "ok": false, "err": "chunk hash mismatch with known manifest" })
                        .to_string()
                        .into_bytes(),
                );
            }
        }
        let dir = self.chunks_dir(bucket);
        // R2: весь файловый I/O обработчика уходит в spawn_blocking —
        // create_dir_all/write чанка не должны занимать воркер рантайма
        // (storage.store прилетает большими батчами и держал воркер на диске).
        let nbytes = data.len();
        {
            let d = dir.clone();
            let made = tokio::task::spawn_blocking(move || std::fs::create_dir_all(&d)).await;
            if !matches!(made, Ok(Ok(()))) {
                return Some(json!({ "ok": false, "err": "io" }).to_string().into_bytes());
            }
        }
        // dedup по содержимому чанка (П.3.5): если такой же blake3 уже хранится на нужном числе нод
        // и эта нода уже в списке — пропускаем запись (экономия места). Запись dedup всё равно обновляем.
        let content_hash = blake3::hash(&data);
        let dedup_key = format!("dedup:{}", hex::encode(content_hash.as_bytes()));
        let want_replicas = 2usize; // RF=2 для dedup (на разных нодах достаточно для отказоустойчивости)
        let mut dedup_hit = false;
        {
            let mut kv = self.kv.write().await;
            if let Some(v) = kv.get(&dedup_key) {
                if let Ok(d) = serde_json::from_str::<serde_json::Value>(&v) {
                    if let Some(nodes) = d["nodes"].as_array() {
                        let have = nodes.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>();
                        if have.len() >= want_replicas
                            && have.iter().any(|h| *h == hex::encode(self.id))
                        {
                            dedup_hit = true;
                        }
                    }
                }
            }
        }
        if dedup_hit {
            // уже есть у этой ноды с достаточным RF — НЕ пишем файл, НО только если
            // файл реально лежит под запрошенным id: иначе манифест ссылается на
            // несуществующий чанк (prune-скрипт мог его убрать, а dedup-индекс ещё
            // жив) — та же дыра, что описана в write_chunk_with_dedup.
            {
                let d = dir.clone();
                let cid = id.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if !d.join(&cid).exists() {
                        let _ = write_chunk_atomic(&d, &cid, &data);
                    }
                })
                .await;
            }
            return Some(
                json!({
                    "ok": true,
                    "chunk_id": id,
                    "bytes": nbytes,
                    "dedup": "hit",
                })
                .to_string()
                .into_bytes(),
            );
        }
        {
            // R2: запись чанка (write+rename) — в blocking-пуле; data переезжает
            // в замыкание, дальше по коду используется только nbytes.
            let d = dir.clone();
            let cid = id.clone();
            let wr = tokio::task::spawn_blocking(move || write_chunk_atomic(&d, &cid, &data)).await;
            if !matches!(wr, Ok(Ok(()))) {
                return Some(json!({ "ok": false, "err": "io" }).to_string().into_bytes());
            }
        }
        // обновить dedup-индекс (LWW по stored_at): добавить наш node_id в список
        {
            let now = crate::dht::now_ms();
            let mut entry = serde_json::Map::new();
            entry.insert("size".into(), serde_json::json!(nbytes));
            entry.insert("ts".into(), serde_json::json!(now));
            let mut nodes: Vec<String> = {
                let mut kv = self.kv.write().await;
                kv.get(&dedup_key)
                    .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
                    .and_then(|d| d["nodes"].as_array().cloned())
                    .map(|arr| {
                        arr.into_iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let me = hex::encode(self.id);
            if !nodes.iter().any(|x| x == &me) {
                nodes.push(me);
            }
            entry.insert("nodes".into(), serde_json::json!(nodes));
            let payload =
                serde_json::to_string(&serde_json::Value::Object(entry)).unwrap_or("{}".into());
            // dedup:* живёт только DEDUP_TTL_MS (5 мин) — иначе ключ копится
            // в kv.json месяцами (см. dht::DEDUP_TTL_MS).
            self.kv
                .write()
                .await
                .store(&dedup_key, payload, crate::dht::DEDUP_TTL_MS, self.id);
        }
        Some(
            json!({
                "ok": true,
                "chunk_id": id,
                "bytes": nbytes,
                "dedup": "stored",
            })
            .to_string()
            .into_bytes(),
        )
    }

    async fn handle_storage_fetch(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let id = v["chunk_id"].as_str().unwrap_or("").to_string();
        if !self.valid_chunk_id(&id) {
            return Some(
                json!({ "ok": false, "err": "bad chunk_id" })
                    .to_string()
                    .into_bytes(),
            );
        }
        let bucket = v["bucket"].as_str().unwrap_or("files");
        if !self.role_allows(bucket) {
            return Some(
                json!({ "ok": false, "err": format!("bucket '{bucket}' is not in this node's role") })
                    .to_string()
                    .into_bytes(),
            );
        }
        let path = self.chunks_dir(bucket).join(&id);
        // R2: чтение чанка в spawn_blocking — storage.fetch тянет мегабайты и
        // не должен блокировать воркер рантайма на read(2).
        let data = tokio::task::spawn_blocking(move || std::fs::read(&path))
            .await
            .ok()
            .and_then(|r| r.ok());
        match data {
            Some(data) => Some(
                json!({
                    "ok": true,
                    "chunk_id": id,
                    "data": base64::engine::general_purpose::STANDARD.encode(&data),
                })
                .to_string()
                .into_bytes(),
            ),
            None => Some(
                json!({ "ok": false, "err": "not found" })
                    .to_string()
                    .into_bytes(),
            ),
        }
    }

    async fn handle_storage_delete(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let id = v["chunk_id"].as_str().unwrap_or("").to_string();
        if !self.valid_chunk_id(&id) {
            return Some(
                json!({ "ok": false, "err": "bad chunk_id" })
                    .to_string()
                    .into_bytes(),
            );
        }
        let bucket = v["bucket"].as_str().unwrap_or("files");
        let path = self.chunks_dir(bucket).join(&id);
        // chunk_id = blake3("{bucket}:{name}:{offset}:{content_hash}") — по нему
        // content_hash не восстановить без чтения файла. Поэтому dedup-индекс
        // обновляем только после чтения файла ниже.
        // Читаем файл (если есть) для корректного обновления dedup.
        // R2: чтение и удаление — в spawn_blocking (аналогично fetch/store).
        let read = {
            let p = path.clone();
            tokio::task::spawn_blocking(move || std::fs::read(&p))
                .await
                .ok()
                .and_then(|r| r.ok())
        };
        if let Some(data) = read {
            let content_hash = blake3::hash(&data);
            let dedup_key = format!("dedup:{}", hex::encode(content_hash.as_bytes()));
            let me = hex::encode(self.id);
            let mut entry_val: Option<serde_json::Value> = None;
            {
                let mut kv = self.kv.write().await;
                if let Some(v) = kv.get(&dedup_key) {
                    if let Ok(mut d) = serde_json::from_str::<serde_json::Value>(&v) {
                        if let Some(arr) = d["nodes"].as_array().cloned() {
                            let filtered: Vec<serde_json::Value> = arr
                                .into_iter()
                                .filter(|x| x.as_str() != Some(&me))
                                .collect();
                            d["nodes"] = serde_json::json!(filtered);
                            entry_val = Some(d);
                        }
                    }
                }
            }
            if let Some(d) = entry_val {
                if d["nodes"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
                    self.kv.write().await.remove(&dedup_key);
                } else {
                    let payload = serde_json::to_string(&d).unwrap_or("{}".into());
                    // dedup:* живёт только DEDUP_TTL_MS (5 мин) — иначе ключ копится
                    // в kv.json месяцами (см. dht::DEDUP_TTL_MS).
                    self.kv.write().await.store(
                        &dedup_key,
                        payload,
                        crate::dht::DEDUP_TTL_MS,
                        self.id,
                    );
                }
            }
        }
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
        Some(
            json!({ "ok": true, "deleted": id })
                .to_string()
                .into_bytes(),
        )
    }

    /// Чтение из локального KV (манифесты storage).
    pub async fn get_local_kv(&self, key: &str) -> Option<String> {
        // Read lock (audit 2026-10-06): the old write-lock serialized every
        // DHT read. `peek` never mutates; no inline expiry cleanup (the sweep
        // collects it at persist).
        self.kv.read().await.peek(key).map(|(v, _)| v)
    }

    /// Ключи локальных манифестов с префиксом (m:/f:) — для proof-of-storage челленджей.
    pub async fn kv_manifest_keys(&self, prefix: &str) -> Vec<String> {
        let map = self.kv.read().await.entries_snapshot();
        let now = crate::dht::now_ms();
        map.iter()
            .filter(|(k, st)| k.starts_with(prefix) && st.expires > now)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Локальная запись в DHT-KV (валидатор хранит копию всегда — самодостаточность).
    /// TTL 30 дней: долгоживущие записи (реестр, индексы) не протухают при одиночной ноде.
    pub async fn kv_store_local(&self, key: &str, value: &str) {
        self.kv_store_local_with_ttl(key, value, 30 * 24 * 3600 * 1000)
            .await;
    }

    /// Локальная запись в DHT-KV с явным TTL (мс).
    ///
    /// Точка входа для retention-окон publisher'ов (напр. stellereum держит
    /// `stell_blocks/*`/`stell_headers/*` только окно STELL_KEEP_BLOCKS):
    /// `StoredValue.expires` выставляется из этого TTL, а существующий sweep
    /// (`KvStore::sweep`, перед каждым persist kv.json) выкидывает просроченное.
    /// Записи без вызова этой функции ведут себя как раньше (30 дней).
    pub async fn kv_store_local_with_ttl(&self, key: &str, value: &str, ttl_ms: i64) {
        self.kv
            .write()
            .await
            .store(key, value.to_string(), ttl_ms, self.id);
        // Local writes must reach kv.json promptly, not only via the 60s
        // dht_refresh persist: a crash inside that window loses publishes AND
        // the prune cursor (audit 2026-10-06). Dirty flag + 1s flush cycle
        // (with its own debounce) pick it up within seconds.
        self.mark_kv_dirty();
    }

    /// Удалить ключ из локального KV.
    pub async fn kv_remove_local(&self, key: &str) {
        self.kv.write().await.remove(key);
        self.mark_kv_dirty();
    }

    /// Удалить блоб из хранилища: манифест локально + удаление чанков на этой ноде
    /// и best-effort на k-ближайших (storage.delete). Возвращает число локально удалённых чанков.
    pub async fn delete_blob(self: &Arc<Self>, bucket: &str, name: &str) -> usize {
        let (deleted, chunk_ids) = self.delete_blob_local_inner(bucket, name).await;
        if !chunk_ids.is_empty() {
            let node = self.clone();
            let bucket = bucket.to_string();
            tokio::spawn(async move {
                for cid in chunk_ids {
                    let h = blake3::hash(format!("{bucket}:{cid}").as_bytes());
                    let mut target = [0u8; NODEID_LEN];
                    target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
                    let closest = node.dht_find_node(&target).await;
                    let payload = json!({ "bucket": bucket, "chunk_id": cid })
                        .to_string()
                        .into_bytes();
                    for n in closest {
                        let _ = node
                            .request_to(n.id, "storage.delete", payload.clone())
                            .await;
                    }
                }
            });
        }
        deleted
    }

    /// Удалить блоб ТОЛЬКО локально: манифест из kv + файлы чанков на этой ноде.
    /// Без сетевого веера (в отличие от `delete_blob`).
    ///
    /// Примитив для height-привязного retention publisher'а (stellereum чистит
    /// `stell_blocks/*`/`stell_headers/*` ниже finalized − KEEP, см. его
    /// `maybe_prune_retained`): каждая нода чистит то, что сама публиковала, по
    /// своему расписанию — веер не нужен, а пачка из сотен удалений за один
    /// проход не должна рождать сотни сетевых задач. Реплики на пирах добирает
    /// TTL манифеста (см. `store_blob_with_ttl`) + тот же prune на самом пире.
    /// Возвращает число локально удалённых чанков.
    pub async fn delete_blob_local(self: &Arc<Self>, bucket: &str, name: &str) -> usize {
        self.delete_blob_local_inner(bucket, name).await.0
    }

    /// Общая локальная часть `delete_blob`/`delete_blob_local`.
    /// Возвращает (локально удалённые чанки, их id для веера `delete_blob`).
    async fn delete_blob_local_inner(
        self: &Arc<Self>,
        bucket: &str,
        name: &str,
    ) -> (usize, Vec<String>) {
        let mkey = Self::blob_manifest_key(bucket, name);
        let manifest_str = self.get_local_kv(&mkey).await;
        let mut deleted = 0usize;
        if let Some(ms) = manifest_str.clone() {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&ms) {
                if let Some(chunks) = manifest["chunks"].as_array() {
                    for c in chunks {
                        if let Some(cid) = c["id"].as_str() {
                            // PENTEST F6 (P1): chunk ids come from the STORED
                            // manifest, and manifests replicate over dht.sync
                            // from UNTRUSTED peers — an unvalidated id
                            // (`../../x`) turns this join into a path-traversal
                            // delete outside the bucket dir. Skip anything that
                            // is not a strict chunk id (same gate as the
                            // network ingress in `handle_storage_store`).
                            if !self.valid_chunk_id(cid) {
                                continue;
                            }
                            // Count only real deletes (audit 2026-10-06: a
                            // missing file used to inflate prune metrics).
                            if std::fs::remove_file(self.chunks_dir(bucket).join(cid)).is_ok() {
                                deleted += 1;
                            }
                        }
                    }
                }
            }
        }
        self.kv_remove_local(&mkey).await;
        let chunk_ids: Vec<String> = manifest_str
            .and_then(|ms| serde_json::from_str::<serde_json::Value>(&ms).ok())
            .and_then(|m| {
                m["chunks"].as_array().map(|a| {
                    a.iter()
                        // PENTEST F6: never fan a traversal id out to peers.
                        .filter_map(|c| c["id"].as_str())
                        .filter(|cid| self.valid_chunk_id(cid))
                        .map(String::from)
                        .collect::<Vec<String>>()
                })
            })
            .unwrap_or_default();
        (deleted, chunk_ids)
    }

    /// Локальный чанк (если эта нода его хранит).
    pub fn local_chunk_get(&self, bucket: &str, chunk_id: &str) -> Option<Vec<u8>> {
        // PENTEST F6: `chunk_id` reaches a filesystem join — gate it the same
        // way as every other ingress (`valid_chunk_id`).
        if !self.valid_chunk_id(chunk_id) {
            return None;
        }
        let path = self.chunks_dir(bucket).join(chunk_id);
        std::fs::read(&path).ok()
    }

    /// Сохранить чанк на RF реплик (k-ближайших к chunk_id по DHT).
    pub async fn store_chunk_replicated(
        self: &Arc<Self>,
        bucket: &str,
        chunk_id: &str,
        data: &[u8],
    ) -> usize {
        let h = blake3::hash(format!("{bucket}:{chunk_id}").as_bytes());
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        let candidates = self.dht_find_node(&target).await;
        let rf = candidates.len().clamp(1, 3);
        let payload = json!({
            "bucket": bucket,
            "chunk_id": chunk_id,
            "data": base64::engine::general_purpose::STANDARD.encode(data),
        })
        .to_string()
        .into_bytes();
        let mut stored = 0usize;
        // Порядок: сначала пиры с ЖИВЫМ соединением. Недоступная нода (за NAT, к которой
        // валидатор не может дозвониться) иначе съедает слот репликации (take(rf)) и держит
        // отправку письма на своём connect-таймауте.
        let mut ordered: Vec<&crate::dht::NodeInfo> = Vec::with_capacity(candidates.len());
        for n in candidates.iter() {
            if self.pick_conn(None, n.id).await.is_some() {
                ordered.push(n);
            }
        }
        for n in candidates.iter() {
            if self.pick_conn(None, n.id).await.is_none() {
                ordered.push(n);
            }
        }
        for n in ordered.iter().take(rf) {
            if !self.peer_allows(&n.id, bucket).await {
                continue;
            }
            if self.ensure_dht_peer(n).await.is_ok() {
                let res = tokio::time::timeout(
                    std::time::Duration::from_millis(2500),
                    self.request_to(n.id, "storage.store", payload.clone()),
                )
                .await;
                if let Ok(Ok(_)) = res {
                    stored += 1;
                }
            }
        }
        // резерв: храним и локально, если реплик меньше rf (и роль позволяет бакет)
        if stored == 0 && self.role_allows(bucket) {
            let dir = self.chunks_dir(bucket);
            let _ = std::fs::create_dir_all(&dir);
            if write_chunk_atomic(&dir, chunk_id, data).is_ok() {
                stored = 1;
            }
        }
        stored
    }

    /// Сохранить письмо в storage (чанки + репликация + манифест в DHT).
    /// Сохранить письмо в storage: ЛОКАЛЬНО сразу (быстро, самодостаточно),
    /// репликация на другие ноды — в фоне (RF добивается асинхронно).
    /// Erasure coding: k информационных шардов + (n-k) чётности (Reed-Solomon GF(256)).
    /// Даёт устойчивость к потере ЛЮБЫХ n-k шардов при хранении в n/k раз меньшем объёме,
    /// чем полная репликация RF=n.
    fn ec_encode(ct: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
        let shard_len = ct.len().div_ceil(k).max(1);
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..k {
            let mut s = vec![0u8; shard_len];
            let start = i * shard_len;
            if start < ct.len() {
                let end = (start + shard_len).min(ct.len());
                s[..end - start].copy_from_slice(&ct[start..end]);
            }
            shards.push(s);
        }
        for _ in k..n {
            shards.push(vec![0u8; shard_len]);
        }
        if let Ok(rs) = ReedSolomon::new(k, n - k) {
            let _ = rs.encode(&mut shards);
        }
        shards
    }

    /// Восстановление ciphertext из любых k доступных шардов.
    fn ec_decode(
        slots: &mut [Option<Vec<u8>>],
        k: usize,
        n: usize,
        ct_len: usize,
    ) -> Option<Vec<u8>> {
        let present = slots.iter().filter(|s| s.is_some()).count();
        if present < k {
            return None;
        }
        let rs = ReedSolomon::new(k, n - k).ok()?;
        rs.reconstruct(slots).ok()?;
        let shard_len = slots.first()?.as_ref()?.len();
        let mut out = Vec::with_capacity(shard_len * k);
        for s in slots.iter().take(k) {
            out.extend_from_slice(s.as_ref()?.as_slice());
        }
        out.truncate(ct_len);
        Some(out)
    }

    /// Сетевой фетч одного чанка (два прохода: живые соединения → остальные;
    /// локальный диск — только резерв, с громким WARN; проверка хэша от подмены).
    pub async fn fetch_chunk_net(
        self: &Arc<Self>,
        bucket: &str,
        cid: &str,
        expected_hash: Option<&str>,
    ) -> Option<Vec<u8>> {
        // ЛОКАЛЬНЫЙ ДИСК — ПЕРВЫМ. Раньше сначала шли два сетевых прохода
        // (до 40 попыток с таймаутами), и только потом локальный резерв:
        // открытие письма, чей чанк лежит у нас, висело/падало по таймауту
        // (наблюдалось: внешнее письмо открывалось без текста, хотя чанк был
        // на диске). Сеть — только если локально нет.
        if let Some(local) = self.local_chunk_get(bucket, cid) {
            // хэш проверяем и для локальных данных (защита от битой записи)
            if let Some(expected) = expected_hash {
                let actual = hex::encode(blake3::hash(&local).as_bytes());
                if actual.eq_ignore_ascii_case(expected) {
                    return Some(local);
                }
            } else {
                return Some(local);
            }
        }
        let mut got: Option<Vec<u8>> = None;
        let h = blake3::hash(format!("{bucket}:{cid}").as_bytes());
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        let closest = self.dht_find_node(&target).await;
        for pass in 0..2u8 {
            if got.is_some() {
                break;
            }
            for n in closest.iter() {
                if got.is_some() {
                    break;
                }
                let live = self.pick_conn(None, n.id).await.is_some();
                if (pass == 0) != live {
                    continue;
                }
                if self.ensure_dht_peer(n).await.is_ok() {
                    let req = json!({ "bucket": bucket, "chunk_id": cid })
                        .to_string()
                        .into_bytes();
                    if let Ok(resp) = self.request_to(n.id, "storage.fetch", req).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["ok"].as_bool().unwrap_or(false) {
                                if let Some(b64) = v["data"].as_str() {
                                    got =
                                        base64::engine::general_purpose::STANDARD.decode(b64).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
        if got.is_none() {
            eprintln!(
                "[node] WARN: chunk {cid} of {bucket} served from LOCAL disk, not from the network"
            );
            got = self.local_chunk_get(bucket, cid);
        }
        if let Some(expected) = expected_hash {
            if let Some(g) = &got {
                let actual = hex::encode(blake3::hash(g).as_bytes());
                if !actual.eq_ignore_ascii_case(expected) {
                    eprintln!("[node] chunk tamper: {cid} in {bucket} (hash mismatch)");
                    got = None;
                }
            }
        }
        got
    }

    /// store_mail с erasure coding: тело режется на k шардов + (n-k) чётности,
    /// шарды раскладываются как обычные чанки. Чтение восстановит тело из любых k.
    pub async fn store_mail_ec(
        self: &Arc<Self>,
        name: &str,
        blob: &[u8],
        owner_pub: Option<&str>,
        k: usize,
        n: usize,
    ) -> usize {
        if k == 0 || n <= k {
            return 0;
        }
        // детерминированное шифрование + content-адресные id шардов (см. blob_key_nonce):
        // повторный store_mail_ec того же письма пишет в те же пути
        let content_hash = blob_content_hash(blob);
        let (data_key, nonce) = blob_key_nonce("mail", name, &content_hash);
        let ct = e2e_encrypt_det(&data_key, &nonce, blob);
        let shards = Self::ec_encode(&ct, k, n);
        let have_mail_role = self.role_allows("mail");
        let mut chunks: Vec<serde_json::Value> = Vec::with_capacity(n);
        let mut stored = 0usize;
        // шарды для фоновой репликации (нода с mail-ролью пишет локально —
        // без этого все шарды оставались только на ней и EC давал 0 отказоустойчивости)
        let mut to_replicate: Vec<(String, Vec<u8>)> = Vec::new();
        for (i, sh) in shards.iter().enumerate() {
            let chunk_id = ec_chunk_id_for("mail", name, i, &content_hash);
            let ok = if have_mail_role {
                let (_a, _dedup, _b) = self.write_chunk_with_dedup("mail", &chunk_id, sh).await;
                to_replicate.push((chunk_id.clone(), sh.clone()));
                true
            } else {
                self.store_chunk_replicated("mail", &chunk_id, sh).await > 0
            };
            if ok {
                stored += 1;
            }
            chunks.push(json!({
                "id": chunk_id,
                "shard": i,
                "len": sh.len(),
                "hash": hex::encode(blake3::hash(sh).as_bytes()),
            }));
        }
        let mut manifest = json!({
            "bucket": "mail",
            "name": name,
            "size": blob.len(),
            "nonce": hex::encode(nonce),
            "ec": { "k": k, "n": n, "ct_len": ct.len(), "shard_len": shards.first().map(|s| s.len()).unwrap_or(0) },
            "chunks": chunks,
        });
        if let Some(pub_hex) = owner_pub {
            if let Some(kb) = box_wrap_key(pub_hex, &data_key) {
                manifest["key_box"] = kb;
            } else {
                manifest["key"] = json!(hex::encode(data_key));
            }
        } else {
            manifest["key"] = json!(hex::encode(data_key));
        }
        let mkey = format!("m:{name}");
        self.kv_store_local(&mkey, &manifest.to_string()).await;
        // фоновая репликация манифеста + EC-шардов (replicate_mail перекладывает
        // только обычные чанки chunk_id_for("mail",..), EC-шарды — отдельно)
        let node = self.clone();
        let name_s = name.to_string();
        let mkey_s = mkey.clone();
        let manifest_s = manifest.to_string();
        tokio::spawn(async move {
            let _ = timeout(
                Duration::from_secs(20),
                node.replicate_mail(&name_s, &[], &manifest_s, &mkey_s, &content_hash),
            )
            .await;
            for (cid, data) in to_replicate {
                node.store_chunk_replicated("mail", &cid, &data).await;
            }
        });
        stored
    }

    pub async fn store_mail(self: &Arc<Self>, name: &str, blob: &[u8]) -> usize {
        self.store_mail_boxed(name, blob, None).await
    }

    /// store_mail с Proton-моделью: если задан owner_pub (X25519 hex получателя),
    /// ключ блоба (data_key) зашифровывается box на его публичный ключ и кладётся в
    /// манифест как key_box вместо открытого "key" — прочитать может только владелец
    /// приватного X25519-ключа (браузер). Сервер/ноды не видят ключ.
    ///
    /// ИДЕМПОТЕНТНОСТЬ: key/nonce и chunk_id выводятся из содержимого (blob_key_nonce /
    /// chunk_id_for) — повторный store того же письма перезаписывает те же файлы чанков,
    /// а не добавляет новые (иначе ретраи федерации раздували каталог chunks/mail).
    pub async fn store_mail_boxed(
        self: &Arc<Self>,
        name: &str,
        blob: &[u8],
        owner_pub: Option<&str>,
    ) -> usize {
        const CHUNK: usize = 1024 * 1024;
        let content_hash = blob_content_hash(blob);
        let (data_key, nonce) = blob_key_nonce("mail", name, &content_hash);
        let ct = e2e_encrypt_det(&data_key, &nonce, blob);
        let mut chunks: Vec<serde_json::Value> = Vec::new();
        let mut offset = 0usize;
        let mut local_chunks = 0usize;
        // РАСПРЕДЕЛЁННОСТЬ: если валидатор НЕ хранит почту (нет mail-роли), чанки пишутся
        // СИНХРОННО на storage-ноды (ждём хотя бы одну реплику), иначе stored==0 → письмо откатится.
        let have_mail_role = self.role_allows("mail");
        let mut repl_ok = false;
        while offset < ct.len() {
            let end = (offset + CHUNK).min(ct.len());
            let chunk = &ct[offset..end];
            let chunk_id = chunk_id_for("mail", name, offset, &content_hash);
            if have_mail_role {
                // dedup по содержимому (П.3.5): если у нас уже есть чанк с таким blake3 —
                // пропускаем запись, но чанк ГАРАНТИРОВАННО лежит под запрошенным id
                // (write_chunk_with_dedup досыпает файл, если его нет).
                // Считаем по `ok`, а не по !dedup_hit: чанк есть локально — иначе
                // идемпотентный репаблиш вернул бы 0 и web откатил квоту с 502.
                let (ok, _dedup_hit, _bytes) =
                    self.write_chunk_with_dedup("mail", &chunk_id, chunk).await;
                if ok {
                    local_chunks += 1;
                }
            } else {
                // синхронная репликация чанка на storage-ноды (ждём подтверждение)
                if self.store_chunk_replicated("mail", &chunk_id, chunk).await > 0 {
                    repl_ok = true;
                }
            }
            chunks.push(json!({
                "id": chunk_id,
                "n": 1,
                "off": offset,
                "len": chunk.len(),
                // хэш содержимого — защита от подмены чанка злонамеренной нодой
                "hash": hex::encode(blake3::hash(chunk).as_bytes()),
            }));
            offset = end;
        }
        let mut manifest = json!({
            "bucket": "mail",
            "name": name,
            "size": blob.len(),
            "nonce": hex::encode(nonce),
            "chunks": chunks,
        });
        if let Some(pub_hex) = owner_pub {
            if let Some(kb) = box_wrap_key(pub_hex, &data_key) {
                manifest["key_box"] = kb;
            } else {
                manifest["key"] = json!(hex::encode(data_key));
            }
        } else {
            manifest["key"] = json!(hex::encode(data_key));
        }
        let mkey = format!("m:{name}");
        self.kv_store_local(&mkey, &manifest.to_string()).await;
        // фоновая репликация на другие ноды (не блокирует отправителя)
        let node = self.clone();
        let name = name.to_string();
        let ct = ct.clone();
        let manifest_str = manifest.to_string();
        let mkey2 = mkey.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                node.replicate_mail(&name, &ct, &manifest_str, &mkey2, &content_hash),
            )
            .await;
        });
        // результат: если валидатор хранит почту — число локальных чанков;
        // если нет (чистый валидатор) — 1, если хотя бы одна нода приняла чанки (иначе 0).
        if have_mail_role {
            local_chunks
        } else if repl_ok {
            1
        } else {
            0
        }
    }

    /// Фоновая репликация письма: чанки + манифест на k-ближайших ноды.
    /// `content_hash` — тот же content id, что и при записи (id обязан совпасть).
    async fn replicate_mail(
        self: &Arc<Self>,
        name: &str,
        ct: &[u8],
        manifest_str: &str,
        mkey: &str,
        content_hash: &[u8; 32],
    ) {
        let mut offset = 0usize;
        const CHUNK: usize = 1024 * 1024;
        while offset < ct.len() {
            let end = (offset + CHUNK).min(ct.len());
            let chunk = &ct[offset..end];
            let chunk_id = chunk_id_for("mail", name, offset, content_hash);
            let _ = self.store_chunk_replicated("mail", &chunk_id, chunk).await;
            offset = end;
        }
        let h = blake3::hash(mkey.as_bytes());
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        let closest = self.dht_find_node(&target).await;
        let payload = json!({ "key": mkey, "value": manifest_str, "ttl": 30 * 24 * 3600 })
            .to_string()
            .into_bytes();
        for n in closest {
            if self.ensure_dht_peer(&n).await.is_ok() {
                let _ = self.request_to(n.id, "dht.store", payload.clone()).await;
            }
        }
    }

    /// Скачать письмо из storage (манифест + чанки + расшифровка).
    /// Работает с открытым ключом манифеста ("key") — старые/незашифрованные блобы.
    pub async fn fetch_mail(self: &Arc<Self>, name: &str) -> Option<Vec<u8>> {
        self.fetch_mail_inner(name, None).await
    }

    /// Скачать Proton-письмо (манифест с key_box) — расшифровывает ключ блоба приватным
    /// X25519-ключом владельца. Используется браузером через web-слой (владение уже проверено).
    pub async fn fetch_mail_owner(
        self: &Arc<Self>,
        name: &str,
        owner_priv_hex: &str,
    ) -> Option<Vec<u8>> {
        self.fetch_mail_inner(name, Some(owner_priv_hex)).await
    }

    /// Backpressure insert for the decrypted-mail cache. The cache is
    /// advisory (a miss just re-reads from network/disk), so the shed is a
    /// silent eviction: expired entries first, else the oldest timestamp.
    /// Memory stays bounded; no counter needed for a cache eviction.
    async fn mail_cache_insert(&self, name: String, blob: Vec<u8>) {
        let now = now_ms();
        let mut c = self.mail_cache.write().await;
        if !c.contains_key(&name) && c.len() >= MAX_MAIL_CACHE_ENTRIES {
            c.retain(|_, (_, ts)| now - *ts < 60_000);
            if c.len() >= MAX_MAIL_CACHE_ENTRIES {
                if let Some(oldest) = c.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| k.clone())
                {
                    c.remove(&oldest);
                }
            }
        }
        c.insert(name, (blob, now));
    }

    async fn fetch_mail_inner(
        self: &Arc<Self>,
        name: &str,
        owner_priv: Option<&str>,
    ) -> Option<Vec<u8>> {
        // кэш: если тело уже читали недавно (<60с) — отдаём из памяти (без сети)
        {
            let now = now_ms();
            let cache = self.mail_cache.read().await;
            if let Some((blob, ts)) = cache.get(name) {
                if now - *ts < 60_000 {
                    return Some(blob.clone());
                }
            }
        }
        let mkey = format!("m:{name}");
        let manifest_str = self.get_local_kv(&mkey).await;
        let manifest_str = if let Some(m) = manifest_str {
            m
        } else {
            let h = blake3::hash(mkey.as_bytes());
            let mut target = [0u8; NODEID_LEN];
            target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
            let closest = self.dht_find_node(&target).await;
            let q = json!({ "key": mkey }).to_string().into_bytes();
            let mut found = None;
            for n in closest.iter() {
                if found.is_some() {
                    break;
                }
                if self.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = self.request_to(n.id, "dht.find_value", q.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                found = v["value"].as_str().map(String::from);
                            }
                        }
                    }
                }
            }
            found?
        };
        let manifest: serde_json::Value = serde_json::from_str(&manifest_str).ok()?;
        let nonce = hex::decode(manifest["nonce"].as_str().unwrap_or("")).ok()?;
        // ключ блоба: "key" (открытый, старая модель) либо "key_box" (Proton) —
        // для key_box нужен приватный X25519-ключ владельца.
        let dk: [u8; 32] = if let Some(kb) = manifest["key_box"].as_object() {
            let priv_hex = owner_priv?;
            box_unwrap_key(&serde_json::Value::Object(kb.clone()), priv_hex).ok()?
        } else {
            let key = hex::decode(manifest["key"].as_str().unwrap_or("")).ok()?;
            if key.len() != 32 {
                return None;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&key);
            k
        };
        // EC-манифест: собираем любые k из n шардов и восстанавливаем ciphertext
        if let Some(ec) = manifest.get("ec").and_then(|v| v.as_object()) {
            let k = ec.get("k").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
            let n = ec.get("n").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let ct_len = ec.get("ct_len").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
            let mut have = 0usize;
            if let Some(chunks) = manifest["chunks"].as_array() {
                for c in chunks {
                    let idx = c["shard"].as_u64().unwrap_or(0) as usize;
                    if idx >= n {
                        continue;
                    }
                    let cid = c["id"].as_str().unwrap_or("");
                    if let Some(data) = self.fetch_chunk_net("mail", cid, c["hash"].as_str()).await
                    {
                        slots[idx] = Some(data);
                        have += 1;
                        if have >= k {
                            break;
                        }
                    }
                }
            }
            if have < k {
                eprintln!("[node] EC: {name}: only {have}/{k} shards available");
                return None;
            }
            let ct = Self::ec_decode(&mut slots, k, n, ct_len)?;
            let plain = e2e_decrypt(&dk, &nonce, &ct).ok();
            if let Some(p) = &plain {
                self.mail_cache_insert(name.to_string(), p.clone()).await;
            }
            return plain;
        }
        let mut buf: Vec<u8> = Vec::new();
        if let Some(chunks) = manifest["chunks"].as_array() {
            for c in chunks {
                let cid = c["id"].as_str().unwrap_or("");
                // ЛОКАЛЬНЫЙ ДИСК — ПЕРВЫМ (как в fetch_chunk_net): свежезаписанное
                // письмо лежит у нас, а сетевые проходы по висящим пирам съедали
                // бюджет чтения (наблюдалось: fetch только что отправленного письма
                // висел 5с и список отдавал пустое тело). Сеть — только при промахе.
                let mut got = self.local_chunk_get("mail", cid);
                if got.is_some() {
                    eprintln!(
                        "[node] WARN: chunk {cid} of {name} served from LOCAL disk, not from the network"
                    );
                }
                if got.is_none() {
                    // РАСПРЕДЕЛЁННОЕ чтение: ближайшие ноды (по DHT).
                    // Цель: валидатор не обязан хранить почту; чанки живут на storage-нодах.
                    {
                        let h = blake3::hash(format!("mail:{cid}").as_bytes());
                        let mut target = [0u8; NODEID_LEN];
                        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
                        let closest = self.dht_find_node(&target).await;
                        // ДВА ПРОХОДА: сначала пиры с ЖИВЫМ соединением (мгновенно), затем остальные.
                        // Иначе недоступный пир (нода за NAT, к которой валидатор не может дозвониться)
                        // держит чтение письма на своём connect-таймауте и Inbox «висит» десятками секунд.
                        for pass in 0..2u8 {
                            if got.is_some() {
                                break;
                            }
                            for n in closest.iter() {
                                if got.is_some() {
                                    break;
                                }
                                let live = self.pick_conn(None, n.id).await.is_some();
                                if (pass == 0) != live {
                                    continue;
                                }
                                if self.ensure_dht_peer(n).await.is_ok() {
                                    if let Ok(resp) = self
                                        .request_to(
                                            n.id,
                                            "storage.fetch",
                                            json!({ "bucket": "mail", "chunk_id": cid })
                                                .to_string()
                                                .into_bytes(),
                                        )
                                        .await
                                    {
                                        if let Ok(v) =
                                            serde_json::from_slice::<serde_json::Value>(&resp)
                                        {
                                            if v["ok"].as_bool().unwrap_or(false) {
                                                if let Some(b64) = v["data"].as_str() {
                                                    got = base64::Engine::decode(
                                                        &base64::engine::general_purpose::STANDARD,
                                                        b64,
                                                    )
                                                    .ok();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // проверка целостности: хэш чанка должен совпасть с манифестом (подмена?)
                if let Some(expected) = c["hash"].as_str() {
                    if let Some(g) = &got {
                        let actual = hex::encode(blake3::hash(g).as_bytes());
                        if !actual.eq_ignore_ascii_case(expected) {
                            eprintln!("[node] chunk tamper: {cid} in {name} (hash mismatch)");
                            got = None;
                        }
                    }
                }
                buf.extend_from_slice(&got?);
            }
        }
        let plain = e2e_decrypt(&dk, &nonce, &buf).ok();
        // кэш расшифрованных тел писем (60с) — повторное чтение Inbox не ходит в сеть
        if let Some(p) = &plain {
            self.mail_cache_insert(name.to_string(), p.clone()).await;
        }
        plain
    }

    /// Обобщённое хранилище блобов (для файлов file.storage): локально сразу + фоновая
    /// репликация, как store_mail, но с произвольным бакетом и манифестом "{bucket}:{name}".
    pub async fn store_blob(self: &Arc<Self>, bucket: &str, name: &str, blob: &[u8]) -> usize {
        self.store_blob_with_ttl(bucket, name, blob, 30 * 24 * 3600 * 1000)
            .await
    }

    /// `store_blob` с явным TTL манифеста (мс).
    ///
    /// Retention publisher'ов (stellereum: тела/заголовки живут окно KEEP):
    /// манифест пишется через `kv_store_local_with_ttl`, тот же TTL едет
    /// репликам (`replicate_blob` → `dht.store`), а чистку просроченного делает
    /// существующий sweep перед persist kv.json. Без вызова — как раньше (30 дней).
    pub async fn store_blob_with_ttl(
        self: &Arc<Self>,
        bucket: &str,
        name: &str,
        blob: &[u8],
        ttl_ms: i64,
    ) -> usize {
        self.store_blob_boxed_with_ttl(bucket, name, blob, None, ttl_ms)
            .await
    }

    /// store_blob с Proton-моделью: если owner_pub задан (X25519 hex владельца), ключ блоба
    /// шифруется box на публичный ключ (key_box в манифесте) — прочитать может только владелец.
    ///
    /// ИДЕМПОТЕНТНОСТЬ: key/nonce и chunk_id выводятся из содержимого (см.
    /// blob_key_nonce / chunk_id_for), поэтому повторный publish того же имени с тем же
    /// контентом пишет в ТЕ ЖЕ файлы чанков (поверх, write_chunk_atomic) и кладёт тот же
    /// манифест — размер каталога не растёт. Другое содержимое => новые id; старые файлы
    /// остаются сиротами до prune-chunk-orphans.
    pub async fn store_blob_boxed(
        self: &Arc<Self>,
        bucket: &str,
        name: &str,
        blob: &[u8],
        owner_pub: Option<&str>,
    ) -> usize {
        self.store_blob_boxed_with_ttl(bucket, name, blob, owner_pub, 30 * 24 * 3600 * 1000)
            .await
    }

    /// `store_blob_boxed` с явным TTL манифеста (мс). См. `store_blob_with_ttl`.
    pub async fn store_blob_boxed_with_ttl(
        self: &Arc<Self>,
        bucket: &str,
        name: &str,
        blob: &[u8],
        owner_pub: Option<&str>,
        ttl_ms: i64,
    ) -> usize {
        const CHUNK: usize = 1024 * 1024;
        // содержимо-адресность: (key, nonce) и id чанков выводятся из H(plaintext)
        let content_hash = blob_content_hash(blob);
        let (data_key, nonce) = blob_key_nonce(bucket, name, &content_hash);
        let ct = e2e_encrypt_det(&data_key, &nonce, blob);
        let mut chunks: Vec<serde_json::Value> = Vec::new();
        let mut offset = 0usize;
        let mut local_chunks = 0usize;
        // РАСПРЕДЕЛЁННОСТЬ: если валидатор НЕ хранит этот бакет (нет роли), чанки пишутся
        // СИНХРОННО на storage-ноды (ждём хотя бы одну реплику) — иначе манифест есть,
        // а чанк теряется (баг: файл "загружен", но не скачивается).
        let have_role = self.role_allows(bucket);
        let mut repl_ok = false;
        while offset < ct.len() {
            let end = (offset + CHUNK).min(ct.len());
            let chunk = &ct[offset..end];
            let chunk_id = chunk_id_for(bucket, name, offset, &content_hash);
            if have_role {
                let dir = self.chunks_dir(bucket);
                let _ = std::fs::create_dir_all(&dir);
                let _ = write_chunk_atomic(&dir, &chunk_id, chunk);
                local_chunks += 1;
            } else {
                // синхронная репликация чанка на storage-ноды
                if self.store_chunk_replicated(bucket, &chunk_id, chunk).await > 0 {
                    repl_ok = true;
                }
            }
            chunks.push(json!({
                "id": chunk_id,
                "n": 1,
                "off": offset,
                "len": chunk.len(),
                "hash": hex::encode(blake3::hash(chunk).as_bytes()),
            }));
            offset = end;
        }
        let mut manifest = json!({
            "bucket": bucket,
            "name": name,
            "size": blob.len(),
            "nonce": hex::encode(nonce),
            "chunks": chunks,
        });
        if let Some(pub_hex) = owner_pub {
            if let Some(kb) = box_wrap_key(pub_hex, &data_key) {
                manifest["key_box"] = kb;
            } else {
                manifest["key"] = json!(hex::encode(data_key));
            }
        } else {
            manifest["key"] = json!(hex::encode(data_key));
        }
        let mkey = Self::blob_manifest_key(bucket, name);
        self.kv_store_local_with_ttl(&mkey, &manifest.to_string(), ttl_ms)
            .await;
        let node = self.clone();
        let name = name.to_string();
        let bucket = bucket.to_string();
        let ct = ct.clone();
        let manifest_str = manifest.to_string();
        let mkey2 = mkey.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                node.replicate_blob(
                    &bucket,
                    &name,
                    &ct,
                    &manifest_str,
                    &mkey2,
                    &content_hash,
                    ttl_ms,
                ),
            )
            .await;
        });
        if have_role {
            local_chunks
        } else if repl_ok {
            1
        } else {
            0
        }
    }

    /// Фоновая репликация блоба (чанки + манифест) на другие ноды.
    /// `content_hash` — тот же content id, что и при записи: id на реплике обязан
    /// совпасть с локальными (иначе манифест уйдёт на пир с чужими путями).
    /// `ttl_ms` — TTL манифеста у реплики: тот же, что у локальной записи, чтобы
    /// retention-окно publisher'а действовало и на копиях (dht.store чтит ttl),
    /// а периодический republish (`dht_refresh`) продлевает их штатно.
    #[allow(clippy::too_many_arguments)] // GATE: replication needs full blob context
    async fn replicate_blob(
        self: &Arc<Self>,
        bucket: &str,
        name: &str,
        ct: &[u8],
        manifest_str: &str,
        mkey: &str,
        content_hash: &[u8; 32],
        ttl_ms: i64,
    ) {
        let mut offset = 0usize;
        const CHUNK: usize = 1024 * 1024;
        while offset < ct.len() {
            let end = (offset + CHUNK).min(ct.len());
            let chunk = &ct[offset..end];
            let chunk_id = chunk_id_for(bucket, name, offset, content_hash);
            let _ = self.store_chunk_replicated(bucket, &chunk_id, chunk).await;
            offset = end;
        }
        let h = blake3::hash(mkey.as_bytes());
        let mut target = [0u8; NODEID_LEN];
        target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        let closest = self.dht_find_node(&target).await;
        // Preserve age on first-hop replication too (audit follow-up): without
        // stored_at the replica resets the clock to receipt time, extending
        // life by a full TTL per hop.
        let stored_at = self.kv.read().await.stored_at(mkey);
        let payload = json!({ "key": mkey, "value": manifest_str, "ttl": ttl_ms / 1000, "stored_at": stored_at }).to_string().into_bytes();
        for n in closest {
            if self.ensure_dht_peer(&n).await.is_ok() {
                let _ = self.request_to(n.id, "dht.store", payload.clone()).await;
            }
        }
    }

    /// Скачать блоб из произвольного бакета (манифест + чанки + расшифровка).
    pub async fn fetch_blob(self: &Arc<Self>, bucket: &str, name: &str) -> Option<Vec<u8>> {
        let mkey = Self::blob_manifest_key(bucket, name);
        let manifest_str = self.get_local_kv(&mkey).await;
        let manifest_str = if let Some(m) = manifest_str {
            m
        } else {
            let h = blake3::hash(mkey.as_bytes());
            let mut target = [0u8; NODEID_LEN];
            target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
            let closest = self.dht_find_node(&target).await;
            let q = json!({ "key": mkey }).to_string().into_bytes();
            let mut found = None;
            for n in closest.iter() {
                if found.is_some() {
                    break;
                }
                if self.ensure_dht_peer(n).await.is_ok() {
                    if let Ok(resp) = self.request_to(n.id, "dht.find_value", q.clone()).await {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                            if v["found"].as_bool().unwrap_or(false) {
                                found = v["value"].as_str().map(String::from);
                            }
                        }
                    }
                }
            }
            found?
        };
        let manifest: serde_json::Value = serde_json::from_str(&manifest_str).ok()?;
        let nonce = hex::decode(manifest["nonce"].as_str().unwrap_or("")).ok()?;
        let key = hex::decode(manifest["key"].as_str().unwrap_or("")).ok()?;
        if key.len() != 32 {
            return None;
        }
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&key);
        let mut buf: Vec<u8> = Vec::new();
        if let Some(chunks) = manifest["chunks"].as_array() {
            for c in chunks {
                let cid = c["id"].as_str().unwrap_or("");
                let mut got = self.local_chunk_get(bucket, cid);
                if got.is_none() {
                    // таргет = blake3("{bucket}:{cid}") — совпадает с записью (store_chunk_replicated)
                    let h = blake3::hash(format!("{bucket}:{cid}").as_bytes());
                    let mut target = [0u8; NODEID_LEN];
                    target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
                    let closest = self.dht_find_node(&target).await;
                    // ДВА ПРОХОДА (см. fetch_mail_inner): живые соединения первыми.
                    for pass in 0..2u8 {
                        if got.is_some() {
                            break;
                        }
                        for n in closest.iter() {
                            if got.is_some() {
                                break;
                            }
                            let live = self.pick_conn(None, n.id).await.is_some();
                            if (pass == 0) != live {
                                continue;
                            }
                            if self.ensure_dht_peer(n).await.is_ok() {
                                if let Ok(resp) = self
                                    .request_to(
                                        n.id,
                                        "storage.fetch",
                                        json!({ "bucket": bucket, "chunk_id": cid })
                                            .to_string()
                                            .into_bytes(),
                                    )
                                    .await
                                {
                                    if let Ok(v) =
                                        serde_json::from_slice::<serde_json::Value>(&resp)
                                    {
                                        if v["ok"].as_bool().unwrap_or(false) {
                                            if let Some(b64) = v["data"].as_str() {
                                                got = base64::Engine::decode(
                                                    &base64::engine::general_purpose::STANDARD,
                                                    b64,
                                                )
                                                .ok();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // проверка целостности: хэш чанка должен совпасть с манифестом (подмена?)
                if let Some(expected) = c["hash"].as_str() {
                    if let Some(g) = &got {
                        let actual = hex::encode(blake3::hash(g).as_bytes());
                        if !actual.eq_ignore_ascii_case(expected) {
                            eprintln!("[node] chunk tamper: {cid} in {name} (hash mismatch)");
                            got = None;
                        }
                    }
                }
                buf.extend_from_slice(&got?);
            }
        }
        e2e_decrypt(&dk, &nonce, &buf).ok()
    }

    // ============ конец Хранилища ============

    // ============ Почта (mail.*) ============

    /// Получить ed_pub пользователя из реестра: локальный KV, затем прямой опрос пиров.
    pub async fn user_ed_pub(self: &Arc<Self>, email: &str) -> Option<String> {
        let key = format!("user:{email}");
        if let Some(v) = self.get_local_kv(&key).await {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&v) {
                if let Some(ed) = meta["ed_pub"].as_str() {
                    return Some(ed.to_string());
                }
            }
        }
        let q = json!({ "key": key }).to_string().into_bytes();
        let peers: Vec<[u8; NODEID_LEN]> = self.peers.read().await.keys().copied().collect();
        for pid in peers {
            if let Ok(resp) = self.request_to(pid, "dht.find_value", q.clone()).await {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp) {
                    if v["found"].as_bool().unwrap_or(false) {
                        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(
                            v["value"].as_str().unwrap_or(""),
                        ) {
                            if let Some(ed) = meta["ed_pub"].as_str() {
                                return Some(ed.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// mail.list: отдаёт индекс ящика ТОЛЬКО владельцу (проверка Ed25519-подписи).
    async fn handle_mail_list(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
        let email = v["email"].as_str().unwrap_or("").to_string();
        let ts = v["ts"].as_i64().unwrap_or(0);
        let sig = hex::decode(v["sig"].as_str().unwrap_or("")).unwrap_or_default();
        // проверка владения: подпись над "email:ts" ключом владельца
        let ed_pub_hex = match self.user_ed_pub(&email).await {
            Some(e) => e,
            None => {
                return Some(
                    json!({ "ok": false, "err": "user not registered" })
                        .to_string()
                        .into_bytes(),
                )
            }
        };
        if sig.len() != 64 {
            return Some(
                json!({ "ok": false, "err": "bad sig" })
                    .to_string()
                    .into_bytes(),
            );
        }
        let edb = match hex::decode(&ed_pub_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                return Some(
                    json!({ "ok": false, "err": "bad ed_pub" })
                        .to_string()
                        .into_bytes(),
                )
            }
        };
        let mut edk = [0u8; 32];
        edk.copy_from_slice(&edb);
        let mut sigk = [0u8; 64];
        sigk.copy_from_slice(&sig);
        let msg = format!("{email}:{ts}");
        if !crate::mailbox::MailKeys::verify(&edk, msg.as_bytes(), &sigk) {
            return Some(
                json!({ "ok": false, "err": "not mailbox owner" })
                    .to_string()
                    .into_bytes(),
            );
        }
        // анти-replay: подпись действительна только в окне ±5 минут
        if now_ms().abs_diff(ts) > 5 * 60 * 1000 {
            return Some(
                json!({ "ok": false, "err": "signature expired" })
                    .to_string()
                    .into_bytes(),
            );
        }
        // владелец подтверждён — читаем индекс ящика
        let ikey = format!("mail:{email}:index");
        let idx = self
            .get_local_kv(&ikey)
            .await
            .unwrap_or_else(|| "[]".to_string());
        Some(json!({ "ok": true, "ids": serde_json::from_str::<Vec<String>>(&idx).unwrap_or_default() }).to_string().into_bytes())
    }

    // ============ конец Почты ============

    // ============ конец Pub/Sub ============

    /// Live-reload конфига по SIGHUP: обновляет пиров/ACL/роли/лимиты без рестарта.
    async fn reload_config(self: &Arc<Self>) {
        let path = &self.config_path;
        let new_cfg = match crate::config::load(path) {
            Ok(c) => c,
            Err(e) => {
                crate::terr!(&self.cfg.name, 0, "reload_failed", err = format!("{e}"));
                return;
            }
        };
        let roles = new_cfg.roles.clone();
        let mut updated = 0usize;
        let mut peers = self.peers.write().await;
        for (pid, link) in peers.iter_mut() {
            if let Some(p) = new_cfg
                .peers
                .iter()
                .find(|p| p.node_id_raw().ok() == Some(*pid))
            {
                let mut p = p.clone();
                p.allow = p.effective_allow(&roles);
                link.cfg.allow = p.allow;
                if !p.endpoints.is_empty() {
                    link.cfg.endpoints = p.endpoints.clone();
                }
                link.cfg.rate_limit_per_sec = p.rate_limit_per_sec;
                link.cfg.role = p.role;
                updated += 1;
            }
        }
        drop(peers);
        // обновляем базовые поля
        {
            let mut guard = self.unknown_allow_cfg.write().await;
            *guard = new_cfg.unknown_allow.clone();
        }
        crate::log::emit(
            2,
            "info",
            &self.cfg.name,
            0,
            "config_reloaded",
            json!({ "updated_peers": updated }),
        );
    }

    /// Серверный режим: слушаем + поддерживаем исходящие соединения.
    pub async fn serve(self: &Arc<Self>) -> Result<()> {
        let (certs, key) = build_tls(&self.keys)?;
        let listen: SocketAddr = self.cfg.listen.parse()?;
        let sc = quinn::ServerConfig::with_single_cert(certs, key)?;
        let mut sc = sc;
        sc.transport_config(Arc::new(transport_config()));
        let server_ep = Endpoint::server(sc, listen)?;
        crate::log::emit(
            2,
            "info",
            &self.cfg.name,
            0,
            "serving",
            json!({ "node": self.id_hex, "listen": listen.to_string() }),
        );
        if let Some(level) = self.cfg.log_level {
            crate::log::set_level(level);
        }
        // Prometheus-метрики
        if let Some(addr) = &self.cfg.metrics_listen {
            let m = self.metrics.clone();
            let svc = self.svc_counters.clone();
            match crate::metrics::spawn(addr, m, svc) {
                Ok(()) => crate::log::emit(
                    2,
                    "info",
                    &self.cfg.name,
                    0,
                    "metrics_up",
                    json!({ "addr": addr }),
                ),
                Err(e) => crate::terr!(&self.cfg.name, 0, "metrics_failed", err = format!("{e}")),
            }
        }

        let accept_node = self.clone();
        tokio::spawn(async move { accept_loop(accept_node, server_ep).await });

        // NAT hole punch: принимаем входящие и на client-сокете (обратный пробой через NAT)
        let punch_node = self.clone();
        let punch_ep = self.client_ep.clone();
        tokio::spawn(async move { accept_loop(punch_node, punch_ep).await });

        let rc_node = self.clone();
        tokio::spawn(async move { reconnect_loop(rc_node).await });

        let flush_node = self.clone();
        tokio::spawn(async move {
            loop {
                flush_node.flush_outbox_once().await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        // R6: debounced flush-цикл kv (паттерн outbox_dirty): раз в секунду
        // пишем kv.json ТОЛЬКО если dirty и прошло debounce-окно с последнего
        // сохранения — всплеск dht.store даёт ОДНУ запись, а не N.
        let kv_flush_node = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                kv_flush_node.kv_flush_if_due().await;
            }
        });

        let gossip_node = self.clone();
        tokio::spawn(async move {
            loop {
                gossip_node.gossip_routes().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        let prune_node = self.clone();
        tokio::spawn(async move {
            loop {
                prune_node.prune_subs().await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        // refresh DHT: пере-пинг ближайших к себе узлов каждые 60с
        let dht_node = self.clone();
        tokio::spawn(async move {
            loop {
                dht_node.dht_refresh().await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // периодический РЕМОНТ ЧАНКОВ: раньше он шёл только при синке с пиром, поэтому
        // недостающие чанки могли висеть неограниченно долго. Теперь раз в 10 минут
        // проходим по известным пирам и дотягиваем отсутствующие чанки своих манифестов
        // (с проверкой хэша по манифесту внутри repair_chunks_from).
        let repair_node = self.clone();
        tokio::spawn(async move {
            // первый проход — вскоре после старта, дальше раз в 10 минут
            tokio::time::sleep(Duration::from_secs(45)).await;
            loop {
                let mut tried = 0usize;
                // 1) СКОНФИГУРИРОВАННЫЕ пиры (по имени): узел-держатель может не попадать
                // в DHT-routing (например, подключается только входящими соединениями),
                // и тогда ремонт его не спрашивал — хотя данные у него есть.
                let names: Vec<String> = repair_node
                    .cfg
                    .peers
                    .iter()
                    .map(|p| p.name.clone())
                    .collect();
                for name in names {
                    if let Ok(pid) = repair_node.resolve(&name) {
                        // ТАЙМАУТ: недоступный пир не должен занимать проход надолго
                        // (иначе ремонт висит минутами и мешает обычным запросам).
                        let _ = tokio::time::timeout(
                            Duration::from_secs(30),
                            repair_node.repair_chunks_from(pid),
                        )
                        .await;
                        tried += 1;
                    }
                }
                // 2) узлы из DHT-таблицы
                let infos = {
                    let r = repair_node.routing.read().await;
                    r.closest(&repair_node.id, 16)
                };
                for info in infos {
                    if repair_node.ensure_dht_peer(&info).await.is_ok() {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(30),
                            repair_node.repair_chunks_from(info.id),
                        )
                        .await;
                        tried += 1;
                    }
                }
                eprintln!("[node] chunk repair pass: peers tried={tried}");
                tokio::time::sleep(Duration::from_secs(600)).await;
            }
        });

        // live-reload конфига по SIGHUP (пиры/ACL/роли/лимиты)
        {
            let node = self.clone();
            tokio::spawn(async move {
                let mut sig =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                        .expect("SIGHUP handler");
                loop {
                    sig.recv().await;
                    node.reload_config().await;
                }
            });
        }

        crate::log::emit(
            2,
            "info",
            &self.cfg.name,
            0,
            "serving_ready",
            json!({ "peers": self.peers.read().await.len() }),
        );
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn accept_loop(node: Arc<Node>, ep: Endpoint) {
    // защита от DoS: максимум одновременных входящих соединений
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_INCOMING));
    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => {
                eprintln!("[{}] accept loop ended", node.cfg.name);
                return;
            }
        };
        let node = node.clone();
        let sem = sem.clone();
        tokio::spawn(async move {
            // F8: fail-closed admission BEFORE the permit is consumed, so a
            // slow-handshake rain cannot wedge MAX_INCOMING on half-open
            // sessions. `remote_address` is available pre-handshake.
            let remote_ip: IpAddr = incoming.remote_address().ip();
            {
                let ip = remote_ip;
                if node.is_banned(&ip).await {
                    node.metrics.auth_bans_hit.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[{}] handshake from banned {ip}, refusing", node.cfg.name);
                    incoming.refuse();
                    return;
                }
                if !node.handshake_allowed(ip).await {
                    eprintln!(
                        "[{}] handshake throttled for {ip}, refusing",
                        node.cfg.name
                    );
                    incoming.refuse();
                    return;
                }
            }
            let permit = match sem.try_acquire() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!(
                        "[{}] too many incoming connections, refusing",
                        node.cfg.name
                    );
                    incoming.refuse();
                    return;
                }
            };
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(_) => return,
            };
            let conn = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[{}] accept error: {e}", node.cfg.name);
                    return;
                }
            };
            // Post-handshake ban re-check: a strike ban may have landed while
            // this handshake was in flight. Close immediately, never serve.
            {
                let ip = conn.remote_address().ip();
                if node.is_banned(&ip).await {
                    node.metrics.auth_bans_hit.fetch_add(1, Ordering::Relaxed);
                    conn.close(quinn::VarInt::from(0u32), b"banned");
                    return;
                }
            }
            node.metrics.conns_accepted.fetch_add(1, Ordering::Relaxed);
            node.metrics.conns_active.fetch_add(1, Ordering::Relaxed);
            // Помечаем соединение как обслуживаемое, чтобы ensure_frame_loop не
            // поднял на нём второй цикл (здесь цикл блокирующий и держит permit).
            let sid = conn.stable_id();
            node.looped
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(sid);
            frame_loop(conn, node, None).await;
            drop(permit);
        });
    }
}

/// Сколько ждать НОВЫЙ поток на уже установленном соединении, прежде чем закрыть его
/// и вернуть пермит MAX_INCOMING. Должно быть заметно больше периода keep-alive (15с).
// Держит пермит MAX_INCOMING ровно столько, сколько живёт простояющее
// соединение. 300с означало, что каждое из сотен соединений, созданных при
// реконнект-шторме, занимало слот приёма на ПЯТЬ минут, и через пару минут
// эндпоинт начинал отказывать в новых рукопожатиях ("the server refused to
// accept a new connection"), т.е. обе стороны теряли консенсус. 30с = 2x
// keep-alive (15с): живое соединение продлевается пингами и не трогает
// таймаут, мёртвое отдаёт слот почти сразу.
#[allow(dead_code)] // GATE: tuning knob for stream-GC rollout
const STREAM_IDLE_TIMEOUT_SECS: u64 = 30;
const MAX_INCOMING: usize = 512;
/// Максимум одновременно обрабатываемых стримов ОДНОГО соединения. Реальные
/// запросы к узлу короткие; лимит нужен, чтобы злоумышленник не открыл тысячи
/// стримов и не исчерпал память/CPU. При исчерпании стрим просто дропается.
// Живой стенд: 64 разрешения исчерпывались (330 shed за 4 мин), и сброшенный
// стрим оставлял отправителя ждать таймаут (~2с) -- тик консенсуса растягивался
// до 10с при ROUND_TIMEOUT=800мс. Запросы короткие, разрешение живёт только
// пока идёт запрос, так что 256 -- запас на пики, а не безразмерие.
const MAX_CONN_STREAMS: usize = 1024;
/// Сколько ждать завершения уже запущенных стрим-тасков при разрыве соединения,
/// прежде чем оборвать их вместе с соединением.
const STREAM_DRAIN_TIMEOUT_SECS: u64 = 2;

async fn reconnect_loop(node: Arc<Node>) {
    loop {
        let ids: Vec<[u8; NODEID_LEN]> = node.peers.read().await.keys().cloned().collect();
        for pid in ids {
            // R18: один peers.read на пира — peer уходит и в проверку has_conn,
            // и (если соединения нет) в connect_or_get (раньше читался дважды).
            let peer = node.peers.read().await.get(&pid).cloned();
            let has_conn = match &peer {
                Some(p) => p.conn.read().await.is_some(),
                None => false,
            };
            if !has_conn {
                // Circuit breaker: a parked peer gets at most ONE single-probe
                // dial per backoff interval (first configured endpoint only —
                // enforced inside `dial_peer` via the parked signal and in
                // `dial_parked_probe` below: no sweep, no NAT punch, no
                // `catch_up` spawn); otherwise it is skipped silently until
                // its probe is due.
                if node.circuit_is_parked(&pid) {
                    if node.circuit_probe_due(&pid) {
                        if let Some(peer) = peer {
                            node.metrics.reconnects.fetch_add(1, Ordering::Relaxed);
                            match node.dial_parked_probe(&peer, pid).await {
                                Ok(conn) => {
                                    node.ensure_frame_loop(conn, Some(pid));
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[{}] parked probe {} failed: {e}",
                                        node.cfg.name,
                                        hex::encode(pid)
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }
                node.metrics.reconnects.fetch_add(1, Ordering::Relaxed);
                if let Some(peer) = peer {
                    if let Ok(conn) = node.connect_or_get(&peer, pid).await {
                        let node_cu = node.clone();
                        // connect_or_get уже поднял цикл; ensure_frame_loop идемпотентен.
                        node.ensure_frame_loop(conn, Some(pid));
                        // догоняющая репликация: тянем пропущенное с только что подключённого пира
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(60),
                                node_cu.catch_up_with(pid),
                            )
                            .await;
                        });
                    }
                }
            } else if node.circuit_is_parked(&pid) {
                // A live connection proves reachability (inbound resets land
                // via `add_conn`; this covers the race where it registered
                // after the park check above).
                node.circuit_record_success(pid);
            }
        }
        tokio::time::sleep(Duration::from_secs(CIRCUIT_RECONNECT_INTERVAL_SECS)).await;
    }
}

async fn frame_loop(conn: Connection, node: Arc<Node>, known_pid: Option<[u8; NODEID_LEN]>) {
    let mut authed: Option<[u8; NODEID_LEN]> = known_pid;
    // F8 pre-auth deadline: a connection with no valid CHALLENGE within N
    // seconds is closed so dead/slow handshakes free their MAX_INCOMING
    // permit. Applies pre-auth only: once `authed` is Some the wait is
    // indefinite again (QUIC 120s idle timeout still bounds dead sessions).
    let preauth_start = tokio::time::Instant::now();
    let preauth_secs = preauth_deadline_secs();
    // Per-connection admission control for spawned stream tasks. An exhausted
    // semaphore means the peer is flooding this connection: log and drop the
    // stream, never tear the connection down.
    let stream_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONN_STREAMS));
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        // Reap finished stream tasks. Their errors are LOG-ONLY: one bad/failed
        // stream must never take down the whole connection (that used to turn a
        // single malformed frame into a full-fleet reconnect storm).
        while let Some(joined) = tasks.try_join_next() {
            if let Err(e) = joined {
                eprintln!("[{}] stream task error: {e}", node.cfg.name);
            }
        }
        // Таймаут ожидания НОВОГО потока. Без него соединение, чей пир перестал открывать
        // потоки, но QUIC-сессия ещё жива (keep_alive сбрасывает max_idle_timeout),
        // висело в accept_bi() вечно и НЕ отпускало пермит MAX_INCOMING — а пермит живёт
        // ровно столько, сколько frame_loop. Узел упирался в «too many incoming
        // connections», отказывал пирам, и меш рассыпался на «aborted by peer: refused».
        // Name the exit reason: `_ => break` hid whether the connection died
        // (peer closed / local reset) or the idle timer fired, and the two have
        // opposite meanings -- closing a HEALTHY connection every time the peer
        // goes quiet for 30s is what turns a working link into a reconnect
        // storm. conn.close_reason() says who ended it.
        // Wait indefinitely for the next stream once authed. The old 30s idle
        // timer had to go: a live QUIC session whose peer is simply quiet for
        // 30s (keep-alive pings are not application streams) looked "idle", so
        // we exited and CLOSED a perfectly healthy connection -- measured live
        // as 40 such idle-exits on one node with close_reason=None, and every
        // one of them told the peer "closed", killing ITS frame_loop too (the
        // cascade was ~2300 conn_closed events per node). The permit is still
        // bounded: pre-auth connections die on `preauth_secs`, and a genuinely
        // dead authed peer stops answering keep-alive so QUIC's idle timeout
        // (120s) closes the session, accept_bi errors, we exit and close --
        // and explicit evictions close their connections directly.
        let (mut send, mut recv) = if authed.is_none() && preauth_secs > 0 {
            let deadline = Duration::from_secs(preauth_secs);
            let elapsed = preauth_start.elapsed();
            if elapsed >= deadline {
                eprintln!(
                    "[{}] pre-auth deadline ({}s) on {}, closing",
                    node.cfg.name,
                    preauth_secs,
                    conn.stable_id()
                );
                node.metrics.preauth_timeouts.fetch_add(1, Ordering::Relaxed);
                conn.close(quinn::VarInt::from(0u32), b"preauth deadline");
                break;
            }
            let remaining = deadline - elapsed;
            match timeout(remaining, conn.accept_bi()).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    eprintln!(
                        "[{}] frame_loop ends on {} ({e}; close_reason={:?})",
                        node.cfg.name,
                        conn.stable_id(),
                        conn.close_reason()
                    );
                    break;
                }
                Err(_) => {
                    eprintln!(
                        "[{}] pre-auth deadline ({}s) on {}, closing",
                        node.cfg.name,
                        preauth_secs,
                        conn.stable_id()
                    );
                    node.metrics.preauth_timeouts.fetch_add(1, Ordering::Relaxed);
                    conn.close(quinn::VarInt::from(0u32), b"preauth deadline");
                    break;
                }
            }
        } else {
            match conn.accept_bi().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[{}] frame_loop ends on {} ({e}; close_reason={:?})",
                        node.cfg.name,
                        conn.stable_id(),
                        conn.close_reason()
                    );
                    break;
                }
            }
        };
        // Patch B: момент приёма стрима — handle_stream измерит disp = start -
        // t_accept (задержка планирования/диспатча, включая sempahore/spawn).
        let t_accept = std::time::Instant::now();
        match authed {
            // Challenge/auth stays SERIAL on the accept loop: only the accept
            // loop owns connection lifecycle and may set the authenticated pid.
            None => {
                match handle_stream(node.clone(), conn.clone(), send, recv, None, t_accept).await {
                    Ok(Some(pid)) => {
                        let ip = conn.remote_address().ip();
                        node.record_auth_success(&ip).await;
                        node.rep_record_valid(&pid).await;
                        authed = Some(pid);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[{}] stream error: {e}", node.cfg.name);
                        let ip = conn.remote_address().ip();
                        node.record_auth_failure(ip).await;
                        conn.close(quinn::VarInt::from(0u32), b"auth failed");
                        break;
                    }
                }
            }
            // Authenticated traffic is handled CONCURRENTLY: each stream gets its
            // own task and its own permit, so one slow/hung request cannot block
            // every other stream on the connection.
            Some(pid) => {
                let permit = match stream_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!(
                            "[{}] too many concurrent streams on one connection, dropping stream",
                            node.cfg.name
                        );
                        // Явный RESET вместо молчаливого дропа: отправитель получает
                        // ошибку сразу, а не ждёт свой таймаут. Молчаливый дроп в части
                        // случаев оставлял поток читающимся до таймаута чтения (5с), то
                        // есть ровно держал разрешение занятым.
                        let _ = send.reset(quinn::VarInt::from(0u32));
                        let _ = recv.stop(quinn::VarInt::from(0u32));
                        continue;
                    }
                };
                let node = node.clone();
                let conn = conn.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) =
                        handle_stream(node.clone(), conn, send, recv, Some(pid), t_accept).await
                    {
                        eprintln!("[{}] stream task error: {e}", node.cfg.name);
                    }
                });
            }
        }
    }
    // Соединение распадается: даём уже запущенным стримам короткое окно
    // завершиться (best-effort), затем обрываем оставшиеся вместе с JoinSet.
    let _ = timeout(Duration::from_secs(STREAM_DRAIN_TIMEOUT_SECS), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let sid = conn.stable_id();
    if let Some(pid) = authed {
        node.drop_conn(pid, Some(sid)).await;
    }
    // Соединение обслуживание закончило — снимаем отметку, чтобы тот же sid
    // снова не считался «уже с циклом» (важно для accept-пути, где цикл
    // блокирующий и сам себя не снимает).
    node.looped
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&sid);
    node.sessions.write().await.remove(&sid);
    node.pq_digests.write().await.remove(&sid);
    node.metrics.conns_closed.fetch_add(1, Ordering::Relaxed);
    node.metrics.conns_active.fetch_sub(1, Ordering::Relaxed);
    crate::log::emit(2, "info", &node.cfg.name, 0, "conn_closed", json!({}));
}

async fn handle_stream(
    node: Arc<Node>,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    authed: Option<[u8; NODEID_LEN]>,
    t_accept: std::time::Instant,
) -> Result<Option<[u8; NODEID_LEN]>> {
    // Patch B: стадии обработки. disp = start - t_accept (диспатч стрима в
    // задачу), read = чтение фрейма, proc = разбор + сервис + запись ответа.
    // Всё пишется в метрики (dispatch_ms_max/handler_ms_max) безусловно, а
    // строка лога "dispatch" выходит только при >=200мс и несёт join-ключ
    // (f.seq, f.ts) — тот же ключ логирует отправитель в "req_stages".
    let t_start = std::time::Instant::now();
    let disp_ms = t_start.saturating_duration_since(t_accept).as_millis() as u64;
    node.metrics
        .dispatch_ms_max
        .fetch_max(disp_ms, Ordering::Relaxed);
    let t_read = std::time::Instant::now();
    // таймаут на чтение фрейма: клиент, открывший стрим и не закончивший его,
    // не должен вечно держать frame_loop (иначе каскад при убитых клиентах).
    // Короткий (был 60s): пока frame_loop ждёт один зависший стрим, ВСЕ
    // остальные сообщения этого соединения стоят в очереди и приходят
    // протухшими на десятки раундов позже -- наблюдалось вживую как голоса,
    // которые всегда опаздывают (кворумы не складываются, хотя все голосуют).
    // Легитимные фреймы на localhost прилетают за миллисекунды, так что 5s --
    // это щедро; настоящие медленные пиры переподключатся.
    let (read_limit, read_to) = if authed.is_none() {
        (proto::MAX_AUTH_FRAME, Duration::from_millis(1500))
    } else {
        (proto::MAX_FRAME, Duration::from_secs(5))
    };
    let bytes = match timeout(read_to, recv.read_to_end(read_limit)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            // F8-rep: an oversize transport frame on an authed connection is
            // attributable to the proven identity (pre-auth there is no
            // identity yet — the IP strike in the caller covers it).
            // Transport closures/timeouts are NOT abuse signals: no penalty.
            if let Some(pid) = authed {
                if crate::reputation::oversize_looking(&e.to_string()) {
                    node.rep_record_oversize(&pid).await;
                }
            }
            return Err(e.into());
        }
        Err(_) => return Err(anyhow!("frame read timeout")),
    };
    let read_ms = t_read.elapsed().as_millis() as u64;
    let t_proc = std::time::Instant::now();
    let f = match Frame::decode(&bytes) {
        Ok(f) => f,
        Err(e) => {
            // F8-rep: undecodable frames on an authed connection come from
            // the proven identity: oversize-looking → oversize debit, else
            // protocol debit. Pre-auth: identity unknown, IP strike covers.
            if let Some(pid) = authed {
                if crate::reputation::oversize_looking(&e.to_string()) {
                    node.rep_record_oversize(&pid).await;
                } else {
                    node.rep_record_protocol_violation(&pid).await;
                }
            }
            return Err(e);
        }
    };
    node.metrics.frames_in.fetch_add(1, Ordering::Relaxed);
    node.metrics
        .bytes_in
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let trace = node.next_trace();
    let tlog = |event: &str, fields: serde_json::Value| {
        crate::log::emit(2, "info", &node.cfg.name, trace, event, fields);
    };
    let terr = |event: &str, fields: serde_json::Value| {
        crate::log::emit(0, "error", &node.cfg.name, trace, event, fields);
    };
    let report_stages = |f: &Frame, proc: Duration| {
        let proc_ms = proc.as_millis() as u64;
        node.metrics
            .handler_ms_max
            .fetch_max(proc_ms, Ordering::Relaxed);
        if disp_ms >= 200 || read_ms >= 200 || proc_ms >= 200 {
            // R6: svc прямо в dispatch — раньше атрибуция медленных proc
            // требовала джойна с req/req_stages по trace/seq+ts (и ломалась
            // на рестартах: trace начинается заново). Стоит только внутри
            // >=200мс-гейта, т.е. ровно на тех строках, что мы и анализируем.
            crate::log::emit(
                2,
                "info",
                &node.cfg.name,
                trace,
                "dispatch",
                json!({
                    "seq": f.seq,
                    "ts": f.ts,
                    "kind": f.kind,
                    "svc": proto::svc_name(f.svc).unwrap_or("?"),
                    "disp_ms": disp_ms,
                    "read_ms": read_ms,
                    "proc_ms": proc_ms,
                }),
            );
        }
    };

    if f.kind == proto::kind::CHALLENGE {
        let claimed = f.src;
        // F8-rep identity gate (extends the IP accept hardening): a banned
        // or soft-throttled identity is refused here even from a fresh IP, so
        // the offender cannot dodge by redialling, while honest peers on the
        // same address are unaffected. These refusals carry NO extra penalty
        // (the score that caused them is enough; penalising would make soft
        // throttle permanent and defeat decay).
        if node.rep_is_banned(&claimed).await {
            node.metrics.rep_refusals.fetch_add(1, Ordering::Relaxed);
            bail!("reputation banned");
        }
        if node.rep_is_throttled(&claimed).await {
            node.metrics.rep_refusals.fetch_add(1, Ordering::Relaxed);
            bail!("reputation throttled");
        }
        // F8-rep: failures below NEVER debit an identity. `claimed` is
        // unproven pre-auth (any sender can put any src on the wire), so a
        // debit here would let an attacker frame honest ids into temp-bans.
        // The connection is dropped fail-closed instead (Err closes it in
        // the pre-auth caller; the per-IP strike still binds the sender's
        // address). Only the proven post-handshake id (`authed` pid, set
        // after a valid CHALLENGE) is ever debited — see the authed path.
        let ch: serde_json::Value = match serde_json::from_slice(&f.payload) {
            Ok(v) => v,
            Err(e) => {
                return Err(e.into());
            }
        };
        // Строгий гейт payload (fail-closed): nonce/at/eph/ed/x обязаны быть
        // на месте и свежими. Раньше проверялись только подпись фрейма и его
        // ts — повтор кадра в окне ±10 мин создавал новую сессию.
        let (ch_nonce, ch_eph, ch_ed, ch_x) = match challenge_fields(&ch) {
            Ok(v) => v,
            Err(e) => {
                return Err(e);
            }
        };
        // Рамочный ts — ДО любых side-эффектов (регистрация TOFU-пира,
        // сессии, маршруты): протухший кадр не оставляет следов.
        if !ts_ok(f.ts) {
            bail!("stale challenge");
        }
        // read-guard в {} освобождается ДО взятия write-lock в add_dynamic_peer (иначе deadlock)
        let known = node.peers.read().await.contains_key(&claimed);
        let peer = if known {
            let peer = match node.peers.read().await.get(&claimed).cloned() {
                Some(p) => p,
                None => {
                    bail!("peer disappeared");
                }
            };
            // Привязка payload к пинну: известный пир обязан предъявить СВОИ
            // ключи, а не чужие валидные (раньше ed/x из payload игнорировались).
            let pinned_ed = match peer.cfg.ed_bytes() {
                Ok(b) => b,
                Err(e) => {
                    return Err(e);
                }
            };
            let pinned_x = match peer.cfg.x_bytes() {
                Ok(b) => b,
                Err(e) => {
                    return Err(e);
                }
            };
            if ch_ed != pinned_ed || ch_x != pinned_x {
                bail!("challenge key mismatch");
            }
            peer
        } else if node.cfg.allow_unknown {
            // TOFU: неизвестная нода доказывает владение ключом подписью CHALLENGE
            let ed_hex = hex::encode(ch_ed);
            let x_hex = hex::encode(ch_x);
            let ed: [u8; 32] = ch_ed;
            let vk = match VerifyingKey::from_bytes(&ed) {
                Ok(v) => v,
                Err(e) => {
                    return Err(e.into());
                }
            };
            if claimed != blake3::hash(vk.as_bytes()).as_bytes()[..NODEID_LEN] {
                bail!("claimed node id does not match public key");
            }
            if !f.verify(&vk) {
                bail!("unknown node could not sign the challenge");
            }
            // детект MITM: если этот node_id уже видели с ДРУГИМ ключом — отказ + громкое предупреждение
            if let Some(known) = node.routes.read().await.get(&claimed) {
                if !known.ed_hex.is_empty() && known.ed_hex != ed_hex {
                    eprintln!(
                        "[{}] !! MITM-WARNING: node inf1:{} is changing keys! was ed={} now ed={} — REFUSED",
                        node.cfg.name,
                        hex::encode(claimed),
                        known.ed_hex,
                        ed_hex
                    );
                    bail!("node key changed (possible MITM)");
                }
            }
            let pcfg = PeerConfig {
                name: format!("dyn-{}", hex::encode(&claimed[..4])),
                node_id: format!("inf1:{}", hex::encode(claimed)),
                ed_pub: ed_hex.clone(),
                x_pub: x_hex,
                // TOFU peers are classical by construction (explicit).
                pq_pub: None,
                endpoints: vec![conn.remote_address().to_string()],
                allow: node.unknown_allow_cfg.read().await.clone(),
                // PENTEST F5: a TOFU identity is the least-trusted peer on the
                // network — it must never be born with 0 = unlimited.
                rate_limit_per_sec: DYNAMIC_PEER_RATE_LIMIT_PER_SEC,
                role: None,
                storage_roles: vec![],
            };
            if let Err(e) = node.add_dynamic_peer(claimed, pcfg).await {
                return Err(e);
            }
            // TOFU: показываем оператору отпечаток для ручной проверки (как SSH fingerprint)
            eprintln!(
                "[{}] !! TOFU: unknown node inf1:{} ed={} from {} accepted — verify the fingerprint!",
                node.cfg.name,
                hex::encode(claimed),
                ed_hex,
                conn.remote_address()
            );
            match node.peers.read().await.get(&claimed).cloned() {
                Some(p) => p,
                None => {
                    bail!("dynamic peer did not appear");
                }
            }
        } else {
            bail!("unknown node claiming {}", hex::encode(claimed));
        };
        let vk = match peer.cfg.ed_bytes() {
            Ok(b) => match VerifyingKey::from_bytes(&b) {
                Ok(v) => v,
                Err(e) => {
                    return Err(e.into());
                }
            },
            Err(e) => {
                return Err(e);
            }
        };
        if !f.verify(&vk) || !ts_ok(f.ts) {
            bail!("challenge bad sig/ts");
        }
        // Anti-replay: nonce одноразовый. Проверяется ПОСЛЕ подписи, чтобы
        // поддельные кадры не засоряли кэш и не вытесняли чужие nonce.
        {
            let mut seen = node.challenge_nonces.lock().await;
            if !crate::proto::claim_nonce(&mut seen, &ch_nonce, now_ms()) {
                bail!("challenge replay");
            }
        }
        // forward secrecy: вычисляем сессионный ключ и отдаём свой эфемерный в AUTH
        let srv_eph = XSecret::random_from_rng(rand::rngs::OsRng);
        let srv_eph_pub = XPub::from(&srv_eph);
        let auth_at = now_ms();
        // PQ handshake offer (default-ON; explicit opt-out
        // `STELL_INF_PQ_HANDSHAKE=0` honored pre-H only): absent PQ fields =>
        // classical path (window tolerance, plan §5), LOUD + counted while
        // pre-H (see `proto::pq_warn_classical_fallback` below). Present =>
        // encapsulate now and answer below with a hybrid session key.
        // Malformed/mis-versioned offers are refused with a clear error and
        // the connection is dropped fail-closed (no identity debit pre-auth,
        // same as every other failure on this path).
        let mut pq_state: Option<(Vec<u8>, PqAgreed)> = None;
        if proto::pq_handshake_active() {
            match pq_responder_accept(
                &ch_eph,
                &ch,
                &f.sign_data(),
                srv_eph_pub.as_bytes(),
                auth_at,
                &node.id,
            ) {
                Ok(s) => pq_state = s,
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if proto::pq_handshake_active() && pq_state.is_none() {
            // PQ active (default-ON) but the initiator offered no PQ fields:
            // pre-H window fallback — loud, counted, explicit.
            proto::pq_warn_classical_fallback("accept");
        }
        let classical = match derive_session_key_server(&node.keys, &peer.cfg, &srv_eph, &f.payload) {
            Ok(k) => k,
            Err(e) => {
                return Err(e);
            }
        };
        let key = match &pq_state {
            Some((_, a)) => proto::pq_hybrid_session_key(&classical, &a.shared, &a.digest),
            None => classical,
        };
        // Backpressure bound on the session table (fail-closed: when full the
        // session is NOT stored, so this conn can serve no requests; the auth
        // decision above is untouched). No fitting metrics counter (follow-up).
        let _ = node.session_insert(conn.stable_id(), key).await;
        // KEX wiring: PQ-negotiated sessions carry their transcript digest so
        // frame seal/open binds the AAD; classical sessions store nothing and
        // stay on the legacy path (same best-effort discipline as above).
        if let Some((_, a)) = &pq_state {
            let _ = node.pq_digest_insert(conn.stable_id(), a.digest).await;
        }
        // Per-connection window: nothing to reset. See connect_with_auth.
        node.add_conn(claimed, conn.clone()).await;
        node.routing_insert(
            claimed,
            &peer.cfg.endpoints,
            &peer.cfg.ed_pub,
            &peer.cfg.x_pub,
        )
        .await;
        *peer.conn.write().await = Some(conn.clone());
        node.remember_peer_addr(&peer, conn.remote_address()).await;
        node.add_route(claimed, conn.remote_address().to_string(), &peer.cfg.ed_pub)
            .await;
        let payload = if let Some((ct, agreed)) = &pq_state {
            json!({
                "node": node.id_hex,
                "name": node.cfg.name,
                "at": auth_at,
                "eph": hex::encode(srv_eph_pub.as_bytes()),
                "pq_ver": proto::PQ_TRANSCRIPT_VERSION,
                "pq_suite": proto::PQ_SUITE_MLKEM768_HYBRID,
                "pq_ct": hex::encode(ct),
                "pq_tag": hex::encode(agreed.tag),
            })
            .to_string()
            .into_bytes()
        } else {
            json!({
                "node": node.id_hex,
                "name": node.cfg.name,
                "at": now_ms(),
                "eph": hex::encode(srv_eph_pub.as_bytes()),
            })
            .to_string()
            .into_bytes()
        };
        let mut a = Frame {
            kind: proto::kind::AUTH,
            seq: node.next_seq(),
            ts: now_ms(),
            src: node.id,
            dst: claimed,
            svc: 0,
            payload,
            nonce: vec![],
            sig: [0; 64],
        };
        node.sign_frame(&mut a);
        send.write_all(&a.encode()).await?;
        let _ = send.finish();
        report_stages(&f, t_proc.elapsed());
        return Ok(Some(claimed));
    }

    let pid = match authed {
        Some(p) => p,
        None => {
            // F8-rep: pre-auth source is unproven — drop the connection
            // with NO identity debit (unframeable by construction).
            bail!("unauthenticated frame");
        }
    };
    if f.src != pid {
        // F8-rep: proven identity speaking under another id.
        node.rep_record_protocol_violation(&pid).await;
        bail!("src mismatch");
    }
    let peer = node
        .peers
        .read()
        .await
        .get(&pid)
        .cloned()
        .ok_or_else(|| anyhow!("unknown peer"))?;
    let vk = VerifyingKey::from_bytes(&peer.cfg.ed_bytes()?)?;
    if !f.verify(&vk) {
        // F8-rep: forged frame from the proven identity.
        node.rep_record_protocol_violation(&pid).await;
        bail!("bad signature");
    }
    if !ts_ok(f.ts) {
        // F8-rep: stale frame from the proven identity.
        node.rep_record_protocol_violation(&pid).await;
        bail!("stale frame");
    }
    {
        // Anti-replay is scoped to THIS connection. The sender's `seq` is a single
        // node-wide counter shared by all of its connections, so a per-peer window
        // rejects legitimate traffic from a second connection or after a reconnect --
        // which tore down frame_loop and stopped the node before consensus.
        //
        // A replayed (or QUIC-reordered) frame is DROPPED, never fatal: tearing
        // down the whole connection on one out-of-order frame turned transient
        // stream races into one-directional blackouts (sender keeps using the
        // dead cached conn, every request times out until a process restart).
        // The application layer is best-effort and re-sends; losing one frame
        // is noise, losing the connection is an outage.
        // ACCEPT duplicates and out-of-order frames -- the gate is diagnostic
        // only. Two things made rejecting them an outage rather than a
        // safety net:
        //
        //  1. With the CONCURRENT frame_loop the sender's node-wide monotonic
        //     `seq` legitimately arrives out of order: this window is a
        //     max-gate, not a set, so any reordering looks like a replay.
        //  2. Rejecting returned `Ok(None)` WITHOUT a response, so the sender
        //     waited its full 2s timeout, evicted the connection and redialled
        //     -- measured live: 5002 drops and ~1800 connection closes in 10
        //     minutes, with consensus starved the whole time.
        //
        // Nothing depends on frame-level replay protection: the frame is
        // authenticated (peer signature over the payload, a ±10min timestamp
        // window, and per-connection e2e encryption with an ephemeral
        // session key an attacker cannot derive), and every service is
        // idempotent at the app layer (VoteSet keeps the first vote per
        // voter/round, KV is an upsert, pubsub marks messages seen). A
        // duplicate therefore costs one cheap execution instead of an
        // outage; a forged frame still dies at `f.verify` above.
        let window = Node::replay_window(&peer, conn.stable_id()).await;
        let mut w = window.lock().await;
        let seen_recently = (now_ms() - w.last_ts) < proto::TS_WINDOW_MS;
        if f.seq <= w.last_seq && seen_recently {
            let n = node
                .metrics
                .out_of_order_frames
                .fetch_add(1, Ordering::Relaxed);
            if n.is_multiple_of(500) {
                eprintln!(
                    "[{}] out-of-order frame accepted (seq {} <= {}, sample {})",
                    node.cfg.name, f.seq, w.last_seq, n
                );
            }
        }
        if f.seq > w.last_seq || !seen_recently {
            w.last_seq = f.seq;
            w.last_ts = f.ts;
        }
    }
    // Never overwrite a dialable address with this connection's source port
    // (see `remember_peer_addr`): on an inbound conn that is an ephemeral
    // client port, and dialing it later wasted the whole request budget.
    node.remember_peer_addr(&peer, conn.remote_address()).await;

    match f.kind {
        proto::kind::PING => {
            // F8-rep: valid, authentic message from the proven identity.
            node.rep_record_valid(&pid).await;
            let mut r = Frame {
                kind: proto::kind::PONG,
                seq: f.seq,
                ts: now_ms(),
                src: node.id,
                dst: f.src,
                svc: 0,
                payload: vec![],
                nonce: vec![],
                sig: [0; 64],
            };
            node.sign_frame(&mut r);
            send.write_all(&r.encode()).await?;
            let _ = send.finish();
            report_stages(&f, t_proc.elapsed());
            Ok(None)
        }
        proto::kind::REQ => {
            if f.dst != node.id {
                bail!("not addressed to me");
            }
            let key = node
                .sessions
                .read()
                .await
                .get(&conn.stable_id())
                .copied()
                .ok_or_else(|| anyhow!("no session key"))?;
            // rate limiting (защита от флуда)
            let rate = peer.cfg.rate_limit_per_sec;
            if !peer.rate.lock().await.allow(rate) {
                // F8-rep: per-peer rate-limit violation by the proven identity.
                node.rep_record_rate_violation(&pid).await;
                let resp = json!({ "ok": false, "err": "rate limit exceeded" })
                    .to_string()
                    .into_bytes();
                // KEX seal site: PQ sessions bind header+digest AAD, classical None.
                let r_ts = now_ms();
                let pq_digest = node.pq_digests.read().await.get(&conn.stable_id()).copied();
                let (ct, nonce) = frame_seal_body(
                    &key,
                    pq_digest,
                    proto::kind::RESP,
                    f.seq,
                    r_ts,
                    &node.id,
                    &f.src,
                    f.svc,
                    &resp,
                );
                let mut r = Frame {
                    kind: proto::kind::RESP,
                    seq: f.seq,
                    ts: r_ts,
                    src: node.id,
                    dst: f.src,
                    svc: f.svc,
                    payload: ct,
                    nonce,
                    sig: [0; 64],
                };
                node.sign_frame(&mut r);
                send.write_all(&r.encode()).await?;
                let _ = send.finish();
                report_stages(&f, t_proc.elapsed());
                return Ok(None);
            }
            // KEX open site: PQ sessions verify the AAD-bound tag and drop the
            // frame fail-closed on failure; classical sessions use legacy open.
            let pq_digest = node.pq_digests.read().await.get(&conn.stable_id()).copied();
            let plain = match frame_open_body(&key, pq_digest, &f) {
                Ok(p) => p,
                Err(e) => {
                    // KEX: PQ open failure is fail-closed + counted (existing
                    // `reqs_errors`); the classical arm is untouched.
                    if pq_digest.is_some() {
                        node.metrics.reqs_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    // F8-rep: undecryptable frame from the proven identity.
                    node.rep_record_protocol_violation(&pid).await;
                    return Err(e);
                }
            };
            // F8-rep: valid, authentic message from the proven identity.
            node.rep_record_valid(&pid).await;
            // ACL применяется КО ВСЕМУ (включая pubsub/dht), иначе TOFU-нода
            // могла бы публиковать/подписываться в обход ограничений.
            let svc_name = proto::svc_name(f.svc).unwrap_or("?").to_string();
            node.metrics.reqs_total.fetch_add(1, Ordering::Relaxed);
            {
                let mut m = node.svc_counters.lock().unwrap();
                *m.entry(svc_name.clone()).or_insert(0) += 1;
            }
            // heartbeat: любой успешный запрос от пира обновляет last_seen —
            // rewards использует его как признак живости (важно для NAT-пиров,
            // которые сами инициируют соединение и шлют dht.update/core.ping).
            {
                *peer.last_seen.lock().await = now_ms();
                // R12: раньше КАЖДЫЙ запрос брал write-lock на всю карту и при
                // размере >2000 делал тут же O(2000) retain — чистая работа на
                // каждом входящем REQ. Теперь read-first: если отметка пира
                // свежее 1с, write-lock не берётся вовсе; вытеснение тоже
                // происходит только на записи (retention 24ч, а единственный
                // потребитель — rewards — читает с трёхминутным окном).
                let now = now_ms();
                let fresh = {
                    let m = node.last_req_from_peer.read().await;
                    m.get(&pid).map(|ts| now - *ts < 1_000).unwrap_or(false)
                };
                if !fresh {
                    let mut m = node.last_req_from_peer.write().await;
                    if m.get(&pid).map(|ts| now - *ts < 1_000).unwrap_or(false) {
                        // свежая запись появилась, пока мы ждали write-lock
                    } else {
                        if m.len() > 2000 {
                            let cutoff = now - 24 * 3600 * 1000;
                            m.retain(|_, ts| *ts > cutoff);
                        }
                        m.insert(pid, now);
                    }
                }
            }
            let resp: Vec<u8> = if !crate::services::is_allowed(&peer.cfg.allow, &svc_name) {
                node.metrics.reqs_denied.fetch_add(1, Ordering::Relaxed);
                tlog(
                    "req_denied",
                    json!({ "svc": svc_name, "from": hex::encode(pid) }),
                );
                json!({"ok": false, "err": "denied by ACL"})
                    .to_string()
                    .into_bytes()
            } else if let Some(resp) = node.handle_node_svc(f.svc, &conn, pid, &plain).await {
                resp
            } else if let Some(h) = crate::services::handler_for(f.svc) {
                let ctx = crate::services::Ctx {
                    node_id_hex: &node.id_hex,
                    node_name: &node.cfg.name,
                    peer_name: &peer.cfg.name,
                    mail_dir: &node.mail_dir,
                    data_dir: &node.data_dir,
                    mail_key: node.mail_key,
                    peer_addr: conn.remote_address(),
                };
                match crate::services::invoke(h, ctx, plain).await {
                    Ok(v) => v,
                    Err(e) => {
                        node.metrics.reqs_errors.fetch_add(1, Ordering::Relaxed);
                        terr(
                            "req_error",
                            json!({ "svc": svc_name, "err": format!("{e}") }),
                        );
                        json!({"ok": false, "err": format!("{e}")})
                            .to_string()
                            .into_bytes()
                    }
                }
            } else {
                node.metrics.reqs_errors.fetch_add(1, Ordering::Relaxed);
                json!({"ok": false, "err": "unknown service"})
                    .to_string()
                    .into_bytes()
            };
            tlog(
                "req",
                json!({ "svc": svc_name, "from": hex::encode(pid), "ok": !resp.starts_with(b"{\"ok\":false") }),
            );
            // KEX seal site: PQ sessions bind header+digest AAD, classical None.
            let r_ts = now_ms();
            let pq_digest = node.pq_digests.read().await.get(&conn.stable_id()).copied();
            let (ct, nonce) = frame_seal_body(
                &key,
                pq_digest,
                proto::kind::RESP,
                f.seq,
                r_ts,
                &node.id,
                &f.src,
                f.svc,
                &resp,
            );
            let mut r = Frame {
                kind: proto::kind::RESP,
                seq: f.seq,
                ts: r_ts,
                src: node.id,
                dst: f.src,
                svc: f.svc,
                payload: ct,
                nonce,
                sig: [0; 64],
            };
            node.sign_frame(&mut r);
            send.write_all(&r.encode()).await?;
            let _ = send.finish();
            report_stages(&f, t_proc.elapsed());
            Ok(None)
        }
        _ => {
            report_stages(&f, t_proc.elapsed());
            Ok(None)
        }
    }
}

pub fn e2e_encrypt(key: &[u8; 32], plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = e2e_encrypt_det(key, &nonce, plain);
    (ct, nonce.to_vec())
}

/// XChaCha20-Poly1305 с ЗАДАННЫМИ key/nonce — детерминированная версия e2e_encrypt.
/// Блоб-хранилище шифрует так, чтобы повторный publish того же содержимого дал
/// байт-в-байт тот же ct (см. blob_key_nonce).
pub fn e2e_encrypt_det(key: &[u8; 32], nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), plain)
        .expect("e2e encrypt")
}

pub fn e2e_decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        bail!("invalid nonce length");
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("e2e decrypt failed (tamper?)"))
}

/// KEX frame seal site (ONE swap): PQ-negotiated sessions seal bodies with
/// `kex_frame_seal_rand` under a canonical AAD (header + session digest);
/// classical sessions (`None`) call legacy `e2e_encrypt` byte-identical.
#[allow(clippy::too_many_arguments)] // GATE: header fields mirror Frame 1:1 for byte-identical AAD rebuild
fn frame_seal_body(
    key: &[u8; 32],
    pq_digest: Option<[u8; 32]>,
    kind: u8,
    seq: u32,
    ts: i64,
    src: &[u8; NODEID_LEN],
    dst: &[u8; NODEID_LEN],
    svc: u64,
    plain: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    match pq_digest {
        Some(d) => {
            let aad = proto::kex_frame_aad(kind, seq, ts, src, dst, svc, &d);
            proto::kex_frame_seal_rand(key, &aad, plain)
        }
        None => e2e_encrypt(key, plain),
    }
}

/// KEX frame open site (ONE swap): PQ-negotiated sessions rebuild the same
/// canonical AAD from the received header and open with `kex_frame_open`
/// (fail-closed: any error drops the frame, never a plaintext fallback);
/// classical sessions (`None`) call legacy `e2e_decrypt` byte-identical.
fn frame_open_body(
    key: &[u8; 32],
    pq_digest: Option<[u8; 32]>,
    f: &Frame,
) -> Result<Vec<u8>> {
    match pq_digest {
        Some(d) => {
            let aad = proto::kex_frame_aad(f.kind, f.seq, f.ts, &f.src, &f.dst, f.svc, &d);
            proto::kex_frame_open(key, &f.nonce, &aad, &f.payload)
        }
        None => e2e_decrypt(key, &f.nonce, &f.payload),
    }
}

/// Content id блоба: blake3(плейнтекст целиком). Из него выводятся и chunk_id
/// (chunk_id_for), и крипто-материалы (blob_key_nonce) — единый источник
/// «содержимого» для идентификации и шифрования.
pub fn blob_content_hash(blob: &[u8]) -> [u8; 32] {
    *blake3::hash(blob).as_bytes()
}

/// Детерминированные крипто-материалы блоба: (key, nonce) = f(bucket, name, H(plaintext)).
///
/// КОРНЕВАЯ ПРИЧИНА РОСТА ДИСКА: раньше key был rand::random() на КАЖДЫЙ publish,
/// поэтому ct — а вместе с ним chunk_id, считавшийся от ct-байтов — менялся каждый
/// раз, и репаблиш того же имени добавлял новый набор файлов вместо перезаписи
/// старых (752 МБ / 187k файлов, 76% — вытесненные дубликаты).
///
/// Теперь одинаковые (bucket, name, содержимое) дают одинаковый key/nonce/ct на
/// любой ноде: повторный publish пишет в ТЕ ЖЕ пути (write_chunk_atomic поверх),
/// а смена содержимого даёт новые key/ct/ids — старые файлы остаются сиротами,
/// их подметает prune-chunk-orphans по текущим манифестам.
///
/// Замечание по модели угроз: ключ воспроизводим из имени+контента, т.е. у
/// держателя data_dir появляется offline-проверка догадки о содержимом. Слой
/// key_box (owner_pub) рассчитан на то, что контент и так зашифрован на уровне
/// приложения (storage_seal/proton_box — так делает web-слой); случайный ключ
/// в манифесте (модель без key_box) и так открыт, здесь ничего не меняется.
pub fn blob_key_nonce(bucket: &str, name: &str, blob_hash: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let h = hex::encode(blob_hash);
    let key_h = blake3::hash(format!("infnode:blob-key:v1:{bucket}:{name}:{h}").as_bytes());
    let nonce_h = blake3::hash(format!("infnode:blob-nonce:v1:{bucket}:{name}:{h}").as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(key_h.as_bytes());
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_h.as_bytes()[..24]);
    (key, nonce)
}

/// Централизованный конструктор chunk_id: blake3("{bucket}:{name}:{offset}:{content_hash}").
///
/// `content_hash` — content id ПЛАЙНТЕКСТА блоба (blob_content_hash), а не хэш
/// ct-среза, как было раньше: ct менялся при каждом publish (случайный ключ) =>
/// менялся и id => репаблиш того же имени создавал новые файлы. Содержимо-
/// адресный id (bucket, name, offset, H(plaintext)) вообще не зависит от
/// ключа/nonce/ct: тот же контент — те же id — те же пути файлов (перезапись,
/// а не дубликат); другой контент — другие id, а старые файлы остаются сиротами
/// (их подметает prune-chunk-orphans).
///
/// Защита от подмены НЕ ослаблена: манифест несёт хэш КАЖДОГО хранимого чанка
/// (hash = blake3(ct-срез)), он сверяется при чтении (fetch_mail/fetch_blob) и
/// при приёме чанка с сети (handle_storage_store) — идентичность ct-байтов
/// дополнительно гарантирует blob_key_nonce (детерминированное шифрование).
///
/// Единая точка: ВСЕ продьюсеры (store_mail, store_mail_ec, store_blob, их
/// replicate_*, CLI storage-put) обязаны вызывать именно её (для EC-шардов —
/// ec_chunk_id_for), передавая content id того же блоба.
pub fn chunk_id_for(bucket: &str, name: &str, offset: usize, content_hash: &[u8; 32]) -> String {
    hex::encode(
        blake3::hash(format!("{bucket}:{name}:{offset}:{}", hex::encode(content_hash)).as_bytes())
            .as_bytes(),
    )
}

/// Конструктор id для EC-шардов: blake3("{bucket}:{name}:ec:{index}:{content_hash}").
/// `content_hash` — тот же content id плейнтекста блоба, что и в chunk_id_for
/// (шарды считаются от детерминированного ct — см. blob_key_nonce).
pub fn ec_chunk_id_for(bucket: &str, name: &str, index: usize, content_hash: &[u8; 32]) -> String {
    hex::encode(
        blake3::hash(
            format!("{bucket}:{name}:ec:{index}:{}", hex::encode(content_hash)).as_bytes(),
        )
        .as_bytes(),
    )
}

/// Атомарная запись чанка: tmp-файл в том же каталоге + rename.
/// Раньше был truncate-in-place `fs::write(dir.join(id), data)`: конкурентный
/// fetch читал частично записанный файл → байты с несовпадающим хэшем
/// ("chunk tamper", torn read). Rename в пределах одной fs — атомарен,
/// читатели видят либо старый файл целиком, либо новый целиком.
fn write_chunk_atomic(dir: &std::path::Path, chunk_id: &str, data: &[u8]) -> std::io::Result<()> {
    // chunk_id уже проверен как hex (valid_chunk_id), но на всякий случай
    // отбрасываем разделители путей.
    let safe_id: String = chunk_id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let tmp_name = format!(
        ".{safe_id}.tmp.{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let tmp = dir.join(tmp_name);
    // Убираем мусор от упавших записей (best-effort).
    let res = (|| {
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, dir.join(&safe_id))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}

/// XSalsa20-Poly1305 (NaCl secretbox) — совместим с tweetnacl на фронте.
/// ВНИМАНИЕ: e2e_encrypt — это XChaCha20 (бэкенд-внутренности, фронт его НЕ открывает).
/// Всё, что должен читать браузер (конверты s1, proton-box), — только через эту функцию.
pub fn xsalsa_encrypt(key: &[u8; 32], plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    salsa_encrypt(key, plain)
}
fn salsa_encrypt(key: &[u8; 32], plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use aead::{Aead, KeyInit};
    use xsalsa20poly1305::XSalsa20Poly1305;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("xsalsa key");
    let ct = cipher
        .encrypt(xsalsa20poly1305::Nonce::from_slice(&nonce), plain)
        .expect("salsa encrypt");
    (ct, nonce.to_vec())
}

fn salsa_decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        bail!("invalid nonce length");
    }
    use aead::{Aead, KeyInit};
    use xsalsa20poly1305::XSalsa20Poly1305;
    let cipher = XSalsa20Poly1305::new_from_slice(key).map_err(|_| anyhow!("xsalsa key"))?;
    cipher
        .decrypt(xsalsa20poly1305::Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("salsa decrypt failed"))
}

/// Proton-инкапсуляция произвольных бинарных данных (вложения): XSalsa20 + box на x_pub.
pub fn proton_box_data(owner_pub_hex: &str, data: &[u8]) -> Option<String> {
    let data_key = rand::random::<[u8; 32]>();
    let (ct, nonce) = salsa_encrypt(&data_key, data);
    let key_box = box_wrap_key(owner_pub_hex, &data_key)?;
    Some(
        json!({
            "proto": "infmail-box-v1",
            "key_box": key_box,
            "nonce": hex::encode(&nonce),
            "ct": hex::encode(&ct),
        })
        .to_string(),
    )
}

/// Proton-инкапсуляция текста: случайный ключ шифрует plain (XSalsa20-Poly1305 = NaCl secretbox,
/// совместим с tweetnacl на фронте), ключ box-заворачивается на публичный X25519 получателя.
/// Возвращает JSON-строку {"proto":"infmail-box-v1","key_box":{...},"nonce":hex,"ct":hex}.
pub fn proton_box_body(owner_pub_hex: &str, plain: &str) -> Option<String> {
    if plain.is_empty() {
        return Some(
            json!({
                "proto": "infmail-box-v1",
                "enc": json!(plain),
            })
            .to_string(),
        );
    }
    let data_key = rand::random::<[u8; 32]>();
    let (ct, nonce) = salsa_encrypt(&data_key, plain.as_bytes());
    let key_box = box_wrap_key(owner_pub_hex, &data_key)?;
    Some(
        json!({
            "proto": "infmail-box-v1",
            "key_box": key_box,
            "nonce": hex::encode(&nonce),
            "ct": hex::encode(&ct),
        })
        .to_string(),
    )
}

/// Расшифровать proton_box_body JSON-строку приватным X25519-ключом. None если формат не тот.
pub fn proton_unbox_body(payload: &str, owner_priv_hex: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    if v["proto"].as_str() != Some("infmail-box-v1") {
        return None;
    }
    if let Some(enc) = v["enc"].as_str() {
        return Some(enc.to_string());
    }
    let kb = v.get("key_box")?;
    let dk = box_unwrap_key(kb, owner_priv_hex).ok()?;
    let nonce = hex::decode(v["nonce"].as_str()?).ok()?;
    let ct = hex::decode(v["ct"].as_str()?).ok()?;
    let dec = salsa_decrypt(&dk, &nonce, &ct).ok()?;
    String::from_utf8(dec).ok()
}

/// Box-шифрование 32-байтного ключа на публичный X25519-ключ получателя (Proton-модель).
/// Использует эфемерный X25519 (ECDH) → общий секрет → XSalsa20-Poly1305. Расшифровать может
/// только владелец приватного X25519-ключа (браузер). Сервер и ноды ключ блоба не видят.
/// Возвращает json-значение { "eph": hex, "nonce": hex, "ct": hex }.
pub fn box_wrap_key(owner_pub_hex: &str, data_key: &[u8; 32]) -> Option<serde_json::Value> {
    let owner_pub_bytes = hex::decode(owner_pub_hex).ok()?;
    if owner_pub_bytes.len() != 32 {
        return None;
    }
    let owner_pub = XPub::from(<[u8; 32]>::try_from(&owner_pub_bytes[..]).ok()?);
    let eph_sec = XSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = XPub::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&owner_pub);
    let (ct, nonce) = salsa_encrypt(shared.as_bytes(), data_key);
    Some(json!({
        "eph": hex::encode(eph_pub.as_bytes()),
        "nonce": hex::encode(&nonce),
        "ct": hex::encode(&ct),
    }))
}

/// Распаковать key_box: даёт data_key (32 байта), если есть приватный X25519-ключ владельца.
pub fn box_unwrap_key(key_box: &serde_json::Value, owner_priv_hex: &str) -> Result<[u8; 32]> {
    let priv_bytes = hex::decode(owner_priv_hex)?;
    if priv_bytes.len() != 32 {
        bail!("private key: invalid length");
    }
    let priv_key =
        XSecret::from(<[u8; 32]>::try_from(&priv_bytes[..]).map_err(|_| anyhow!("priv key"))?);
    let eph_pub_bytes = hex::decode(key_box["eph"].as_str().unwrap_or(""))?;
    if eph_pub_bytes.len() != 32 {
        bail!("eph key: invalid length");
    }
    let eph_pub =
        XPub::from(<[u8; 32]>::try_from(&eph_pub_bytes[..]).map_err(|_| anyhow!("eph pub"))?);
    let shared = priv_key.diffie_hellman(&eph_pub);
    let nonce = hex::decode(key_box["nonce"].as_str().unwrap_or(""))?;
    let ct = hex::decode(key_box["ct"].as_str().unwrap_or(""))?;
    let dec = salsa_decrypt(shared.as_bytes(), &nonce, &ct)?;
    let mut key = [0u8; 32];
    if dec.len() != 32 {
        bail!("key_box: invalid length");
    }
    key.copy_from_slice(&dec);
    Ok(key)
}

fn transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.max_concurrent_bidi_streams(2048u32.into());
    tc.max_concurrent_uni_streams(2048u32.into());
    tc.stream_receive_window(quinn::VarInt::from_u64(64 * 1024 * 1024).unwrap());
    tc.receive_window(quinn::VarInt::from_u64(256 * 1024 * 1024).unwrap());
    tc.send_window(256 * 1024 * 1024);
    tc.max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));
    tc.keep_alive_interval(Some(Duration::from_secs(2)));
    tc.initial_rtt(Duration::from_millis(40));
    // BBR устойчив к потерям (наш линк теряет ~20% UDP под нагрузкой), Cubic сжимается
    tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    tc
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn rand_u64() -> u64 {
    rand::random()
}

/// Ключ шифрования почты at rest: файл mail.key (0600) в data_dir.
fn load_or_create_mail_key(data_dir: &std::path::Path) -> [u8; 32] {
    let path = data_dir.join("mail.key");
    if let Ok(raw) = std::fs::read(&path) {
        if raw.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&raw);
            return k;
        }
    }
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    let _ = std::fs::write(&path, k);
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    k
}

/// Строгий разбор CHALLENGE-payload (fail-closed, audit 2026-11-01): все поля
/// обязаны присутствовать и быть свежими. Раньше `nonce`/`at`/`eph` вообще не
/// проверялись — повторяемый в пределах ±10 мин кадр создавал новую сессию.
/// Parsed CHALLENGE payload: (nonce hex, eph pub, ed pub, x pub).
type ChallengeFields = (String, [u8; 32], [u8; 32], [u8; 32]);

fn challenge_fields(v: &serde_json::Value) -> Result<ChallengeFields> {
    let nonce = v["nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("challenge without nonce"))?;
    if nonce.len() < 8 || nonce.len() > 128 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("bad challenge nonce");
    }
    let at = v["at"]
        .as_i64()
        .ok_or_else(|| anyhow!("challenge without at"))?;
    if !ts_ok(at) {
        bail!("stale challenge");
    }
    let eph = hex_fixed_32(v["eph"].as_str(), "eph")?;
    let ed = hex_fixed_32(v["ed"].as_str(), "ed")?;
    let x = hex_fixed_32(v["x"].as_str(), "x")?;
    Ok((nonce.to_string(), eph, ed, x))
}

fn hex_fixed_32(s: Option<&str>, what: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.ok_or_else(|| anyhow!("challenge without {what}"))?)?;
    b.try_into()
        .map_err(|_| anyhow!("{what} is not 32 bytes"))
}

/// Сессионный ключ со стороны инициатора: eph_sec — наш эфемерный, peer_payload — AUTH (содержит eph пира).
fn derive_session_key(
    keys: &NodeKeys,
    peer: &PeerConfig,
    eph_sec: &XSecret,
    peer_payload: &[u8],
) -> Result<[u8; 32]> {
    let v: serde_json::Value = serde_json::from_slice(peer_payload)?;
    let peer_eph_hex = v["eph"]
        .as_str()
        .ok_or_else(|| anyhow!("AUTH without eph"))?;
    let peer_eph_bytes: [u8; 32] = hex::decode(peer_eph_hex)?
        .try_into()
        .map_err(|_| anyhow!("eph is not 32 bytes"))?;
    let peer_eph = XPub::from(peer_eph_bytes);
    let peer_static = XPub::from(peer.x_bytes()?);
    // X3DH: четыре симметричных секрета (обе стороны считают одинаковые значения)
    let shared_w = *keys.e2e_sec.diffie_hellman(&peer_static).as_bytes(); // S_A x S_B
    let shared_x = *keys.e2e_sec.diffie_hellman(&peer_eph).as_bytes(); // S_A x E_B
    let shared_y = *eph_sec.diffie_hellman(&peer_static).as_bytes(); // E_A x S_B
    let shared_z = *eph_sec.diffie_hellman(&peer_eph).as_bytes(); // E_A x E_B
    let (lo, hi) = (&keys.id(), &peer.node_id_raw()?);
    Ok(proto::session_key(
        &shared_w, &shared_x, &shared_y, &shared_z, lo, hi,
    ))
}

/// Сессионный ключ со стороны сервера (обработка CHALLENGE).
fn derive_session_key_server(
    keys: &NodeKeys,
    peer: &PeerConfig,
    srv_eph: &XSecret,
    peer_payload: &[u8],
) -> Result<[u8; 32]> {
    let v: serde_json::Value = serde_json::from_slice(peer_payload)?;
    let peer_eph_hex = v["eph"]
        .as_str()
        .ok_or_else(|| anyhow!("CHALLENGE without eph"))?;
    let peer_eph_bytes: [u8; 32] = hex::decode(peer_eph_hex)?
        .try_into()
        .map_err(|_| anyhow!("eph is not 32 bytes"))?;
    let peer_eph = XPub::from(peer_eph_bytes);
    let peer_static = XPub::from(peer.x_bytes()?);
    // X3DH с точки зрения сервера (B): те же значения, другой порядок операндов
    let shared_w = *keys.e2e_sec.diffie_hellman(&peer_static).as_bytes(); // S_B x S_A
    let shared_x = *srv_eph.diffie_hellman(&peer_static).as_bytes(); // E_B x S_A
    let shared_y = *keys.e2e_sec.diffie_hellman(&peer_eph).as_bytes(); // S_B x E_A
    let shared_z = *srv_eph.diffie_hellman(&peer_eph).as_bytes(); // E_B x E_A
    let (lo, hi) = (&keys.id(), &peer.node_id_raw()?);
    Ok(proto::session_key(
        &shared_w, &shared_x, &shared_y, &shared_z, lo, hi,
    ))
}

/// PQ HANDSHAKE helpers (default-ON since PQ 9.1 — same
/// `proto::pq_handshake_active` gate; explicit `STELL_INF_PQ_HANDSHAKE=0`
/// opts out pre-H only).
/// KEX: ephemeral ML-KEM-768 per handshake (vendored crate, no new deps).
/// Auth (INTERIM, honest): transcript MAC keyed by the ML-KEM shared secret
/// over the `proto::PqTranscript` digest — the same digest bytes a future
/// Falcon-512 backend will sign (see `proto.rs` PQ docs; Falcon is
/// lead-gated per `docs/PQ_TRANSPORT_PLAN.md` §7). Verified BEFORE any
/// session key is derived; refusals carry clear errors and never silently
/// downgrade. Mixed-mode window policy is `proto::pq_mixed_policy` (plan §5:
/// verify dual-or-classical, route by classical id), height-gated by
/// `proto::pq_mixed_policy_at` / `proto::PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`.
/// `NodeId` unchanged (see `keyring.rs`). Opted-out => none of this runs:
/// payloads and KDF stay byte-identical to classical.
pub struct PqInitOffer {
    /// Initiator ephemeral decapsulation key, kept until the AUTH answer.
    pub dk: ml_kem::DecapsulationKey768,
    /// Initiator ephemeral encapsulation key, sent in CHALLENGE (`pq_ek`).
    pub ek: Vec<u8>,
}

/// Agreed PQ material (identical on both sides after a verified handshake).
pub struct PqAgreed {
    /// ML-KEM shared secret (implicit-rejection fallback never reaches here:
    /// a tampered ct yields a wrong key that fails tag verification).
    pub shared: [u8; 32],
    /// Transcript digest both sides authenticated.
    pub digest: [u8; 32],
    /// Transcript tag sent in AUTH (`pq_tag`).
    pub tag: [u8; 32],
}

/// Fresh ephemeral ML-KEM-768 keypair from OS randomness via `from_seed`
/// (`generate_keypair` needs the crate's `getrandom` feature, which is not
/// enabled; seeding from `OsRng` bytes is equivalent — the seed is the sole
/// secret input).
pub fn pq_initiator_offer() -> Result<PqInitOffer> {
    use ml_kem::kem::{FromSeed, KeyExport};
    use rand::RngCore;
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let (dk, ek) = ml_kem::MlKem768::from_seed(&seed.into());
    Ok(PqInitOffer {
        dk,
        ek: ek.to_bytes().as_slice().to_vec(),
    })
}

/// Encapsulate to a peer's 1184-byte `ek`; returns `(ct_bytes, shared)`.
/// Fresh random `m` comes from `OsRng` (see `pq_initiator_offer` for why the
/// deterministic entry point is used: it is what `encapsulate_with_rng`
/// does internally, and that trait is unreachable with `rand 0.8`).
pub fn pq_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if ek_bytes.len() != 1184 {
        bail!("pq ek malformed");
    }
    let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey768>::try_from(ek_bytes)
        .map_err(|_| anyhow!("pq ek malformed"))?;
    let ek = ml_kem::EncapsulationKey768::new(&key).map_err(|_| anyhow!("pq ek malformed"))?;
    use rand::RngCore;
    let mut m = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut m);
    let (ct, ss) = ek.encapsulate_deterministic(&m.into());
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), shared))
}

/// Decapsulate a 1088-byte `ct`; returns the shared secret. The KEM is
/// infallible by signature: a tampered ct yields the implicit-rejection
/// fallback key (never an error) which then fails tag verification — the
/// fail-closed refuse path, never a silent accept.
pub fn pq_decapsulate(dk: &ml_kem::DecapsulationKey768, ct_bytes: &[u8]) -> Result<[u8; 32]> {
    use ml_kem::kem::Decapsulate;
    if ct_bytes.len() != 1088 {
        bail!("pq ct malformed");
    }
    let ct: ml_kem::kem::Ciphertext<ml_kem::MlKem768> =
        ct_bytes.try_into().map_err(|_| anyhow!("pq ct malformed"))?;
    let ss = dk.decapsulate(&ct);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok(shared)
}

/// Build the shared transcript from full-size KEX values + frame bindings.
pub fn pq_build_transcript(
    ek_full: &[u8],
    ct_full: &[u8],
    eph_init: &[u8; 32],
    eph_resp: &[u8; 32],
    ch_sign_data: &[u8],
    auth_bind: &[u8],
) -> proto::PqTranscript {
    proto::PqTranscript {
        pq_init: proto::pq_hash_field(ek_full),
        pq_resp: proto::pq_hash_field(ct_full),
        eph_init: *eph_init,
        eph_resp: *eph_resp,
        chan_bind: proto::PQ_CHAN_BIND_PLACEHOLDER,
        nonce_init: proto::pq_hash_field(ch_sign_data),
        nonce_resp: proto::pq_hash_field(auth_bind),
    }
}

/// Responder-side AUTH binding: `eph_resp || at_le || resp_id`. Known before
/// the AUTH frame is built (no circularity) and recomputable by the dialer
/// from the received AUTH payload.
pub fn pq_auth_bind(eph_resp: &[u8; 32], auth_at: i64, resp_id: &[u8; NODEID_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 8 + NODEID_LEN);
    v.extend_from_slice(eph_resp);
    v.extend_from_slice(&auth_at.to_le_bytes());
    v.extend_from_slice(resp_id);
    v
}

fn pq_read_u64(v: &serde_json::Value, k: &str) -> Result<u64> {
    v.get(k)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow!("pq {k} malformed"))
}

/// Accept-side PQ offer check. `Ok(None)` = no PQ fields: pure classical
/// (window tolerance, plan §5). `Ok(Some)` = verified offer material for the
/// AUTH answer + hybrid key. `Err` = explicitly offered PQ that is malformed
/// or versioned wrong: refuse with a clear error (no silent downgrade).
pub fn pq_responder_accept(
    ch_eph: &[u8; 32],
    ch: &serde_json::Value,
    ch_sign_data: &[u8],
    srv_eph: &[u8; 32],
    auth_at: i64,
    resp_id: &[u8; NODEID_LEN],
) -> Result<Option<(Vec<u8>, PqAgreed)>> {
    if ch.get("pq_ek").is_none() {
        return Ok(None);
    }
    let ver = pq_read_u64(ch, "pq_ver")?;
    let suite = pq_read_u64(ch, "pq_suite")?;
    if ver != proto::PQ_TRANSCRIPT_VERSION as u64
        || suite != proto::PQ_SUITE_MLKEM768_HYBRID as u64
    {
        bail!("unsupported pq suite/version");
    }
    let ek_hex = ch
        .get("pq_ek")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("pq ek malformed"))?;
    let ek = hex::decode(ek_hex).map_err(|_| anyhow!("pq ek malformed"))?;
    if ek.len() != 1184 {
        bail!("pq ek malformed");
    }
    let (ct, shared) = pq_encapsulate(&ek)?;
    let t = pq_build_transcript(
        &ek,
        &ct,
        ch_eph,
        srv_eph,
        ch_sign_data,
        &pq_auth_bind(srv_eph, auth_at, resp_id),
    );
    let digest = t.digest(
        proto::PQ_TRANSCRIPT_VERSION,
        proto::PQ_SUITE_MLKEM768_HYBRID,
    );
    let tag = proto::pq_auth_tag(&shared, &digest);
    Ok(Some((ct, PqAgreed { shared, digest, tag })))
}

/// Dial-side PQ answer check. `Ok(None)` = classical responder: window
/// fallback to the X3DH key (plan §5). `Ok(Some)` = verified agreement.
/// `Err` = fail-closed refusal: explicitly offered PQ that fails shape,
/// suite, or tag checks, or an answer that arrives with no offer outstanding.
pub fn pq_initiator_answer(
    offer: &Option<PqInitOffer>,
    ch_sign_data: &[u8],
    own_eph: &[u8; 32],
    auth: &proto::Frame,
) -> Result<Option<PqAgreed>> {
    let av: serde_json::Value = serde_json::from_slice(&auth.payload)?;
    if av.get("pq_ct").is_none() {
        return Ok(None);
    }
    let offer = offer
        .as_ref()
        .ok_or_else(|| anyhow!("pq answer without offer"))?;
    let ver = pq_read_u64(&av, "pq_ver").unwrap_or(u64::MAX);
    let suite = pq_read_u64(&av, "pq_suite").unwrap_or(u64::MAX);
    let suite_ok =
        ver == proto::PQ_TRANSCRIPT_VERSION as u64 && suite == proto::PQ_SUITE_MLKEM768_HYBRID as u64;
    let ct = av
        .get("pq_ct")
        .and_then(|x| x.as_str())
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();
    let tag_raw = av
        .get("pq_tag")
        .and_then(|x| x.as_str())
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();
    let auth_eph = av
        .get("eph")
        .and_then(|x| x.as_str())
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();
    let auth_at = av.get("at").and_then(|x| x.as_i64()).unwrap_or(-1);
    let wellformed = ct.len() == 1088 && tag_raw.len() == 32 && auth_eph.len() == 32 && auth_at >= 0;
    let mut tag_ok = false;
    let mut agreed = PqAgreed {
        shared: [0u8; 32],
        digest: [0u8; 32],
        tag: [0u8; 32],
    };
    if wellformed && suite_ok {
        let mut eph_resp = [0u8; 32];
        eph_resp.copy_from_slice(&auth_eph);
        let shared = pq_decapsulate(&offer.dk, &ct)?;
        let t = pq_build_transcript(
            &offer.ek,
            &ct,
            own_eph,
            &eph_resp,
            ch_sign_data,
            &pq_auth_bind(&eph_resp, auth_at, &auth.src),
        );
        let digest = t.digest(
            proto::PQ_TRANSCRIPT_VERSION,
            proto::PQ_SUITE_MLKEM768_HYBRID,
        );
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&tag_raw);
        tag_ok = proto::pq_verify_tag(&proto::pq_auth_tag(&shared, &digest), &tag);
        agreed = PqAgreed { shared, digest, tag };
    }
    match proto::pq_mixed_policy(
        true,
        Some(proto::PqOfferCheck {
            wellformed,
            suite_ok,
            tag_ok,
        }),
    ) {
        Ok(proto::PqMode::Pq) => Ok(Some(agreed)),
        Ok(proto::PqMode::Classical) => Ok(None),
        Err(e) => bail!("{e}"),
    }
}

/// PQ FALCON TAG + identity binding (default-ON since PQ 9.1 — same
/// `proto::pq_handshake_active` gate; explicit `STELL_INF_PQ_HANDSHAKE=0`
/// opts out pre-H only).
/// Pure helpers; no live handshake path calls them yet, so opted-out (or
/// absent PQ identity) leaves production behavior byte-identical. Follow-up
/// (explicit, out of this change's zone): load `pq-identity.key` at startup
/// (`main.rs` key-load sites — `PqKeys::load_or_generate` is the one-line
/// hook), hold `Option<PqKeys>` on `Node`, and emit/
/// check `pq_pub`/`pq_id`/`pq_sig` in CHALLENGE/AUTH when
/// `proto::pq_handshake_active()` — via `pq_announce_fields` +
/// `proto::pq_falcon_policy` below (fail-closed, same refuse arms as the
/// KEM path, mixed-mode window per plan §5).
///
/// Outcome of announcing a PQ long-term key for a classical id.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PqBindOutcome {
    /// First valid claim: bound sticky (first-PQ-wins, plan §3.4).
    NewBound,
    /// Same key re-announced with a valid tag: steady state.
    AlreadyBound,
    /// Different key (or malformed claim) without rollback ceremony:
    /// quarantined, fail closed — mirrors the classical MITM rule.
    Quarantined,
}

/// Sticky first-PQ-wins registry: classical id -> bound Falcon-512 pub.
/// Pure binding rule (executable form of `pq_transport.rs::pqplan_resolve`);
/// the live session-table hookup is a follow-up (see module note).
#[derive(Default)]
pub struct PqIdentityRegistry {
    bound: HashMap<[u8; NODEID_LEN], Vec<u8>>,
}

impl PqIdentityRegistry {
    pub fn new() -> Self {
        Self {
            bound: HashMap::new(),
        }
    }

    /// Announce `pq_pub` (raw 897-byte Falcon-512 key) for `classical`,
    /// with `tag_ok` = result of `proto::pq_falcon_verify` over the
    /// finalized transcript digest. Malformed keys and bad tags never bind.
    pub fn announce(
        &mut self,
        classical: &[u8; NODEID_LEN],
        pq_pub: &[u8],
        tag_ok: bool,
    ) -> PqBindOutcome {
        if pq_pub.len() != proto::PQ_FALCON_PK_LEN || !tag_ok {
            // Bad tag on a KNOWN peer is a key-change attack pattern;
            // on an unknown peer it is garbage either way: quarantine.
            return PqBindOutcome::Quarantined;
        }
        match self.bound.get(classical) {
            None => {
                self.bound.insert(*classical, pq_pub.to_vec());
                PqBindOutcome::NewBound
            }
            Some(bound) if bound.as_slice() == pq_pub => PqBindOutcome::AlreadyBound,
            Some(_) => PqBindOutcome::Quarantined,
        }
    }

    /// Bound PQ key for a classical id, if any (sticky until ceremony).
    pub fn bound_pq(&self, classical: &[u8; NODEID_LEN]) -> Option<&[u8]> {
        self.bound.get(classical).map(|v| v.as_slice())
    }
}

/// Additive announce fields for CHALLENGE/AUTH JSON: `(pq_pub_hex,
/// pq_id_hex, pq_sig_hex)` where `pq_sig` is the Falcon-512 tag over the
/// finalized transcript digest by the long-term PQ key. The caller merges
/// these into the existing payload ONLY when the PQ handshake is enabled
/// AND local PQ identity is present; absent identity emits nothing
/// (classical-explicit, plan §5).
pub fn pq_announce_fields(pq: &PqKeys, digest: &[u8; 32]) -> (String, String, String) {
    let sig = pq.sign_digest(digest);
    (pq.pq_pub_hex(), pq.pq_id_hex(), hex::encode(sig))
}

/// Canonical re-ceremony call site: PQ-primary `NodeId` derivation
/// (`keyring::resolve_node_id` — same construction, no duplicate logic).
/// This is the one function new code calls to derive a local id; the
/// pre-ceremony `keys.id()` call sites below stay byte-identical legacy
/// until startup PQ enrolment lands (follow-up, out of this change's zone).
pub fn ceremony_local_id(keys: &NodeKeys, pq: Option<&PqKeys>) -> [u8; NODEID_LEN] {
    crate::keyring::resolve_node_id(keys, pq).id
}

/// Finalized transcript digest bytes the Falcon tag covers (same canonical
/// encoding as the KEM path, Falcon suite id — see `proto::pq_falcon_digest`).
pub fn pq_falcon_transcript_digest(t: &proto::PqTranscript) -> [u8; 32] {
    proto::pq_falcon_digest(t)
}

fn parse_dht_node(v: &serde_json::Value) -> Option<crate::dht::NodeInfo> {
    let id_hex = v["node_id"].as_str()?;
    let b = hex::decode(id_hex.strip_prefix("inf1:").unwrap_or(id_hex)).ok()?;
    if b.len() != NODEID_LEN {
        return None;
    }
    let mut id = [0u8; NODEID_LEN];
    id.copy_from_slice(&b);
    // Fail-closed: ответы find_node/find_value из сети проверяются тем же
    // гейтом, что ensure_dht_peer/dht.update (иначе отравленный ответ
    // привязывал честный node_id к ключу атакующего).
    let ed_hex = v["ed_pub"].as_str().unwrap_or("").to_string();
    let x_hex = v["x_pub"].as_str().unwrap_or("").to_string();
    let endpoints: Vec<String> = v["endpoints"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str())
                .filter(|e| crate::dht::endpoint_ok(e))
                .take(crate::proto::MAX_ENDPOINTS_PER_NODE)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if !crate::dht::node_info_valid(&id, &ed_hex, &x_hex, &endpoints) {
        return None;
    }
    Some(crate::dht::NodeInfo {
        id,
        endpoints,
        ed_hex,
        x_hex,
        last_seen: crate::dht::now_ms(),
    })
}

/// Текущий сессионный ключ соединения (stable_id).
async fn session_key_of(node: &Node, conn: &Connection) -> Option<[u8; 32]> {
    node.sessions.read().await.get(&conn.stable_id()).copied()
}

/// Ожидание появления сессионного ключа с микроопросом (до max_wait_ms).
async fn wait_session_key(node: &Node, conn: &Connection, max_wait_ms: u64) -> Option<[u8; 32]> {
    if let Some(key) = session_key_of(node, conn).await {
        return Some(key);
    }
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(10);
    while start.elapsed() < Duration::from_millis(max_wait_ms) {
        tokio::time::sleep(poll_interval).await;
        if let Some(key) = session_key_of(node, conn).await {
            return Some(key);
        }
    }
    None
}

fn build_tls(keys: &NodeKeys) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use pkcs8::EncodePrivateKey;
    let der = keys
        .signing
        .to_pkcs8_der()
        .map_err(|e| anyhow!("pkcs8: {e}"))?;
    let der_bytes = der.as_bytes().to_vec();
    let pkcs8 = PrivatePkcs8KeyDer::from(der_bytes.clone());
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
        .map_err(|e| anyhow!("rcgen keypair: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![])?;
    // CN содержит hex публичного ключа ноды — используется для pinning в verifier.
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("infnode-{}", hex::encode(keys.verifying.as_bytes())),
    );
    params.is_ca = rcgen::IsCa::NoCa;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let cert = params
        .self_signed(&kp)
        .map_err(|e| anyhow!("self_signed: {e}"))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_bytes));
    Ok((vec![cert_der], key_der))
}

#[derive(Debug)]
struct PinnedVerifier {
    pinned: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let expected = format!("infnode-{}", hex::encode(self.pinned));
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("bad cert".to_string()))?;
        // Срок действия: раньше `_now` игнорировался — просроченный/ещё не
        // действующий сертификат принимался.
        let now_asn1 = x509_parser::time::ASN1Time::from_timestamp(
            i64::try_from(now.as_secs()).unwrap_or(0),
        )
        .map_err(|_| rustls::Error::General("bad now".to_string()))?;
        if !cert.validity().is_valid_at(now_asn1) {
            return Err(rustls::Error::General("cert not valid at now".to_string()));
        }
        // SPKI-pinning: сравниваем СЫРОЙ ключ сертификата с пином. Раньше
        // проверялся только CN (произвольная строка) — любой мог выпустить
        // самоподписанный серт с чужим CN и пройти TLS-гейт.
        let spki = cert.public_key().subject_public_key.data.as_ref();
        if spki != self.pinned.as_slice() {
            return Err(rustls::Error::General(
                "pinned pubkey mismatch (MITM?)".to_string(),
            ));
        }
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|v| v.as_str().ok())
            .ok_or_else(|| rustls::Error::General("no cn".to_string()))?;
        if cn != expected {
            return Err(rustls::Error::General(
                "pinned pubkey mismatch (MITM?)".to_string(),
            ));
        }
        cert.verify_signature(None)
            .map_err(|_| rustls::Error::General("self-signature invalid".to_string()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls12 disabled".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod proton_tests {
    use super::*;

    #[test]
    fn proton_box_body_roundtrip() {
        // владелец: X25519 ключ пара
        let owner_sec = XSecret::random_from_rng(rand::rngs::OsRng);
        let owner_pub = XPub::from(&owner_sec);
        let plain = "Hello, Steam code: 123456";
        let payload = proton_box_body(&hex::encode(owner_pub.as_bytes()), plain).expect("box body");
        assert!(payload.contains("infmail-box-v1"));
        // сервер НЕ может расшифровать без приватного ключа: формат не plaintext
        assert!(!payload.contains(plain));
        // браузер (владелец) расшифровывает
        let dec = proton_unbox_body(&payload, &hex::encode(owner_sec.to_bytes())).expect("unbox");
        assert_eq!(dec, plain);
    }

    #[test]
    fn proton_box_body_empty() {
        let owner_sec = XSecret::random_from_rng(rand::rngs::OsRng);
        let owner_pub = XPub::from(&owner_sec);
        let payload = proton_box_body(&hex::encode(owner_pub.as_bytes()), "").unwrap();
        // пустой текст инкапсулируется без шифрования (enc=)
        let dec = proton_unbox_body(&payload, &hex::encode(owner_sec.to_bytes())).unwrap();
        assert_eq!(dec, "");
    }

    #[test]
    fn proton_unbox_wrong_format_returns_none() {
        assert!(proton_unbox_body("plain text", "00".repeat(32).as_str()).is_none());
        assert!(proton_unbox_body("{\"proto\":\"other\"}", "00".repeat(32).as_str()).is_none());
    }
}

#[cfg(test)]
mod chunk_hash_tests {

    #[test]
    fn chunk_hash_matches_content() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let hash = blake3::hash(&data);
        // проверяем сам факт: blake3 детерминирован
        assert_eq!(blake3::hash(&data), blake3::hash(&data));
        assert_ne!(blake3::hash(&data), blake3::hash(b"other"));
        let _ = hash;
    }
}

#[cfg(test)]
mod ec_tests {
    use super::Node;

    #[test]
    fn ec_roundtrip_no_loss() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for (k, n) in [(3usize, 5usize), (2, 3), (4, 6)] {
            let shards = Node::ec_encode(&data, k, n);
            assert_eq!(shards.len(), n);
            let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            let back = Node::ec_decode(&mut slots, k, n, data.len()).expect("decode");
            assert_eq!(back, data, "k={k} n={n}");
        }
    }

    #[test]
    fn ec_survives_n_minus_k_losses() {
        let data: Vec<u8> = (0..4096u32).map(|i| ((i * 7) % 253) as u8).collect();
        let (k, n) = (3usize, 5usize);
        let shards = Node::ec_encode(&data, k, n);
        // теряем ровно n-k шардов (любые)
        let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        slots[0] = None;
        slots[3] = None;
        let back = Node::ec_decode(&mut slots, k, n, data.len()).expect("decode with 2 losses");
        assert_eq!(back, data);
    }

    #[test]
    fn ec_rejects_too_few_shards() {
        let data: Vec<u8> = vec![9u8; 300];
        let (k, n) = (3usize, 5usize);
        let shards = Node::ec_encode(&data, k, n);
        let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        slots[0] = None;
        slots[1] = None;
        slots[2] = None; // осталось 2 < k
        assert!(Node::ec_decode(&mut slots, k, n, data.len()).is_none());
    }

    #[test]
    fn ec_handles_non_multiple_lengths() {
        for len in [1usize, 7, 1000, 1234, 65537] {
            let data: Vec<u8> = (0..len).map(|i| (i % 199) as u8).collect();
            let shards = Node::ec_encode(&data, 3, 5);
            let mut slots: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            slots[1] = None;
            slots[4] = None;
            let back = Node::ec_decode(&mut slots, 3, 5, len).expect("decode");
            assert_eq!(back.len(), len);
            assert_eq!(back, data, "len={len}");
        }
    }
}

#[cfg(test)]
mod disk_growth_tests {
    //! Регресс-тесты на две причины роста диска:
    //! 1) репаблиш того же имени добавлял новые файлы чанков (свежий rand-ключ
    //!    при каждом publish => новый chunk_id) — теперь id/ct детерминированы;
    //! 2) kv.json копил просроченные и dedup:* записи — теперь sweep на сохранении.
    use super::*;

    fn test_cfg(name: &str) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            listen: "127.0.0.1:0".to_string(),
            client_listen: None,
            advertise: None,
            peers: vec![],
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: Some(0),
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators: vec![],
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        }
    }

    async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
        let tmp =
            std::env::temp_dir().join(format!("infnode-growth-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("tmpdir");
        let node = Node::new(
            test_cfg("T"),
            NodeKeys::generate(),
            tmp.clone(),
            PathBuf::new(),
        )
        .await
        .expect("node");
        (node, tmp)
    }

    /// Отсортированные имена файлов чанков бакета (включая мусорные .tmp — их быть не должно).
    fn chunk_files(node: &Node, bucket: &str) -> Vec<String> {
        let dir = node.chunks_dir(bucket);
        let mut v: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn sample_blob(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn blob_crypt_material_and_ids_are_content_deterministic() {
        let blob = sample_blob(10_000);
        let other = sample_blob(10_001);

        let h = blob_content_hash(&blob);
        assert_eq!(h, blob_content_hash(&blob), "content id стабилен");
        let (k1, n1) = blob_key_nonce("files", "doc", &h);
        let (k2, n2) = blob_key_nonce("files", "doc", &h);
        assert_eq!(
            k1, k2,
            "ключ детерминирован (как на одной ноде, так и между нодами)"
        );
        assert_eq!(n1, n2, "nonce детерминирован");
        // шифрование с одними key/nonce даёт байт-в-байт тот же ct
        let ct1 = e2e_encrypt_det(&k1, &n1, &blob);
        let ct2 = e2e_encrypt_det(&k2, &n2, &blob);
        assert_eq!(ct1, ct2);

        // тот же контент => те же id; другой контент => другие id
        assert_eq!(
            chunk_id_for("files", "doc", 0, &h),
            chunk_id_for("files", "doc", 0, &blob_content_hash(&blob))
        );
        assert_ne!(
            chunk_id_for("files", "doc", 0, &h),
            chunk_id_for("files", "doc", 0, &blob_content_hash(&other))
        );
        // id разный для разных offset/бакетов/имён — как и раньше
        assert_ne!(
            chunk_id_for("files", "doc", 0, &h),
            chunk_id_for("files", "doc", 1024, &h)
        );
        assert_ne!(
            chunk_id_for("files", "doc", 0, &h),
            chunk_id_for("mail", "doc", 0, &h),
            "id обязан быть уникален на бакет (баг-регрессия прошлого фикса)"
        );
        // другой контент => другой ключ, т.е. ct (а значит и хранимые байты) не пересекается
        let (k_other, _) = blob_key_nonce("files", "doc", &blob_content_hash(&other));
        assert_ne!(k1, k_other);
    }

    #[tokio::test]
    async fn republish_same_name_and_content_is_idempotent() {
        let (node, tmp) = test_node("republish").await;
        let blob = sample_blob(3_000_000); // ct > 2 MiB => несколько чанков

        let n1 = node.store_blob("files", "doc.bin", &blob).await;
        let files1 = chunk_files(&node, "files");
        assert!(n1 > 0, "first publish must store chunks");
        assert_eq!(
            files1.len(),
            n1,
            "на диске ровно те чанки, что вернул store"
        );

        let mkey = Node::blob_manifest_key("files", "doc.bin");
        let manifest1 = node
            .get_local_kv(&mkey)
            .await
            .expect("manifest after publish");

        // ПОВТОРНЫЙ publish того же имени с тем же контентом
        let n2 = node.store_blob("files", "doc.bin", &blob).await;
        let files2 = chunk_files(&node, "files");
        let manifest2 = node
            .get_local_kv(&mkey)
            .await
            .expect("manifest after republish");

        assert_eq!(
            files1.len(),
            files2.len(),
            "file count must not grow on republish"
        );
        assert_eq!(files1, files2, "republish must reuse the same chunk paths");
        assert_eq!(n1, n2);
        assert_eq!(
            manifest1, manifest2,
            "манифест байт-в-байт тот же (id/key/nonce)"
        );
        assert!(
            !files2.iter().any(|f| f.ends_with(".tmp")),
            "не должно оставаться временных файлов"
        );

        let back = node.fetch_blob("files", "doc.bin").await.expect("fetch");
        assert_eq!(back, blob, "контент читается после репаблиша");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn changed_content_gets_new_ids_and_old_files_linger() {
        let (node, tmp) = test_node("changed").await;
        let a = sample_blob(1_500_000);
        let b = sample_blob(1_500_001); // другой контент => другой H => другие id

        node.store_blob("files", "doc.bin", &a).await;
        let files_a = chunk_files(&node, "files");
        node.store_blob("files", "doc.bin", &b).await;
        let files_now = chunk_files(&node, "files");

        assert!(
            files_now.len() > files_a.len(),
            "новый контент => новые id/файлы"
        );

        let mkey = Node::blob_manifest_key("files", "doc.bin");
        let manifest: serde_json::Value =
            serde_json::from_str(&node.get_local_kv(&mkey).await.expect("manifest")).unwrap();
        let ids: Vec<String> = manifest["chunks"]
            .as_array()
            .expect("chunks")
            .iter()
            .map(|c| c["id"].as_str().expect("id").to_string())
            .collect();
        assert!(!ids.is_empty());
        for id in &ids {
            assert!(files_now.contains(id), "манифест указывает на текущие id");
            assert!(!files_a.contains(id), "другой контент => другие id");
        }
        // старые файлы остаются сиротами (их подметает prune-chunk-orphans)
        let orphans: Vec<&String> = files_now.iter().filter(|f| !ids.contains(f)).collect();
        assert!(!orphans.is_empty(), "старый набор файлов остаётся на диске");

        let back = node.fetch_blob("files", "doc.bin").await.expect("fetch");
        assert_eq!(back, b, "fetch отдаёт НОВЫЙ контент");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn republish_mail_is_idempotent_and_still_counts_chunks() {
        let (node, tmp) = test_node("mail").await;
        let blob = sample_blob(2_000_000);

        let n1 = node.store_mail("mail:abc", &blob).await;
        let files1 = chunk_files(&node, "mail");
        assert!(n1 > 0);
        assert_eq!(files1.len(), n1);

        // повтор в пределах dedup-окна: запись пропускается (dedup_hit), но чанки
        // есть локально — store_mail обязан вернуть n1, а не 0 (web трактует 0
        // как отказ и откатывает квоту)
        let n2 = node.store_mail("mail:abc", &blob).await;
        let files2 = chunk_files(&node, "mail");
        assert_eq!(
            n1, n2,
            "идемпотентный репаблиш не должен выглядеть как отказ"
        );
        assert_eq!(files1, files2, "повторное store_mail не добавляет файлов");

        let back = node.fetch_mail("mail:abc").await.expect("fetch mail");
        assert_eq!(back, blob);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn persist_kv_sweeps_expired_and_stale_dedup() {
        let (node, tmp) = test_node("kv").await;
        // живая запись
        node.kv_store_local("files:alice", "[]").await;
        // уже просроченная
        node.kv
            .write()
            .await
            .store("expired:key", "x".into(), -1_000, node.id);
        // свежий dedup
        node.kv.write().await.store(
            "dedup:fresh",
            "{}".into(),
            crate::dht::DEDUP_TTL_MS,
            node.id,
        );
        // легаси-dedup: 30-дневный TTL, но последняя запись была 10 минут назад
        {
            let mut kv = node.kv.write().await;
            kv.restore(
                "dedup:stale".into(),
                crate::dht::StoredValue {
                    value: "{}".into(),
                    expires: crate::dht::now_ms() + 30 * 24 * 3600 * 1000,
                    origin: node.id,
                    ttl_ms: 30 * 24 * 3600 * 1000,
                    stored_at: crate::dht::now_ms() - 2 * crate::dht::DEDUP_TTL_MS,
                },
            );
        }

        let before = node.kv.read().await.len();
        assert_eq!(before, 4, "до: live + expired + fresh dedup + stale dedup");

        node.persist_kv().await;

        let after = node.kv.read().await.len();
        assert_eq!(after, 2, "после: live + свежий dedup");

        let raw = std::fs::read_to_string(tmp.join("kv.json")).expect("kv.json");
        let on_disk: HashMap<String, serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            on_disk.len(),
            after,
            "в файле не должно остаться мёртвых ключей"
        );
        assert!(on_disk.contains_key("files:alice"));
        assert!(on_disk.contains_key("dedup:fresh"));
        assert!(!on_disk.contains_key("dedup:stale"), "старый dedup вычищен");
        assert!(
            !on_disk.contains_key("expired:key"),
            "просроченная вычищена"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn dedup_entries_use_short_ttl() {
        let (node, tmp) = test_node("dedup").await;
        let data = b"dedup-window-probe".to_vec();
        let chunk_id = "ab".repeat(32); // валидный hex-id (64 символа)

        let (ok, dedup_hit, _) = node.write_chunk_with_dedup("files", &chunk_id, &data).await;
        assert!(ok);
        assert!(!dedup_hit, "первая запись — не дедуп");

        let dedup_key = format!("dedup:{}", hex::encode(blake3::hash(&data).as_bytes()));
        let entries = node.kv.read().await.entries_clone();
        let e = entries.get(&dedup_key).expect("dedup-ключ записан");
        assert_eq!(
            e.ttl_ms,
            crate::dht::DEDUP_TTL_MS,
            "dedup:* живёт только окно mark_seen (5 мин), а не 30 дней"
        );
        assert!(
            e.expires <= crate::dht::now_ms() + crate::dht::DEDUP_TTL_MS + 1000,
            "expires не дальше чем на DEDUP_TTL_MS вперёд"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Миграция: манифесты, записанные ДО фикса (случайный ключ + id от ct-среза),
    /// обязаны читаться без перезаписи данных — fetch ходит по id из манифеста,
    /// а не пересчитывает их.
    #[tokio::test]
    async fn legacy_manifest_with_pre_fix_ids_stays_readable() {
        let (node, tmp) = test_node("legacy").await;
        let blob = sample_blob(1_500_000);

        // эмуляция publish ДО фикса: свежий случайный ключ/nonce
        let data_key = rand::random::<[u8; 32]>();
        let (ct, nonce) = e2e_encrypt(&data_key, &blob);
        let dir = node.chunks_dir("files");
        std::fs::create_dir_all(&dir).expect("chunks dir");
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        while offset < ct.len() {
            let end = (offset + 1024 * 1024).min(ct.len());
            let chunk = &ct[offset..end];
            // СТАРАЯ формула id (до фикса): blake3("{bucket}:{name}:{offset}:{H(ct-срез)}")
            let legacy_id = hex::encode(
                blake3::hash(
                    format!(
                        "files:doc.bin:{offset}:{}",
                        hex::encode(blake3::hash(chunk).as_bytes())
                    )
                    .as_bytes(),
                )
                .as_bytes(),
            );
            write_chunk_atomic(&dir, &legacy_id, chunk).expect("legacy chunk");
            chunks.push(json!({
                "id": legacy_id,
                "n": 1,
                "off": offset,
                "len": chunk.len(),
                "hash": hex::encode(blake3::hash(chunk).as_bytes()),
            }));
            offset = end;
        }
        let manifest = json!({
            "bucket": "files",
            "name": "doc.bin",
            "size": blob.len(),
            "nonce": hex::encode(&nonce),
            "key": hex::encode(data_key),
            "chunks": chunks,
        });
        let mkey = Node::blob_manifest_key("files", "doc.bin");
        node.kv_store_local(&mkey, &manifest.to_string()).await;

        let back = node
            .fetch_blob("files", "doc.bin")
            .await
            .expect("legacy manifest + старые id читаются без миграции");
        assert_eq!(back, blob);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// (c) Ротация копий kv.json троттлится: 4 сохранения подряд = 1 копия,
    /// а не 4 (раньше каждое сохранение копировало весь файл).
    #[tokio::test]
    async fn kv_backup_rotation_is_throttled() {
        let (node, tmp) = test_node("bak").await;
        node.kv_store_local("files:alice", "[]").await;

        node.persist_kv().await; // файл только создаётся — копии ещё нет
        node.persist_kv().await; // первая ротация
        node.persist_kv().await; // внутри интервала — без копии
        node.persist_kv().await;

        let baks: Vec<_> = std::fs::read_dir(&tmp)
            .expect("tmpdir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("kv.json.bak-"))
            .collect();
        assert_eq!(baks.len(), 1, "4 сохранения подряд => максимум 1 копия");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// R3: 1-секундный flush-цикл пишет outbox.json только при dirty-флаге.
    /// Раньше каждый вызов flush_outbox_once переписывал файл, даже когда
    /// outbox не менялся, — один гарантированный disk write(2) в секунду.
    #[tokio::test]
    async fn outbox_flush_persists_only_when_dirty() {
        let (node, tmp) = test_node("outbox").await;
        let outbox_file = tmp.join("outbox.json");

        // (1) чистый вызов: флаг не поднят -> flush обязан ПРОПУСТИТЬ persist
        // (до патча здесь бы создался outbox.json с "{}").
        node.flush_outbox_once().await;
        assert!(
            !outbox_file.exists(),
            "clean flush must skip the persist (outbox_dirty never set)"
        );

        // (2) мутация поднимает dirty и персистится сразу (enqueue).
        let pid = [7u8; 20];
        node.enqueue(
            pid,
            QueuedMsg {
                topic: "t".into(),
                data: "d".into(),
                msg_id: 1,
                seq: 1,
                origin: "x".into(),
                attempts: 0,
                ts: now_ms(),
            },
        )
        .await;
        assert!(
            outbox_file.exists(),
            "enqueue (a mutation) must persist outbox"
        );

        // (3) flush, который мутирует outbox (ретрай неудачной доставки),
        // обязан поднять dirty и перезаписать файл даже после его удаления.
        std::fs::remove_file(&outbox_file).expect("remove outbox.json");
        node.flush_outbox_once().await;
        assert!(
            outbox_file.exists(),
            "flush mutations (attempts++) must set dirty and persist"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// R6-регрессия: всплеск dht.store ВНУТРИ debounce-окна даёт РОВНО ОДИН
    /// persist kv.json. Раньше КАЖДЫЙ dht.store полным пересохранением всей
    /// карты (на стенде 48–85 МБ, ~6/мин) — это и был convoy на persist-гейте.
    #[tokio::test]
    async fn dht_store_burst_triggers_single_kv_persist_within_debounce() {
        let (node, tmp) = test_node("kvdebounce").await;
        // окно управляемо из теста — без реальных пауз
        node.kv_debounce_ms.store(60_000, Ordering::SeqCst);
        let persists = || node.metrics.kv_persists_total.load(Ordering::SeqCst);
        let base = persists();

        for i in 0..20u64 {
            let v = json!({ "key": format!("test:burst-{i}"), "value": "v", "ttl": 3600 });
            let resp = node
                .handle_dht_store(&v, [1u8; NODEID_LEN])
                .await
                .expect("store");
            assert!(String::from_utf8_lossy(&resp).contains("\"ok\":true"));
        }
        assert_eq!(
            persists(),
            base,
            "сам dht.store не должен перезаписывать kv.json — только dirty-флаг"
        );
        assert!(!tmp.join("kv.json").exists(), "до flush файла ещё нет");

        // весь всплеск => ровно один flush
        node.kv_flush_if_due().await;
        assert_eq!(persists(), base + 1, "один flush на весь всплеск dht.store");

        // второй всплеск В ПРЕДЕЛАХ окна — persist'а не происходит
        for i in 20..40u64 {
            let v = json!({ "key": format!("test:burst-{i}"), "value": "v", "ttl": 3600 });
            node.handle_dht_store(&v, [1u8; NODEID_LEN])
                .await
                .expect("store");
        }
        node.kv_flush_if_due().await;
        assert_eq!(persists(), base + 1, "debounce-окно подавляет второй flush");

        // окно истекло => следующий flush проходит и записи всплеска на диске
        node.kv_debounce_ms.store(0, Ordering::SeqCst);
        node.kv_flush_if_due().await;
        assert_eq!(persists(), base + 2, "после окна flush проходит");
        let raw = std::fs::read_to_string(tmp.join("kv.json")).expect("kv.json");
        let on_disk: HashMap<String, serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert!(
            on_disk.len() >= 40,
            "в файле все записи обоих всплесков ({} < 40)",
            on_disk.len()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// R6-регрессия: долгая kv-запись (гейт kv занят) НЕ блокирует
    /// outbox-persist. Раньше ОДИН глобальный persist_gate ставил в одну
    /// очередь и kv, и outbox/subs/routes/dht.json — медленная перезапись
    /// 85 МБ kv поднимала proc у всех остальных сервисов на секунды.
    #[tokio::test]
    async fn slow_kv_write_does_not_block_outbox_persist() {
        let (node, tmp) = test_node("perfilegates").await;
        let outbox_file = tmp.join("outbox.json");

        // занять kv-гейт = «на диске сейчас идёт долгая kv-запись»
        let kv_gate = node.gates.kv.lock().await;

        // outbox-persist обязан пройти, пока kv-гейт занят
        let t0 = std::time::Instant::now();
        let pid = [9u8; 20];
        timeout(
            Duration::from_secs(2),
            node.enqueue(
                pid,
                QueuedMsg {
                    topic: "t".into(),
                    data: "d".into(),
                    msg_id: 1,
                    seq: 1,
                    origin: "x".into(),
                    attempts: 0,
                    ts: now_ms(),
                },
            ),
        )
        .await
        .expect("outbox persist must not wait for the in-flight kv write");
        assert!(
            t0.elapsed() < Duration::from_millis(1000),
            "outbox persist прошёл мимо kv-гейта за {:?}",
            t0.elapsed()
        );
        assert!(
            outbox_file.exists(),
            "outbox.json записан при занятом kv-гейте"
        );

        // ...а сам kv-persist за СВОИМ гейтом встаёт (гейт per-file, kv ждёт только kv)
        let fut = node.persist_kv();
        tokio::pin!(fut);
        assert!(
            timeout(Duration::from_millis(300), &mut fut).await.is_err(),
            "kv persist обязан ждать свой kv-гейт"
        );
        drop(kv_gate);
        timeout(Duration::from_secs(5), fut)
            .await
            .expect("kv persist проходит, когда гейт освобождён");
        assert!(
            node.metrics.kv_persists_total.load(Ordering::SeqCst) >= 1,
            "kv persist состоялся"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Retention publisher'а: явный TTL на blob/kv-записях, чистка просрочки
    /// штатным sweep'ом, локальный prune без сетевого веера, и backwards
    /// compat (дефолтные пути — те же 30 дней, что раньше).
    #[tokio::test]
    async fn retention_ttl_and_local_prune() {
        let (node, tmp) = test_node("retention").await;

        // (a) store_blob_with_ttl выставляет expires ≈ now+ttl на манифесте...
        let ttl: i64 = 2 * 3600 * 1000;
        let before = crate::dht::now_ms();
        node.store_blob_with_ttl("stell_blocks", "epoch_blk_deadbeef", b"body-bytes", ttl)
            .await;
        let mkey = Node::blob_manifest_key("stell_blocks", "epoch_blk_deadbeef");
        let entries = node.kv.read().await.entries_clone();
        let e = entries.get(&mkey).expect("manifest stored");
        assert!(
            e.ttl_ms == ttl
                && e.expires >= before + ttl
                && e.expires <= crate::dht::now_ms() + ttl + 5_000,
            "manifest carries the requested TTL (ttl={}, expires={})",
            e.ttl_ms,
            e.expires
        );
        // ...и тело читается, пока TTL живо.
        let back = node
            .fetch_blob("stell_blocks", "epoch_blk_deadbeef")
            .await
            .expect("fetch");
        assert_eq!(back, b"body-bytes");

        // (b) Дефолтный store_blob — те же 30 дней, что раньше (old data safety).
        node.store_blob("stell_blocks", "epoch_blk_legacy", b"legacy")
            .await;
        let mkey_legacy = Node::blob_manifest_key("stell_blocks", "epoch_blk_legacy");
        let entries = node.kv.read().await.entries_clone();
        let el = entries.get(&mkey_legacy).expect("legacy manifest stored");
        assert_eq!(el.ttl_ms, 30 * 24 * 3600 * 1000, "default TTL unchanged");

        // (c) kv_store_local_with_ttl + sweep: просроченные stell-ключи уходят,
        // живые и долгоживущие (без expiry-концепта — далёкий expires) остаются.
        node.kv_store_local_with_ttl("stell:height:0", "42000:deadbeef", ttl)
            .await;
        node.kv_store_local("stell:height:1", "42000:deadbeef")
            .await;
        node.kv
            .write()
            .await
            .store("stell_blocks:gone", "x".into(), -1_000, node.id);
        let (removed, _, _) = node.kv.write().await.sweep(crate::dht::now_ms());
        assert_eq!(removed, 1, "only the expired stell key");
        assert!(
            node.get_local_kv("stell:height:0").await.is_some(),
            "live TTL key kept"
        );
        assert!(
            node.get_local_kv("stell:height:1").await.is_some(),
            "30d key kept"
        );
        assert!(
            node.get_local_kv("stell_blocks:gone").await.is_none(),
            "expired dropped"
        );

        // (d) delete_blob_local: манифест + чанки уходят локально, fetch — None,
        // сетевого веера нет (в тесте пиров нет; важно — функция не падает и
        // возвращает число удалённых чанков).
        let n = node
            .delete_blob_local("stell_blocks", "epoch_blk_deadbeef")
            .await;
        assert!(n >= 1, "local chunks removed");
        assert!(node.get_local_kv(&mkey).await.is_none(), "manifest gone");
        assert!(node
            .fetch_blob("stell_blocks", "epoch_blk_deadbeef")
            .await
            .is_none());
        // повторное удаление — идемпотентный no-op
        assert_eq!(
            node.delete_blob_local("stell_blocks", "epoch_blk_deadbeef")
                .await,
            0
        );
        // дефолтный delete_blob поверх того же local-механизма — тоже ок
        assert!(node.delete_blob("stell_blocks", "epoch_blk_legacy").await >= 1);
        assert!(node.get_local_kv(&mkey_legacy).await.is_none());

        // (e) persist_kv выкидывает просроченные stell-манифесты из kv.json.
        node.store_blob_with_ttl("stell_headers", "epoch_h_1", b"hdr", -1_000)
            .await;
        node.persist_kv().await;
        let raw = std::fs::read_to_string(tmp.join("kv.json")).expect("kv.json");
        let on_disk: HashMap<String, serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert!(
            !on_disk.keys().any(|k| k == "stell_headers:epoch_h_1"),
            "expired stell manifest must not reach kv.json"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod session_heal_tests {
    //! A cached conn can lose its session (its frame_loop tore down and took
    //! the session entry with it while the object stayed cached). Every later
    //! request then failed in ~10µs with "no session key for conn" until a
    //! process restart — observed live as a one-directional consensus blackout
    //! (nodeB broadcasting nothing for 4.5h while receiving everything,
    //! height 71587 stalled). `conn_with_session` must self-heal instead:
    //! drop the dead object, reconnect (with the guarded dial fallback for
    //! the higher-id side), and serve the request.
    use super::*;
    use crate::config::{NodeConfig, PeerConfig};
    use crate::keyring::NodeKeys;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn cfg(name: &str, listen: &str, peers: Vec<PeerConfig>) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            listen: listen.to_string(),
            client_listen: None,
            advertise: None,
            peers,
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: Some(0),
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators: vec![],
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        }
    }

    fn peer_of(name: &str, keys: &NodeKeys, listen: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            node_id: keys.id_hex(),
            ed_pub: hex::encode(keys.verifying.to_bytes()),
            x_pub: hex::encode(keys.e2e_pub.as_bytes()),
            pq_pub: None,
            endpoints: vec![listen.to_string()],
            allow: vec!["*".to_string()],
            rate_limit_per_sec: 0,
            role: None,
            storage_roles: vec![],
        }
    }

    struct Pair {
        lo: Arc<Node>,
        hi: Arc<Node>,
        lo_id: [u8; crate::proto::NODEID_LEN],
        hi_id: [u8; crate::proto::NODEID_LEN],
        tmp: PathBuf,
        serves: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    }

    impl Pair {
        async fn start(tag: &str, port_base: u16) -> Pair {
            let tmp =
                std::env::temp_dir().join(format!("infnode-sessheal-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).expect("tmpdir");
            let ka = NodeKeys::generate();
            let kb = NodeKeys::generate();
            let (lo_keys, hi_keys, lo_listen, hi_listen) = if ka.id() < kb.id() {
                (
                    ka,
                    kb,
                    format!("127.0.0.1:{port_base}"),
                    format!("127.0.0.1:{}", port_base + 1),
                )
            } else {
                (
                    kb,
                    ka,
                    format!("127.0.0.1:{}", port_base + 1),
                    format!("127.0.0.1:{port_base}"),
                )
            };
            let lo_listen: &str = Box::leak(lo_listen.into_boxed_str());
            let hi_listen: &str = Box::leak(hi_listen.into_boxed_str());
            let lo = Node::new(
                cfg("LO", lo_listen, vec![peer_of("HI", &hi_keys, hi_listen)]),
                lo_keys.clone(),
                tmp.join("lo"),
                PathBuf::new(),
            )
            .await
            .expect("node LO");
            let hi = Node::new(
                cfg("HI", hi_listen, vec![peer_of("LO", &lo_keys, lo_listen)]),
                hi_keys.clone(),
                tmp.join("hi"),
                PathBuf::new(),
            )
            .await
            .expect("node HI");
            let mut serves = Vec::new();
            for n in [&lo, &hi] {
                let c = n.clone();
                serves.push(tokio::spawn(async move { c.serve().await }));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            let lo_id = lo_keys.id();
            let hi_id = hi_keys.id();
            Pair {
                lo,
                hi,
                lo_id,
                hi_id,
                tmp,
                serves,
            }
        }

        fn stop(&self) {
            for h in &self.serves {
                h.abort();
            }
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }

    async fn echo(from: &Arc<Node>, to_id: [u8; crate::proto::NODEID_LEN], tag: &[u8]) {
        let got = tokio::time::timeout(
            Duration::from_secs(20),
            from.request_to(to_id, "core.echo", tag.to_vec()),
        )
        .await
        .unwrap_or_else(|_| panic!("request timed out after session wipe"))
        .expect("request must self-heal after session wipe");
        assert_eq!(got, tag);
    }

    /// Dialer (lower-id) side: wipe its sessions, the next request must drop
    /// the dead object, redial, and succeed — fast (no tie-break wait).
    #[tokio::test(flavor = "multi_thread")]
    async fn dialer_side_heals_sessionless_cache() {
        let p = Pair::start("dialer", 19640).await;
        echo(&p.lo, p.hi_id, b"warm").await;
        // Simulate the torn-down frame_loop: session entry gone, conn cached.
        p.lo.sessions.write().await.clear();
        let t = std::time::Instant::now();
        echo(&p.lo, p.hi_id, b"healed").await;
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "redial must be fast on the dialing side"
        );
        p.stop();
    }

    /// Higher-id side (the live nodeB case): leave exactly ONE cached conn
    /// with no session, the next request must drop the dead object, wait out
    /// the tie-break, use the guarded dial fallback, and succeed.
    #[tokio::test(flavor = "multi_thread")]
    async fn higher_side_heals_sessionless_cache_via_fallback_dial() {
        let p = Pair::start("higher", 19650).await;
        echo(&p.hi, p.lo_id, b"warm").await;
        // Exactly one cached conn and no survivor to shortcut through: drop
        // everything, let the lower side dial once (fresh inbound + session),
        // then kill only the sessions.
        p.hi.drop_conn(p.lo_id, None).await;
        echo(&p.lo, p.hi_id, b"poke").await;
        p.hi.sessions.write().await.clear();
        // Must take the tie-break wait + dial: proves the full path (no
        // short-circuit through the cached, session-less conn).
        //
        // The wait is now SHORT (`SIMOPEN_WAIT_MS_DEFAULT` = 100ms, was
        // 15 x 50ms = 750ms): a reconnect to a restarting/loaded peer must
        // not pay ~1s of pure sleep. The bound below pins BOTH halves: the
        // tie-break still happens (elapsed >= the wait window) and the old
        // artificial delay is gone (elapsed < the old 750ms window).
        let t = std::time::Instant::now();
        echo(&p.hi, p.lo_id, b"healed").await;
        let took = t.elapsed();
        assert!(
            took >= Duration::from_millis(SIMOPEN_WAIT_MS_DEFAULT),
            "must have gone through the tie-break wait + fallback dial, took {took:?}"
        );
        assert!(
            took < Duration::from_millis(700),
            "the artificial tie-break delay must stay gone, took {took:?}"
        );
        // And the cache is healthy again afterwards (no repeated 1.5s waits).
        let t = std::time::Instant::now();
        echo(&p.hi, p.lo_id, b"again").await;
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "second request must reuse the healed session"
        );
        p.stop();
    }

    /// The tie-break rule itself (pure): the lower id always dials at once,
    /// the higher id waits ONLY for a static peer (one our config says dials
    /// us back). A peer that is not in the config must not delay us.
    #[test]
    #[allow(clippy::assertions_on_constants)] // GATE: pins tie-break constants against drift
    fn tie_break_wait_applies_only_to_static_peers_on_the_higher_side() {
        let lo = [0x01u8; NODEID_LEN];
        let hi = [0x02u8; NODEID_LEN];
        // Higher side + static peer: wait (the simultaneous-open storm).
        assert!(simopen_should_wait(&hi, &lo, true));
        // Higher side + NON-static peer (TOFU/DHT): no wait — it is not
        // obliged to dial us back, and waiting delayed every reconnect.
        assert!(!simopen_should_wait(&hi, &lo, false));
        // Lower side: always dials at once, static or not.
        assert!(!simopen_should_wait(&lo, &hi, true));
        assert!(!simopen_should_wait(&lo, &hi, false));
        // And the window itself is short.
        assert!(
            SIMOPEN_WAIT_MS_DEFAULT <= 100,
            "the tie-break wait must stay short"
        );
    }
}

#[cfg(test)]
mod pentest_net_tests {
    //! Agent P1 (network pentest) exploit/regression tests. Each test
    //! demonstrates an attack that succeeds on the pre-fix code and is
    //! refused after the fix. Code-only, localhost ephemeral nodes only.
    use super::*;

    fn pentest_cfg(name: &str) -> NodeConfig {
        NodeConfig {
            name: name.to_string(),
            listen: "127.0.0.1:0".to_string(),
            client_listen: None,
            advertise: None,
            peers: vec![],
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: Some(0),
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators: vec![],
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        }
    }

    async fn pentest_node(tag: &str) -> (Arc<Node>, PathBuf) {
        let tmp =
            std::env::temp_dir().join(format!("infnode-pentest-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("tmpdir");
        let node = Node::new(
            pentest_cfg("P"),
            NodeKeys::generate(),
            tmp.clone(),
            PathBuf::new(),
        )
        .await
        .expect("node");
        (node, tmp)
    }

    /// PENTEST F5 (P0): dynamic peers must be born rate-limited.
    ///
    /// Exploit: every TOFU/DHT-discovered identity used to get
    /// `rate_limit_per_sec: 0` = unlimited (`RateBucket::allow(0)` always
    /// returns true), so one ephemeral identity could flood discovery RPCs
    /// (`dht.lookup`/`find_node`/`find_value`) with no per-peer budget.
    #[test]
    #[allow(clippy::assertions_on_constants)] // GATE: pins rate-limit constants against drift
    fn pentest_dynamic_peers_are_born_rate_limited() {
        assert!(
            DYNAMIC_PEER_RATE_LIMIT_PER_SEC > 0,
            "dynamic peers must carry a nonzero budget (0 = unlimited)"
        );
        assert!(
            DYNAMIC_PEER_RATE_LIMIT_PER_SEC <= 100,
            "the dynamic budget must stay small enough to matter"
        );
        // And the budget actually binds: a fresh bucket holds ONE token
        // (see `RateBucket::new`), the second immediate request denies —
        // an unlimited bucket would allow everything.
        let mut bucket = RateBucket::new();
        let rate = DYNAMIC_PEER_RATE_LIMIT_PER_SEC;
        assert!(bucket.allow(rate), "first request passes");
        assert!(
            !bucket.allow(rate),
            "a dynamic peer must be capped, not unlimited"
        );
        // Refill is rate-paced (20/s => ~50ms per token), not instant.
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(bucket.allow(rate), "budget refills at the configured rate");
    }

    /// PENTEST F6 (P1): a hostile replicated manifest must not delete files
    /// outside the bucket dir.
    ///
    /// Exploit: manifests replicate over `dht.sync` from untrusted peers and
    /// their `chunks[].id` values flowed straight into
    /// `chunks_dir(bucket).join(cid)` + `remove_file` in
    /// `delete_blob_local_inner`. A manifest carrying `"../sentinel"` made
    /// the victim delete a file OUTSIDE its chunk directory.
    #[tokio::test]
    async fn pentest_poisoned_manifest_cannot_traverse_delete() {
        let (node, tmp) = pentest_node("traverse").await;
        // Sentinel OUTSIDE the bucket dir (data_dir/sentinel); the poisoned
        // manifest id `../sentinel` resolves exactly there.
        let sentinel = tmp.join("sentinel");
        std::fs::write(&sentinel, b"do not delete").expect("sentinel");
        let bucket = "stell_blocks";
        let mkey = Node::blob_manifest_key(bucket, "epoch_blk_evil");
        let manifest = serde_json::json!({
            "chunks": [
                {"id": "../sentinel", "hash": "00"},
                {"id": "/abs", "hash": "00"},
                {"id": "..\\win", "hash": "00"},
            ]
        })
        .to_string();
        node.kv_store_local(&mkey, &manifest).await;
        let deleted = node.delete_blob_local(bucket, "epoch_blk_evil").await;
        assert_eq!(deleted, 0, "no traversal id may count as a delete");
        assert!(
            sentinel.exists(),
            "EXPLOIT: a replicated manifest deleted a file outside the bucket dir"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel"),
            b"do not delete",
            "sentinel contents must be untouched"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// PENTEST F6 (P1), read side: `local_chunk_get` must refuse traversal ids.
    #[tokio::test]
    async fn pentest_local_chunk_get_refuses_traversal_ids() {
        let (node, tmp) = pentest_node("chunkget").await;
        assert!(node.local_chunk_get("mail", "../sentinel").is_none());
        assert!(node.local_chunk_get("mail", "/etc/passwd").is_none());
        assert!(node.local_chunk_get("mail", "").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// VERIFICATION F5-hardening: the 20/s budget must actually bind a live
    /// dynamic peer, and identity rotation must be expensive.
    ///
    /// Stronger than the original pentest:
    /// * a DHT-discovered peer (the `ensure_dht_peer` constructor, not just
    ///   the constant) carries the 20/s budget on its live `PeerLink`;
    /// * 21 rapid `dht.lookup`-shaped admissions from that fresh identity:
    ///   #1 passes (initial token), #2..#21 are refused — the flood shape
    ///   from the finding, end to end through the peer's own bucket;
    /// * rotation-cost pin: a fresh identity is only usable after a full
    ///   handshake (QUIC + TLS + signed CHALLENGE proving key ownership —
    ///   `claimed node id matches public key` + `verify`), which costs the
    ///   attacker a keypair, a signature and a round trip per identity while
    ///   yielding ~1 immediate request token. Rotating to defeat a 20/s
    ///   budget means ~1 handshake per request — the handshake is orders of
    ///   magnitude more expensive than the request it buys, so rotation does
    ///   not scale the flood (and `allow_unknown: false` by default closes
    ///   TOFU entirely on nodes that never opted in).
    #[tokio::test]
    async fn verification_dht_peer_flood_is_bound_per_identity() {
        let (node, tmp) = pentest_node("dynflood").await;
        let keys = NodeKeys::generate();
        let info = crate::dht::NodeInfo {
            id: keys.id(),
            endpoints: vec!["127.0.0.1:1".to_string()],
            ed_hex: keys.ed_hex(),
            x_hex: keys.x_hex(),
            last_seen: crate::dht::now_ms(),
        };
        node.ensure_dht_peer(&info).await.expect("dht peer inserts");
        let link = node
            .peers
            .read()
            .await
            .get(&info.id)
            .cloned()
            .expect("dynamic peer present");
        assert_eq!(
            link.cfg.rate_limit_per_sec, DYNAMIC_PEER_RATE_LIMIT_PER_SEC,
            "a DHT-discovered identity must be born at the dynamic budget"
        );
        assert_eq!(
            link.cfg.allow,
            vec![
                "dht.lookup".to_string(),
                "dht.update".to_string(),
                "dht.find_node".to_string()
            ],
            "a DHT-discovered identity must keep the discovery-only ACL"
        );
        // 21 rapid admissions through the peer's OWN bucket: #1 passes, the
        // rest refuse until the 20/s refill.
        let mut rate = link.rate.lock().await;
        assert!(
            rate.allow(link.cfg.rate_limit_per_sec),
            "first lookup passes"
        );
        for i in 2..=21u32 {
            assert!(
                !rate.allow(link.cfg.rate_limit_per_sec),
                "lookup #{i} from a fresh identity must be refused (budget spent)"
            );
        }
        drop(rate);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// VERIFICATION F6-hardening: the filesystem gate must hold on every
    /// path that joins an id — delete fan-out, network fetch, and the atomic
    /// writer under a pre-planted symlink.
    ///
    /// Stronger than the original pentest (which covered the local delete):
    /// * the DHT fan-out list (`delete_blob_local_inner`'s returned chunk
    ///   ids, forwarded to peers as `storage.delete`) excludes traversal
    ///   ids — a poisoned manifest must not turn peers into confused
    ///   deputies either;
    /// * `fetch_chunk_net` with a traversal id resolves to `None` without
    ///   touching the network (the local gate fires first);
    /// * `handle_storage_fetch` answers `bad chunk_id`, never a file;
    /// * a symlink pre-planted AT the target name is REPLACED by the atomic
    ///   writer (`rename` swaps the dentry, it does not follow it), so the
    ///   link target outside the bucket dir is untouched and the chunk lands
    ///   as a regular file.
    #[tokio::test]
    async fn verification_chunk_gate_holds_on_every_path() {
        let (node, tmp) = pentest_node("chunkpaths").await;
        let bucket = "mail";
        // Poisoned manifest: traversal ids among one honest id.
        let honest_id = "ab".repeat(32);
        let mkey = Node::blob_manifest_key(bucket, "epoch_blk_poison");
        let manifest = serde_json::json!({
            "chunks": [
                {"id": "../escape1", "hash": "00"},
                {"id": honest_id, "hash": "00"},
                {"id": "/abs", "hash": "00"},
                {"id": "..\\win", "hash": "00"},
                {"id": "%2e%2e/encoded", "hash": "00"},
                {"id": "ab".repeat(41), "hash": "00"},
            ]
        })
        .to_string();
        node.kv_store_local(&mkey, &manifest).await;
        let (deleted, fanout) = node
            .delete_blob_local_inner(bucket, "epoch_blk_poison")
            .await;
        assert_eq!(deleted, 0, "traversal ids must not count as deletes");
        assert_eq!(
            fanout,
            vec![honest_id.clone()],
            "only the honest id may fan out to peers as storage.delete: {fanout:?}"
        );
        // Network fetch with a traversal id: None, no filesystem escape.
        assert!(node
            .fetch_chunk_net(bucket, "../escape1", None)
            .await
            .is_none());
        assert!(node
            .fetch_chunk_net(bucket, "/etc/passwd", None)
            .await
            .is_none());
        assert!(node.fetch_chunk_net(bucket, "", None).await.is_none());
        // RPC fetch handler: loud refusal, never file bytes.
        let v = serde_json::json!({"bucket": bucket, "chunk_id": "../escape1"});
        let resp = node
            .handle_storage_fetch(&v)
            .await
            .expect("handler answers");
        let rv: serde_json::Value = serde_json::from_slice(&resp).expect("json");
        assert_eq!(rv["ok"], false);
        assert_eq!(rv["err"], "bad chunk_id");
        // Overlong id (81 hex chars): refused on the read path too.
        assert!(node.local_chunk_get(bucket, &"ab".repeat(41)).is_none());
        // Symlink pre-planted at the target: the writer replaces the link,
        // the outside file survives, the chunk is a regular file.
        let dir = node.chunks_dir(bucket);
        std::fs::create_dir_all(&dir).expect("chunk dir");
        let outside = tmp.join("outside");
        std::fs::write(&outside, b"precious").expect("outside file");
        let target_id = "cd".repeat(32);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join(&target_id)).expect("plant symlink");
        write_chunk_atomic(&dir, &target_id, b"legit-bytes").expect("atomic write");
        assert_eq!(
            std::fs::read(&outside).expect("outside"),
            b"precious",
            "EXPLOIT: the writer followed a planted symlink outside the bucket dir"
        );
        let landed = dir.join(&target_id);
        assert!(
            landed.is_file()
                && !std::fs::symlink_metadata(&landed)
                    .expect("meta")
                    .is_symlink(),
            "the chunk must land as a regular file (symlink replaced)"
        );
        assert_eq!(std::fs::read(&landed).expect("chunk"), b"legit-bytes");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
