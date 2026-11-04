//! Per-peer outbound-dial circuit breaker (redial-storm incident).
//!
//! A dead peer used to be redialled on every endpoint every 20s forever,
//! abuse-flagging a host for "hammering ports". The breaker counts
//! consecutive failed dial attempts per peer in a LOCAL map (unreachable is
//! not abusive: this state never feeds handshake-auth or reputation) and
//! parks the peer after [`CIRCUIT_FAIL_THRESHOLD`] failures with exponential
//! backoff (20s → 5min → 30min, compiled in — no env knobs). Parked means a
//! single probe of the first configured endpoint per interval (no sweep, no
//! NAT punch, no `catch_up` spawn); any success — outbound dial or inbound
//! accept, both registering via `add_conn` — resets to closed.
//!
//! All tests are pure state-machine (no network, no sleeps): the backoff
//! clock only advances on failed probes (minutes apart live), so time-based
//! assertions use the pure [`circuit_backoff_secs`] schedule plus the
//! stored `next_probe_at` state, and the 10-virtual-minute storm bound
//! replays the reconnect tick against the PRODUCTION consts/fns (changing
//! them breaks the test — the numbers below are the proof, not a copy).

use infnode::config::NodeConfig;
use infnode::keyring::NodeKeys;
use infnode::node::{
    circuit_backoff_secs, circuit_probe_endpoint, circuit_should_park,
    CIRCUIT_BACKOFF_FIRST_SECS, CIRCUIT_BACKOFF_MAX_SECS,
    CIRCUIT_BACKOFF_SECOND_SECS, CIRCUIT_FAIL_THRESHOLD,
    CIRCUIT_RECONNECT_INTERVAL_SECS, MAX_CIRCUIT_PEERS,
};
use infnode::node::Node;
use infnode::proto::NODEID_LEN;
use std::path::PathBuf;
use std::sync::Arc;

fn cfg(name: &str) -> NodeConfig {
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

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "infnode-circuit-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn fresh_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let tmp = tmpdir(tag);
    let keys = NodeKeys::generate();
    let node = Node::new(cfg("C"), keys, tmp.join("c"), PathBuf::new())
        .await
        .expect("node");
    (node, tmp)
}

fn dead_pid() -> [u8; NODEID_LEN] {
    NodeKeys::generate().id()
}

// ---------------------------------------------------------------------------
// 1. Park after K=5 consecutive failures (4 is still closed).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn park_after_5_fails() {
    let (node, tmp) = fresh_node("park").await;
    let pid = dead_pid();
    for i in 1..=4 {
        node.circuit_record_failure(pid);
        assert_eq!(
            node.circuit_consecutive_failures(&pid),
            i,
            "failure {i} counted"
        );
        assert!(
            !node.circuit_is_parked(&pid),
            "{i} failures must not park (K={CIRCUIT_FAIL_THRESHOLD})"
        );
    }
    assert_eq!(node.circuit_parks_total(), 0, "no park before threshold");
    node.circuit_record_failure(pid);
    assert_eq!(node.circuit_consecutive_failures(&pid), 5);
    assert!(node.circuit_is_parked(&pid), "5th failure parks");
    assert_eq!(node.circuit_parks_total(), 1, "exactly one park event");
    // Freshly parked: probe is NOT due (backoff 20s just started).
    assert!(
        !node.circuit_probe_due(&pid),
        "probe due only after the backoff elapses"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 2. Backoff schedule exact: 20s → 5min → 30min cap.
// ---------------------------------------------------------------------------

#[test]
fn backoff_schedule_exact() {
    assert_eq!(CIRCUIT_FAIL_THRESHOLD, 5);
    assert_eq!(CIRCUIT_BACKOFF_FIRST_SECS, 20);
    assert_eq!(CIRCUIT_BACKOFF_SECOND_SECS, 300);
    assert_eq!(CIRCUIT_BACKOFF_MAX_SECS, 1800);
    // Pure schedule: at/below threshold → 20s, next → 5min, then 30min cap.
    for fails in 0..=5 {
        assert_eq!(
            circuit_backoff_secs(fails),
            20,
            "fails={fails} → first backoff"
        );
        assert_eq!(
            circuit_should_park(fails),
            fails >= 5,
            "park iff fails >= K"
        );
    }
    assert_eq!(circuit_backoff_secs(6), 300, "first failed probe → 5min");
    for fails in [7u32, 8, 9, 100, u32::MAX] {
        assert_eq!(
            circuit_backoff_secs(fails),
            1800,
            "fails={fails} → 30min cap"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_backoff_escalates_per_failed_probe() {
    let (node, tmp) = fresh_node("escalate").await;
    let pid = dead_pid();
    for _ in 0..5 {
        node.circuit_record_failure(pid);
    }
    assert_eq!(node.circuit_current_backoff_secs(&pid), 20);
    // Each failed probe extends the park to the next step (no new park event:
    // the counter counts closed→parked transitions only).
    node.circuit_record_failure(pid);
    assert_eq!(node.circuit_current_backoff_secs(&pid), 300);
    assert_eq!(node.circuit_parks_total(), 1);
    node.circuit_record_failure(pid);
    assert_eq!(node.circuit_current_backoff_secs(&pid), 1800);
    assert_eq!(node.circuit_parks_total(), 1, "escalation is not a new park");
    node.circuit_record_failure(pid);
    assert_eq!(
        node.circuit_current_backoff_secs(&pid),
        1800,
        "backoff stays capped"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 3. Single-probe shape in park: first configured endpoint ONLY.
// ---------------------------------------------------------------------------

#[test]
fn single_probe_shape_in_park() {
    // Parked probe shape, bound to production code: `dial_parked_probe` —
    // the SOLE parked dial path (both the `reconnect_loop` due-probe and
    // the parked `dial_peer` branch funnel through it) — dials exactly what
    // `circuit_probe_endpoint` returns: the first configured endpoint ONLY.
    // No sweep, no gossip, no NAT punch, regardless of what else is known.
    let configured = vec![
        "127.0.0.1:9001".to_string(),
        "127.0.0.1:9002".to_string(),
        "127.0.0.1:9003".to_string(),
    ];
    assert_eq!(
        circuit_probe_endpoint(&configured),
        Some("127.0.0.1:9001".to_string()),
        "parked probe = first configured endpoint only"
    );
    // Single-endpoint peer: the probe is that endpoint.
    assert_eq!(
        circuit_probe_endpoint(&["127.0.0.1:9001".to_string()]),
        Some("127.0.0.1:9001".to_string())
    );
    // No configured endpoints: no probe at all (the park extends without
    // attempting a dial, so an empty config cannot spin).
    assert_eq!(circuit_probe_endpoint(&[]), None);
}

// ---------------------------------------------------------------------------
// 4. Any success — outbound dial or inbound accept — resets to closed.
//    (Both register via `add_conn`, which calls `circuit_record_success`;
//    the loop's live-connection race is covered the same way.)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn reset_on_success_closes_breaker() {
    let (node, tmp) = fresh_node("reset").await;
    let pid = dead_pid();
    for _ in 0..5 {
        node.circuit_record_failure(pid);
    }
    assert!(node.circuit_is_parked(&pid), "parked first");
    // Success (models either an outbound dial success or an inbound accept,
    // which both funnel through the same reset call in `add_conn`).
    node.circuit_record_success(pid);
    assert!(!node.circuit_is_parked(&pid), "success unparks");
    assert_eq!(node.circuit_consecutive_failures(&pid), 0, "count cleared");
    assert!(
        !node.circuit_probe_due(&pid),
        "closed peers are never probe-due"
    );
    assert_eq!(node.circuit_current_backoff_secs(&pid), 0);
    assert_eq!(node.circuit_unparks_total(), 1, "unpark counted");
    // A fresh failure streak starts from zero, not from the old count.
    node.circuit_record_failure(pid);
    assert_eq!(node.circuit_consecutive_failures(&pid), 1);
    assert!(!node.circuit_is_parked(&pid));
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 5. Healthy peers never park: unknown, sub-threshold, and reset-fast all
//    stay closed with silent counters.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn healthy_peer_never_parked() {
    let (node, tmp) = fresh_node("healthy").await;
    let pid = dead_pid();
    // Unknown peer: fully closed, probe never due.
    assert!(!node.circuit_is_parked(&pid));
    assert!(!node.circuit_probe_due(&pid));
    assert_eq!(node.circuit_consecutive_failures(&pid), 0);
    assert_eq!(node.circuit_current_backoff_secs(&pid), 0);
    // Success on an unknown peer is a silent no-op (the hot path: every
    // healthy `add_conn` lands here).
    node.circuit_record_success(pid);
    assert_eq!(node.circuit_parks_total(), 0);
    assert_eq!(node.circuit_unparks_total(), 0);
    // Sub-threshold failures then success: never parked, fully cleared.
    for _ in 0..4 {
        node.circuit_record_failure(pid);
    }
    assert!(!node.circuit_is_parked(&pid));
    node.circuit_record_success(pid);
    assert_eq!(node.circuit_consecutive_failures(&pid), 0);
    assert_eq!(node.circuit_parks_total(), 0, "healthy peer never parks");
    assert_eq!(node.circuit_unparks_total(), 0, "nothing to unpark");
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 6. Storm-rate assertion over 10 virtual minutes: replay the reconnect tick
//    against the PRODUCTION consts/schedule. Before: every 20s tick sweeps
//    every endpoint (+NAT punch). After: 5 dials, then single probes at the
//    backoff steps. Bound: dials to the dead peer < 10 (was 120 at 3
//    endpoints + punch).
// ---------------------------------------------------------------------------

#[test]
fn storm_rate_bound_10_virtual_min() {
    const VIRTUAL_SECS: u64 = 600;
    const ENDPOINTS: usize = 3;
    let tick = CIRCUIT_RECONNECT_INTERVAL_SECS;
    assert_eq!(tick, 20, "reconnect cadence the incident showed");
    let ticks = VIRTUAL_SECS / tick; // 30 sweeps per 10 virtual min

    // BEFORE: each tick dials every endpoint plus the NAT-punch fallback.
    let old_dials = ticks as usize * (ENDPOINTS + 1);
    assert_eq!(old_dials, 120);

    // AFTER: replay the breaker against the production schedule. One dial
    // per attempt (sweep width is separately capped; parked probes are
    // single-endpoint by construction — see `single_probe_shape_in_park`).
    let mut fails: u32 = 0;
    let mut parked_until: Option<u64> = None;
    let mut new_dials: usize = 0;
    let mut t: u64 = 0;
    while t < VIRTUAL_SECS {
        let open = fails >= CIRCUIT_FAIL_THRESHOLD;
        let due = match parked_until {
            Some(u) => t >= u,
            None => false,
        };
        if !open || due {
            // One dial this tick (initial sweep or single probe).
            new_dials += 1;
            fails = fails.saturating_add(1);
            parked_until = Some(t + circuit_backoff_secs(fails));
        }
        t += tick;
    }
    // 5 initial dials + probes at t=100 (20s park) and t=400 (5min park);
    // the next probe (30min park) lands past the 10min window.
    assert_eq!(new_dials, 7, "5 dials + 2 probes in 10 virtual min");
    assert!(new_dials < 10, "storm bound: {new_dials} < 10 (was {old_dials})");
    assert!(
        new_dials * 10 < old_dials,
        ">10x reduction: {new_dials} vs {old_dials}"
    );
    println!("storm-rate 10 virtual min: before={old_dials} after={new_dials}");
}

// ---------------------------------------------------------------------------
// 7. Breaker map is capped: a flood of distinct dead peers cannot grow
//    memory, and parked peers are never evicted (no silent unpark).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn breaker_map_capped_parked_never_evicted() {
    let (node, tmp) = fresh_node("cap").await;
    let parked = dead_pid();
    for _ in 0..5 {
        node.circuit_record_failure(parked);
    }
    assert!(node.circuit_is_parked(&parked));
    // Flood with distinct dead peers (one failure each: closed entries).
    for _ in 0..(MAX_CIRCUIT_PEERS + 64) {
        node.circuit_record_failure(dead_pid());
    }
    assert!(
        node.circuit_len() <= MAX_CIRCUIT_PEERS,
        "breaker map bounded, len={}",
        node.circuit_len()
    );
    assert!(
        node.circuit_is_parked(&parked),
        "cap pressure must never evict a parked peer"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
