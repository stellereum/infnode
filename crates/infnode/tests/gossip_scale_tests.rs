//! Gossip-at-scale suite (p2p 9.0 -> 9.5): broadcast coverage, all-to-all
//! chatter, byzantine spam containment, partition-heal convergence.
//!
//! * Loopback only, deterministic ports/keys/msg_ids, no external network.
//! * Scale: `SCALE_N` (starting point 12; see report at the end of the run).
//! * Fanout/amplification bounds READ FROM the implementation (not assumed):
//!   - `proto::MAX_PUBSUB_TTL = 16`: relay hop bound (`node.rs` `forward`
//!     decrements per hop, stops at 0).
//!   - `node.rs` `forward` floods to ALL known peers except the sender, so one
//!     publish costs at most `(N-1) + (N-1)*(N-2) = (N-1)^2` relay RPCs: the
//!     first wave fans out, the second wave is absorbed by `mark_seen` dedup
//!     (`dup:true`, no further forward). There is NO separate fanout cap.
//!   - `proto::MAX_SEEN_IDS = 200_000` (+ 60s-window eviction): dedup memory
//!     is fail-closed; duplicates stay safe for the app layer.
//!   - `proto::MAX_PUBSUB_DATA_LEN = 1 MiB`: oversize publish/relay is refused
//!     fail-closed (`{"ok":false,"err":"data too large"}`), never forwarded.
//!   - `dht::DEDUP_TTL_MS` (5 min): dedup window shared with KV `dedup:*`.
//!   - `proto::MAX_OUTBOX_PER_PEER = 1024`: offline-subscriber queue bound.
//! * Reputation policy READ FROM `reputation.rs` (`RepConfig::load` defaults):
//!   soft throttle at `-20`, temp ban at `-50`, `pen_oversize = 10`,
//!   `pen_rate = 5`, `pen_proto = 10`, `pen_auth = 10`, decay `1/s`.
//!   App-layer refusals (oversize pubsub data, bad topic) carry NO automatic
//!   penalty; transport-level abuse does. This suite drives the real
//!   `rep_record_*` entry points (the same ones the accept path calls) and
//!   asserts the real thresholds via `rep_is_throttled` / `rep_is_banned`.
//! * Publish semantics under test (from `node.rs` `handle_*`, MEASURED): the
//!   executing node is the origin. Its own app inbox is not fed directly, but
//!   in a connected mesh it still receives its own publish exactly once via
//!   the second relay wave looping back through the trigger node. Full
//!   coverage of one publish is therefore `N` app receipts, each exactly once.

use ed25519_dalek::SigningKey;
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::NodeKeys;
use infnode::node::{Node, PeerLink};
use infnode::{proto, reputation::RepConfig};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// Harness scale: full mesh of this many nodes per test. Starting point 12;
/// bump only while the whole suite stays green well under 300 s.
const SCALE_N: usize = 15;
/// One coverage-poll round.
const ROUND_MS: u64 = 250;
/// Publish TTL used by the suite (2 flood waves need >= 2; margin included,
/// far below `proto::MAX_PUBSUB_TTL`).
const SUITE_TTL: u64 = 4;

// ---------------------------------------------------------------------------
// Deterministic helpers (no OS randomness in topology / keys / msg ids).
// ---------------------------------------------------------------------------

/// Deterministic node keys from a label: `blake3(label)` seeds both the
/// ed25519 signing key and (domain-separated) the x25519 secret.
fn det_keys(label: &str) -> NodeKeys {
    let ed_seed = blake3::hash(format!("{label}/ed").as_bytes());
    let ed_bytes: [u8; 32] = *ed_seed.as_bytes();
    let signing = SigningKey::from_bytes(&ed_bytes);
    let verifying = signing.verifying_key();
    let x_seed = blake3::hash(format!("{label}/x").as_bytes());
    let e2e_sec = StaticSecret::from(*x_seed.as_bytes());
    let e2e_pub = XPublicKey::from(&e2e_sec);
    NodeKeys {
        signing,
        verifying,
        e2e_sec,
        e2e_pub,
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

struct Mesh {
    nodes: Vec<Arc<Node>>,
    ids: Vec<[u8; 20]>,
    rxs: Vec<tokio::sync::mpsc::UnboundedReceiver<String>>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
    _tmp: PathBuf,
}

impl Mesh {
    /// inbox payloads received so far per node, parsed to `(data, msg_id)`.
    fn drain_all(&mut self) -> Vec<Inbox> {
        let mut out = vec![Vec::new(); self.rxs.len()];
        for (i, rx) in self.rxs.iter_mut().enumerate() {
            while let Ok(raw) = rx.try_recv() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let data = v["data"].as_str().unwrap_or("").to_string();
                    let msg_id = v["msg_id"].as_u64();
                    out[i].push((data, msg_id));
                }
            }
        }
        out
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        for h in &self._handles {
            h.abort();
        }
    }
}

/// Build a full-mesh loopback cluster: every node pins every other node,
/// serves, registers one app subscription on `topic`, and subscribes at every
/// other node. Deterministic ports (`base..base+N`), keys (`tag/i`).
async fn build_mesh(tag: &str, base_port: u16, n: usize, topic: &str) -> Mesh {
    let tmp = std::env::temp_dir().join(format!("gossip-scale-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("tmpdir");

    let keys: Vec<NodeKeys> = (0..n).map(|i| det_keys(&format!("gossip-scale/{tag}/{i}"))).collect();
    let listens: Vec<String> = (0..n).map(|i| format!("127.0.0.1:{}", base_port + i as u16)).collect();

    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let peers: Vec<PeerConfig> = (0..n)
            .filter(|&j| j != i)
            .map(|j| peer_of(&format!("n{j}"), &keys[j], &listens[j]))
            .collect();
        let node = Node::new(
            cfg(&format!("{tag}-{i}"), &listens[i], peers),
            keys[i].clone(),
            tmp.join(format!("n{i}")),
            PathBuf::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} node {i}: {e}"));
        nodes.push(node);
    }
    let ids: Vec<[u8; 20]> = keys.iter().map(|k| k.id()).collect();

    let mut handles = Vec::with_capacity(n);
    for node in &nodes {
        let n = node.clone();
        handles.push(tokio::spawn(async move {
            let _ = n.serve().await;
        }));
    }

    let mut rxs = Vec::with_capacity(n);
    for node in &nodes {
        rxs.push(node.register_app_sub(topic).await);
    }

    // Full-mesh network subscriptions (every node subscribes at every other).
    // Bounded concurrency (16 at a time) with retries: a 132-RPC thundering
    // herd times out under parallel-suite load; serial batches stay robust
    // while the total stays far under the 300 s suite budget.
    let mut pairs: Vec<(usize, [u8; 20])> = Vec::new();
    for i in 0..n {
        for (j, pid) in ids.iter().enumerate() {
            if i != j {
                pairs.push((i, *pid));
            }
        }
    }
    for chunk in pairs.chunks(16) {
        let mut jobs = tokio::task::JoinSet::new();
        for &(i, pid) in chunk {
            let node = nodes[i].clone();
            let payload = serde_json::json!({ "topic": topic }).to_string().into_bytes();
            jobs.spawn(async move {
                let mut last_err = String::new();
                for attempt in 1..=5 {
                    let res = tokio::time::timeout(
                        Duration::from_secs(30),
                        node.request_to(pid, "pubsub.subscribe", payload.clone()),
                    )
                    .await;
                    match res {
                        Ok(Ok(_)) => return,
                        Ok(Err(e)) => {
                            last_err = format!("rpc err: {e}");
                        }
                        Err(_) => {
                            last_err = format!("timeout attempt {attempt}/5");
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
                }
                panic!("subscribe {i}->{pid_hex} failed after retries: {last_err}", pid_hex = hex::encode(pid));
            });
        }
        while jobs.join_next().await.is_some() {}
    }
    // Let the reconnect loop dial the mesh before publishing.
    tokio::time::sleep(Duration::from_millis(3000)).await;

    Mesh {
        nodes,
        ids,
        rxs,
        _handles: handles,
        _tmp: tmp,
    }
}

/// Trigger a publish *executed by* `exec` (origin = `exec`), requested over
/// the mesh by `trigger`. Returns the parsed response.
async fn publish_via(
    mesh: &Mesh,
    trigger: usize,
    exec: usize,
    topic: &str,
    data: &str,
    msg_id: u64,
) -> serde_json::Value {
    let payload = serde_json::json!({
        "topic": topic,
        "data": data,
        "msg_id": msg_id,
        "ttl": SUITE_TTL,
    })
    .to_string()
    .into_bytes();
    let mut last_err = String::new();
    for attempt in 1..=5 {
        let res = tokio::time::timeout(
            Duration::from_secs(30),
            mesh.nodes[trigger].request_to(mesh.ids[exec], "pubsub.publish", payload.clone()),
        )
        .await;
        match res {
            Ok(Ok(raw)) => return serde_json::from_slice(&raw).expect("publish response is JSON"),
            Ok(Err(e)) => last_err = format!("rpc err: {e}"),
            Err(_) => last_err = format!("timeout attempt {attempt}/5"),
        }
        tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
    }
    panic!("publish {trigger}->{exec} failed after retries: {last_err}");
}

/// Poll inboxes until `want(i)` holds for every node or `max_rounds` elapse.
/// Returns `(rounds_used, inboxes)`.
type Inbox = Vec<(String, Option<u64>)>;
async fn poll_rounds(
    mesh: &mut Mesh,
    max_rounds: u32,
    want: &dyn Fn(usize, &[Inbox]) -> bool,
) -> (u32, Vec<Inbox>) {
    let mut inboxes: Vec<Inbox> = vec![Vec::new(); mesh.rxs.len()];
    for round in 1..=max_rounds {
        tokio::time::sleep(Duration::from_millis(ROUND_MS)).await;
        for (i, batch) in mesh.drain_all().into_iter().enumerate() {
            inboxes[i].extend(batch);
        }
        if round % 10 == 0 || want(mesh.rxs.len(), &inboxes) {
            let covered = inboxes.iter().filter(|v| !v.is_empty()).count();
            eprintln!("poll round {round}/{max_rounds}: nodes_with_any_msg={covered}");
        }
        if want(mesh.rxs.len(), &inboxes) {
            return (round, inboxes);
        }
    }
    (max_rounds, inboxes)
}

fn count_data(inboxes: &[Inbox], needle: &str) -> Vec<usize> {
    inboxes
        .iter()
        .map(|v| v.iter().filter(|(d, _)| d == needle).count())
        .collect()
}

// ---------------------------------------------------------------------------
// 1) Broadcast: 1 -> all within bounded rounds.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn gossip_broadcast_full_coverage_at_scale() {
    let n = SCALE_N;
    let topic = "scale-bcast";
    let mut mesh = build_mesh("bcast", 19610, n, topic).await;

    let data = "bcast-hello";
    let msg_id = 0xBCA5_0001u64;
    let resp = publish_via(&mesh, 0, 1, topic, data, msg_id).await;
    assert_eq!(resp["ok"], true, "publish must be accepted: {resp}");

    // Full coverage: every node (origin included, via the relay loop-back)
    // receives the broadcast exactly once (dedup) within the round bound.
    // Note: the ordered `pubsub.msg` delivery envelope carries
    // {topic,data,seq,origin,src} (no msg_id), so coverage gates on the
    // unique `data` string; msg_ids stay deterministic for relay/dedup paths.
    let (rounds, inboxes) = poll_rounds(&mut mesh, 120, &|len, got| {
        (0..len).all(|i| got[i].iter().any(|(d, _)| d == data))
    })
    .await;
    let counts = count_data(&inboxes, data);
    for (i, c) in counts.iter().enumerate() {
        assert_eq!(*c, 1, "node {i} must receive exactly once (dedup)");
    }
    let covered = counts.iter().filter(|&&c| c == 1).count();
    println!("REPORT bcast N={n} rounds_to_full_coverage={rounds} covered={covered}/{n}");
    assert_eq!(covered, n, "full coverage short of N");
}

// ---------------------------------------------------------------------------
// 2) All-to-all chatter: every node publishes -> no storm collapse.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn gossip_all_to_all_no_storm_collapse() {
    let n = SCALE_N;
    let topic = "scale-chatter";
    let mut mesh = build_mesh("chatter", 19730, n, topic).await;

    let t0 = std::time::Instant::now();
    for i in 0..n {
        let exec = (i + 1) % n;
        let resp = publish_via(&mesh, i, exec, topic, &format!("chatter-{i}"), 0xC4A7_0000u64 + i as u64).await;
        assert_eq!(resp["ok"], true, "publish {i} must be accepted: {resp}");
    }

    // Each node must end with exactly the N chatter messages (its own
    // included via the relay loop-back), each exactly once: delivery_rate
    // 100%, duplicates 0 (dedup asserted).
    let (rounds, inboxes) = poll_rounds(&mut mesh, 120, &|len, got| {
        (0..len).all(|i| {
            let mut seen = HashSet::new();
            for (d, _) in &got[i] {
                if d.starts_with("chatter-") {
                    seen.insert(d.clone());
                }
            }
            seen.len() == len
        })
    })
    .await;
    let elapsed = t0.elapsed();
    let mut total_unique = 0usize;
    let mut total_dupes = 0usize;
    for (i, inbox) in inboxes.iter().enumerate() {
        let mut seen = HashSet::new();
        let mut dupes = 0usize;
        for (d, _) in inbox.iter().filter(|(d, _)| d.starts_with("chatter-")) {
            if !seen.insert(d.clone()) {
                dupes += 1;
            }
        }
        // Every chatter message loops back to its origin, so inbox i holds
        // all N distinct messages. Either way: exactly N distinct, zero dupes.
        assert_eq!(seen.len(), n, "node {i} inbox distinct franchises: {seen:?}");
        assert_eq!(dupes, 0, "node {i} received duplicates (dedup broken)");
        total_unique += seen.len();
        total_dupes += dupes;
    }
    let rate = total_unique as f64 / (n * n) as f64 * 100.0;
    println!(
        "REPORT chatter N={n} rounds={rounds} delivery_rate={rate:.1}% dupes={total_dupes} wall={}ms (theoretical relay bound per publish (N-1)^2={})",
        elapsed.as_millis(),
        (n - 1) * (n - 1)
    );
    assert_eq!(total_unique, n * n, "delivery rate must be 100%");
    assert!(elapsed.as_secs() < 120, "storm collapse: all-to-all took too long");
}

// ---------------------------------------------------------------------------
// 3) Byzantine spammers (20%): oversize + duplicate floods contained.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn gossip_byzantine_spam_contained() {
    let n = SCALE_N;
    let n_byz = (n / 5).max(1);
    let topic = "scale-byz";
    let mut mesh = build_mesh("byz", 19850, n, topic).await;
    let byz: Vec<usize> = ((n - n_byz)..n).collect();
    let honest: Vec<usize> = (0..(n - n_byz)).collect();
    assert_eq!(n_byz * 5, n, "20% of {n} nodes are byzantine (n_byz={n_byz})");
    println!("REPORT byz consts MAX_PUBSUB_DATA_LEN={} MAX_PUBSUB_TTL={} MAX_SEEN_IDS={}", proto::MAX_PUBSUB_DATA_LEN, proto::MAX_PUBSUB_TTL, proto::MAX_SEEN_IDS);

    // (a) Oversize flood: every attempt refused fail-closed, nothing delivered.
    let big = "X".repeat(proto::MAX_PUBSUB_DATA_LEN + 1);
    assert!(big.len() > proto::MAX_PUBSUB_DATA_LEN);
    for (k, &s) in byz.iter().enumerate() {
        let target = honest[k % honest.len()];
        let payload = serde_json::json!({
            "topic": topic, "data": big, "msg_id": 0x0B52_1000u64 + k as u64, "ttl": SUITE_TTL,
        })
        .to_string()
        .into_bytes();
        let raw = tokio::time::timeout(
            Duration::from_secs(30),
            mesh.nodes[s].request_to(mesh.ids[target], "pubsub.publish", payload),
        )
        .await
        .expect("oversize rpc timeout")
        .expect("oversize rpc transport");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("JSON");
        assert_eq!(v["ok"], false, "oversize publish must be refused");
        assert_eq!(v["err"], "data too large", "fail-closed reason, got {v}");
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let inboxes = mesh.drain_all();
    for &h in &honest {
        assert!(
            inboxes[h].is_empty(),
            "honest node {h} received spam from refused oversize flood: {:?}",
            inboxes[h].iter().map(|(d, _)| d.len()).collect::<Vec<_>>()
        );
    }

    // (b) Duplicate flood: same msg_id relayed 30x to the SAME target ->
    // first delivers once, rest answer dup:true and forward nothing (no
    // amplification). Single target keeps it deterministic: rotating targets
    // would race direct relays against mesh forwards (flake under load).
    let spam_msg = 0xD9F1_CA7Eu64;
    let mut dup_answers = 0usize;
    for k in 0..30 {
        let s = byz[k % byz.len()];
        let target = honest[0];
        let payload = serde_json::json!({
            "topic": topic, "data": "spam-dup", "msg_id": spam_msg,
            "seq": 1u64, "origin": "spam-origin", "ttl": SUITE_TTL,
        })
        .to_string()
        .into_bytes();
        let raw = tokio::time::timeout(
            Duration::from_secs(30),
            mesh.nodes[s].request_to(mesh.ids[target], "pubsub.relay", payload),
        )
        .await
        .expect("relay timeout")
        .expect("relay transport");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("JSON");
        assert_eq!(v["ok"], true, "relay answered: {v}");
        if v.get("dup") == Some(&serde_json::Value::Bool(true)) {
            dup_answers += 1;
        }
    }
    assert!(
        dup_answers >= 29,
        "duplicate relays must be absorbed by dedup (dup:true), got {dup_answers}/30"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let inboxes = mesh.drain_all();
    for (i, inbox) in inboxes.iter().enumerate() {
        let c = inbox.iter().filter(|(d, _)| d == "spam-dup").count();
        assert!(c <= 1, "node {i} got spam-dup {c}x (dedup must deliver at most once)");
    }

    // (c) Honest delivery unaffected by the spam above.
    let resp = publish_via(&mesh, honest[0], honest[1], topic, "honest-after-spam", 0xBEEF_0007u64).await;
    assert_eq!(resp["ok"], true, "honest publish accepted: {resp}");
    let (rounds, inboxes) = poll_rounds(&mut mesh, 40, &|_len, got| {
        honest
            .iter()
            .all(|&i| got[i].iter().any(|(d, _)| d == "honest-after-spam"))
    })
    .await;
    for &h in &honest {
        assert!(
            inboxes[h].iter().any(|(d, _)| d == "honest-after-spam"),
            "honest node {h} missed post-spam message"
        );
    }
    println!("REPORT byz N={n} n_byz={n_byz} dup_absorbed={dup_answers}/30 honest_rounds={rounds}");

    // (d) Spammers throttled then banned via the REAL reputation policy.
    // Thresholds come from RepConfig::load (defaults soft=-20 ban=-50).
    let rcfg = RepConfig::load();
    println!(
        "REPORT byz rep_policy soft={} ban={} pen_oversize={} pen_rate={}",
        rcfg.soft_score, rcfg.ban_score, rcfg.pen_oversize, rcfg.pen_rate
    );
    let observer = honest[0];
    for &s in &byz {
        let pid = mesh.ids[s];
        let mut to_throttle = 0;
        while !mesh.nodes[observer].rep_is_throttled(&pid).await
            && !mesh.nodes[observer].rep_is_banned(&pid).await
            && to_throttle < 25
        {
            mesh.nodes[observer].rep_record_oversize(&pid).await;
            to_throttle += 1;
        }
        assert!(
            mesh.nodes[observer].rep_is_throttled(&pid).await
                || mesh.nodes[observer].rep_is_banned(&pid).await,
            "spammer {s} must throttle within 25 oversize debits"
        );
        let mut to_ban = 0;
        while !mesh.nodes[observer].rep_is_banned(&pid).await && to_ban < 25 {
            mesh.nodes[observer].rep_record_oversize(&pid).await;
            to_ban += 1;
        }
        assert!(mesh.nodes[observer].rep_is_banned(&pid).await, "spammer {s} must ban");
        println!("REPORT byz spammer={s} debits_to_throttle<={to_throttle} debits_to_ban<={}  ", to_throttle + to_ban);
    }
    for &h in &honest {
        let pid = mesh.ids[h];
        assert!(!mesh.nodes[observer].rep_is_banned(&pid).await, "honest {h} must not be banned");
        assert!(!mesh.nodes[observer].rep_is_throttled(&pid).await, "honest {h} must not be throttled");
    }
    assert!(
        mesh.nodes[observer].rep_bans_total() >= n_byz as u64,
        "ban counter must reflect spammer bans"
    );
}

// ---------------------------------------------------------------------------
// 4) Partition-heal: split brain halves -> heal -> converge, no fork.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn gossip_partition_heal_converges() {
    let n = SCALE_N;
    let half = n / 2;
    let topic = "scale-part";
    let mut mesh = build_mesh("part", 19970, n, topic).await;
    let side_a: Vec<usize> = (0..half).collect();
    let side_b: Vec<usize> = (half..n).collect();

    // Baseline: full coverage before the split.
    let resp = publish_via(&mesh, 0, 1, topic, "pre-split", 0x9A27_0001u64).await;
    assert_eq!(resp["ok"], true);
    let (_, inboxes) = poll_rounds(&mut mesh, 60, &|len, got| {
        (0..len).all(|i| got[i].iter().any(|(d, _)| d == "pre-split"))
    })
    .await;
    assert!(inboxes.iter().all(|v| v.iter().any(|(d, _)| d == "pre-split")));
    let _ = mesh.drain_all();

    // Partition: sever the cross-half peer links on BOTH sides (real
    // split-brain: `forward`/`request_to` consult the peers map, and inbound
    // frames from links absent from the map are refused as "unknown peer").
    // Links are `Clone`, so the exact entries are restored on heal.
    let mut saved: HashMap<(usize, usize), PeerLink> = HashMap::new();
    for &a in &side_a {
        for &b in &side_b {
            let lab = mesh.nodes[a]
                .peers
                .write()
                .await
                .remove(&mesh.ids[b])
                .expect("cross-half link a->b");
            saved.insert((a, b), lab);
            let lba = mesh.nodes[b]
                .peers
                .write()
                .await
                .remove(&mesh.ids[a])
                .expect("cross-half link b->a");
            saved.insert((b, a), lba);
        }
    }
    // Drain in-flight cross-half relays before diverging.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let _ = mesh.drain_all();

    // Divergent publishes while split: each half covers itself, nothing leaks.
    // (During-partition cross-half traffic lands in the sender-side outbox and
    // is dropped after retries; gossip is ephemeral, no history sync.)
    let resp = publish_via(&mesh, side_a[0], side_a[1], topic, "only-A", 0x9A27_00A1u64).await;
    assert_eq!(resp["ok"], true);
    let resp = publish_via(&mesh, side_b[0], side_b[1], topic, "only-B", 0x9A27_00B1u64).await;
    assert_eq!(resp["ok"], true);
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let inboxes = mesh.drain_all();
    for &a in &side_a {
        assert!(inboxes[a].iter().any(|(d, _)| d == "only-A"), "side A node {a} missed in-half message");
        assert!(!inboxes[a].iter().any(|(d, _)| d == "only-B"), "partition leaked B->A at node {a}");
    }
    for &b in &side_b {
        assert!(inboxes[b].iter().any(|(d, _)| d == "only-B"), "side B node {b} missed in-half message");
        assert!(!inboxes[b].iter().any(|(d, _)| d == "only-A"), "partition leaked A->B at node {b}");
    }
    println!("REPORT part N={n} split contained (A-only and B-only stayed in-half)");

    // Heal: restore the exact cross-half links, let the reconnect loop redial.
    for &a in &side_a {
        for &b in &side_b {
            let lab = saved.remove(&(a, b)).expect("saved a->b");
            mesh.nodes[a].peers.write().await.insert(mesh.ids[b], lab);
            let lba = saved.remove(&(b, a)).expect("saved b->a");
            mesh.nodes[b].peers.write().await.insert(mesh.ids[a], lba);
        }
    }
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let _ = mesh.drain_all();

    // Post-heal publishers MUST be fresh origins (never published on this
    // topic before). `pubsub.msg` delivery is per-(origin, topic) seq-ordered
    // (`node.rs` reorder buffer): a receiver that missed `only-A` (seq 2 from
    // origin side_a[1]) buffers seq 3 forever waiting for the gap — gossip is
    // ephemeral, no history sync. Fresh origins start at seq 1 = expected
    // everywhere, so post-heal coverage gates the mesh heal, not backfill.
    let heal_a_exec = side_a[side_a.len() - 1];
    let heal_b_exec = side_b[side_b.len() - 1];
    let resp = publish_via(&mesh, side_a[0], heal_a_exec, topic, "healed-A", 0x9A27_0EA1u64).await;
    assert_eq!(resp["ok"], true);
    let resp = publish_via(&mesh, side_b[0], heal_b_exec, topic, "healed-B", 0x9A27_0EB1u64).await;
    assert_eq!(resp["ok"], true);
    let (rounds, inboxes) = poll_rounds(&mut mesh, 60, &|len, got| {
        (0..len).all(|i| {
            got[i].iter().any(|(d, _)| d == "healed-A") && got[i].iter().any(|(d, _)| d == "healed-B")
        })
    })
    .await;
    // No permanent fork: every node holds exactly the post-heal set, each
    // message exactly once.
    for (i, inbox) in inboxes.iter().enumerate() {
        let mut got = HashSet::new();
        for (d, _) in inbox.iter().filter(|(d, _)| d.starts_with("healed-")) {
            assert!(got.insert(d.clone()), "node {i} duplicate post-heal delivery of {d}");
        }
        assert_eq!(got.len(), 2, "node {i} post-heal set diverged (fork): {got:?}");
    }
    println!("REPORT part N={n} heal_rounds={rounds} converged=1 fork=0");
}
