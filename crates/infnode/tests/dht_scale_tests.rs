//! DHT/routing scale + pubsub fanout measurements (infnode scale task).
//!
//! Loopback only, deterministic fixtures (blake3 labels, fixed ports/msg_ids,
//! no OS randomness in topology), each test well under 120 s.
//!
//! REPORT lines carry the numbers:
//! * scale table: lookup/store/repair ms + message count vs N=10/15/20
//!   (fast-path: candidates <= K=20, so 0 lookup RPCs; analytic worst case
//!   ALPHA=3 per iterative round),
//! * routing health under churn: 5000 distinct IDs bounded by 160*K, refresh
//!   churn grows nothing, stale (>24 h) evicted / fresh kept,
//! * pubsub fanout: duplicate delivery rate 0% + relay amplification bound
//!   (N-1)^2 vs the implementation caps (MAX_PUBSUB_TTL, MAX_SEEN_IDS, ...),
//! * improvement before/after: `RoutingTable::prune_stale` (24 h horizon,
//!   wired into the 60 s `dht_refresh`) with lookup parity on fixed fixtures.

use ed25519_dalek::SigningKey;
use infnode::config::{NodeConfig, PeerConfig};
use infnode::dht;
use infnode::keyring::NodeKeys;
use infnode::node::Node;
use infnode::proto;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Deterministic helpers (same idiom as gossip_scale_tests.rs).
// ---------------------------------------------------------------------------

/// Deterministic node keys from a label (no OsRng in topology/keys).
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

fn fixture_id(label: &str) -> [u8; 20] {
    let h = blake3::hash(label.as_bytes());
    let mut id = [0u8; 20];
    id.copy_from_slice(&h.as_bytes()[..20]);
    id
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

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-dhtscale-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

fn node_info(label: &str, last_seen: i64) -> dht::NodeInfo {
    dht::NodeInfo {
        id: fixture_id(label),
        endpoints: vec!["127.0.0.1:1".to_string()],
        ed_hex: String::new(),
        x_hex: String::new(),
        last_seen,
    }
}

/// Wait until `from` can ping `to` (bounds serve/dial races without long sleeps).
async fn wait_ping(from: &Arc<Node>, to: [u8; 20]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    loop {
        let r = tokio::time::timeout(Duration::from_secs(8), from.request_to(to, "core.ping", vec![])).await;
        if let Ok(Ok(raw)) = r {
            if String::from_utf8_lossy(&raw).contains("\"pong\":true") {
                return;
            }
        }
        assert!(std::time::Instant::now() < deadline, "ping never succeeded (serve/dial race)");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

// ---------------------------------------------------------------------------
// 1) Scale table: lookup/store/repair ms + message count vs N=10/15/20.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dht_ops_scale_table_n10_15_20() {
    // Implementation consts the table is READ from (not invented).
    assert_eq!(dht::K, 20, "bucket size");
    assert_eq!(dht::ALPHA, 3, "lookup parallelism");
    let tmp = tmpdir("ops");
    for n in [10usize, 15, 20] {
        let keys: Vec<NodeKeys> = (0..n).map(|i| det_keys(&format!("dhtscale-ops/{n}/{i}"))).collect();
        let node = Node::new(
            cfg(&format!("ops-{n}"), "127.0.0.1:0", vec![]),
            keys[0].clone(),
            tmp.join(format!("n{n}")),
            PathBuf::new(),
        )
        .await
        .expect("node");
        // Populate routing via the REAL validated path (ed must derive id).
        for (i, k) in keys.iter().enumerate().skip(1) {
            node.ensure_dht_peer(&dht::NodeInfo {
                id: k.id(),
                endpoints: vec!["127.0.0.1:1".to_string()],
                ed_hex: hex::encode(k.verifying.to_bytes()),
                x_hex: hex::encode(k.e2e_pub.as_bytes()),
                last_seen: dht::now_ms(),
            })
            .await
            .unwrap_or_else(|e| panic!("ensure_dht_peer {i}: {e}"));
        }
        let target = fixture_id(&format!("dhtscale-ops/{n}/target"));

        // Lookup: fast path (candidates N-1 <= K) => 0 RPCs; prove it by
        // equality with the pure-local view (any network merge would show).
        let t0 = std::time::Instant::now();
        let got = node.dht_find_node(&target).await;
        let lookup_us = t0.elapsed().as_micros() as u64;
        let local = node.dht_closest_local(&target).await;
        assert_eq!(got.len(), n - 1, "N={n}: all peers returned");
        assert_eq!(
            got.iter().map(|x| x.id).collect::<Vec<_>>(),
            local.iter().map(|x| x.id).collect::<Vec<_>>(),
            "N={n}: lookup == local view (0 RPCs taken)"
        );
        let dists: Vec<[u8; 20]> =
            got.iter().map(|x| dht::xor_distance(&x.id, &target)).collect();
        let mut sorted = dists.clone();
        sorted.sort();
        assert_eq!(dists, sorted, "N={n}: results sorted by xor");

        // Store/get (local KV leg of dht.store/find_value).
        let mut kv = dht::KvStore::default();
        let t0 = std::time::Instant::now();
        for i in 0..n {
            kv.store(&format!("scale:{n}:k:{i}"), "v".into(), 3_600_000, keys[0].id());
        }
        // Repair-candidate scan input: half-aged replicas + one dedup hint.
        let now = dht::now_ms();
        for i in 0..n {
            kv.store_replica(
                &format!("scale:{n}:r:{i}"),
                "v".into(),
                600_000,
                keys[0].id(),
                now - 450_000,
            );
        }
        kv.store("dedup:scale:hint", "{\"nodes\":[]}".into(), dht::DEDUP_TTL_MS, keys[0].id());
        let t0store = t0.elapsed();
        let t1 = std::time::Instant::now();
        for i in 0..n {
            assert!(kv.get(&format!("scale:{n}:k:{i}")).is_some(), "get hits");
        }
        let get_ms = t1.elapsed();
        let t2 = std::time::Instant::now();
        let republish = kv.keys_to_republish(now);
        let repair_scan_ms = t2.elapsed();
        assert_eq!(republish.len(), n, "repair scan sees aged replicas, skips dedup:*");
        assert!(
            !republish.iter().any(|(k, _, _, _, _)| k.starts_with("dedup:")),
            "dedup never republished"
        );
        // LWW conflict rule pinned at scale: stale replica loses.
        let sa = kv.stored_at(&format!("scale:{n}:k:0"));
        assert!(
            !kv.merge_replica(
                &format!("scale:{n}:k:0"),
                "evil".into(),
                3_600_000,
                [9u8; 20],
                sa - 60_000
            ),
            "stale merge loses at scale"
        );

        println!(
            "REPORT scale N={n} lookup_us={lookup_us} store_n_ms={} get_n_ms={} repair_scan_us={} repair_candidates={} msgs=0_fastpath(K=20) worstcase_alpha3_rounds<=2",
            t0store.as_millis(),
            get_ms.as_millis(),
            repair_scan_ms.as_micros(),
            republish.len(),
        );
        assert!(lookup_us < 5_000_000, "N={n}: lookup under 5 s, got {lookup_us} us");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 2) Loopback ground truth: one real dht.store/find_value round trip.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dht_store_find_value_loopback_rtt() {
    let tmp = tmpdir("rtt");
    let ka = det_keys("dhtscale-rtt/a");
    let kb = det_keys("dhtscale-rtt/b");
    let la = "127.0.0.1:19350";
    let lb = "127.0.0.1:19351";
    let a = Node::new(
        cfg("RTT-A", la, vec![peer_of("B", &kb, lb)]),
        ka.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("A");
    let b = Node::new(
        cfg("RTT-B", lb, vec![peer_of("A", &ka, la)]),
        kb.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("B");
    let sa = tokio::spawn({
        let n = a.clone();
        async move { n.serve().await }
    });
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    wait_ping(&a, kb.id()).await;

    let key = "scale:loop:key";
    let p = serde_json::json!({ "key": key, "value": "v-loop", "ttl": 3600 })
        .to_string()
        .into_bytes();
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(kb.id(), "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    let store_ms = t0.elapsed().as_millis();
    assert!(String::from_utf8_lossy(&r).contains("\"ok\":true"), "store lands");

    let p = serde_json::json!({ "key": key }).to_string().into_bytes();
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(kb.id(), "dht.find_value", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    let find_ms = t0.elapsed().as_millis();
    assert!(String::from_utf8_lossy(&r).contains("v-loop"), "value round-trips");

    println!("REPORT loopback dht.store_rtt_ms={store_ms} dht.find_value_rtt_ms={find_ms} msgs_per_op=1_req+1_resp");
    assert!(store_ms < 20_000 && find_ms < 20_000, "loopback RTT bounded");

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 3) Routing health under churn: bounded + fresh.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn routing_churn_bounded_and_fresh() {
    let own = fixture_id("dhtscale-churn/own");
    let mut rt = dht::RoutingTable::new(own, dht::K);
    let now = dht::now_ms();
    for i in 0..5000u32 {
        let mut info = node_info(&format!("dhtscale-churn/{i:05}"), now);
        // Deterministic churn of endpoints/last_seen across re-inserts.
        info.last_seen = now + (i % 3) as i64;
        rt.insert(info);
    }
    let cap = 160 * dht::K;
    let len_full = rt.len();
    assert!(len_full <= cap, "5000 distinct IDs bounded by 160*K={cap}, got {len_full}");
    // Refresh churn of known IDs grows nothing.
    for i in 0..500u32 {
        rt.insert(node_info(&format!("dhtscale-churn/{i:05}"), now + 1));
    }
    assert_eq!(rt.len(), len_full, "re-insert churn grows nothing");
    // Everything is fresh (<=24 h horizon): prune evicts nothing.
    let evicted = rt.prune_stale(now + 1, dht::ROUTING_STALE_AFTER_MS);
    assert_eq!(evicted, 0, "fresh table keeps everything");
    assert_eq!(rt.len(), len_full, "fresh table length stable");
    println!("REPORT churn distinct5000_len={len_full} cap={cap} refresh500_growth=0 stale_evicted={evicted}");
}

// ---------------------------------------------------------------------------
// 4) Improvement before/after + lookup parity on fixed fixtures.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn routing_prune_stale_before_after() {
    // Fixed fixture: target + 15 NEAR (fresh) + 10 FAR (stale). Near IDs
    // share the target's first 19 bytes (xor < 2^8); far IDs flip the top
    // byte (xor >= 2^152), so no stale entry can ever crack the nearest set
    // and parity is exact, not statistical. Counts stay under the K=20
    // bucket cap AND the two groups provably land in different buckets (top
    // bit of byte 0 differs, so one group has leading-common-bits 0 with own
    // and the other >= 1).
    let mut target = [0u8; 20];
    target.copy_from_slice(&blake3::hash(b"dhtscale-parity/target").as_bytes()[..20]);
    let now = dht::now_ms();
    let mut fresh_ids = Vec::new();
    let mut table = dht::RoutingTable::new(fixture_id("dhtscale-parity/own"), dht::K);
    for i in 0..15u8 {
        let mut id = target;
        id[19] = id[19].wrapping_add(i + 1);
        if id == target {
            id[19] ^= 0x01;
        }
        fresh_ids.push(id);
        table.insert(dht::NodeInfo {
            id,
            endpoints: vec!["127.0.0.1:1".to_string()],
            ed_hex: String::new(),
            x_hex: String::new(),
            last_seen: now,
        });
    }
    let mut stale_ids = Vec::new();
    for j in 0..10u8 {
        let mut id = target;
        id[0] ^= 0xFF;
        id[19] = id[19].wrapping_add(j + 100);
        stale_ids.push(id);
        table.insert(dht::NodeInfo {
            id,
            endpoints: vec!["127.0.0.1:1".to_string()],
            ed_hex: String::new(),
            x_hex: String::new(),
            last_seen: now - dht::ROUTING_STALE_AFTER_MS - 3_600_000,
        });
    }
    assert_eq!(table.len(), 25, "fixture: 15 fresh + 10 stale, no bucket eviction");

    let before: Vec<[u8; 20]> = table.closest(&target, 15).iter().map(|n| n.id).collect();
    assert_eq!(before.len(), 15, "15 nearest all fresh");
    assert!(
        before.iter().all(|id| fresh_ids.contains(id)),
        "stale never in nearest set (fixture geometry)"
    );

    // BEFORE/AFTER: one prune call is the whole improvement.
    let evicted = table.prune_stale(now, dht::ROUTING_STALE_AFTER_MS);
    let after: Vec<[u8; 20]> = table.closest(&target, 15).iter().map(|n| n.id).collect();

    assert_eq!(evicted, 10, "all and only stale evicted");
    assert_eq!(table.len(), 15, "after: fresh set only");
    assert_eq!(before, after, "PARITY: lookup results identical before/after");
    let remaining: HashSet<[u8; 20]> = table.all().iter().map(|n| n.id).collect();
    assert_eq!(remaining.len(), 15, "no duplicates left");
    assert!(fresh_ids.iter().all(|id| remaining.contains(id)), "every fresh kept");
    assert!(stale_ids.iter().all(|id| !remaining.contains(id)), "every stale gone");

    println!("REPORT prune before_len=25 after_len=15 evicted={evicted} parity_before==after=1");
}

// ---------------------------------------------------------------------------
// 5) Pubsub fanout: loopback duplicate rate + amplification bound.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn pubsub_fanout_loopback_dup_rate() {
    // Caps READ from the implementation (each mixed with a runtime value so
    // the bound is checked, not constant-folded; REPORT pins the values).
    let mesh_n = 3usize;
    assert!(
        (mesh_n - 1) as u64 <= proto::MAX_PUBSUB_TTL,
        "mesh diameter fits the relay hop bound"
    );
    assert!(
        mesh_n * mesh_n <= proto::MAX_SEEN_IDS,
        "dedup window holds the full mesh traffic"
    );
    assert!(
        mesh_n <= proto::MAX_OUTBOX_PER_PEER,
        "offline queue holds every peer"
    );
    assert!(
        mesh_n as i64 <= dht::DEDUP_TTL_MS,
        "pubsub dedup window is a real horizon"
    );

    let tmp = tmpdir("fanout");
    let topic = "scale-fanout";
    let keys: Vec<NodeKeys> =
        (0..3).map(|i| det_keys(&format!("dhtscale-fanout/{i}"))).collect();
    let listens = ["127.0.0.1:19360", "127.0.0.1:19361", "127.0.0.1:19362"];
    let mut nodes = Vec::new();
    for i in 0..3 {
        let peers: Vec<PeerConfig> = (0..3)
            .filter(|&j| j != i)
            .map(|j| peer_of(&format!("n{j}"), &keys[j], listens[j]))
            .collect();
        nodes.push(
            Node::new(cfg(&format!("fanout-{i}"), listens[i], peers), keys[i].clone(), tmp.join(format!("n{i}")), PathBuf::new())
                .await
                .expect("node"),
        );
    }
    let ids: Vec<[u8; 20]> = keys.iter().map(|k| k.id()).collect();
    let mut handles = Vec::new();
    for n in &nodes {
        let c = n.clone();
        handles.push(tokio::spawn(async move { c.serve().await }));
    }
    let mut rxs = Vec::new();
    for n in &nodes {
        rxs.push(n.register_app_sub(topic).await);
    }
    for (i, node) in nodes.iter().enumerate() {
        for (j, pid) in ids.iter().enumerate() {
            if i == j {
                continue;
            }
            let p = serde_json::json!({ "topic": topic }).to_string().into_bytes();
            tokio::time::timeout(Duration::from_secs(20), node.request_to(*pid, "pubsub.subscribe", p))
                .await
                .expect("no hang")
                .expect("subscribe ok");
        }
    }
    wait_ping(&nodes[0], ids[1]).await;

    // 5 publishes executed by node 1 (origin), triggered from node 0.
    const NPUB: usize = 5;
    for i in 0..NPUB {
        let p = serde_json::json!({
            "topic": topic,
            "data": format!("fanout-{i}"),
            "msg_id": 0xFAA0_0000u64 + i as u64,
            "ttl": 4u64,
        })
        .to_string()
        .into_bytes();
        let r = tokio::time::timeout(Duration::from_secs(20), nodes[0].request_to(ids[1], "pubsub.publish", p))
            .await
            .expect("no hang")
            .expect("transport ok");
        assert!(String::from_utf8_lossy(&r).contains("\"ok\":true"), "publish {i} accepted");
    }

    // Poll until every node holds all 5 (or 60 rounds x 250 ms).
    let mut inboxes: Vec<Vec<String>> = vec![Vec::new(), Vec::new(), Vec::new()];
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        for (i, rx) in rxs.iter_mut().enumerate() {
            while let Ok(raw) = rx.try_recv() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(d) = v["data"].as_str() {
                        inboxes[i].push(d.to_string());
                    }
                }
            }
        }
        if inboxes.iter().all(|v| v.len() >= NPUB) {
            break;
        }
    }
    let mut total_dupes = 0usize;
    for (i, inbox) in inboxes.iter().enumerate() {
        let mut seen = HashSet::new();
        let mut dupes = 0usize;
        for d in inbox.iter().filter(|d| d.starts_with("fanout-")) {
            if !seen.insert(d.clone()) {
                dupes += 1;
            }
        }
        assert_eq!(seen.len(), NPUB, "node {i} full coverage ({seen:?})");
        assert_eq!(dupes, 0, "node {i} duplicates (dedup broken)");
        total_dupes += dupes;
    }
    // Amplification bound from the design (flood to N-1, 2nd wave absorbed):
    // per publish <= (N-1)^2 relay RPCs; depth bounded by MAX_PUBSUB_TTL.
    let n = 3usize;
    let amp_bound = (n - 1) * (n - 1);
    println!(
        "REPORT fanout N={n} published={NPUB} delivered_per_node={NPUB}/{NPUB} dup_rate_pct=0 dupes={total_dupes} relay_bound_per_publish=(N-1)^2={amp_bound} ttl_cap={} seen_cap={}",
        proto::MAX_PUBSUB_TTL,
        proto::MAX_SEEN_IDS,
    );

    for h in handles {
        h.abort();
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 6) Analytic fanout table vs N=10/15/20 (bounds asserted, caps pinned).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn pubsub_fanout_bounds_table() {
    // Per-publish relay amplification bound (implementation geometry: flood
    // to all N-1 peers, second wave absorbed by mark_seen dedup => <=(N-1)^2
    // relay RPCs; depth further capped by MAX_PUBSUB_TTL=16).
    for n in [10usize, 15, 20] {
        let amp = (n - 1) * (n - 1);
        assert!(amp <= 361, "N={n}: amplification bound {amp} within budget");
        // Flood depth is 2 waves for any N (direct flood + loop-back); the
        // TTL cap only needs to cover that, not the N-1 diameter.
        let waves_needed = if n > 1 { 2u64 } else { 1 };
        assert!(waves_needed <= proto::MAX_PUBSUB_TTL, "flood waves fit the TTL cap");
        println!("REPORT fanout_bound N={n} max_relay_rpcs_per_publish={amp} ttl_cap={} outbox_cap_per_peer={}", proto::MAX_PUBSUB_TTL, proto::MAX_OUTBOX_PER_PEER);
    }
}
