//! Routing-level peer scoring and fast eviction (mesh wave, task 2).
//!
//! The circuit breaker (`circuit_*`) is per-circuit dial backoff: it decides
//! when a peer is worth redialling. This suite pins the DIFFERENT rule:
//! after three consecutive transport failures a peer is suspected dead and
//! withheld from DHT targets (`dht_closest_local` / `dht_find_node`), while
//! remaining explicitly dialable. A cooldown then allows exactly one
//! reconnect; a success clears the counter and restores the peer.

use infnode::config::NodeConfig;
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{Node, PEER_EVICT_COOLDOWN_MS, PEER_EVICT_FAIL_THRESHOLD};
use infnode::proto::{now_ms, NODEID_LEN};
use std::path::PathBuf;
use std::sync::Arc;

fn cfg() -> NodeConfig {
    NodeConfig {
        name: "peer-eviction-test".to_string(),
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
        "infnode-peer-evict-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let dir = tmpdir(tag);
    let node = Node::new(
        cfg(),
        NodeKeys::generate(),
        PqKeys::generate(),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, dir)
}

/// A valid, dialable DHT record for a synthetic peer.
fn peer_info(seed: u8, endpoint: &str) -> infnode::dht::NodeInfo {
    let pq = PqKeys::from_seed([seed; 32]);
    let pq_hex = pq.pq_pub_hex();
    let id = infnode::proto::pq_id_from_pub(&hex::decode(&pq_hex).expect("pq hex"));
    infnode::dht::NodeInfo {
        id,
        endpoints: vec![endpoint.to_string()],
        pq_hex,
        last_seen: now_ms(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_consecutive_failures_evict_a_peer_from_dht_targets() {
    let (node, dir) = test_node("three-failures").await;
    let peer = peer_info(0x41, "127.0.0.1:19991");
    node.ensure_dht_peer(&peer).await.expect("register peer");

    // Baseline: a live record is returned as a DHT target.
    let target = node.dht_closest_local(&peer.id).await;
    assert!(
        target.iter().any(|n| n.id == peer.id),
        "fresh peer must be a DHT target"
    );

    let now = now_ms();
    node.peer_record_failure_at(peer.id, now);
    node.peer_record_failure_at(peer.id, now);
    assert_eq!(
        node.peer_score(&peer.id).map(|s| s.consecutive_failures),
        Some(2),
        "two failures must not evict"
    );
    assert!(
        !node.peer_suspected(&peer.id),
        "threshold is {PEER_EVICT_FAIL_THRESHOLD} consecutive failures"
    );
    assert!(
        node.dht_closest_local(&peer.id)
            .await
            .iter()
            .any(|n| n.id == peer.id),
        "a peer under the threshold must still be a DHT target"
    );

    // Third consecutive failure: suspected dead, evicted from the target set.
    let score = node.peer_record_failure_at(peer.id, now);
    assert!(
        score.suspected,
        "third failure must mark the peer suspected"
    );
    assert_eq!(score.evictions, 1);
    assert_eq!(node.peer_evictions_total(), 1);
    assert!(
        node.dht_closest_local(&peer.id)
            .await
            .iter()
            .all(|n| n.id != peer.id),
        "suspected-dead peer must not be returned by dht_closest_local"
    );
    assert!(
        node.dht_find_node(&peer.id)
            .await
            .iter()
            .all(|n| n.id != peer.id),
        "suspected-dead peer must not be returned by dht_find_node"
    );
    assert_eq!(
        node.suspected_peers()
            .iter()
            .filter(|(id, _)| *id == peer.id)
            .count(),
        1,
        "the suspicion set must expose the dead peer"
    );

    // Explicit-destination rule: registering/dialling it still succeeds —
    // eviction only removes it from ROUTING, never from the address book.
    assert!(
        node.ensure_dht_peer(&peer).await.is_ok(),
        "a suspected peer stays explicitly dialable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cooldown_allows_one_reconnect_and_success_restores_the_peer() {
    let (node, dir) = test_node("cooldown").await;
    let peer = peer_info(0x42, "127.0.0.1:19992");
    node.ensure_dht_peer(&peer).await.expect("register peer");

    let t0 = now_ms();
    for _ in 0..PEER_EVICT_FAIL_THRESHOLD {
        node.peer_record_failure_at(peer.id, t0);
    }
    let score = node.peer_score(&peer.id).expect("score");
    assert!(score.suspected);
    assert_eq!(
        score.suspect_until_ms,
        t0 + PEER_EVICT_COOLDOWN_MS as i64,
        "default cooldown is 60 s"
    );
    assert!(
        !node.peer_reconnect_due(&peer.id),
        "no reconnect before the cooldown elapses"
    );
    assert!(
        !score.reconnect_due(t0 + PEER_EVICT_COOLDOWN_MS as i64 - 1),
        "one ms before expiry is still in cooldown"
    );
    assert!(
        score.reconnect_due(t0 + PEER_EVICT_COOLDOWN_MS as i64),
        "the cooldown boundary allows a reconnect attempt"
    );

    // Still withheld from routing after the cooldown: the retry is explicit.
    assert!(
        node.dht_closest_local(&peer.id)
            .await
            .iter()
            .all(|n| n.id != peer.id),
        "cooldown expiry alone must not re-advertise a dead peer"
    );

    // A successful reconnect clears the streak and suspicion.
    node.peer_record_success_at(peer.id, t0 + PEER_EVICT_COOLDOWN_MS as i64);
    let score = node.peer_score(&peer.id).expect("score");
    assert!(!score.suspected);
    assert_eq!(score.consecutive_failures, 0);
    assert!(
        node.dht_closest_local(&peer.id)
            .await
            .iter()
            .any(|n| n.id == peer.id),
        "a restored peer is a DHT target again"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eviction_cooldown_is_configurable_and_suspicion_is_sticky_through_it() {
    let (node, dir) = test_node("configurable").await;
    node.set_peer_evict_cooldown_ms(25);
    assert_eq!(node.peer_evict_cooldown_ms(), 25);

    let peer = peer_info(0x43, "127.0.0.1:19993");
    node.ensure_dht_peer(&peer).await.expect("register peer");
    let t0 = 1_000_000i64;
    for _ in 0..PEER_EVICT_FAIL_THRESHOLD {
        node.peer_record_failure_at(peer.id, t0);
    }
    let score = node.peer_score(&peer.id).expect("score");
    assert_eq!(score.suspect_until_ms, t0 + 25);
    assert!(score.suspected, "suspicion is sticky until a success");

    // A retry loop that keeps failing re-arms the cooldown but must not
    // re-advertise the peer at any point.
    node.peer_record_failure_at(peer.id, t0 + 30);
    assert!(node.peer_suspected(&peer.id));
    assert!(node
        .dht_closest_local(&peer.id)
        .await
        .iter()
        .all(|n| n.id != peer.id));

    // Different peers are scored independently.
    let healthy = peer_info(0x44, "127.0.0.1:19994");
    node.ensure_dht_peer(&healthy)
        .await
        .expect("register healthy");
    assert!(!node.peer_suspected(&healthy.id));
    assert!(node
        .dht_closest_local(&healthy.id)
        .await
        .iter()
        .any(|n| n.id == healthy.id));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_retry_rearms_the_cooldown_instead_of_hot_looping() {
    let (node, dir) = test_node("rearm").await;
    node.set_peer_evict_cooldown_ms(25);
    let peer = peer_info(0x47, "127.0.0.1:19997");
    let t0 = 1_000_000i64;
    for _ in 0..PEER_EVICT_FAIL_THRESHOLD {
        node.peer_record_failure_at(peer.id, t0);
    }
    let score = node.peer_score(&peer.id).expect("score");
    assert_eq!(score.suspect_until_ms, t0 + 25);

    // A failed explicit retry is a NEW failure, not a frozen past deadline:
    // without re-arming, `reconnect_due` stayed true forever and every
    // recovery pass retried the dead peer (hot loop).
    let score = node.peer_record_failure_at(peer.id, t0 + 30);
    assert_eq!(
        score.suspect_until_ms,
        t0 + 30 + 25,
        "a failed post-cooldown retry must re-arm the window"
    );
    assert!(
        !score.reconnect_due(t0 + 30),
        "the peer is back in cooldown immediately after the failed retry"
    );
    assert!(score.reconnect_due(t0 + 55));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dht_lookup_never_resolves_a_suspected_peer() {
    let (node, dir) = test_node("lookup-dead").await;
    let dead = peer_info(0x48, "127.0.0.1:19998");
    let target = format!("inf1:{}", hex::encode(dead.id));
    let routes = serde_json::json!({
        target.clone(): {
            "endpoints": dead.endpoints,
            "pq_pub": dead.pq_hex,
        }
    });
    let resp = node
        .bp_handle_dht_update_from(serde_json::json!({ "routes": routes }), [0xAA; NODEID_LEN])
        .await
        .expect("update response");
    assert!(String::from_utf8_lossy(&resp).contains("\"ok\":true"));

    let before = node
        .bp_handle_dht_lookup(&target, [0xBB; NODEID_LEN])
        .await
        .expect("lookup response");
    let before: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(before["found"], true, "a fresh route resolves");

    for _ in 0..PEER_EVICT_FAIL_THRESHOLD {
        node.peer_record_failure(dead.id);
    }
    let after = node
        .bp_handle_dht_lookup(&target, [0xBB; NODEID_LEN])
        .await
        .expect("lookup response");
    let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(
        after["found"], false,
        "a suspected-dead peer must not be handed to a searcher (wasted dial / black hole)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn third_party_gossip_cannot_rewrite_a_pinned_peer_endpoint() {
    use infnode::config::PeerConfig;

    let dir = tmpdir("pinned-endpoints");
    let pinned_pq = PqKeys::from_seed([0x49; 32]);
    let pinned_id = pinned_pq.pq_id();
    let pinned_endpoint = "127.0.0.1:19949".to_string();
    let cfg = NodeConfig {
        name: "pinned-endpoints".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![PeerConfig {
            name: "pinned".to_string(),
            consensus_pub: None,
            pq_pub: Some(pinned_pq.pq_pub_hex()),
            endpoints: vec![pinned_endpoint.clone()],
            allow: vec!["*".to_string()],
            rate_limit_per_sec: 0,
            role: None,
            storage_roles: vec![],
        }],
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
    };
    let node = Node::new(
        cfg,
        NodeKeys::generate(),
        PqKeys::generate(),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    let target = format!("inf1:{}", hex::encode(pinned_id));
    let attacker_endpoint = "127.0.0.1:9".to_string();
    let poisoned = serde_json::json!({
        target.clone(): {
            "endpoints": [attacker_endpoint.clone()],
            "pq_pub": pinned_pq.pq_pub_hex(),
        }
    });
    let resp = node
        .bp_handle_dht_update_from(
            serde_json::json!({ "routes": poisoned }),
            [0xAC; NODEID_LEN],
        )
        .await
        .expect("update response");
    assert!(String::from_utf8_lossy(&resp).contains("\"ok\":true"));

    let reply = node
        .bp_handle_dht_lookup(&target, [0xBB; NODEID_LEN])
        .await
        .expect("lookup response");
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["found"], true);
    let endpoints: Vec<String> = reply["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert!(
        endpoints.contains(&pinned_endpoint),
        "the pinned address stays authoritative, got {endpoints:?}"
    );
    assert!(
        !endpoints.contains(&attacker_endpoint),
        "third-party gossip must not append its endpoint to a pinned identity"
    );

    // ... but the peer advertising its OWN new endpoint is legitimate.
    let moved = serde_json::json!({
        target.clone(): {
            "endpoints": ["127.0.0.1:19950"],
            "pq_pub": pinned_pq.pq_pub_hex(),
        }
    });
    node.bp_handle_dht_update_from(serde_json::json!({ "routes": moved }), pinned_id)
        .await
        .expect("self update response");
    let reply = node
        .bp_handle_dht_lookup(&target, [0xBB; NODEID_LEN])
        .await
        .expect("lookup response");
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    let endpoints: Vec<String> = reply["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert!(
        endpoints.contains(&"127.0.0.1:19950".to_string()),
        "a self-advertised endpoint change is accepted, got {endpoints:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspicious_peers_are_not_advertised_to_dht_searchers() {
    let (node, dir) = test_node("not-advertised").await;
    let dead = peer_info(0x45, "127.0.0.1:19995");
    let live = peer_info(0x46, "127.0.0.1:19996");
    node.ensure_dht_peer(&dead).await.expect("register dead");
    node.ensure_dht_peer(&live).await.expect("register live");

    for _ in 0..PEER_EVICT_FAIL_THRESHOLD {
        node.peer_record_failure(dead.id);
    }
    assert!(node.peer_suspected(&dead.id));

    // The local "who is closest" answer (used for storage placement) never
    // includes the dead peer, while the live one survives.
    let targets: Vec<[u8; NODEID_LEN]> = node
        .dht_closest_local(&[0u8; NODEID_LEN])
        .await
        .into_iter()
        .map(|n| n.id)
        .collect();
    assert!(!targets.contains(&dead.id));
    assert!(targets.contains(&live.id));

    let _ = std::fs::remove_dir_all(&dir);
}
