//! SEC-S1 regression: the attacker-fed transport maps in `infnode::node` must
//! stay hard-bounded.
//!
//! Three tables are keyed by values an unauthenticated peer can mint cheaply:
//!
//! * `handshake_buckets`  — source IP (an IPv6 /64 is free);
//! * `auth_bans`          — source IP (after N failed handshakes);
//! * `peer_protocol`      — PQ identity (a fresh Falcon keypair per handshake).
//!
//! Before this fix each of them grew without a hard cap (the old "reap" only
//! ran above a soft threshold and could free nothing, and `peer_protocol` was
//! never pruned at all), i.e. a remote OOM primitive. These tests drive the
//! real production entry points and assert the observable live population
//! never exceeds the published cap, so they fail on the pre-fix code and pass
//! after it.

use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{Node, MAX_AUTH_BANS, MAX_HANDSHAKE_BUCKETS, MAX_PEER_PROTOCOL_ENTRIES};
use infnode::proto::{Capabilities, Hello, ProtocolVersion, INFNODE_FORK_ID};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

fn cfg(name: &str, listen: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
        client_listen: None,
        advertise: None,
        peers: Vec::<PeerConfig>::new(),
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
        web_static: None,
        wallet: None,
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "infnode-sec-s1-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let tmp = tmpdir(tag);
    let node = Node::new(
        cfg("SEC-S1", "127.0.0.1:0"),
        NodeKeys::generate(),
        PqKeys::generate(),
        tmp.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, tmp)
}

fn ip_in(base: u32, i: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(base.wrapping_add(i as u32)))
}

fn pid_of(i: usize) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[..8].copy_from_slice(&(i as u64).to_le_bytes());
    p[8] = 0x5a;
    p
}

#[tokio::test]
async fn attacker_fed_transport_maps_stay_hard_bounded() {
    // Ban on every failed handshake; long window/cooldown so nothing expires
    // during the test and the ONLY thing that can bound the map is the fix.
    std::env::set_var("STELL_INF_HANDSHAKE_PER_IP_PER_SEC", "30");
    std::env::set_var("STELL_INF_AUTH_FAIL_THRESHOLD", "1");
    std::env::set_var("STELL_INF_AUTH_FAIL_WINDOW_SECS", "3600");
    std::env::set_var("STELL_INF_AUTH_BAN_COOLDOWN_SECS", "3600");

    let (node, tmp) = test_node("maps").await;

    // 1) Handshake token-buckets: one distinct source IP per attempt.
    let handshake_n = MAX_HANDSHAKE_BUCKETS + 64;
    for i in 0..handshake_n {
        let allowed = node.handshake_allowed(ip_in(0x0a00_0000, i)).await;
        assert!(allowed, "a fresh IP must still be admitted (LRU eviction)");
    }
    let buckets = node.handshake_bucket_count().await;
    assert!(
        buckets <= MAX_HANDSHAKE_BUCKETS,
        "handshake_buckets grew to {buckets} > MAX_HANDSHAKE_BUCKETS ({MAX_HANDSHAKE_BUCKETS})"
    );

    // 2) Strike-bans: one ban per distinct source IP (threshold is 1 above).
    // The observable population is `is_banned` over every IP we fed; the
    // pre-fix map returned true for ALL of them (unbounded growth).
    // Disjoint range from the handshake IPs above.
    let ban_base = 0x0b00_0000u32;
    let ban_n = MAX_AUTH_BANS + 64;
    for i in 0..ban_n {
        node.record_auth_failure(ip_in(ban_base, i)).await;
    }
    let mut live_bans = 0usize;
    for i in 0..ban_n {
        if node.is_banned(&ip_in(ban_base, i)).await {
            live_bans += 1;
        }
    }
    assert!(
        live_bans <= MAX_AUTH_BANS,
        "auth_bans kept {live_bans} live bans > MAX_AUTH_BANS ({MAX_AUTH_BANS})"
    );

    // 3) Protocol verdicts: a fresh (cheap) PQ identity per HELLO. Count the
    // still-negotiated identities through the pre-existing accessor; pre-fix
    // all of them remained, unbounded.
    let hello = Hello::new(
        ProtocolVersion::new(1, 0),
        INFNODE_FORK_ID,
        Capabilities::ALL,
    );
    let proto_n = MAX_PEER_PROTOCOL_ENTRIES + 64;
    for i in 0..proto_n {
        node.apply_peer_hello(pid_of(i), hello);
    }
    let mut live_verdicts = 0usize;
    for i in 0..proto_n {
        if node.peer_protocol_state(&pid_of(i)).is_some() {
            live_verdicts += 1;
        }
    }
    assert!(
        live_verdicts <= MAX_PEER_PROTOCOL_ENTRIES,
        "peer_protocol kept {live_verdicts} verdicts > MAX_PEER_PROTOCOL_ENTRIES \
         ({MAX_PEER_PROTOCOL_ENTRIES})"
    );

    drop(node);
    let _ = std::fs::remove_dir_all(tmp);
}

/// SEC-S1: a peer's `dht.find_node` answer is capped BEFORE entry validation
/// and allocation. One answer can be a 32 MiB frame and each valid `NodeInfo`
/// carries a 1794-char `pq_pub`; without the cap a single hostile answer made
/// the node build/sort tens of megabytes of node records per lookup.
///
/// On the pre-fix code this test does not compile (the bounded helper does not
/// exist), which is the regression guard for the missing cap.
#[test]
fn dht_find_node_answer_is_capped_before_processing() {
    use infnode::proto::MAX_ROUTES_PER_UPDATE;

    let pq = PqKeys::generate();
    let node = serde_json::json!({
        "node_id": pq.pq_id_hex(),
        "endpoints": ["127.0.0.1:9411"],
        "pq_pub": pq.pq_pub_hex(),
    });
    let entries: Vec<serde_json::Value> = (0..MAX_ROUTES_PER_UPDATE + 100)
        .map(|_| node.clone())
        .collect();
    let answer = serde_json::json!({ "ok": true, "nodes": entries });

    let parsed = infnode::node::parse_dht_node_list(&answer);
    assert_eq!(
        parsed.len(),
        MAX_ROUTES_PER_UPDATE,
        "the answer walk must stop at MAX_ROUTES_PER_UPDATE before validating entries"
    );
}
