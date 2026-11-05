//! Backpressure audit tests (2026-11-03): caps, sheds, fairness.
//!
//! Scope: connection/backpressure tables in `node.rs` only. Every test drives
//! the REAL production path via the `bp_*` hooks (no logic duplication):
//! cap enforcement per structure, abusive-peer starvation attempt defeated
//! (enqueue isolation + fair drain), honest throughput unaffected, and shed
//! counters moving on the existing `outbox_dropped` metric.

use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{
    Node, MAX_APP_SUBS_PER_TOPIC, MAX_CONN_PEERS_TOTAL, MAX_CONNS_PER_PEER,
    MAX_MAIL_CACHE_ENTRIES, MAX_OUTBOX_FLUSH_PER_PEER, MAX_OUTBOX_PEERS_TOTAL,
    MAX_REORDER_BUF_PER_KEY, MAX_REORDER_KEYS, MAX_ROUTES_TOTAL,
    MAX_SESSIONLESS_GUARD_PEERS, MAX_SESSIONS_TOTAL, MAX_SUBS_PEERS_PER_TOPIC,
    MAX_SUBS_TOPICS, MAX_TOPIC_SEQ_TOPICS,
};
use infnode::proto::MAX_OUTBOX_PER_PEER;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn cfg(name: &str, listen: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
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
        web_static: None,
        wallet: None,
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-bp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let tmp = tmpdir(tag);
    let node = Node::new(
        cfg("T", "127.0.0.1:0"),
        NodeKeys::generate(),
        PqKeys::generate(),
        tmp.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, tmp)
}

fn pid(byte: u8, salt: u8) -> [u8; 20] {
    let mut p = [byte; 20];
    p[0] = salt;
    p[19] = byte;
    p
}

fn pid_n(n: usize) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[..8].copy_from_slice(&(n as u64).to_le_bytes());
    p[8..16].copy_from_slice(&((n as u64).wrapping_mul(0x9E3779B97F4A7C15)).to_le_bytes());
    p
}

// ---------------------------------------------------------------------------
// Outbox: per-peer cap + shed counter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn outbox_per_peer_cap_enforced_and_counted() {
    let (node, tmp) = test_node("per-peer").await;
    let evil = pid(1, 7);
    let over = MAX_OUTBOX_PER_PEER + 6;
    for i in 0..over {
        node.bp_enqueue_outbox(
            evil,
            "t".to_string(),
            format!("d{i}"),
            i as u64,
            i as u64,
            "o".to_string(),
        )
        .await;
    }
    assert_eq!(node.bp_outbox_len(evil).await, MAX_OUTBOX_PER_PEER);
    // Fail-closed shed: newest beyond the cap are dropped, counter moves.
    assert_eq!(node.outbox_dropped_total(), 6);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Outbox: outer peer-queue cap (many peer ids must not grow memory)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn outbox_outer_peer_cap_enforced_and_counted() {
    let (node, tmp) = test_node("outer").await;
    let n = MAX_OUTBOX_PEERS_TOTAL + 5;
    for i in 0..n {
        node.bp_enqueue_outbox(
            pid_n(i),
            "t".to_string(),
            "d".to_string(),
            i as u64,
            i as u64,
            "o".to_string(),
        )
        .await;
    }
    assert_eq!(node.bp_outbox_peer_count().await, MAX_OUTBOX_PEERS_TOTAL);
    assert_eq!(node.outbox_dropped_total(), 5);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Fairness, enqueue side: abusive flood cannot evict honest queues
// ---------------------------------------------------------------------------

#[tokio::test]
async fn abusive_peer_cannot_starve_honest_queues() {
    let (node, tmp) = test_node("isolate").await;
    let evil = pid(9, 9);
    let honest = pid(3, 3);
    for i in 0..(MAX_OUTBOX_PER_PEER + 50) {
        node.bp_enqueue_outbox(
            evil,
            "t".to_string(),
            format!("evil{i}"),
            i as u64,
            i as u64,
            "evil".to_string(),
        )
        .await;
    }
    for i in 0..3u64 {
        node.bp_enqueue_outbox(
            honest,
            "t".to_string(),
            format!("honest{i}"),
            1_000_000 + i,
            i,
            "honest".to_string(),
        )
        .await;
    }
    // Honest queue is fully intact despite the abusive flood next to it.
    assert_eq!(node.bp_outbox_len(honest).await, 3);
    assert_eq!(node.bp_outbox_len(evil).await, MAX_OUTBOX_PER_PEER);
    assert_eq!(node.outbox_dropped_total(), 50);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Fairness, drain side: one flush cycle services every peer (round-robin)
//
// Drain semantics (pre-existing): an unsendable head-of-line message is
// retried in place until `attempts >= 5`, then dropped and counted. One
// message therefore costs 6 iterations. The per-peer budget
// (`MAX_OUTBOX_FLUSH_PER_PEER`) bounds how many iterations ONE peer can
// consume per cycle, so an abusive flood cannot monopolize the drain while
// honest peers wait behind it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flush_is_fair_and_honest_throughput_unaffected() {
    let (node, tmp) = test_node("fair").await;
    let evil = pid(9, 9);
    let honest = pid(3, 3);
    // Evil queue far beyond one flush budget; honest queue small.
    for i in 0..200u64 {
        node.bp_enqueue_outbox(
            evil,
            "t".to_string(),
            format!("evil{i}"),
            i,
            i,
            "evil".to_string(),
        )
        .await;
    }
    for i in 0..3u64 {
        node.bp_enqueue_outbox(
            honest,
            "t".to_string(),
            format!("honest{i}"),
            1_000_000 + i,
            i,
            "honest".to_string(),
        )
        .await;
    }
    node.bp_flush_outbox_once().await;

    // Honest peer fully serviced in the FIRST cycle despite the flood next
    // to it (unsendable here: no route, so serviced == attempts exhausted).
    assert_eq!(node.bp_outbox_len(honest).await, 0);
    // Evil peer got exactly one budget slice. Drain semantics: an unsendable
    // head costs 6 iterations (5 bumps + expiry pop), so one 32-iteration
    // budget expires exactly 5 messages and bumps the 6th twice.
    let expired = MAX_OUTBOX_FLUSH_PER_PEER / 6;
    assert_eq!(node.bp_outbox_len(evil).await, 200 - expired);
    assert_eq!(
        node.bp_outbox_attempts(evil).await[0] as usize,
        MAX_OUTBOX_FLUSH_PER_PEER - expired * 6
    );
    // Shed accounting pins the mechanism: 5 evil + 3 honest expiry drops.
    // Without the budget the same cycle would drop all 203 at once.
    assert_eq!(node.outbox_dropped_total(), 8);

    // Honest throughput unaffected: an honest-only baseline drains its queue
    // in one cycle exactly the same way, flood or no flood.
    let (solo, tmp2) = test_node("fair-solo").await;
    for i in 0..3u64 {
        solo.bp_enqueue_outbox(
            honest,
            "t".to_string(),
            format!("honest{i}"),
            1_000_000 + i,
            i,
            "honest".to_string(),
        )
        .await;
    }
    solo.bp_flush_outbox_once().await;
    assert_eq!(solo.bp_outbox_len(honest).await, 0);
    assert_eq!(solo.bp_outbox_attempts(honest).await.len(), 0);
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&tmp2);
}

fn peer_of(name: &str, keys: &NodeKeys, pq: &PqKeys, listen: &str) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        ed_pub: hex::encode(keys.verifying.to_bytes()),
        pq_pub: Some(pq.pq_pub_hex()),
        endpoints: vec![listen.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

fn mesh_cfg(name: &str, listen: &str, peers: Vec<PeerConfig>) -> NodeConfig {
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
        web_static: None,
        wallet: None,
    }
}

/// Live fairness: honest delivery succeeds end-to-end (real QUIC + auth +
/// app inbox) while an abusive flood sits in the same outbox.
#[tokio::test]
async fn honest_delivery_succeeds_despite_abusive_flood() {
    let base = tmpdir("live");
    let keys_a = NodeKeys::generate();
    let pq_a = PqKeys::generate();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();
    let listen_a = "127.0.0.1:21100".to_string();
    let listen_b = "127.0.0.1:21101".to_string();
    let cfg_a = mesh_cfg("live-a", &listen_a, vec![peer_of("b", &keys_b, &pq_b, &listen_b)]);
    let cfg_b = mesh_cfg("live-b", &listen_b, vec![peer_of("a", &keys_a, &pq_a, &listen_a)]);
    let dir_a = base.join("a");
    let dir_b = base.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let node_a = Node::new(cfg_a, keys_a, pq_a, dir_a, PathBuf::new()).await.unwrap();
    let id_b = pq_b.pq_id();
    let node_b = Node::new(cfg_b, keys_b, pq_b, dir_b, PathBuf::new()).await.unwrap();
    // Only B serves: A dials on demand inside flush. (Serving A too would
    // start A's background flush loop and make the counts below racy.)
    let hb = tokio::spawn({
        let n = node_b.clone();
        async move {
            let _ = n.serve().await;
        }
    });
    let mut rx_b = node_b.register_app_sub("t").await;

    // Abusive flood to an unknown (undialable) peer + one honest message.
    let evil = pid(9, 9);
    for i in 0..200u64 {
        node_a
            .bp_enqueue_outbox(evil, "t".to_string(), format!("evil{i}"), i, i, "evil".to_string())
            .await;
    }
    node_a
        .bp_enqueue_outbox(id_b, "t".to_string(), "honest-live".to_string(), 777, 1, "a".to_string())
        .await;
    node_a.bp_flush_outbox_once().await;

    // Honest message delivered to the live peer's app inbox.
    let mut got = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if let Ok(raw) = rx_b.try_recv() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if v["data"].as_str() == Some("honest-live") {
                    got = Some(raw);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(got.is_some(), "honest message must be delivered despite flood");
    // Honest queue drained by delivery; evil flood bounded to one budget.
    assert_eq!(node_a.bp_outbox_len(id_b).await, 0);
    assert_eq!(
        node_a.bp_outbox_len(evil).await,
        200 - MAX_OUTBOX_FLUSH_PER_PEER / 6
    );
    hb.abort();
    let _ = std::fs::remove_dir_all(&base);
}

// ---------------------------------------------------------------------------
// Reorder buffer: outer keys + inner buffer caps; shed delivers, not drops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reorder_tables_bounded_and_shed_delivers() {
    let (node, _tmp) = test_node("reorder").await;
    // Inner buffer first (table still empty, key admitted): hold `next` at
    // 1, buffer 2..=129 (128 entries, no drain).
    for seq in 2..=(MAX_REORDER_BUF_PER_KEY as u64 + 1) {
        let ready = node
            .bp_reorder_offer(
                "buf-origin".to_string(),
                "t".to_string(),
                seq,
                format!("d{seq}"),
                "s".to_string(),
            )
            .await;
        assert!(ready.is_empty(), "gap must buffer, seq={seq}");
    }
    let (_, max_buf) = node.bp_reorder_sizes().await;
    assert_eq!(max_buf, MAX_REORDER_BUF_PER_KEY);
    // Far-future seq beyond a full buffer: delivered now, buffer untouched.
    let ready = node
        .bp_reorder_offer(
            "buf-origin".to_string(),
            "t".to_string(),
            50_000,
            "far".to_string(),
            "s".to_string(),
        )
        .await;
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].0, "far");
    assert_eq!(node.bp_reorder_sizes().await.1, MAX_REORDER_BUF_PER_KEY);
    // Ordering still works: seq 1 drains itself plus the contiguous run.
    let ready = node
        .bp_reorder_offer(
            "buf-origin".to_string(),
            "t".to_string(),
            1,
            "first".to_string(),
            "s".to_string(),
        )
        .await;
    assert_eq!(ready.len(), MAX_REORDER_BUF_PER_KEY + 1);
    assert_eq!(ready[0].0, "first");

    // Fill distinct keys beyond the cap: each first-seq message drains.
    for i in 0..(MAX_REORDER_KEYS + 10) {
        let ready = node
            .bp_reorder_offer(
                format!("origin{i}"),
                "t".to_string(),
                1,
                "d".to_string(),
                "s".to_string(),
            )
            .await;
        assert_eq!(ready.len(), 1, "contiguous seq must drain immediately");
    }
    let (keys, _) = node.bp_reorder_sizes().await;
    assert!(keys <= MAX_REORDER_KEYS, "keys={keys}");

    // Unknown key beyond cap: shed delivers immediately, table not grown.
    let before = node.bp_reorder_sizes().await.0;
    let ready = node
        .bp_reorder_offer(
            "new-origin-beyond-cap".to_string(),
            "t".to_string(),
            1,
            "d".to_string(),
            "s".to_string(),
        )
        .await;
    assert_eq!(ready.len(), 1);
    assert_eq!(node.bp_reorder_sizes().await.0, before);
}

// ---------------------------------------------------------------------------
// Mail cache: bounded with eviction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mail_cache_bounded() {
    let (node, _tmp) = test_node("mailcache").await;
    for i in 0..(MAX_MAIL_CACHE_ENTRIES + 50) {
        node.bp_mail_cache_insert(format!("mail{i}"), vec![i as u8; 16])
            .await;
    }
    assert!(node.bp_mail_cache_len().await <= MAX_MAIL_CACHE_ENTRIES);
}

// ---------------------------------------------------------------------------
// Subs: topic + peer caps, fail-closed refuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subs_tables_bounded_fail_closed() {
    let (node, _tmp) = test_node("subs").await;
    for i in 0..(MAX_SUBS_TOPICS + 10) {
        let ok = node.bp_sub_book(&format!("topic{i}"), pid_n(i)).await;
        if i < MAX_SUBS_TOPICS {
            assert!(ok, "under cap must admit");
        } else {
            assert!(!ok, "beyond cap must shed");
        }
    }
    let (topics, _) = node.bp_subs_sizes().await;
    assert_eq!(topics, MAX_SUBS_TOPICS);

    // Peers of one topic.
    let (node2, _tmp2) = test_node("subs-peers").await;
    for i in 0..(MAX_SUBS_PEERS_PER_TOPIC + 10) {
        let ok = node2.bp_sub_book("single", pid_n(i)).await;
        if i < MAX_SUBS_PEERS_PER_TOPIC {
            assert!(ok);
        } else {
            assert!(!ok);
        }
    }
    let (_, max_peers) = node2.bp_subs_sizes().await;
    assert_eq!(max_peers, MAX_SUBS_PEERS_PER_TOPIC);
}

// ---------------------------------------------------------------------------
// Sessions: bounded, fail-closed refuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sessions_table_bounded_fail_closed() {
    let (node, _tmp) = test_node("sessions").await;
    for i in 0..MAX_SESSIONS_TOTAL {
        assert!(node.bp_session_insert(i, [i as u8; 32]).await);
    }
    assert_eq!(node.bp_sessions_len().await, MAX_SESSIONS_TOTAL);
    assert!(!node.bp_session_insert(usize::MAX, [0xFF; 32]).await);
    assert_eq!(node.bp_sessions_len().await, MAX_SESSIONS_TOTAL);
}

// ---------------------------------------------------------------------------
// Conns: per-peer cap with oldest eviction; total peer cap
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls12 disabled".to_string()))
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Mint `n` real loopback QUIC connections (distinct stable_ids).
async fn mint_conns(n: usize) -> Vec<quinn::Connection> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der =
        rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(
        certified.key_pair.serialize_der(),
    )
    .unwrap();
    let server_cfg = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der).unwrap();
    let server_ep = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server_ep.accept().await {
            if let Ok(conn) = incoming.await {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    drop(conn);
                });
            }
        }
    });
    let mut client_ep =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).unwrap();
    let rc = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
    .with_no_client_auth();
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(std::sync::Arc::new(rc)).unwrap();
    client_ep.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(quic_cfg)));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        out.push(conn);
    }
    out
}

#[tokio::test]
async fn conns_tables_bounded() {
    let (node, _tmp) = test_node("conns").await;
    let conns = mint_conns(MAX_CONNS_PER_PEER + 2).await;
    let peer = pid(5, 5);
    for c in &conns {
        node.bp_conn_insert(peer, c.clone()).await;
    }
    // Per-peer cap: oldest evicted, cap holds.
    assert_eq!(node.bp_conns_len(peer).await, MAX_CONNS_PER_PEER);

    // Total peer cap: one shared conn object across many peer ids (cheap,
    // exercises the admission rule, not the handshake).
    let shared = conns[0].clone();
    for i in 0..(MAX_CONN_PEERS_TOTAL + 5) {
        node.bp_conn_insert(pid_n(1_000_000 + i), shared.clone()).await;
    }
    assert!(node.bp_conns_peers().await <= MAX_CONN_PEERS_TOTAL);
}

// ---------------------------------------------------------------------------
// Topic seq: bounded, saturates to unordered seq at cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topic_seq_bounded_saturates() {
    let (node, _tmp) = test_node("tseq").await;
    for i in 0..MAX_TOPIC_SEQ_TOPICS {
        assert_eq!(node.bp_next_topic_seq(&format!("t{i}")).await, 1);
    }
    assert_eq!(node.bp_topic_seq_len().await, MAX_TOPIC_SEQ_TOPICS);
    // Unknown topic beyond cap: seq 0 (unordered legacy path), table not grown.
    assert_eq!(node.bp_next_topic_seq("one-too-many").await, 0);
    assert_eq!(node.bp_topic_seq_len().await, MAX_TOPIC_SEQ_TOPICS);
    // Known topics keep incrementing.
    assert_eq!(node.bp_next_topic_seq("t0").await, 2);
}

// ---------------------------------------------------------------------------
// Sessionless guard: bounded, fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sessionless_guard_bounded_fail_closed() {
    let (node, _tmp) = test_node("guard").await;
    for i in 0..MAX_SESSIONLESS_GUARD_PEERS {
        assert!(node.bp_guard_admit(pid_n(i)).await);
    }
    assert!(!node.bp_guard_admit(pid(0xAA, 0xBB)).await);
}

// ---------------------------------------------------------------------------
// Routes: total cap via the real gossip-merge path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routes_total_bounded_via_gossip_path() {
    let (node, _tmp) = test_node("routes").await;
    // 10 updates x 500 routes: each under MAX_ROUTES_PER_UPDATE, total far
    // beyond MAX_ROUTES_TOTAL.
    for batch in 0..10 {
        let mut routes = serde_json::Map::new();
        for i in 0..500 {
            let n = batch * 500 + i;
            let id_hex = format!("inf1:{}", hex::encode(pid_n(42_000 + n)));
            routes.insert(
                id_hex,
                serde_json::json!({
                    "endpoints": ["127.0.0.1:9"],
                    "ed_hex": "",
                }),
            );
        }
        let v = serde_json::json!({ "routes": routes });
        let resp = node.bp_handle_dht_update(v).await.expect("response");
        let rv: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(rv["ok"], true);
    }
    assert!(node.bp_routes_len().await <= MAX_ROUTES_TOTAL);
}

// ---------------------------------------------------------------------------
// App subs: dead receivers pruned, per-topic cap fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn app_subs_prune_dead_and_cap_live() {
    let (node, _tmp) = test_node("appsubs").await;
    // Dead receivers must not accumulate: register, drop, re-register.
    let mut rxs = Vec::new();
    for _ in 0..5 {
        rxs.push(node.register_app_sub("dead-topic").await);
    }
    assert_eq!(node.bp_app_subs_len("dead-topic").await, 5);
    drop(rxs);
    let _fresh = node.register_app_sub("dead-topic").await;
    assert_eq!(
        node.bp_app_subs_len("dead-topic").await,
        1,
        "dead receivers pruned on register"
    );

    // Live cap: keep receivers alive, overflow is shed.
    let mut live = Vec::new();
    for _ in 0..(MAX_APP_SUBS_PER_TOPIC + 10) {
        live.push(node.register_app_sub("live-topic").await);
    }
    assert_eq!(
        node.bp_app_subs_len("live-topic").await,
        MAX_APP_SUBS_PER_TOPIC
    );
    drop(live);
}

// ---------------------------------------------------------------------------
// Shed accounting: counters only ever move on real sheds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shed_counters_start_zero_and_move_only_on_shed() {
    let (node, tmp) = test_node("counters").await;
    assert_eq!(node.outbox_dropped_total(), 0);
    // Under-cap traffic: no drops.
    for i in 0..10u64 {
        node.bp_enqueue_outbox(
            pid(1, 1),
            "t".to_string(),
            "d".to_string(),
            i,
            i,
            "o".to_string(),
        )
        .await;
    }
    assert_eq!(node.outbox_dropped_total(), 0);
    assert_eq!(node.bp_outbox_len(pid(1, 1)).await, 10);
    let _ = std::fs::remove_dir_all(&tmp);
}
