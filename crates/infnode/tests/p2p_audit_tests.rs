//! P2P transport security audit (2026-11-01) — attack tests, fail-closed.
//!
//! Scope: infnode crate only. Each test demonstrates an attack shape and
//! asserts the node refuses it without alloc blowup, crash, or outage:
//!   1. handshake flood — N rapid dials stay bounded, node stays responsive;
//!   2. oversized messages — refused before any big allocation;
//!   3. forged peer auth — bad sig, wrong key, replayed nonce, stale ts;
//!   4. DHT poison — oversized/forged blobs and route records refused;
//!   5. pubsub spam — dynamic peers denied, floods quotaed, TTL clamped;
//!   6. privilege inflation — a peer cannot widen its own ACL or budget.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::NodeKeys;
use infnode::node::Node;
use infnode::proto::{self, Frame, NODEID_LEN};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn cfg(name: &str, listen: &str, peers: Vec<PeerConfig>, allow_unknown: bool) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
        client_listen: None,
        advertise: None,
        peers,
        allow_unknown,
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

fn peer_of(
    name: &str,
    keys: &NodeKeys,
    listen: &str,
    rate: u32,
    storage_roles: Vec<String>,
) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        node_id: keys.id_hex(),
        ed_pub: hex::encode(keys.verifying.to_bytes()),
        x_pub: hex::encode(keys.e2e_pub.as_bytes()),
        pq_pub: None,
        endpoints: vec![listen.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: rate,
        role: None,
        storage_roles,
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-audit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn ping_ok(from: &Arc<Node>, pid: [u8; NODEID_LEN]) -> bool {
    tokio::time::timeout(Duration::from_secs(15), from.request_to(pid, "core.ping", vec![]))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

fn resp_text(resp: &[u8]) -> String {
    String::from_utf8_lossy(resp).to_string()
}

// ---------------------------------------------------------------------------
// 1. handshake flood: N rapid dials — accepted or rate-limited, but bounded.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn audit_handshake_flood_is_bounded() {
    let tmp = tmpdir("flood");
    let la = "127.0.0.1:19820";
    let lb = "127.0.0.1:19821";
    let ka = NodeKeys::generate();
    let kb = NodeKeys::generate();
    // B throttles A to 10 req/s: the flood must surface as explicit
    // rate-limit refusals, not hangs, errors, or an outage.
    let a = Node::new(
        cfg("A", la, vec![peer_of("B", &kb, lb, 0, vec![])], false),
        ka.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let b = Node::new(
        cfg("B", lb, vec![peer_of("A", &ka, la, 10, vec![])], false),
        kb.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");
    let sa = tokio::spawn({
        let n = a.clone();
        async move { n.serve().await }
    });
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let b_id = kb.id();

    let mut tasks = Vec::new();
    for _ in 0..60u32 {
        let n = a.clone();
        tasks.push(tokio::spawn(async move {
            n.request_to(b_id, "core.ping", vec![]).await
        }));
    }
    let mut passed = 0usize;
    let mut limited = 0usize;
    let mut errored = 0usize;
    for t in tasks {
        match tokio::time::timeout(Duration::from_secs(20), t).await {
            Ok(Ok(Ok(resp))) if resp_text(&resp).contains("\"pong\":true") => passed += 1,
            Ok(Ok(Ok(resp))) if resp_text(&resp).contains("rate limit exceeded") => {
                limited += 1;
            }
            _ => errored += 1,
        }
    }
    assert_eq!(
        passed + limited + errored,
        60,
        "every dial must resolve (no hangs)"
    );
    assert_eq!(errored, 0, "no dial may fail with a transport error");
    assert!(
        limited >= 20,
        "flood must be visibly quotaed, got {limited} refusals / {passed} passes"
    );
    // Node stays responsive after the flood (bucket refills).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(ping_ok(&a, b_id).await, "node must serve after the flood");

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 2. oversized messages: refused, no alloc blowup.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn audit_oversized_messages_refused() {
    let tmp = tmpdir("oversize");
    let la = "127.0.0.1:19822";
    let lb = "127.0.0.1:19823";
    let ka = NodeKeys::generate();
    let kb = NodeKeys::generate();
    let a = Node::new(
        cfg("A", la, vec![peer_of("B", &kb, lb, 0, vec![])], false),
        ka.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let b = Node::new(
        cfg("B", lb, vec![peer_of("A", &ka, la, 0, vec![])], false),
        kb.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");
    let sa = tokio::spawn({
        let n = a.clone();
        async move { n.serve().await }
    });
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let b_id = kb.id();

    // DHT value 2 MiB over the 1 MiB service cap (far under the 32 MiB frame).
    let big_value = "v".repeat(2 * 1024 * 1024);
    let p = serde_json::json!({ "key": "audit:big", "value": big_value, "ttl": 3600 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("value too large"),
        "oversized DHT value must be refused, got {}",
        resp_text(&r).chars().take(120).collect::<String>()
    );

    // Oversized key.
    let p = serde_json::json!({ "key": "k".repeat(600), "value": "v", "ttl": 60 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("bad key"), "oversized key refused");

    // Bad TTLs: zero, negative-as-default-bypass, huge.
    for ttl in [
        serde_json::json!(0),
        serde_json::json!(-5),
        serde_json::json!(u64::MAX),
    ] {
        let p = serde_json::json!({ "key": "audit:ttl", "value": "v", "ttl": ttl })
            .to_string()
            .into_bytes();
        let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
            .await
            .expect("no hang")
            .expect("transport ok");
        assert!(
            resp_text(&r).contains("bad ttl"),
            "ttl {ttl} must be refused"
        );
    }

    // Storage chunk 3 MiB decoded over the 2 MiB cap.
    let chunk = vec![7u8; 3 * 1024 * 1024];
    let p = serde_json::json!({
        "bucket": "files",
        "chunk_id": "ab".repeat(32),
        "data": base64::engine::general_purpose::STANDARD.encode(&chunk),
    })
    .to_string()
    .into_bytes();
    let r = tokio::time::timeout(
        Duration::from_secs(20),
        a.request_to(b_id, "storage.store", p),
    )
    .await
    .expect("no hang")
    .expect("transport ok");
    assert!(
        resp_text(&r).contains("chunk too large"),
        "oversized chunk refused"
    );

    // Pubsub payload 2 MiB over the 1 MiB cap.
    let p = serde_json::json!({ "topic": "audit", "data": "d".repeat(2 * 1024 * 1024) })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "pubsub.publish", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("data too large"),
        "oversized publish refused"
    );

    // Frame envelope itself: plen beyond MAX_FRAME never decodes.
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut f = Frame {
        kind: 4,
        seq: 1,
        ts: 1,
        src: [1u8; NODEID_LEN],
        dst: [2u8; NODEID_LEN],
        svc: 0,
        payload: b"tiny".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    let mut wire = f.encode();
    wire[64..68].copy_from_slice(&((proto::MAX_FRAME + 1) as u32).to_le_bytes());
    assert!(
        Frame::decode(&wire).is_err(),
        "frame over MAX_FRAME refused"
    );

    assert!(ping_ok(&a, b_id).await, "node responsive after refusals");
    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 3. forged peer auth over raw QUIC: bad sig, wrong key, replay, stale ts.
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

async fn raw_connect(addr: SocketAddr) -> quinn::Connection {
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback"))
        .expect("client endpoint");
    let rc = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
    .with_no_client_auth();
    let quic_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(std::sync::Arc::new(rc)).expect("quic");
    let mut cc = quinn::ClientConfig::new(std::sync::Arc::new(quic_cfg));
    cc.transport_config(std::sync::Arc::new(quinn::TransportConfig::default()));
    ep.set_default_client_config(cc);
    ep.connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake")
}

/// None = refused (connection closed / timeout / non-AUTH). Some = accepted.
async fn raw_handshake(conn: &quinn::Connection, wire: &[u8]) -> Option<Frame> {
    let (mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
            .await
            .ok()?
            .ok()?;
    send.write_all(wire).await.ok()?;
    let _ = send.finish();
    let bytes = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(65536))
        .await
        .ok()?
        .ok()?;
    Frame::decode(&bytes).ok().filter(|f| f.kind == proto::kind::AUTH)
}

fn challenge_wire(signing: &SigningKey, src: [u8; NODEID_LEN], payload_hex: &str, ts: i64) -> Vec<u8> {
    let mut f = Frame {
        kind: proto::kind::CHALLENGE,
        seq: 1,
        ts,
        src,
        dst: [0u8; NODEID_LEN],
        svc: 0,
        payload: payload_hex.as_bytes().to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = signing.sign(d.as_bytes()).to_bytes();
    f.encode()
}

fn tofu_payload(keys: &NodeKeys, nonce_hex: &str, at: i64) -> String {
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    serde_json::json!({
        "nonce": nonce_hex,
        "at": at,
        "eph": hex::encode(eph_pub.as_bytes()),
        "ed": hex::encode(keys.verifying.to_bytes()),
        "x": hex::encode(keys.e2e_pub.as_bytes()),
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_forged_auth_refused() {
    let tmp = tmpdir("forged");
    let listen: SocketAddr = "127.0.0.1:19824".parse().expect("addr");
    // TOFU on: unknown identities reach the challenge gate (strictest path).
    let keys_b = NodeKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19824", vec![], true),
        keys_b.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let now = proto::now_ms();

    // --- bad signature: valid fields, one flipped sig byte.
    let ka = NodeKeys::generate();
    let good = tofu_payload(&ka, &"ab".repeat(16), now);
    let mut bad_sig = challenge_wire(&ka.signing, ka.id(), &good, now);
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xff;
    let c = raw_connect(listen).await;
    assert!(
        raw_handshake(&c, &bad_sig).await.is_none(),
        "bad signature must be refused"
    );

    // --- wrong key: claims A's id, signs with B's... (different) key.
    let kb = NodeKeys::generate();
    let payload_a = tofu_payload(&ka, &"cd".repeat(16), now);
    let wrong_key = challenge_wire(&kb.signing, ka.id(), &payload_a, now);
    let c = raw_connect(listen).await;
    assert!(
        raw_handshake(&c, &wrong_key).await.is_none(),
        "wrong signing key must be refused"
    );

    // --- stale timestamp (frame ts and payload at, both 700s old).
    let kc = NodeKeys::generate();
    let stale = now - 700_000;
    let stale_payload = tofu_payload(&kc, &"ef".repeat(16), stale);
    let stale_wire = challenge_wire(&kc.signing, kc.id(), &stale_payload, stale);
    let c = raw_connect(listen).await;
    assert!(
        raw_handshake(&c, &stale_wire).await.is_none(),
        "stale challenge must be refused"
    );
    assert!(!proto::ts_ok(stale), "stale ts outside window");
    assert!(proto::ts_ok(now), "fresh ts inside window");

    // --- replayed nonce: identical bytes twice on fresh connections.
    let kd = NodeKeys::generate();
    let payload = tofu_payload(&kd, &"12".repeat(16), proto::now_ms());
    let wire = challenge_wire(&kd.signing, kd.id(), &payload, proto::now_ms());
    let c1 = raw_connect(listen).await;
    assert!(
        raw_handshake(&c1, &wire).await.is_some(),
        "first handshake must be accepted"
    );
    let c2 = raw_connect(listen).await;
    assert!(
        raw_handshake(&c2, &wire).await.is_none(),
        "replayed nonce must be refused"
    );

    // Pure-function replay gate pins the behavior without network.
    let mut seen: HashMap<String, i64> = HashMap::new();
    let t = proto::now_ms();
    assert!(proto::claim_nonce(&mut seen, &"aa".repeat(16), t));
    assert!(
        !proto::claim_nonce(&mut seen, &"aa".repeat(16), t),
        "same nonce twice refused"
    );
    assert!(
        !proto::claim_nonce(&mut seen, "not-hex!!", t),
        "malformed nonce refused"
    );
    assert!(
        proto::claim_nonce(&mut seen, &"aa".repeat(16), t + 700_000),
        "nonce reusable after window expiry"
    );

    // Tampered frames never verify (signature binds the payload).
    let vk = ka.verifying;
    let mut f = Frame {
        kind: 4,
        seq: 9,
        ts: now,
        src: [3u8; NODEID_LEN],
        dst: [4u8; NODEID_LEN],
        svc: 0,
        payload: b"original".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = ka.signing.sign(d.as_bytes()).to_bytes();
    assert!(f.verify(&vk));
    f.payload = b"tampered".to_vec();
    assert!(!f.verify(&vk), "tampered payload must not verify");

    // Server still accepts a fresh honest handshake afterwards.
    let ke = NodeKeys::generate();
    let p = tofu_payload(&ke, &"34".repeat(16), proto::now_ms());
    let w = challenge_wire(&ke.signing, ke.id(), &p, proto::now_ms());
    let c = raw_connect(listen).await;
    assert!(
        raw_handshake(&c, &w).await.is_some(),
        "server must stay open to honest handshakes"
    );

    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 4. DHT poison: forged records and oversized blobs refused.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn audit_dht_poison_refused() {
    let tmp = tmpdir("dhtpoison");
    let la = "127.0.0.1:19825";
    let lb = "127.0.0.1:19826";
    let ka = NodeKeys::generate();
    let kb = NodeKeys::generate();
    // B believes A stores files only: mail writes from A must be denied.
    let a = Node::new(
        cfg("A", la, vec![peer_of("B", &kb, lb, 0, vec![])], false),
        ka.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let mut b_peer_a = peer_of("A", &ka, la, 0, vec!["files".to_string()]);
    b_peer_a.allow = vec!["*".to_string()];
    let b = Node::new(cfg("B", lb, vec![b_peer_a], false), kb.clone(), tmp.join("b"), PathBuf::new())
        .await
        .expect("node B");
    let sa = tokio::spawn({
        let n = a.clone();
        async move { n.serve().await }
    });
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let b_id = kb.id();

    // Wrong-bucket write from a files-only peer.
    let p = serde_json::json!({ "key": "mail:alice:index", "value": "[]", "ttl": 60 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("peer role denies mail"),
        "cross-bucket write refused"
    );

    // Local-authoritative keys never land over the network.
    for key in ["recovery:alice", "blacklist:x", "share:tok"] {
        let p = serde_json::json!({ "key": key, "value": "evil", "ttl": 60 })
            .to_string()
            .into_bytes();
        let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
            .await
            .expect("no hang")
            .expect("transport ok");
        assert!(
            resp_text(&r).contains("local-authoritative"),
            "{key} store refused"
        );
        let p = serde_json::json!({ "key": key }).to_string().into_bytes();
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            a.request_to(b_id, "dht.find_value", p),
        )
        .await
        .expect("no hang")
        .expect("transport ok");
        assert!(
            resp_text(&r).contains("\"found\":false"),
            "{key} never served"
        );
    }

    // Poisoned route record: node id bound to an attacker's key is skipped,
    // so a later lookup does not resolve to attacker endpoints.
    let evil = NodeKeys::generate();
    let poison_id = "inf1:".to_string() + &hex::encode([0xabu8; NODEID_LEN]);
    let routes = serde_json::json!({
        poison_id.clone(): {
            "endpoints": ["127.0.0.1:9"],
            "ed_pub": hex::encode(evil.verifying.to_bytes()),
        }
    });
    let p = serde_json::json!({ "routes": routes }).to_string().into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.update", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"ok\":true"), "update answered");
    let p = serde_json::json!({ "node": poison_id, "ttl": 1 }).to_string().into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.lookup", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("\"found\":false"),
        "poisoned route must not resolve, got {}",
        resp_text(&r).chars().take(200).collect::<String>()
    );

    // Oversized gossip object refused outright (600 DISTINCT ids — a u8
    // truncation here would collapse them to 256 and duck under the cap).
    let mut big = serde_json::Map::new();
    for i in 0..600u32 {
        let mut id = [0u8; NODEID_LEN];
        id[..4].copy_from_slice(&i.to_le_bytes());
        big.insert(
            format!("inf1:{}", hex::encode(id)),
            serde_json::json!({ "endpoints": [], "ed_pub": "" }),
        );
    }
    assert_eq!(big.len(), 600, "test must actually send 600 routes");
    let p = serde_json::json!({ "routes": big }).to_string().into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.update", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("routes too large"),
        "gossip flood refused"
    );

    // Pure-function record gate pins the rule without network.
    let honest = NodeKeys::generate();
    assert!(infnode::dht::node_info_valid(
        &honest.id(),
        &hex::encode(honest.verifying.to_bytes()),
        &hex::encode(honest.e2e_pub.as_bytes()),
        &["127.0.0.1:1".to_string()],
    ));
    assert!(!infnode::dht::node_info_valid(
        &honest.id(),
        &hex::encode(evil.verifying.to_bytes()),
        &hex::encode(evil.e2e_pub.as_bytes()),
        &["127.0.0.1:1".to_string()],
    ));
    assert!(!infnode::dht::endpoint_ok("not an endpoint"));
    assert!(!infnode::dht::endpoint_ok(""));
    assert!(infnode::dht::endpoint_ok("127.0.0.1:1"));

    assert!(ping_ok(&a, b_id).await, "node responsive after poison");
    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 5. pubsub spam: denied for outsiders, quotaed for peers, TTL clamped.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn audit_pubsub_spam_contained() {
    let tmp = tmpdir("pubsubspam");
    let la = "127.0.0.1:19827";
    let lb = "127.0.0.1:19828";
    let ka = NodeKeys::generate();
    let kb = NodeKeys::generate();
    let a = Node::new(
        cfg("A", la, vec![peer_of("B", &kb, lb, 0, vec![])], false),
        ka.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    // B throttles A to 10/s and also learns A as a DHT peer (discovery-only).
    let b = Node::new(
        cfg("B", lb, vec![peer_of("A", &ka, la, 10, vec![])], false),
        kb.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");
    let sa = tokio::spawn({
        let n = a.clone();
        async move { n.serve().await }
    });
    let sb = tokio::spawn({
        let n = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let b_id = kb.id();

    // A huge TTL is clamped, not amplified: answered ok, no hang.
    let p = serde_json::json!({ "topic": "audit", "data": "x", "ttl": u64::MAX })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "pubsub.publish", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("\"ok\":true"),
        "clamped TTL publish answered"
    );

    // Flood: 40 rapid publishes, quota must bite, nothing hangs.
    let mut limited = 0usize;
    let mut ok_count = 0usize;
    for i in 0..40u32 {
        let p = serde_json::json!({ "topic": "audit", "data": format!("spam-{i}") })
            .to_string()
            .into_bytes();
        let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "pubsub.publish", p))
            .await
            .expect("no hang")
            .expect("transport ok");
        let t = resp_text(&r);
        if t.contains("rate limit exceeded") {
            limited += 1;
        } else if t.contains("\"ok\":true") {
            ok_count += 1;
        }
    }
    assert_eq!(ok_count + limited, 40, "every publish resolves");
    assert!(
        limited >= 10,
        "publish flood must be quotaed, got {limited} refusals"
    );

    // A DHT-discovered identity (discovery-only ACL) cannot publish at all.
    // NOTE: B2 must not pin A statically — otherwise ensure_dht_peer is a
    // no-op and the assertions below would read the static entry.
    let b2 = Node::new(
        cfg("B2", "127.0.0.1:19829", vec![], false),
        NodeKeys::generate(),
        tmp.join("b2"),
        PathBuf::new(),
    )
    .await
    .expect("node B2");
    b2.ensure_dht_peer(&infnode::dht::NodeInfo {
        id: ka.id(),
        endpoints: vec![la.to_string()],
        ed_hex: hex::encode(ka.verifying.to_bytes()),
        x_hex: hex::encode(ka.e2e_pub.as_bytes()),
        last_seen: infnode::dht::now_ms(),
    })
    .await
    .expect("dynamic peer inserts");
    let link = b2
        .peers
        .read()
        .await
        .get(&ka.id())
        .cloned()
        .expect("dynamic peer present");
    assert_eq!(
        link.cfg.rate_limit_per_sec,
        infnode::node::DYNAMIC_PEER_RATE_LIMIT_PER_SEC,
        "dynamic identity is born rate-limited"
    );
    assert!(
        !infnode::services::is_allowed(&link.cfg.allow, "pubsub.publish"),
        "dynamic identity cannot publish"
    );
    assert!(
        !infnode::services::is_allowed(&link.cfg.allow, "dht.store"),
        "dynamic identity cannot write DHT"
    );

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(ping_ok(&a, b_id).await, "node responsive after spam");
    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 6. privilege inflation: no self-service ACL widening or budget escape.
// ---------------------------------------------------------------------------

#[test]
fn audit_no_privilege_inflation() {
    // Discovery-only ACL grants nothing beyond discovery.
    let discovery = vec![
        "dht.lookup".to_string(),
        "dht.update".to_string(),
        "dht.find_node".to_string(),
    ];
    for svc in [
        "pubsub.publish",
        "pubsub.subscribe",
        "pubsub.relay",
        "pubsub.msg",
        "dht.store",
        "dht.sync",
        "dht.find_value",
        "storage.store",
        "storage.fetch",
        "consensus.sign",
        "core.storage",
    ] {
        assert!(
            !infnode::services::is_allowed(&discovery, svc),
            "discovery ACL must not grant {svc}"
        );
    }
    for svc in ["dht.lookup", "dht.update", "dht.find_node"] {
        assert!(
            infnode::services::is_allowed(&discovery, svc),
            "discovery ACL keeps {svc}"
        );
    }

    // Prefix grants stay inside their own namespace.
    assert!(infnode::services::is_allowed(
        &["core.*".to_string()],
        "core.ping"
    ));
    assert!(!infnode::services::is_allowed(
        &["core.*".to_string()],
        "pubsub.publish"
    ));

    // Dynamic identities are born bounded: nonzero, small budget.
    let rate = infnode::node::DYNAMIC_PEER_RATE_LIMIT_PER_SEC;
    assert!(rate > 0 && rate <= 100);
    let mut bucket = infnode::node::RateBucket::new();
    assert!(bucket.allow(rate));
    assert!(
        !bucket.allow(rate),
        "second immediate request from a fresh identity refused"
    );

    // Service-level caps pin the fail-closed envelope.
    assert!(proto::topic_ok("consensus/votes/1"));
    assert!(!proto::topic_ok(""));
    assert!(!proto::topic_ok(&"t".repeat(300)));
    assert!(proto::dht_key_ok("mail:alice:index"));
    assert!(!proto::dht_key_ok(""));
    assert!(!proto::dht_key_ok(&"k".repeat(600)));
    assert!(!proto::dht_value_ok(&"v".repeat(2 * 1024 * 1024)));
    assert!(!proto::pubsub_data_ok(&"d".repeat(2 * 1024 * 1024)));
}
