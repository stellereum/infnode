//! Eclipse / poison resistance battery (p2p 8.0 -> 9.0).
//!
//! NEW-FILE-ONLY suite: asserts attacker containment without touching existing
//! files. All tests are deterministic in outcome (fixed counts, fixed hex
//! nonces `{:032x}`, fixed loopback ports), loopback-only, each well under
//! 120s.
//!
//! Shared env (SAME in every test: parallel threads share process env):
//! reputation soft -20 / ban -50, pen_auth 10 (2 bad handshakes throttle,
//! 5 ban), base ban 2s / cap 8s / decay 2/s; IP hardening WIDE OPEN
//! (30/s bucket, strike threshold 1000) so every refusal below proves the
//! per-identity reputation layer, never the per-IP layer. Per-IP behaviour
//! itself is pinned at the pure `RateBucket` level (test 2).
//!
//! GAPS (inexpressible in this harness, covered at closest expressible level):
//! * G1 distinct source IPs (/24 spread): every raw dial originates from
//!   127.0.0.1 as seen by the server, so per-IP *distribution* of a sybil
//!   burst cannot be exercised on loopback. Per-IP bounding is proven via
//!   `RateBucket` unit semantics (burst = rate*2, then throttle) instead.
//! * G2 real wall-clock ban expiry inside the flood test is skipped (expiry
//!   already proven in `reputation_tests.rs`); here bans are asserted live.
//! * G3 `Node.peers` has no eviction cap in-tree, so an *unbounded distinct
//!   identity* churn assertion would fail by design; the churn test proves
//!   reconnect churn of a fixed peer set leaves tables constant plus
//!   `RoutingTable` K-bucket capping under 5000 distinct IDs.

use ed25519_dalek::Signer;
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{Node, RateBucket};
use infnode::proto::{self, Frame, NODEID_LEN};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Shared harness idiom (mirrors reputation_tests.rs / p2p_audit_tests.rs).
// ---------------------------------------------------------------------------

fn eclipse_env() {
    std::env::set_var("STELL_INF_REP_SOFT_SCORE", "-20");
    std::env::set_var("STELL_INF_REP_BAN_SCORE", "-50");
    std::env::set_var("STELL_INF_REP_BAN_SECS", "2");
    std::env::set_var("STELL_INF_REP_MAX_BAN_SECS", "8");
    std::env::set_var("STELL_INF_REP_DECAY_PER_SEC", "2");
    std::env::set_var("STELL_INF_REP_REWARD_VALID", "1");
    std::env::set_var("STELL_INF_REP_PEN_AUTH", "10");
    std::env::set_var("STELL_INF_REP_PEN_OVERSIZE", "10");
    std::env::set_var("STELL_INF_REP_PEN_RATE", "5");
    std::env::set_var("STELL_INF_REP_PEN_PROTO", "10");
    // IP gates ON but wide: refusals below must come from identity reputation.
    std::env::set_var("STELL_INF_HANDSHAKE_PER_IP_PER_SEC", "30");
    std::env::set_var("STELL_INF_AUTH_FAIL_THRESHOLD", "1000");
    std::env::set_var("STELL_INF_AUTH_FAIL_WINDOW_SECS", "60");
    std::env::set_var("STELL_INF_AUTH_BAN_COOLDOWN_SECS", "6");
    std::env::set_var("STELL_INF_PREAUTH_DEADLINE_SECS", "15");
}

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

fn peer_of(name: &str, keys: &NodeKeys, pq: &PqKeys, listen: &str, rate: u32) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        ed_pub: hex::encode(keys.verifying.to_bytes()),
        pq_pub: Some(pq.pq_pub_hex()),
        endpoints: vec![listen.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: rate,
        role: None,
        storage_roles: vec![],
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-eclipse-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

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

async fn raw_connect(addr: SocketAddr) -> anyhow::Result<quinn::Connection> {
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rc = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("{e}"))?
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
    .with_no_client_auth();
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(std::sync::Arc::new(rc))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut cc = quinn::ClientConfig::new(std::sync::Arc::new(quic_cfg));
    cc.transport_config(std::sync::Arc::new(quinn::TransportConfig::default()));
    ep.set_default_client_config(cc);
    let connecting = ep
        .connect(addr, "localhost")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    std::mem::forget(ep);
    Ok(conn)
}

/// None = refused. Some = accepted (AUTH frame back).
async fn raw_handshake(conn: &quinn::Connection, wire: &[u8]) -> Option<Frame> {
    let (mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await.ok()?.ok()?;
    send.write_all(wire).await.ok()?;
    let _ = send.finish();
    let bytes = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(65536))
        .await
        .ok()?
        .ok()?;
    Frame::decode(&bytes).ok().filter(|f| f.kind == proto::kind::AUTH)
}

fn challenge_wire(
    signing: &ed25519_dalek::SigningKey,
    src: [u8; NODEID_LEN],
    payload: &str,
    ts: i64,
) -> Vec<u8> {
    let mut f = Frame {
        kind: proto::kind::CHALLENGE,
        seq: 1,
        ts,
        src,
        dst: [0u8; NODEID_LEN],
        svc: 0,
        payload: payload.as_bytes().to_vec(),
        nonce: vec![],
        sig: [0; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = signing.sign(d.as_bytes()).to_bytes();
    f.encode()
}

/// Deterministic TOFU payload: fixed hex nonce + fixed eph derived from seed.
/// Avoids OsRng in test logic (outcome identical every run).
fn det_payload(keys: &NodeKeys, seed: u64, at: i64) -> String {
    let nonce = format!("{seed:032x}");
    // Deterministic 32-byte eph stand-in (format-only; server only checks presence).
    let eph = format!("{seed:064x}");
    serde_json::json!({
        "nonce": nonce,
        "at": at,
        "eph": eph,
        "ed": hex::encode(keys.verifying.to_bytes()),
        "pq_ver": infnode::proto::PQ_TRANSCRIPT_VERSION,
        "pq_suite": infnode::proto::PQ_SUITE_MLKEM768_HYBRID,
        "pq_ek": hex::encode(&infnode::node::pq_initiator_offer().expect("pq offer").ek),
    })
    .to_string()
}

fn det_good_wire(keys: &NodeKeys, seed: u64) -> Vec<u8> {
    let now = proto::now_ms();
    let p = det_payload(keys, seed, now);
    challenge_wire(&keys.signing, keys.id(), &p, now)
}

fn det_bad_wire(keys: &NodeKeys, seed: u64) -> Vec<u8> {
    let mut w = det_good_wire(keys, seed);
    let last = w.len() - 1;
    w[last] ^= 0xff;
    w
}

fn resp_text(resp: &[u8]) -> String {
    String::from_utf8_lossy(resp).to_string()
}

// ---------------------------------------------------------------------------
// (a) Dial flood: many-identity attacker throttled/banned, honest unaffected.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eclipse_flood_dials_honest_unaffected_attacker_throttled() {
    eclipse_env();
    let tmp = tmpdir("flood");
    let listen: SocketAddr = "127.0.0.1:19741".parse().unwrap();
    let keys_v = NodeKeys::generate();
    let pq_v = PqKeys::generate();
    let keys_h = NodeKeys::generate();
    let pq_h = PqKeys::generate();
    let victim = Node::new(
        cfg("V", "127.0.0.1:19741", vec![peer_of("H", &keys_h, &pq_h, "127.0.0.1:19742", 0)], true),
        keys_v.clone(), pq_v.clone(),
        tmp.join("v"),
        PathBuf::new(),
    )
    .await
    .expect("victim");
    let sv = tokio::spawn({
        let n = victim.clone();
        async move { n.serve().await }
    });
    // Honest full node H with static route to V (for core.ping delivery rate).
    let honest = Node::new(
        cfg("H", "127.0.0.1:19742", vec![peer_of("V", &keys_v, &pq_v, "127.0.0.1:19741", 0)], false),
        keys_h.clone(), pq_h.clone(),
        tmp.join("h"),
        PathBuf::new(),
    )
    .await
    .expect("honest");
    let sh = tokio::spawn({
        let n = honest.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let v_id = pq_v.pq_id();

    // Warmup: honest ping works pre-attack.
    let r = tokio::time::timeout(Duration::from_secs(15), honest.request_to(v_id, "core.ping", vec![]))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"pong\":true"), "warmup ping");

    // Phase 1: single attacker identity, bad handshakes -> refused per
    // connection AND dropped, with no identity trace (framing-impossible:
    // pre-auth failures are never attributed to the claimed id).
    let atk_keys = NodeKeys::generate();
    let atk_id = atk_keys.id();
    let mut attacker_refused = 0usize;
    let mut seed = 100u64;
    for _ in 0..8 {
        let c = raw_connect(listen).await.expect("admission passes");
        assert!(
            raw_handshake(&c, &det_bad_wire(&atk_keys, seed)).await.is_none(),
            "bad signature refused"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), c.closed())
                .await
                .is_ok(),
            "attacker connection dropped"
        );
        attacker_refused += 1;
        seed += 1;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    assert_eq!(
        victim.rep_score(&atk_id).await,
        0,
        "pre-auth abuse leaves no score trace"
    );
    assert!(
        !victim.rep_is_throttled(&atk_id).await,
        "bad dials alone never throttle"
    );
    assert!(!victim.rep_is_banned(&atk_id).await, "bad dials alone never ban");

    // Honest unaffected while the attacker is refused (raw + full-node paths).
    let h1 = NodeKeys::generate();
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &det_good_wire(&h1, 9001)).await.is_some(),
        "honest raw dial passes during throttle"
    );
    let r = tokio::time::timeout(Duration::from_secs(15), honest.request_to(v_id, "core.ping", vec![]))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"pong\":true"), "honest ping during throttle");

    // Phase 2: 8-identity sybil burst -> every dial refused + dropped, every
    // sybil untouched (framing-impossible). Throttle-gate coverage is then
    // primed via the authed-path-equivalent records and refused with a valid
    // wire, proving the gate still bites once attribution is genuine.
    let mut sybils = Vec::new();
    for s in 0..8u64 {
        let k = NodeKeys::generate();
        sybils.push((k, 200 + s * 100));
    }
    let refused_before = victim.rep_refusals_total();
    for (i, (k, base)) in sybils.iter().enumerate() {
        let mut s = *base;
        for _ in 0..2 {
            let c = raw_connect(listen).await.expect("admission passes");
            assert!(
                raw_handshake(&c, &det_bad_wire(k, s)).await.is_none(),
                "sybil bad dial refused"
            );
            attacker_refused += 1;
            s += 1;
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
        assert_eq!(
            victim.rep_score(&k.id()).await,
            0,
            "sybil {i} untouched by its own bad dials"
        );
        assert!(!victim.rep_is_banned(&k.id()).await, "sybil dials never ban");
        // Genuine (attributed) abuse throttles the sybil at its own gate time.
        victim.rep_record_auth_failure(&k.id()).await;
        victim.rep_record_auth_failure(&k.id()).await;
        assert!(
            victim.rep_is_throttled(&k.id()).await,
            "sybil {i} throttled once abuse is attributed"
        );
        assert!(!victim.rep_is_banned(&k.id()).await, "sybil throttle, not ban");
        // Gate refusal with a VALID wire, immediately (no decay gap).
        let c = raw_connect(listen).await.expect("admission passes");
        assert!(
            raw_handshake(&c, &det_good_wire(k, 7000 + i as u64)).await.is_none(),
            "throttled identity refused even when valid"
        );
        attacker_refused += 1;
    }
    assert!(
        victim.rep_refusals_total() >= refused_before + 8,
        "gate refusals counted, got {}",
        victim.rep_refusals_total()
    );

    // Phase 3: attributed post-auth abuse escalates the prime offender to ban.
    // Bounded drive: the prime score is neutral (bad dials leave no trace),
    // so sustained attributed abuse must cross the full ban threshold.
    for _ in 0..10 {
        if victim.rep_is_banned(&atk_id).await {
            break;
        }
        victim.rep_record_protocol_violation(&atk_id).await;
    }
    assert!(victim.rep_is_banned(&atk_id).await, "prime offender banned");
    assert!(victim.rep_bans_total() >= 1, "ban counter bumps");
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &det_good_wire(&atk_keys, 4242)).await.is_none(),
        "banned identity refused even when valid"
    );
    attacker_refused += 1;

    // Honest delivery rate: 5/5 pings during full attack pressure.
    let mut honest_ok = 0usize;
    for _ in 0..5 {
        let r =
            tokio::time::timeout(Duration::from_secs(15), honest.request_to(v_id, "core.ping", vec![]))
                .await
                .expect("no hang")
                .expect("transport ok");
        if resp_text(&r).contains("\"pong\":true") {
            honest_ok += 1;
        }
    }
    assert_eq!(honest_ok, 5, "honest delivery 5/5 while attacker fully throttled/banned");
    // Attacker refuse rate: every attacker dial refused (8 bad dials phase 1,
    // 16 bad + 8 gate refusals phase 2, 1 ban refusal phase 3 => 33 total).
    assert!(
        attacker_refused > 2 + 16 + 8,
        "attacker dial floor, got {attacker_refused}"
    );
    assert!(
        victim.rep_refusals_total() >= 9,
        "attacker gate-refuse bound, got {}",
        victim.rep_refusals_total()
    );
    // IP itself never strike-banned (threshold 1000 >> our failures).
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(!victim.is_banned(&loopback).await, "no shared-IP blast radius");

    sv.abort();
    sh.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// (b) Sybil burst: per-IP + per-identity limits both bite, attacker share bounded.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eclipse_sybil_burst_per_ip_and_per_identity_limits() {
    eclipse_env();
    let tmp = tmpdir("sybil");
    let listen: SocketAddr = "127.0.0.1:19743".parse().unwrap();
    let keys_v = NodeKeys::generate();
    let pq_v = PqKeys::generate();
    let victim = Node::new(
        cfg("V", "127.0.0.1:19743", vec![], true),
        keys_v.clone(), pq_v.clone(),
        tmp.join("v"),
        PathBuf::new(),
    )
    .await
    .expect("victim");
    let sv = tokio::spawn({
        let n: Arc<Node> = victim.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Per-identity layer: N=16 distinct sybils, 2 auth debits each.
    const N: usize = 16;
    let mut sybils = Vec::new();
    for _ in 0..N {
        sybils.push(NodeKeys::generate());
    }
    for k in &sybils {
        let id = k.id();
        victim.rep_record_auth_failure(&id).await;
        victim.rep_record_auth_failure(&id).await;
    }
    let mut throttled = 0usize;
    let mut banned = 0usize;
    for k in &sybils {
        let id = k.id();
        if victim.rep_is_throttled(&id).await {
            throttled += 1;
        }
        if victim.rep_is_banned(&id).await {
            banned += 1;
        }
    }
    assert_eq!(throttled, N, "per-identity limit bites every sybil ({N}/{N})");
    assert_eq!(banned, 0, "throttle imposes no ban: attacker ban share 0/{N}");

    // Honest identity born neutral at the same layer while sybils burn.
    let honest = PqKeys::generate().pq_id();
    assert_eq!(victim.rep_score(&honest).await, 0, "honest stays neutral");
    assert!(!victim.rep_is_throttled(&honest).await);
    assert!(!victim.rep_is_banned(&honest).await);

    // Per-IP layer (pure bucket, burst = rate*2): rate 3/s admits exactly the
    // 6-token burst, then throttles — the bound a shared /24 bucket enforces.
    // (G1: distinct source IPs inexpressible on loopback; this is the closest
    // expressible per-IP bound.)
    let mut b = RateBucket::new_full(3);
    let mut admitted = 0usize;
    for _ in 0..10 {
        if b.allow(3) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 6, "per-IP burst bound is rate*2 = 6, then throttle");

    // Network: honest raw dial passes while all 16 sybils are throttled.
    let hk = NodeKeys::generate();
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &det_good_wire(&hk, 31337)).await.is_some(),
        "honest passes under sybil pressure"
    );
    // Bounded attacker share: 0 banned honest, 16/16 sybils contained.
    assert_eq!(victim.rep_bans_total(), 0, "no ban without sustained abuse");

    sv.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// (c) DHT poisoning: honest records win per the LWW conflict rule.
// Rule (read, not invented): `merge_replica` applies peer value ONLY if
// stored_at > local stored_at; stored_at <= 0 never overwrites. Network
// `dht.store` keeps local on stale/future-skew/no-clock-overwrite, and
// `node_info_valid` requires ed key to derive the node id.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eclipse_dht_poison_honest_records_persist() {
    eclipse_env();

    // Pure LWW rule first (pins the conflict rule without network).
    let mut kv = infnode::dht::KvStore::default();
    let origin = [7u8; NODEID_LEN];
    kv.store("eclipse:rule", "v-honest".to_string(), 3_600_000, origin);
    let local_sa = kv.stored_at("eclipse:rule");
    assert!(local_sa > 0, "honest record has a clock");
    // Stale replica loses.
    assert!(
        !kv.merge_replica("eclipse:rule", "v-evil-stale".into(), 3_600_000, [9u8; NODEID_LEN], local_sa - 60_000),
        "older stored_at must not overwrite"
    );
    // Clockless replica loses against present local.
    assert!(
        !kv.merge_replica("eclipse:rule", "v-evil-noclock".into(), 3_600_000, [9u8; NODEID_LEN], 0),
        "missing stored_at must not overwrite"
    );
    assert_eq!(kv.get("eclipse:rule").as_deref(), Some("v-honest"), "honest persists (pure)");
    // Newer replica wins (proves the rule direction, not attacker-favouring).
    assert!(
        kv.merge_replica(
            "eclipse:rule",
            "v-honest-v2".into(),
            3_600_000,
            origin,
            local_sa + 1_000
        ),
        "newer stored_at wins"
    );
    assert_eq!(kv.get("eclipse:rule").as_deref(), Some("v-honest-v2"));

    // Route-record gate (FULL-PQ): honest PQ binding valid, forged binding
    // refused (`pq` must derive `id`; `ed` is the frozen auth pin, NOT identity).
    let honest_keys = NodeKeys::generate();
    let honest_keys_pq = PqKeys::generate();
    let evil_keys = NodeKeys::generate();
    let evil_keys_pq = PqKeys::generate();
    assert!(infnode::dht::node_info_valid(
        &honest_keys_pq.pq_id(),
        &hex::encode(honest_keys.verifying.to_bytes()),
        &honest_keys_pq.pq_pub_hex(),
        &["127.0.0.1:1".to_string()],
    ));
    assert!(
        !infnode::dht::node_info_valid(
            &honest_keys_pq.pq_id(),
            &hex::encode(evil_keys.verifying.to_bytes()),
            &evil_keys_pq.pq_pub_hex(),
            &["127.0.0.1:1".to_string()],
        ),
        "bogus advertisement for honest PQ ID refused (pq must derive id)"
    );
    assert!(!infnode::dht::endpoint_ok("not an endpoint"));
    assert!(infnode::dht::endpoint_ok("127.0.0.1:1"));

    // Network: honest store then poison attempts over real RPC.
    let tmp = tmpdir("dhtpoison");
    let ka = NodeKeys::generate();
    let pa = PqKeys::generate();
    let kb = NodeKeys::generate();
    let pb = PqKeys::generate();
    let a = Node::new(
        cfg("A", "127.0.0.1:19744", vec![peer_of("B", &kb, &pb, "127.0.0.1:19745", 0)], false),
        ka.clone(), pa.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let b = Node::new(
        cfg("B", "127.0.0.1:19745", vec![peer_of("A", &ka, &pa, "127.0.0.1:19744", 0)], false),
        kb.clone(), pb.clone(),
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
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b_id = pb.pq_id();
    let key = "eclipse:honest:key";

    // Honest write lands.
    let p = serde_json::json!({ "key": key, "value": "v1-honest", "ttl": 3600 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"ok\":true"), "honest store lands");

    // Poison 1: stale clock (stored_at=1, ancient) -> lww local, kept.
    let p = serde_json::json!({ "key": key, "value": "v-evil-stale", "ttl": 3600, "stored_at": 1 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"lww\":\"local\""), "stale keeps local, got {}", resp_text(&r).chars().take(160).collect::<String>());

    // Poison 2: no clock overwrite attempt -> local-present, kept.
    let p = serde_json::json!({ "key": key, "value": "v-evil-noclock", "ttl": 3600 })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("local-present"),
        "clockless overwrite keeps local, got {}",
        resp_text(&r).chars().take(160).collect::<String>()
    );

    // Poison 3: far-future clock (skew) -> skew guard keeps local.
    let skew = infnode::dht::now_ms() + 3_600_000;
    let p = serde_json::json!({ "key": key, "value": "v-evil-future", "ttl": 3600, "stored_at": skew })
        .to_string()
        .into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.store", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(resp_text(&r).contains("\"lww\":\"skew\""), "future skew keeps local, got {}", resp_text(&r).chars().take(160).collect::<String>());

    // Honest value persists byte-for-byte after all three poison attempts.
    let p = serde_json::json!({ "key": key }).to_string().into_bytes();
    let r = tokio::time::timeout(Duration::from_secs(20), a.request_to(b_id, "dht.find_value", p))
        .await
        .expect("no hang")
        .expect("transport ok");
    assert!(
        resp_text(&r).contains("v1-honest"),
        "honest record persists, got {}",
        resp_text(&r).chars().take(200).collect::<String>()
    );

    // Poison 4: bogus route advertisement for an honest-looking ID is skipped.
    let poison_id = "inf1:".to_string() + &hex::encode([0xabu8; NODEID_LEN]);
    let routes = serde_json::json!({
        poison_id.clone(): {
            "endpoints": ["127.0.0.1:9"],
            "ed_pub": hex::encode(evil_keys.verifying.to_bytes()),
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
        "poisoned route never resolves, got {}",
        resp_text(&r).chars().take(200).collect::<String>()
    );

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// (d) Churn storm: rapid connect/disconnect leaves no state leak.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn eclipse_churn_storm_peer_table_bounded() {
    eclipse_env();

    // Routing-table cap under distinct-ID pressure (deterministic IDs).
    let own = [0x11u8; NODEID_LEN];
    let mut rt = infnode::dht::RoutingTable::new(own, infnode::dht::K);
    for i in 0..5000u32 {
        let h = blake3::hash(format!("eclipse-churn-{i:05}").as_bytes());
        let mut id = [0u8; NODEID_LEN];
        id.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        rt.insert(infnode::dht::NodeInfo {
            id,
            endpoints: vec!["127.0.0.1:1".to_string()],
            ed_hex: String::new(),
            pq_hex: String::new(),
            last_seen: 1,
        });
    }
    let cap = 160 * infnode::dht::K;
    assert!(
        rt.len() <= cap,
        "routing table capped at 160*K={cap}, got {}",
        rt.len()
    );
    let len_before_refresh = rt.len();
    for i in 0..500u32 {
        let h = blake3::hash(format!("eclipse-churn-{i:05}").as_bytes());
        let mut id = [0u8; NODEID_LEN];
        id.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        rt.insert(infnode::dht::NodeInfo {
            id,
            endpoints: vec!["127.0.0.1:1".to_string()],
            ed_hex: String::new(),
            pq_hex: String::new(),
            last_seen: 2,
        });
    }
    assert_eq!(rt.len(), len_before_refresh, "refresh churn grows nothing");

    // Live reconnect churn between two static peers.
    let tmp = tmpdir("churn");
    let ka = NodeKeys::generate();
    let pa = PqKeys::generate();
    let kb = NodeKeys::generate();
    let pb = PqKeys::generate();
    let a = Node::new(
        cfg("A", "127.0.0.1:19746", vec![peer_of("B", &kb, &pb, "127.0.0.1:19747", 0)], false),
        ka.clone(), pa.clone(),
        tmp.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let b = Node::new(
        cfg("B", "127.0.0.1:19747", vec![peer_of("A", &ka, &pa, "127.0.0.1:19746", 0)], false),
        kb.clone(), pb.clone(),
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
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b_id = pb.pq_id();
    let peers_before = a.peers.read().await.len();
    let known_before = a.known_peers().await.len();

    // 30 rapid connect/use/disconnect cycles, each bounded at 15s.
    for _ in 0..30 {
        let r = tokio::time::timeout(Duration::from_secs(15), a.request_to(b_id, "core.ping", vec![]))
            .await
            .expect("no hang")
            .expect("transport ok");
        assert!(resp_text(&r).contains("\"pong\":true"), "ping inside churn");
        a.invalidate_peer_conn(b_id).await;
    }
    let peers_after = a.peers.read().await.len();
    let known_after = a.known_peers().await.len();
    assert_eq!(peers_before, peers_after, "peer table constant under churn ({peers_before})");
    assert_eq!(known_before, known_after, "known set constant under churn ({known_before})");
    assert!(known_after <= 8, "known set small bound, got {known_after}");

    // Invalid DHT-discovered records never enter the peer table (FULL-PQ:
    // `pq` must derive `id`; forged `fake` ids with attacker `pq` are refused).
    let evil = NodeKeys::generate();
    let evil_pq = PqKeys::generate();
    let peers_pre_poison = b.peers.read().await.len();
    for i in 0..20u32 {
        let mut fake = [0xCDu8; NODEID_LEN];
        fake[0] = i as u8;
        let res = b
            .ensure_dht_peer(&infnode::dht::NodeInfo {
                id: fake,
                endpoints: vec!["127.0.0.1:9".to_string()],
                ed_hex: hex::encode(evil.verifying.to_bytes()),
                pq_hex: evil_pq.pq_pub_hex(),
                last_seen: infnode::dht::now_ms(),
            })
            .await;
        assert!(res.is_err(), "forged dht peer refused ({i})");
    }
    assert_eq!(
        b.peers.read().await.len(),
        peers_pre_poison,
        "poison churn grows nothing"
    );

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
