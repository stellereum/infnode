//! F8 residual (M2 blast radius, `docs/PENTEST_NET_API.md`): per-identity
//! reputation for the QUIC accept path.
//!
//! The accept path already gates on source IP (pre-auth deadline, per-IP
//! handshake buckets, failed-auth strikes — see `accept_hardening_tests.rs`,
//! untouched here). This file covers the EXTENSION that scores the peer
//! **identity** (`[u8; 20]` node id, 1:1 with the ed25519 key) instead:
//! credit on valid handshake/message, debit on auth failure / oversize /
//! rate violation / protocol violation, soft throttle, escalating temp bans
//! (never permanent), decay/forgiveness.
//!
//! Env (`STELL_INF_REP_*`, fail-closed defaults in `RepConfig`): ALL tests in
//! this file use the SAME values, so parallel execution cannot race on env
//! (same pattern as `accept_hardening_tests.rs`). The IP gates are tuned
//! wide open here (30/s bucket, strike threshold 1000) so every refusal
//! below proves identity reputation, never the per-IP layer.

use ed25519_dalek::{Signer, SigningKey};
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::NodeKeys;
use infnode::node::Node;
use infnode::proto::{self, Frame, NODEID_LEN};
use infnode::reputation::{REP_SCORE_MAX, REP_SCORE_MIN};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

// Soft -20 / ban -50 with pen_auth 10: 2 bad handshakes throttle, 5 ban.
// Ban base 2s (expiry testable), cap 8s (escalation observable: 2s -> 4s).
// Decay 2/s: sub-second test steps see ~0 decay (truncation), multi-second
// sleeps see real forgiveness.
fn rep_env() {
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
    // IP hardening stays ON but wide: refusals below must come from identity
    // reputation (asserted via `is_banned` + `rep_refusals_total`).
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

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-rep-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn fresh_node(tag: &str) -> (std::sync::Arc<Node>, PathBuf) {
    rep_env();
    let tmp = tmpdir(tag);
    let keys = NodeKeys::generate();
    let node = Node::new(
        cfg("S", "127.0.0.1:0", vec![], false),
        keys,
        tmp.join("s"),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, tmp)
}

// ---------------------------------------------------------------------------
// 1. Good peer unaffected: unknown identity is neutral, valid handshake/message
//    credits without tripping any gate.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_good_peer_unaffected() {
    let (node, tmp) = fresh_node("good").await;
    let good = NodeKeys::generate().id();
    // Unknown identity: neutral score, no throttle, no ban.
    assert_eq!(node.rep_score(&good).await, 0, "unknown identity is neutral");
    assert!(!node.rep_is_throttled(&good).await, "neutral is not throttled");
    assert!(!node.rep_is_banned(&good).await, "neutral is not banned");
    // Valid handshake/message credits (clamped, never a gate trip).
    node.rep_record_valid(&good).await;
    assert!(node.rep_score(&good).await > 0, "valid activity credits");
    assert!(!node.rep_is_throttled(&good).await, "good peer not throttled");
    assert!(!node.rep_is_banned(&good).await, "good peer not banned");
    assert_eq!(node.rep_bans_total(), 0, "no ban imposed");
    assert_eq!(node.rep_ban_count(&good).await, 0, "no escalation memory");
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 2. Abusive peer throttled, then banned (relational asserts: robust to
//    scheduling stalls, since decay only ever moves scores toward zero and a
//    -10 debit step always crosses the soft threshold before the ban one).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_abuse_throttles_then_bans() {
    let (node, tmp) = fresh_node("throttle-ban").await;
    let bad = NodeKeys::generate().id();
    node.rep_record_auth_failure(&bad).await;
    assert!(
        !node.rep_is_throttled(&bad).await,
        "one failure is below the soft threshold"
    );
    assert!(!node.rep_is_banned(&bad).await, "one failure never bans");
    // Drive to the soft threshold (bounded: stalls only add decay, debits win).
    for _ in 0..10 {
        if node.rep_is_throttled(&bad).await {
            break;
        }
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(
        node.rep_is_throttled(&bad).await,
        "repeat auth failures throttle"
    );
    assert!(
        !node.rep_is_banned(&bad).await,
        "soft throttle imposes no ban"
    );
    // Drive to the ban threshold.
    for _ in 0..10 {
        if node.rep_is_banned(&bad).await {
            break;
        }
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(node.rep_is_banned(&bad).await, "sustained abuse bans");
    assert!(
        node.rep_bans_total() >= 1,
        "ban counter bumps, got {}",
        node.rep_bans_total()
    );
    assert_eq!(
        node.rep_ban_count(&bad).await,
        1,
        "first ban is escalation level 1"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 3. Ban expires (temp, never permanent) with forgiveness: after expiry the
//    identity is neither banned nor throttled, so one packet can neither
//    re-ban nor re-throttle.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_ban_expires_with_forgiveness() {
    let (node, tmp) = fresh_node("expiry").await;
    let bad = NodeKeys::generate().id();
    for _ in 0..5 {
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(node.rep_is_banned(&bad).await, "banned first");
    // Base ban is 2s: 3s of real time must clear it (margin 1s).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!node.rep_is_banned(&bad).await, "temp ban must expire");
    assert!(
        !node.rep_is_throttled(&bad).await,
        "forgiveness lifts past the soft threshold"
    );
    let s = node.rep_score(&bad).await;
    assert!(
        (-19..0).contains(&s),
        "forgiven score sits just above soft (-19), got {s}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 4. Repeat offenders escalate (2s -> 4s, capped at 8s), and even escalated
//    bans still expire.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_repeat_offenders_escalate_but_never_permanent() {
    let (node, tmp) = fresh_node("escalate").await;
    let bad = NodeKeys::generate().id();
    for _ in 0..5 {
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(node.rep_is_banned(&bad).await, "first ban");
    assert_eq!(node.rep_ban_count(&bad).await, 1);
    // Outlive the 2s base ban (margin 1s), then re-offend to the threshold.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!node.rep_is_banned(&bad).await, "first ban expired");
    for _ in 0..10 {
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(node.rep_is_banned(&bad).await, "second ban");
    assert_eq!(
        node.rep_ban_count(&bad).await,
        2,
        "escalation memory kept across expiry"
    );
    // Second ban lasts 4s: still in force 2.5s after imposition (a base 2s
    // ban would already have expired — this gap proves the doubling).
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        node.rep_is_banned(&bad).await,
        "escalated ban outlives the base duration"
    );
    // ...but it still expires: no permanent ban, ever.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !node.rep_is_banned(&bad).await,
        "escalated ban must still expire"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 5. Bans don't affect other peers (the F8 point: identity-keyed, so no
//    shared-IP blast radius at this layer).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_bans_do_not_touch_other_peers() {
    let (node, tmp) = fresh_node("isolation").await;
    let bad = NodeKeys::generate().id();
    let good = NodeKeys::generate().id();
    let stranger = NodeKeys::generate().id();
    for _ in 0..5 {
        node.rep_record_auth_failure(&bad).await;
    }
    assert!(node.rep_is_banned(&bad).await, "offender banned");
    for pid in [&good, &stranger] {
        assert_eq!(node.rep_score(pid).await, 0, "other peer stays neutral");
        assert!(!node.rep_is_throttled(pid).await, "other peer not throttled");
        assert!(!node.rep_is_banned(pid).await, "other peer not banned");
        assert_eq!(node.rep_ban_count(pid).await, 0, "no escalation spill");
    }
    // Good peer keeps earning credit while the offender serves its ban.
    node.rep_record_valid(&good).await;
    assert!(node.rep_score(&good).await > 0, "good peer unaffected");
    assert!(node.rep_is_banned(&bad).await, "offender still banned");
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 6. Score decay over time + full recovery resets escalation memory.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_score_decays_and_recovery_resets_escalation() {
    let (node, tmp) = fresh_node("decay").await;
    let pid = NodeKeys::generate().id();
    node.rep_record_auth_failure(&pid).await;
    assert!(node.rep_score(&pid).await < 0, "debit lands");
    // -10 at 2/s needs 5s to fully decay; 6s gives 1s margin (oversleep is
    // harmless: decay clamps at neutral, never overshoots).
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        node.rep_score(&pid).await,
        0,
        "score decays back to neutral"
    );
    // Escalation memory clears only on FULL recovery (score 0, no ban):
    // ban once, let it expire (forgiven to -19), then earn 19 credits.
    for _ in 0..5 {
        node.rep_record_auth_failure(&pid).await;
    }
    assert!(node.rep_is_banned(&pid).await, "banned");
    assert_eq!(node.rep_ban_count(&pid).await, 1);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!node.rep_is_banned(&pid).await, "expired");
    // Earn back to neutral in +1 steps (bounded; decay can only help, and a
    // +1 step from a negative integer can never overshoot zero).
    for _ in 0..60 {
        if node.rep_score(&pid).await >= 0 {
            break;
        }
        node.rep_record_valid(&pid).await;
    }
    assert_eq!(node.rep_score(&pid).await, 0, "fully recovered");
    assert_eq!(
        node.rep_ban_count(&pid).await,
        0,
        "full recovery resets escalation"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 7. Every penalty kind debits; scores clamp both ways (flood-bounded).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rep_penalty_kinds_debit_and_scores_clamp() {
    let (node, tmp) = fresh_node("kinds").await;
    let pid = NodeKeys::generate().id();
    node.rep_record_oversize(&pid).await; // -10
    node.rep_record_rate_violation(&pid).await; // -5
    node.rep_record_protocol_violation(&pid).await; // -10
    assert!(
        node.rep_is_throttled(&pid).await,
        "combined debits (-25) cross the soft threshold"
    );
    assert!(
        !node.rep_is_banned(&pid).await,
        "-25 is above the ban threshold"
    );
    // Floor: unbounded negativity is impossible (recovery stays in reach).
    let floor = NodeKeys::generate().id();
    for _ in 0..150 {
        node.rep_record_auth_failure(&floor).await;
    }
    assert_eq!(
        node.rep_score(&floor).await,
        REP_SCORE_MIN,
        "score clamps at the floor"
    );
    // Ceiling: a chatty peer banks no permanent trust.
    let chatty = NodeKeys::generate().id();
    for _ in 0..300 {
        node.rep_record_valid(&chatty).await;
    }
    let s = node.rep_score(&chatty).await;
    assert!(
        s > 0 && s <= REP_SCORE_MAX,
        "credit clamps at the ceiling, got {s}"
    );
    assert!(!node.rep_is_throttled(&chatty).await);
    assert!(!node.rep_is_banned(&chatty).await);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 8. End to end over real QUIC: the ban follows the abusive IDENTITY, not
//    the IP. Same loopback address throughout: bad pre-auth handshakes are
//    refused per-connection AND dropped, leaving no identity trace
//    (framing-impossible — pre-auth failures are never attributed); throttle
//    and temp-ban still come from attributed (proven-identity, authed-path)
//    abuse, which this test models with the `rep_record_*` calls the authed
//    message path makes for a misbehaving peer. An honest peer from the same
//    IP passes the whole time; the IP itself is never strike-banned; the
//    offender recovers after the temp ban expires.
//
//    (Gate refusals deliberately carry no penalty — decay alone must be able
//    to lift a throttle — so a refused CHALLENGE never deepens any score.
//    Escalation to a ban comes only from attributed violations.)
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

/// None = refused (connection closed / timeout / non-AUTH). Some = accepted.
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

fn challenge_wire(signing: &SigningKey, src: [u8; NODEID_LEN], payload: &str, ts: i64) -> Vec<u8> {
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

fn good_wire(keys: &NodeKeys) -> Vec<u8> {
    let nonce: String = hex::encode(rand::random::<[u8; 16]>());
    let p = tofu_payload(keys, &nonce, proto::now_ms());
    challenge_wire(&keys.signing, keys.id(), &p, proto::now_ms())
}

/// Bad-signature wire from the SAME identity: the signature (last 64 bytes of
/// the encoding) is corrupted, so framing still decodes and the failure is
/// attributed to the claimed identity.
fn bad_wire(keys: &NodeKeys) -> Vec<u8> {
    let mut w = good_wire(keys);
    let last = w.len() - 1;
    w[last] ^= 0xff;
    w
}

#[tokio::test(flavor = "multi_thread")]
async fn rep_quic_ban_follows_identity_not_ip() {
    rep_env();
    let tmp = tmpdir("quic");
    let listen: SocketAddr = "127.0.0.1:19931".parse().unwrap();
    let keys_b = NodeKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19931", vec![], true),
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

    let bad_keys = NodeKeys::generate();
    let bad_id = bad_keys.id();
    // Two bad handshakes: refused AND dropped, with no identity trace —
    // pre-auth failures are never attributed to the claimed id.
    for _ in 0..2 {
        let c = raw_connect(listen).await.expect("admission passes");
        assert!(
            raw_handshake(&c, &bad_wire(&bad_keys)).await.is_none(),
            "bad signature refused"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), c.closed())
                .await
                .is_ok(),
            "attacker connection dropped"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert_eq!(
        b.rep_score(&bad_id).await,
        0,
        "pre-auth abuse leaves no score trace"
    );
    assert!(
        !b.rep_is_throttled(&bad_id).await,
        "handshake abuse alone never throttles"
    );
    assert!(
        !b.rep_is_banned(&bad_id).await,
        "handshake abuse alone never bans"
    );
    // Same loopback IP, honest identity: passes while the offender's bad
    // handshakes are refused — no shared-IP blast radius at this layer.
    let good_keys = NodeKeys::generate();
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &good_wire(&good_keys)).await.is_some(),
        "honest peer passes while offender throttled"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Three more bad handshakes: still refused per-connection, still no
    // identity trace — sustained handshake abuse alone escalates nothing.
    for _ in 0..3 {
        let c = raw_connect(listen).await.expect("admission passes");
        assert!(
            raw_handshake(&c, &bad_wire(&bad_keys)).await.is_none(),
            "bad signature refused"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert_eq!(
        b.rep_score(&bad_id).await,
        0,
        "sustained handshake abuse leaves no score trace"
    );
    assert!(
        !b.rep_is_throttled(&bad_id).await,
        "sustained handshake abuse stalls at nothing"
    );
    assert!(
        !b.rep_is_banned(&bad_id).await,
        "handshake abuse alone does not ban"
    );
    // Attributed abuse (the authed message path's records for a misbehaving
    // proven peer) still throttles, then escalates the identity to a ban.
    for _ in 0..2 {
        b.rep_record_auth_failure(&bad_id).await;
    }
    assert!(
        b.rep_is_throttled(&bad_id).await,
        "proven-identity abuse throttles"
    );
    // A now-VALID handshake from the throttled identity is refused at the gate
    // (fail-closed), and counted — without any extra score penalty.
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &good_wire(&bad_keys)).await.is_none(),
        "throttled identity refused even with a valid handshake"
    );
    assert!(
        b.rep_refusals_total() >= 1,
        "reputation refusals counted, got {}",
        b.rep_refusals_total()
    );
    // Attributed post-auth abuse (what the authed message path records for a
    // misbehaving peer) escalates the throttled identity to a temp ban.
    for _ in 0..3 {
        b.rep_record_protocol_violation(&bad_id).await;
    }
    assert!(b.rep_is_banned(&bad_id).await, "offender banned");
    // A now-VALID handshake from the banned identity is refused at the gate
    // (fail-closed), and counted — without any extra score penalty.
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &good_wire(&bad_keys)).await.is_none(),
        "banned identity refused even with a valid handshake"
    );
    assert!(
        b.rep_refusals_total() >= 1,
        "reputation refusals counted, got {}",
        b.rep_refusals_total()
    );
    // Fresh honest identity still passes; the IP itself was never banned
    // (strike threshold 1000 >> our ~6 failures).
    let good2 = NodeKeys::generate();
    let c = raw_connect(listen).await.expect("admission passes");
    assert!(
        raw_handshake(&c, &good_wire(&good2)).await.is_some(),
        "honest peer passes while offender banned"
    );
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        !b.is_banned(&loopback).await,
        "identity ban must not spill onto the shared IP"
    );

    // Temp ban expires on its own: the offender's valid handshake passes
    // again with no restart, no manual unban.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!b.rep_is_banned(&bad_id).await, "ban expired");
    let c = raw_connect(listen)
        .await
        .expect("connect passes after expiry");
    assert!(
        raw_handshake(&c, &good_wire(&bad_keys)).await.is_some(),
        "offender recovers after the temp ban"
    );
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
