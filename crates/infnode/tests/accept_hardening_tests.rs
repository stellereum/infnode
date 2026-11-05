//! F8 accept-path hardening (2026-11-01 audit): fail-closed tests.
//!
//! Scope: infnode crate only. Covers the three bounded layers around the
//! unchanged wire/auth semantics:
//!   1. pre-auth deadline (`STELL_INF_PREAUTH_DEADLINE_SECS`, default 15):
//!      connections with no valid CHALLENGE are closed, permits freed;
//!      established/authed sessions are never deadline-closed.
//!   2. per-IP handshake bucket (`STELL_INF_HANDSHAKE_PER_IP_PER_SEC`,
//!      default 30, `RateBucket` style): legit redials pass, bursts throttle.
//!   3. failed-auth strikes with cooldown (`STELL_INF_AUTH_FAIL_THRESHOLD`
//!      default 5, `STELL_INF_AUTH_FAIL_WINDOW_SECS` default 60,
//!      `STELL_INF_AUTH_BAN_COOLDOWN_SECS` default 300): N failures in window
//!      bans the IP for the cooldown; success resets.
//!
//! These tests run with tightened env (deadline 2s, rate 3/s, threshold 3,
//! cooldown 6s) so they finish in seconds. All tests in this file use the
//! SAME env values, so parallel execution cannot race on env.

use ed25519_dalek::{Signer, SigningKey};
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{Node, RateBucket};
use infnode::proto::{self, Frame, NODEID_LEN};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn harden_env() {
    std::env::set_var("STELL_INF_PREAUTH_DEADLINE_SECS", "2");
    std::env::set_var("STELL_INF_HANDSHAKE_PER_IP_PER_SEC", "3");
    std::env::set_var("STELL_INF_AUTH_FAIL_THRESHOLD", "3");
    std::env::set_var("STELL_INF_AUTH_FAIL_WINDOW_SECS", "60");
    std::env::set_var("STELL_INF_AUTH_BAN_COOLDOWN_SECS", "6");
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
    let d = std::env::temp_dir().join(format!("infnode-harden-{tag}-{}", std::process::id()));
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
    // Keep the endpoint alive as long as the connection: forgetting `ep`
    // drops the last handle but the runtime keeps the UDP socket via the
    // connection itself, so this is safe for short tests.
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
    // FULL-PQ: CHALLENGE carries ephemeral ML-KEM `pq_ek` (KEM-only session,
    // X3DH leg cut — sibling). Without `pq_*` the responder fails closed
    // (`pq handshake required`). Same construction as production
    // `connect_with_auth` (reuse `pq_initiator_offer`, no new crypto).
    let offer = infnode::node::pq_initiator_offer().expect("pq offer");
    serde_json::json!({
        "nonce": nonce_hex,
        "at": at,
        "eph": hex::encode(eph_pub.as_bytes()),
        "ed": hex::encode(keys.verifying.to_bytes()),
        "pq_ver": infnode::proto::PQ_TRANSCRIPT_VERSION,
        "pq_suite": infnode::proto::PQ_SUITE_MLKEM768_HYBRID,
        "pq_ek": hex::encode(&offer.ek),
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Pure gate logic: bucket burst allows legit redials, throttles sustained rain.
// ---------------------------------------------------------------------------

#[test]
fn harden_bucket_burst_then_throttle() {
    // Mirrors RateBucket semantics used by the per-IP handshake gate:
    // fresh identity gets one immediate handshake, burst is bounded.
    let rate = 3u32;
    let mut b = RateBucket::new();
    assert!(b.allow(rate), "first handshake passes");
    assert!(!b.allow(rate), "immediate second handshake throttled");
    // After ~700ms at 3/s ~2 tokens refill, so one more passes.
    std::thread::sleep(std::time::Duration::from_millis(700));
    assert!(b.allow(rate), "bucket refills at the configured rate");
}

// ---------------------------------------------------------------------------
// Pure strike logic without network: failures accumulate, success resets.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn harden_strikes_reset_on_success() {
    harden_env();
    let tmp = tmpdir("strikes-pure");
    let keys = NodeKeys::generate();
    let pq = PqKeys::generate();
    let node = Node::new(
        cfg("S", "127.0.0.1:0", vec![], false),
        keys, pq,
        tmp.join("s"),
        PathBuf::new(),
    )
    .await
    .expect("node");
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    // 2 failures (< threshold 3): not banned.
    node.record_auth_failure(ip).await;
    node.record_auth_failure(ip).await;
    assert!(!node.is_banned(&ip).await, "below threshold not banned");
    // Success resets the count.
    node.record_auth_success(&ip).await;
    node.record_auth_failure(ip).await;
    node.record_auth_failure(ip).await;
    assert!(
        !node.is_banned(&ip).await,
        "success must reset strikes (2 fresh failures not banned)"
    );
    node.record_auth_failure(ip).await;
    assert!(node.is_banned(&ip).await, "3 failures in window bans");
    assert!(node.auth_bans_total() >= 1, "ban counter bumps");
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 1. slow-handshake rain gets deadline-closed (permits free).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn harden_slow_handshake_rain_deadline_closes() {
    harden_env();
    let tmp = tmpdir("slow-rain");
    let listen: SocketAddr = "127.0.0.1:19911".parse().unwrap();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19911", vec![], true),
        keys_b.clone(), pq_b.clone(),
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

    // RateBucket starts with 1 token and refills at 3/s: space dials by
    // 400ms so all 5 pass admission, then idle with no CHALLENGE.
    let mut held = Vec::new();
    for _ in 0..5 {
        let c = raw_connect(listen).await.expect("connect passes admission");
        held.push(c);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    // Hold past the 2s pre-auth deadline, then the server must have closed
    // every idle connection and freed its permit.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let mut closed = 0usize;
    for c in &held {
        // Server close surfaces as a close reason or an immediately-ready
        // `closed()` future; either proves the deadline fired.
        let by_reason = c.close_reason().is_some();
        let by_closed = !by_reason
            && tokio::time::timeout(Duration::from_millis(500), c.closed())
                .await
                .is_ok();
        if by_reason || by_closed {
            closed += 1;
        }
        c.close(0u32.into(), b"test done");
    }
    assert!(
        closed >= 4,
        "slow handshakes must be deadline-closed, got {closed}/5"
    );
    assert!(
        b.preauth_timeouts_total() >= 4,
        "deadline counter must bump, got {}",
        b.preauth_timeouts_total()
    );
    // Permits are free: a fresh legit handshake is accepted immediately.
    // (Bucket refilled while we waited, so admission passes.)
    tokio::time::sleep(Duration::from_millis(800)).await;
    let ke = NodeKeys::generate();
    let nonce: String = hex::encode(rand::random::<[u8; 16]>());
    let p = tofu_payload(&ke, &nonce, proto::now_ms());
    let w = challenge_wire(&ke.signing, ke.id(), &p, proto::now_ms());
    let c = raw_connect(listen).await.expect("permits free after deadline");
    assert!(
        raw_handshake(&c, &w).await.is_some(),
        "server serves honestly after the rain"
    );
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 2. burst dials throttled per bucket.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn harden_burst_dials_throttled() {
    harden_env();
    let tmp = tmpdir("burst");
    let listen: SocketAddr = "127.0.0.1:19912".parse().unwrap();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19912", vec![], true),
        keys_b.clone(), pq_b.clone(),
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

    // 14 back-to-back QUIC handshakes against a 3/s (burst 6) bucket:
    // the first burst passes, the excess must be refused pre-permit.
    let mut ok = 0usize;
    let mut refused = 0usize;
    let mut held = Vec::new();
    for _ in 0..14 {
        match tokio::time::timeout(Duration::from_secs(6), raw_connect(listen)).await {
            Ok(Ok(c)) => {
                ok += 1;
                held.push(c);
            }
            _ => refused += 1,
        }
    }
    assert!(
        refused >= 3,
        "burst must be throttled, got ok={ok} refused={refused}"
    );
    assert!(
        b.handshake_throttled_total() >= 3,
        "throttle counter must bump, got {}",
        b.handshake_throttled_total()
    );
    for c in held {
        c.close(0u32.into(), b"test done");
    }
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 3. strikes -> cooldown -> recovery cycle.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn harden_strikes_cooldown_recovery() {
    harden_env();
    let tmp = tmpdir("strikes-net");
    let listen: SocketAddr = "127.0.0.1:19913".parse().unwrap();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19913", vec![], true),
        keys_b.clone(), pq_b.clone(),
        tmp.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");
    let sb = tokio::spawn({
        let n: Arc<Node> = b.clone();
        async move { n.serve().await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Spacing (600ms) stays under the 3/s handshake bucket so refusals below
    // prove strike logic, not bucket throttling.
    let bad_once = |nonce: &str| {
        let k = NodeKeys::generate();
        let good = tofu_payload(&k, nonce, proto::now_ms());
        let mut wire = challenge_wire(&k.signing, k.id(), &good, proto::now_ms());
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        wire
    };
    let good_wire = || {
        let k = NodeKeys::generate();
        let nonce: String = hex::encode(rand::random::<[u8; 16]>());
        let p = tofu_payload(&k, &nonce, proto::now_ms());
        challenge_wire(&k.signing, k.id(), &p, proto::now_ms())
    };

    // 2 failures (< threshold 3): honest handshake still passes and resets.
    for n in ["01", "02"] {
        let wire = bad_once(&format!("0{n}").repeat(16));
        let c = raw_connect(listen).await.expect("admission passes");
        assert!(
            raw_handshake(&c, &wire).await.is_none(),
            "bad sig refused"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
    let w = good_wire();
    let c = raw_connect(listen).await.expect("not banned yet");
    assert!(
        raw_handshake(&c, &w).await.is_some(),
        "honest handshake passes below threshold (and resets)"
    );
    tokio::time::sleep(Duration::from_millis(600)).await;

    // 3 fresh failures hit the threshold: IP banned for 6s.
    for n in ["11", "12", "13"] {
        let wire = bad_once(&format!("1{n}").repeat(16));
        let c = raw_connect(listen).await.expect("admission passes pre-ban");
        let _ = raw_handshake(&c, &wire).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
    assert!(b.auth_bans_total() >= 1, "ban must be imposed");
    // While banned even a fresh honest handshake is refused at accept time.
    let w2 = good_wire();
    let banned = match tokio::time::timeout(Duration::from_secs(6), raw_connect(listen)).await {
        Ok(Ok(c)) => raw_handshake(&c, &w2).await.is_none(),
        _ => true,
    };
    assert!(banned, "banned IP must be refused");

    // Cooldown expiry restores service without a restart.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let w3 = good_wire();
    let c = raw_connect(listen)
        .await
        .expect("connect passes after cooldown");
    assert!(
        raw_handshake(&c, &w3).await.is_some(),
        "honest handshake recovers after cooldown"
    );
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// 4. legit handshake unaffected (control).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn harden_legit_handshake_unaffected() {
    harden_env();
    let tmp = tmpdir("legit");
    let listen: SocketAddr = "127.0.0.1:19914".parse().unwrap();
    let keys_b = NodeKeys::generate();
    let pq_b = PqKeys::generate();
    let b = Node::new(
        cfg("B", "127.0.0.1:19914", vec![], true),
        keys_b.clone(), pq_b.clone(),
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

    let ke = NodeKeys::generate();
    let nonce: String = hex::encode(rand::random::<[u8; 16]>());
    let p = tofu_payload(&ke, &nonce, proto::now_ms());
    let w = challenge_wire(&ke.signing, ke.id(), &p, proto::now_ms());
    let c = raw_connect(listen).await.expect("connect passes");
    assert!(
        raw_handshake(&c, &w).await.is_some(),
        "single honest handshake must be accepted"
    );
    assert_eq!(
        b.handshake_throttled_total(),
        0,
        "control must not trip the bucket"
    );
    assert_eq!(b.preauth_timeouts_total(), 0, "control must not time out");
    sb.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
