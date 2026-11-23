//! Protocol version / fork id / capability negotiation (transport control
//! plane).
//!
//! The rules under test are the ones the node enforces after the PQ+AUTH
//! handshake: a fork mismatch or a protocol two minors away is refused for
//! CONSENSUS participation (loudly), N-1 is accepted with the capability
//! intersection, and any unknown control kind is ignored without touching the
//! stream.

use infnode::config::NodeConfig;
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::Node;
use infnode::proto::{
    classify_peer, decode_control, fork_id_from_parts, is_control_kind, kind, local_identity,
    Capabilities, ControlMessage, Hello, NegotiationRefusal, ProtocolIdentity, ProtocolVersion,
    DEFAULT_IDENTITY, HELLO_WIRE_LEN, INFNODE_FORK_ID,
};
use std::path::PathBuf;
use std::sync::Arc;

fn local() -> ProtocolIdentity {
    ProtocolIdentity {
        protocol_version: ProtocolVersion::new(1, 2),
        fork_id: 0xDEAD_BEEF,
        capabilities: Capabilities::ALL,
    }
}

// ---------------------------------------------------------------------------
// 1. fork id mismatch is refused for consensus with a specific, loud error.
// ---------------------------------------------------------------------------

#[test]
fn fork_mismatch_is_refused_for_consensus_with_specific_error() {
    let peer = Hello::new(
        ProtocolVersion::new(1, 2),
        local().fork_id ^ 1,
        Capabilities::ALL,
    );
    let err = proto_negotiate(local(), peer).expect_err("a fork mismatch must never be accepted");
    match err {
        NegotiationRefusal::ForkMismatch { local: l, peer: p } => {
            assert_eq!(l, 0xDEAD_BEEF);
            assert_eq!(p, 0xDEAD_BEEF ^ 1);
        }
        other => panic!("expected ForkMismatch, got {other:?}"),
    }
    let text = err.to_string();
    assert!(
        text.contains("CONSENSUS REFUSED") && text.contains("fork_id"),
        "the refusal must be LOUD and name the fork id: {text}"
    );

    // The peer stays connected for DHT/blobs, but has ZERO consensus
    // capabilities and cannot be voted with.
    let state = classify_peer(local(), peer);
    assert!(!state.consensus_eligible());
    assert_eq!(state.capabilities(), Capabilities::NONE);
    assert!(state.may_serve_non_consensus());
    assert!(matches!(
        state.refusal,
        Some(NegotiationRefusal::ForkMismatch { .. })
    ));
}

// ---------------------------------------------------------------------------
// 2. one minor behind connects with the INTERSECTION of capabilities.
// ---------------------------------------------------------------------------

#[test]
fn one_minor_behind_connects_with_capability_intersection() {
    let peer = Hello::new(
        ProtocolVersion::new(1, 1),
        local().fork_id,
        Capabilities::COMPACT_GOSSIP, // no MESH_DIRECT
    );
    let state = classify_peer(local(), peer);
    assert!(state.consensus_eligible(), "N-1 must be accepted");
    assert_eq!(state.capabilities(), Capabilities::COMPACT_GOSSIP);
    let agreement = state.agreement.expect("agreement");
    assert!(agreement.advisory, "N-1 must be flagged as advisory");
    assert_eq!(agreement.protocol_version, ProtocolVersion::new(1, 1));

    // N+1 (peer ahead) is symmetric: accepted and intersected.
    let ahead = Hello::new(
        ProtocolVersion::new(1, 3),
        local().fork_id,
        Capabilities::MESH_DIRECT,
    );
    let state = classify_peer(local(), ahead);
    assert!(state.consensus_eligible());
    assert_eq!(state.capabilities(), Capabilities::MESH_DIRECT);
    assert!(state.agreement.expect("agreement").advisory);
}

// ---------------------------------------------------------------------------
// 3. two versions behind is refused for consensus (and so is two ahead).
// ---------------------------------------------------------------------------

#[test]
fn two_minors_behind_is_refused() {
    let old = Hello::new(
        ProtocolVersion::new(1, 0),
        local().fork_id,
        Capabilities::ALL,
    );
    let err = proto_negotiate(local(), old).expect_err("N-2 must be refused");
    assert!(matches!(err, NegotiationRefusal::VersionTooOld { .. }));
    assert!(err.to_string().contains("CONSENSUS REFUSED"));
    assert!(!classify_peer(local(), old).consensus_eligible());

    let ahead = Hello::new(
        ProtocolVersion::new(1, 4),
        local().fork_id,
        Capabilities::ALL,
    );
    let err = proto_negotiate(local(), ahead).expect_err("N+2 must be refused");
    assert!(matches!(err, NegotiationRefusal::VersionTooNew { .. }));
    assert!(!classify_peer(local(), ahead).consensus_eligible());
}

#[test]
fn different_major_is_refused() {
    let peer = Hello::new(
        ProtocolVersion::new(2, 2),
        local().fork_id,
        Capabilities::ALL,
    );
    assert!(matches!(
        proto_negotiate(local(), peer),
        Err(NegotiationRefusal::MajorMismatch { .. })
    ));
}

// ---------------------------------------------------------------------------
// 4. unknown control messages are ignored; the stream stays usable.
// ---------------------------------------------------------------------------

#[test]
fn unknown_control_kind_is_ignored_and_stream_stays_usable() {
    // Unknown kind: no panic, no error, simply `None` = ignore.
    assert_eq!(decode_control(0x7f, b"future-control-payload"), None);
    assert_eq!(decode_control(0xff, b""), None);
    assert!(!is_control_kind(0x7f));
    assert!(is_control_kind(kind::HELLO));

    // A known control kind with a malformed payload is also ignored, never a
    // disconnect.
    assert_eq!(decode_control(kind::HELLO, b"short"), None);

    // After ignoring the unknown frame, a real Hello still decodes: frame
    // boundaries are self-delimiting, so skipping one cannot desync the next.
    let hello = Hello::new(
        ProtocolVersion::new(1, 2),
        INFNODE_FORK_ID,
        Capabilities::ALL,
    );
    assert_eq!(
        decode_control(kind::HELLO, &hello.encode()),
        Some(ControlMessage::Hello(hello))
    );

    // Two wire frames decode independently even though the first kind is
    // unknown to this build.
    let future = infnode::proto::Frame {
        kind: 0x7f,
        seq: 1,
        ts: 1,
        src: [1u8; 20],
        dst: [2u8; 20],
        svc: 0,
        payload: b"opaque".to_vec(),
        nonce: Vec::new(),
        sig: Vec::new(),
    };
    let decoded = infnode::proto::Frame::decode(&future.encode())
        .expect("an unknown KIND is still a valid v2 frame");
    assert_eq!(decoded.kind, 0x7f);
    assert_eq!(decode_control(decoded.kind, &decoded.payload), None);
}

// ---------------------------------------------------------------------------
// 5. Hello codec + constant-only fork id derivation.
// ---------------------------------------------------------------------------

#[test]
fn hello_roundtrips_and_ignores_trailing_extension_bytes() {
    let hello = Hello::new(
        ProtocolVersion::new(3, 7),
        0x1234_5678,
        Capabilities::COMPACT_GOSSIP.union(Capabilities::MESH_DIRECT),
    );
    let bytes = hello.encode();
    assert_eq!(bytes.len(), HELLO_WIRE_LEN);
    assert_eq!(Hello::decode(&bytes), Some(hello));

    // Forward compatibility: a future build may append fields; this decoder
    // reads the known prefix and ignores the rest.
    let mut extended = bytes.clone();
    extended.extend_from_slice(b"FUTURE");
    assert_eq!(Hello::decode(&extended), Some(hello));

    // A truncated payload is refused (ignored by the caller), never a panic.
    assert_eq!(Hello::decode(&bytes[..HELLO_WIRE_LEN - 1]), None);
    assert_eq!(Hello::decode(b"IHL2\x00\x00\x00\x00"), None);
}

#[test]
fn fork_id_is_derived_from_constants_and_moves_with_the_ruleset() {
    let base = fork_id_from_parts(&[2, 1, 0x4d, 65_536, 33_554_432]);
    assert_eq!(base, INFNODE_FORK_ID, "default must be constant-derived");
    // Same inputs -> same id (stable across runs/rebuilds).
    assert_eq!(base, fork_id_from_parts(&[2, 1, 0x4d, 65_536, 33_554_432]));
    // One changed rule -> a different id.
    for idx in 0..5 {
        let mut changed = [2u32, 1, 0x4d, 65_536, 33_554_432];
        changed[idx] ^= 1;
        assert_ne!(
            base,
            fork_id_from_parts(&changed),
            "changing ruleset input {idx} must change the fork id"
        );
    }
    assert_eq!(DEFAULT_IDENTITY.fork_id, INFNODE_FORK_ID);
}

/// Small local alias so the test reads as the production call.
fn proto_negotiate(
    local: ProtocolIdentity,
    peer: Hello,
) -> Result<infnode::proto::Agreement, NegotiationRefusal> {
    infnode::proto::negotiate(local, peer)
}

// ---------------------------------------------------------------------------
// 6. The NODE stores the Hello verdict and the status read exposes it.
// ---------------------------------------------------------------------------

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
        wallet: None,
        web_static: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_records_hello_and_status_exposes_protocol_identity() {
    let dir = std::env::temp_dir().join(format!("infnode-protocol-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let node = Arc::new(
        Node::new(
            cfg("proto", "127.0.0.1:0"),
            NodeKeys::generate(),
            PqKeys::generate(),
            dir.join("n"),
            PathBuf::new(),
        )
        .await
        .expect("node"),
    );

    // Unknown until a Hello arrives: legacy v2 peers are admitted (the
    // pre-negotiation wire behaviour is unchanged).
    let pid = [0x42u8; 20];
    assert!(node.peer_protocol_state(&pid).is_none());
    assert!(node.peer_consensus_admitted(&pid));
    assert_eq!(node.peer_capabilities(&pid), None);

    // Fork-mismatched Hello: stored, refused for consensus, DHT still allowed.
    let local = local_identity();
    let bad = Hello::new(local.protocol_version, local.fork_id ^ 1, Capabilities::ALL);
    let state = node.apply_peer_hello(pid, bad);
    assert!(!state.consensus_eligible());
    assert!(state.may_serve_non_consensus());
    assert!(!node.peer_consensus_admitted(&pid));
    assert_eq!(node.peer_capabilities(&pid), Some(Capabilities::NONE));

    // The `core.status` read carries the local identity and (for negotiated
    // peers) the per-peer verdict.
    let status: serde_json::Value =
        serde_json::from_str(&node.status().await.expect("status")).expect("json");
    assert_eq!(
        status["protocol"]["fork_id"].as_u64(),
        Some(u64::from(local.fork_id))
    );
    assert_eq!(
        status["protocol"]["protocol_version"].as_str(),
        Some(local.protocol_version.to_string().as_str())
    );
    assert!(status["protocol"]["capabilities"].as_u64().is_some());

    let _ = std::fs::remove_dir_all(&dir);
}
