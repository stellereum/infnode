//! NodeId PQ-only tests (FULL-PQ wipe: no window, no legacy alias).
//!
//! Covers the PQ-only `NodeId` using only the public API:
//! * PQ derivation vector (fixed seed — structural + hardcoded),
//! * PQ-only announce (single id) + parse round-trip,
//! * first-PQ-wins rebinding refusal (attacker cannot rebind honest ed),
//! * classical-only refused (no LEGACY arm; `primary_id`/`dual_announce`
//!   error without `pq_pub`; `resolve_node_id` requires PQ),
//! * old single-ed configs fail LOUDLY at parse (clear migration error,
//!   never silent classical).
//!
//! Env-safety: no env vars are touched here (passphrase/perms paths are owned
//! by `keystore_security_tests.rs`); no wall-clock asserts.

use infnode::config::PeerConfig;
use infnode::keyring::{
    dual_announce_hex, dual_announce_ids, parse_dual_announce, resolve_node_id,
    NodeIdKind, NodeKeys, PqKeys, ResolvedNodeId,
};
use infnode::node::{ceremony_local_id, PqBindOutcome, PqIdentityRegistry};
use infnode::proto::{self};

/// Fixed-seed PQ identity (deterministic keygen — same keypair every run).
fn fixed_pq() -> PqKeys {
    PqKeys::from_seed([0x5Au8; 32])
}

/// Hardcoded derivation vector for `fixed_pq()` (seed `[0x5A; 32]`).
const EXPECTED_PQ_ID_HEX: &str = "a2b41ccbd40e4454d025ce9d4587bc8f7af739d8";

fn peer_cfg(pq_pub: Option<String>) -> PeerConfig {
    PeerConfig {
        name: "p".to_string(),
        ed_pub: hex::encode([2u8; 32]),
        pq_pub,
        endpoints: vec![],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

// ---------------------------------------------------------------------------
// 1. PQ NodeId derivation vector: fixed seed => fixed id, PQ-only.
// ---------------------------------------------------------------------------

#[test]
fn ceremony_01_pq_nodeid_derivation_vector() {
    let pq = fixed_pq();
    let ed = NodeKeys::generate();

    // Structural: pq_id is a pure function of the PQ pub (not of any ed key).
    assert_eq!(pq.pq_id(), proto::pq_id_from_pub(&pq.pq_pub()));
    assert_eq!(pq.pq_id_hex(), format!("inf1:{}", hex::encode(pq.pq_id())));

    // Ceremony rule: PQ-only, kind marked PQ.
    let r = resolve_node_id(&ed, &pq);
    assert_eq!(r.kind, NodeIdKind::Pq);
    assert!(!r.is_legacy());
    assert_eq!(r.kind_label(), "PQ");
    assert_eq!(r.id, pq.pq_id());
    assert_eq!(r, ResolvedNodeId { id: pq.pq_id(), kind: NodeIdKind::Pq });

    // Canonical call site agrees.
    assert_eq!(ceremony_local_id(&ed, &pq), pq.pq_id());

    // Hardcoded vector pins the derivation byte-exactly.
    assert_eq!(hex::encode(r.id), EXPECTED_PQ_ID_HEX, "ceremony vector");

    // A different PQ seed => a different PQ id (key-bound, not constant).
    let other = PqKeys::from_seed([0x3Bu8; 32]);
    assert_ne!(other.pq_id(), pq.pq_id());
}

// ---------------------------------------------------------------------------
// 2. PQ-only announce: single id; parse round-trips; PeerConfig mirrors it.
// ---------------------------------------------------------------------------

#[test]
fn ceremony_02_pq_announce_single_id() {
    let ed = NodeKeys::generate();
    let pq = fixed_pq();

    // PQ-only: exactly one id (no legacy alias).
    let ids = dual_announce_ids(&ed, &pq);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], pq.pq_id(), "PQ id announced");

    // Hex form round-trips through the parser.
    let hex_ids = dual_announce_hex(&ed, &pq);
    assert_eq!(hex_ids.len(), 1);
    assert!(hex_ids[0].starts_with("inf1:"));
    let parsed = parse_dual_announce(&hex_ids).expect("parse pq");
    assert_eq!(parsed, ids);

    // PeerConfig mirror: pq pinned => primary is pq, dual is [pq].
    let cfg = peer_cfg(Some(pq.pq_pub_hex()));
    assert_eq!(cfg.primary_id().expect("primary"), pq.pq_id());
    assert_eq!(cfg.dual_announce_ids().expect("dual"), ids);

    // Fail-closed parse: empty, 2 ids, malformed, wrong length all refuse.
    assert!(parse_dual_announce(&[]).is_err());
    let two: Vec<String> = vec![hex_ids[0].clone(), hex_ids[0].clone()];
    assert!(parse_dual_announce(&two).is_err());
    assert!(parse_dual_announce(&["zz".to_string()]).is_err());
    assert!(parse_dual_announce(&[format!("inf1:{}", hex::encode([0u8; 19]))]).is_err());
}

// ---------------------------------------------------------------------------
// 3. Rebinding refused: honest ed binds first; attacker cannot rebind the
//    honest classical id to its own PQ key (first-PQ-wins sticks).
// ---------------------------------------------------------------------------

#[test]
fn ceremony_03_rebinding_refused_first_pq_wins() {
    let honest_ed = NodeKeys::generate();
    let honest_pq = fixed_pq();
    let attacker_pq = PqKeys::from_seed([0x3Bu8; 32]);
    let classical = honest_ed.id();

    let mut reg = PqIdentityRegistry::new();

    // Honest enrolment binds first (ed↔pq link).
    assert_eq!(
        reg.announce(&classical, &honest_pq.pq_pub(), true),
        PqBindOutcome::NewBound
    );
    // Attacker rebinds the HONEST classical id to its OWN pq key with a
    // valid-for-its-own-key tag: quarantined, binding UNCHANGED.
    assert_eq!(
        reg.announce(&classical, &attacker_pq.pq_pub(), true),
        PqBindOutcome::Quarantined,
        "attacker must not rebind honest ed to own pq"
    );
    assert_eq!(reg.bound_pq(&classical), Some(honest_pq.pq_pub().as_slice()));
    // Attacker retry with bad tag: still quarantined, still unchanged.
    assert_eq!(
        reg.announce(&classical, &attacker_pq.pq_pub(), false),
        PqBindOutcome::Quarantined
    );
    assert_eq!(reg.bound_pq(&classical), Some(honest_pq.pq_pub().as_slice()));
    // Honest re-announce is steady state, not a re-bind.
    assert_eq!(
        reg.announce(&classical, &honest_pq.pq_pub(), true),
        PqBindOutcome::AlreadyBound
    );
}

// ---------------------------------------------------------------------------
// 4. Classical-only refused: no LEGACY arm; PQ required everywhere.
// ---------------------------------------------------------------------------

#[test]
fn ceremony_04_classical_only_refused() {
    // Only the PQ kind exists.
    assert_eq!(NodeIdKind::Pq.label(), "PQ");
    // Legacy classical id is NOT a NodeId: no resolve path accepts it
    // (resolve requires `&PqKeys` at the type level — there is no `None`
    // arm to test). The classical `blake3(ed)[..20]` helper remains only
    // for frozen route/TLS-pin call sites, never as identity.
    let ed = NodeKeys::generate();
    let pq = fixed_pq();
    assert_ne!(ed.id(), pq.pq_id(), "classical helper must differ from PQ id");
    assert_eq!(ceremony_local_id(&ed, &pq), pq.pq_id());

    // PeerConfig without pq_pub (code-constructed dynamic): refused.
    // Parsed configs without `pq_pub` fail LOUDLY at parse (see
    // `ceremony_05`), never silently classical.
    let legacy_cfg = peer_cfg(None);
    assert!(legacy_cfg.primary_id().is_err(), "classical peer refused");
    assert!(legacy_cfg.dual_announce_ids().is_err(), "classical peer refused");
}

// ---------------------------------------------------------------------------
// 5. Old single-ed configs fail LOUDLY at parse (clear migration error).
// ---------------------------------------------------------------------------

#[test]
fn ceremony_05_legacy_config_fails_loudly_at_parse() {
    // Old shape with `node-id`/`ed-pub`/`x-pub`, no `pq-pub`: must NOT parse
    // (FULL-PQ wipe, nodes wiped, no compat). Error is a clear migration
    // message, never a silent classical fallback.
    let yaml_old = r#"
name: oldnode
listen: "0.0.0.0:9400"
peers:
  - name: pal
    node-id: "inf1:0102030405060708090a0b0c0d0e0f1011121314"
    ed-pub: "0202020202020202020202020202020202020202020202020202020202020202"
    x-pub: "0303030303030303030303030303030303030303030303030303030303030303"
    endpoints: []
"#;
    let err = serde_yaml::from_str::<infnode::config::NodeConfig>(yaml_old)
        .expect_err("old single-ed config must fail at parse");
    let msg = err.to_string();
    assert!(
        msg.contains("FULL-PQ") || msg.contains("pq-pub") || msg.contains("node-id") || msg.contains("x-pub"),
        "migration error must be clear, got: {msg}"
    );

    // Missing `pq-pub` (ed-only, new field names) also fails loudly.
    let yaml_no_pq = r#"
name: oldnode
listen: "0.0.0.0:9400"
peers:
  - name: pal
    ed-pub: "0202020202020202020202020202020202020202020202020202020202020202"
    endpoints: []
"#;
    let err2 = serde_yaml::from_str::<infnode::config::NodeConfig>(yaml_no_pq)
        .expect_err("ed-only config without pq-pub must fail at parse");
    let msg2 = err2.to_string();
    assert!(
        msg2.contains("FULL-PQ") || msg2.contains("pq-pub") || msg2.contains("mandatory"),
        "migration error must be clear, got: {msg2}"
    );

    // New shape (ed + pq) parses and derives the PQ id (same property as
    // `ceremony_02`, PQ materials).
    let pq = fixed_pq();
    let yaml_new = format!(
        r#"
name: newnode
listen: "0.0.0.0:9400"
peers:
  - name: pal
    ed-pub: "0202020202020202020202020202020202020202020202020202020202020202"
    pq-pub: "{}"
    endpoints: []
"#,
        pq.pq_pub_hex()
    );
    let cfg: infnode::config::NodeConfig =
        serde_yaml::from_str(&yaml_new).expect("pq config parses");
    assert_eq!(cfg.peers.len(), 1);
    assert!(cfg.peers[0].pq_pub.is_some());
    assert_eq!(cfg.peers[0].primary_id().expect("primary"), pq.pq_id());
}
