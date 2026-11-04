//! NodeId re-ceremony tests (HDAE, lead-commits-only: NEW FILE ONLY).
//!
//! Covers the PQ-primary `NodeId` migration window using only the public API:
//! * PQ derivation vector (fixed seed — structural + hardcoded),
//! * dual-announce ordering (PQ first) + parse round-trip,
//! * first-PQ-wins rebinding refusal (attacker cannot rebind honest ed),
//! * legacy-only explicit LEGACY mark,
//! * window-end refusal on an injected clock (no wall-clock asserts),
//! * old single-ed configs keep working pre-window-end (serde unchanged).
//!
//! Env-safety: no env vars are touched here (passphrase/perms paths are owned
//! by `keystore_security_tests.rs`); all time is injected.

use infnode::config::PeerConfig;
use infnode::keyring::{
    self, dual_announce_hex, dual_announce_ids, legacy_alias_accepted_at,
    parse_dual_announce, resolve_node_id, NodeIdKind, NodeKeys, PqKeys,
    ResolvedNodeId, LEGACY_ALIAS_END_UNIX_MS,
};
use infnode::node::{ceremony_local_id, PqBindOutcome, PqIdentityRegistry};
use infnode::proto::{self, NODEID_LEN};

/// Fixed-seed PQ identity (deterministic keygen — same keypair every run).
fn fixed_pq() -> PqKeys {
    PqKeys::from_seed([0x5Au8; 32])
}

/// Hardcoded derivation vector for `fixed_pq()` (seed `[0x5A; 32]`).
const EXPECTED_PQ_ID_HEX: &str = "a2b41ccbd40e4454d025ce9d4587bc8f7af739d8";

fn peer_cfg(node_id_hex: &str, pq_pub: Option<String>) -> PeerConfig {
    PeerConfig {
        name: "p".to_string(),
        node_id: node_id_hex.to_string(),
        ed_pub: hex::encode([2u8; 32]),
        x_pub: hex::encode([3u8; 32]),
        pq_pub,
        endpoints: vec![],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

// ---------------------------------------------------------------------------
// 1. PQ NodeId derivation vector: fixed seed => fixed id, PQ-primary,
//    same construction as `proto::pq_id_from_pub` (no duplicate logic).
// ---------------------------------------------------------------------------

#[test]
fn ceremony_01_pq_nodeid_derivation_vector() {
    let pq = fixed_pq();
    let ed = NodeKeys::generate();

    // Structural: pq_id is a pure function of the PQ pub (not of any ed key).
    assert_eq!(pq.pq_id(), proto::pq_id_from_pub(&pq.pq_pub()));
    assert_eq!(pq.pq_id_hex(), format!("inf1:{}", hex::encode(pq.pq_id())));

    // Ceremony rule: PQ present => PQ-primary, kind marked PQ.
    let r = resolve_node_id(&ed, Some(&pq));
    assert_eq!(r.kind, NodeIdKind::Pq);
    assert!(!r.is_legacy());
    assert_eq!(r.kind_label(), "PQ");
    assert_eq!(r.id, pq.pq_id());
    assert_eq!(r, ResolvedNodeId { id: pq.pq_id(), kind: NodeIdKind::Pq });

    // Canonical call site agrees.
    assert_eq!(ceremony_local_id(&ed, Some(&pq)), pq.pq_id());

    // Hardcoded vector pins the derivation byte-exactly.
    assert_eq!(hex::encode(r.id), EXPECTED_PQ_ID_HEX, "ceremony vector");

    // A different PQ seed => a different PQ id (key-bound, not constant).
    let other = PqKeys::from_seed([0x3Bu8; 32]);
    assert_ne!(other.pq_id(), pq.pq_id());
}

// ---------------------------------------------------------------------------
// 2. Dual-announce: both ids, PQ FIRST; parse round-trips; legacy-only is a
//    single alias. PeerConfig mirrors the same ordering.
// ---------------------------------------------------------------------------

#[test]
fn ceremony_02_dual_announce_parse_pq_first() {
    let ed = NodeKeys::generate();
    let pq = fixed_pq();

    // With PQ: [pq_id, legacy_id] — PQ first.
    let ids = dual_announce_ids(&ed, Some(&pq));
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], pq.pq_id(), "PQ id must be announced first");
    assert_eq!(ids[1], ed.id(), "legacy alias second");

    // Hex form round-trips through the parser, order preserved.
    let hex_ids = dual_announce_hex(&ed, Some(&pq));
    assert_eq!(hex_ids.len(), 2);
    assert!(hex_ids[0].starts_with("inf1:"));
    let parsed = parse_dual_announce(&hex_ids).expect("parse dual");
    assert_eq!(parsed, ids);

    // PeerConfig mirror: pq pinned => primary is pq, dual is [pq, classical].
    let cfg = peer_cfg(&ed.id_hex(), Some(pq.pq_pub_hex()));
    assert_eq!(cfg.primary_id().expect("primary"), pq.pq_id());
    assert_eq!(cfg.dual_announce_ids().expect("dual"), ids);

    // Legacy-only: single classical alias (pre-window-end compat).
    let legacy_ids = dual_announce_ids(&ed, None);
    assert_eq!(legacy_ids, vec![ed.id()]);
    let legacy_hex = dual_announce_hex(&ed, None);
    assert_eq!(parse_dual_announce(&legacy_hex).expect("parse legacy"), legacy_ids);
    let legacy_cfg = peer_cfg(&ed.id_hex(), None);
    assert_eq!(legacy_cfg.primary_id().expect("legacy primary"), ed.id());
    assert_eq!(legacy_cfg.dual_announce_ids().expect("legacy dual"), legacy_ids);

    // Fail-closed parse: empty, >2, malformed, wrong length all refuse.
    assert!(parse_dual_announce(&[]).is_err());
    let three: Vec<String> =
        vec![legacy_hex[0].clone(), legacy_hex[0].clone(), legacy_hex[0].clone()];
    assert!(parse_dual_announce(&three).is_err());
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
// 4. Legacy-only explicit mark: no PQ identity => LEGACY kind in type AND
//    label; legacy id itself stays byte-identical `blake3(ed)[..20]`.
// ---------------------------------------------------------------------------

#[test]
fn ceremony_04_legacy_only_explicit_mark() {
    let ed = NodeKeys::generate();
    let r = resolve_node_id(&ed, None);
    assert_eq!(r.kind, NodeIdKind::Legacy);
    assert!(r.is_legacy());
    assert_eq!(r.kind_label(), "LEGACY");
    assert_eq!(NodeIdKind::Legacy.label(), "LEGACY");
    assert_eq!(NodeIdKind::Pq.label(), "PQ");
    // Legacy id unchanged: manual blake3(ed_pub)[..20].
    let raw = hex::decode(ed.ed_hex()).expect("ed hex");
    let hb = blake3::hash(&raw);
    let mut expect = [0u8; NODEID_LEN];
    expect.copy_from_slice(&hb.as_bytes()[..NODEID_LEN]);
    assert_eq!(r.id, expect);
    assert_eq!(r.id, ed.id());
    assert_eq!(r.id_hex(), ed.id_hex());
    assert_eq!(ceremony_local_id(&ed, None), ed.id());

    // keyring re-export sanity: ceremony helpers live where the zone says.
    let _ = keyring::NodeIdKind::Pq;
    let _ = ResolvedNodeId { id: [0u8; NODEID_LEN], kind: NodeIdKind::Pq };
}

// ---------------------------------------------------------------------------
// 5. Window-end refusal: const-driven, injected clock only (no wall-clock).
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)] // GATE: pins the documented far-future window-end value against drift
fn ceremony_05_window_end_refusal_injected_clock() {
    // Documented far-future default: 2035-01-01T00:00:00Z.
    assert_eq!(LEGACY_ALIAS_END_UNIX_MS, 2_051_222_400_000);
    // Just inside the window: legacy alias honored.
    assert!(legacy_alias_accepted_at(LEGACY_ALIAS_END_UNIX_MS - 1));
    assert!(legacy_alias_accepted_at(0));
    // At/after the end: legacy alias refused (const-driven, no timers).
    assert!(!legacy_alias_accepted_at(LEGACY_ALIAS_END_UNIX_MS));
    assert!(!legacy_alias_accepted_at(LEGACY_ALIAS_END_UNIX_MS + 1));
    assert!(!legacy_alias_accepted_at(i64::MAX));
}

// ---------------------------------------------------------------------------
// 6. Old single-ed configs keep working pre-window-end: serde shape
//    unchanged (`pq_pub` absent => classical-explicit, no error).
// ---------------------------------------------------------------------------

#[test]
fn ceremony_06_legacy_config_compat_unchanged() {
    let yaml = r#"
name: oldnode
listen: "0.0.0.0:9400"
peers:
  - name: pal
    node-id: "inf1:0102030405060708090a0b0c0d0e0f1011121314"
    ed-pub: "0202020202020202020202020202020202020202020202020202020202020202"
    x-pub: "0303030303030303030303030303030303030303030303030303030303030303"
    endpoints: []
"#;
    let cfg: infnode::config::NodeConfig = serde_yaml::from_str(yaml).expect("old config parses");
    assert_eq!(cfg.peers.len(), 1);
    assert!(cfg.peers[0].pq_pub.is_none(), "absent stays classical-explicit");
    assert!(cfg.peers[0].pq_bytes().expect("none").is_none());
    let dual = cfg.peers[0].dual_announce_ids().expect("dual");
    assert_eq!(dual.len(), 1, "legacy peer announces a single alias");
    assert_eq!(dual[0], cfg.peers[0].node_id_raw().expect("raw"));
}
