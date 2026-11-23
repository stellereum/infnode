//! DNS federation security tests (offline: parsing, self-consistency, trust anchor).
//! Network resolution (DoH multi-resolver) is exercised live, not here.
//!
//! FULL-PQ: records bind the Falcon-512 key — `node_id ==
//! pq_id_from_pub(pq_pub)`. Legacy Ed25519-pin and key-less records are
//! REFUSED (never TOFU-accepted).

use infnode::federation::{
    parse_validator_record, record_self_consistent, txt_name, validator_txt, ValidatorRecord,
    TXT_PREFIX,
};
use infnode::keyring::PqKeys;

/// Build a self-consistent record: node_id = inf1:pq_id_from_pub(pq_pub).
fn consistent_txt(ip: &str) -> (String, String, String) {
    let pq = PqKeys::from_seed([7u8; 32]);
    let pq_hex = pq.pq_pub_hex();
    let node_id = pq.pq_id_hex();
    let txt = validator_txt(&node_id, &pq_hex, ip);
    (node_id, pq_hex, txt)
}

fn pq_hex() -> String {
    PqKeys::from_seed([9u8; 32]).pq_pub_hex()
}

#[test]
fn txt_name_and_format() {
    assert_eq!(txt_name("infmail.org"), "_infnode.infmail.org");
    assert_eq!(txt_name("infmail.org."), "_infnode.infmail.org"); // trailing dot trimmed
}

#[test]
fn parse_new_format_with_pq_pub() {
    let pq = pq_hex();
    let txt = format!("infnode-validator=inf1:abcdef:{pq}:1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert_eq!(rec.node_id, "inf1:abcdef");
    assert_eq!(rec.pq_pub.as_deref(), Some(pq.as_str()));
    assert_eq!(rec.ip, "1.2.3.4:9400");
}

#[test]
fn parse_legacy_ed_pin_and_keyless_are_refused() {
    // Removed classical format (64-hex Ed25519 pin) — refused.
    let ed = "a".repeat(64);
    let legacy_ed = format!("infnode-validator=inf1:abcdef:{ed}:1.2.3.4:9400");
    assert!(
        parse_validator_record(&legacy_ed).is_none(),
        "legacy Ed25519-pinned record must be refused"
    );
    // Key-less record: identity cannot be bound — refused (no TOFU).
    assert!(parse_validator_record("infnode-validator=inf1:abcdef:1.2.3.4:9400").is_none());
}

#[test]
fn parse_rejects_malformed() {
    assert!(parse_validator_record("garbage").is_none());
    assert!(parse_validator_record("infnode-validator=inf1:only").is_none());
    assert!(parse_validator_record(&format!("{TXT_PREFIX}notinf1:a:b:c")).is_none());
    assert!(parse_validator_record("").is_none());
    // PQ key present but wrong length: refused.
    let short = "ab".repeat(32);
    assert!(
        parse_validator_record(&format!("{TXT_PREFIX}inf1:abc:{short}:1.2.3.4:9400")).is_none()
    );
}

#[test]
fn self_consistency_accepts_valid_record() {
    let (_id, _pq, txt) = consistent_txt("1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert!(
        record_self_consistent(&rec),
        "valid node_id==pq_id_from_pub(pq_pub) must pass"
    );
}

#[test]
fn self_consistency_rejects_forged_node_id() {
    // pq_pub is real, but node_id is forged (does not derive from it).
    let pq = pq_hex();
    let txt = format!("{TXT_PREFIX}inf1:deadbeef:{pq}:1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert!(
        !record_self_consistent(&rec),
        "node_id not derived from pq_pub must be rejected"
    );
}

#[test]
fn self_consistency_rejects_bad_pq_pub_length() {
    // A 64-hex (Ed25519-sized) key is not a valid PQ pin: the parser refuses
    // the whole record, so there is no "unverifiable but accepted" path.
    let txt = format!("{TXT_PREFIX}inf1:abc:{}:1.2.3.4:9400", "zz".repeat(32));
    assert!(parse_validator_record(&txt).is_none());
}

#[test]
fn keyless_record_is_refused_not_tofu() {
    let rec = ValidatorRecord {
        node_id: "inf1:abc".to_string(),
        pq_pub: None,
        ip: "1.2.3.4:9400".to_string(),
    };
    // No key to bind the id: consistency cannot be established -> refused.
    assert!(!record_self_consistent(&rec));
}

#[test]
fn trust_anchor_record_is_parsed_and_consistent() {
    // Simulate what resolve_with_trust_anchor relies on: a pinned key matches a
    // consistent DNS record.
    let (_id, pq, txt) = consistent_txt("5.6.7.8:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert_eq!(rec.pq_pub.as_deref(), Some(pq.as_str()));
    assert!(record_self_consistent(&rec));
}
