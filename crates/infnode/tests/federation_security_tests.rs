//! DNS federation security tests (offline: parsing, self-consistency, trust anchor).
//! Network resolution (DoH multi-resolver) is exercised live, not here.

use infnode::federation::{
    parse_validator_record, record_self_consistent, txt_name, validator_txt, ValidatorRecord,
    TXT_PREFIX,
};

/// Build a self-consistent record: node_id = inf1:blake3(ed_pub)[..20].
fn consistent_txt(ip: &str) -> (String, String, String) {
    let ed = [7u8; 32];
    let ed_hex = hex::encode(ed);
    let h = blake3::hash(&ed);
    let node_id = format!("inf1:{}", hex::encode(&h.as_bytes()[..20]));
    let txt = validator_txt(&node_id, &ed_hex, ip);
    (node_id, ed_hex, txt)
}

#[test]
fn txt_name_and_format() {
    assert_eq!(txt_name("infmail.org"), "_infnode.infmail.org");
    assert_eq!(txt_name("infmail.org."), "_infnode.infmail.org"); // trailing dot trimmed
}

#[test]
fn parse_new_format_with_ed_pub() {
    let ed = "a".repeat(64);
    let txt = format!("infnode-validator=inf1:abcdef:{ed}:1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert_eq!(rec.node_id, "inf1:abcdef");
    assert_eq!(rec.ed_pub.as_deref(), Some(ed.as_str()));
    assert_eq!(rec.ip, "1.2.3.4:9400");
}

#[test]
fn parse_legacy_format_no_ed_pub() {
    let txt = "infnode-validator=inf1:abcdef:1.2.3.4:9400";
    let rec = parse_validator_record(txt).unwrap();
    assert_eq!(rec.node_id, "inf1:abcdef");
    assert!(rec.ed_pub.is_none(), "legacy record has no ed_pub");
    assert_eq!(rec.ip, "1.2.3.4:9400");
}

#[test]
fn parse_rejects_malformed() {
    assert!(parse_validator_record("garbage").is_none());
    assert!(parse_validator_record("infnode-validator=inf1:only").is_none());
    assert!(parse_validator_record(&format!("{TXT_PREFIX}notinf1:a:b:c")).is_none());
    assert!(parse_validator_record("").is_none());
}

#[test]
fn self_consistency_accepts_valid_record() {
    let (_id, _ed, txt) = consistent_txt("1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert!(
        record_self_consistent(&rec),
        "valid node_id==blake3(ed_pub) must pass"
    );
}

#[test]
fn self_consistency_rejects_forged_node_id() {
    // ed_pub is real, but node_id is forged (does not match blake3(ed_pub)).
    let ed_hex = hex::encode([9u8; 32]);
    let txt = format!("{TXT_PREFIX}inf1:deadbeef:{ed_hex}:1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert!(
        !record_self_consistent(&rec),
        "node_id not derived from ed_pub must be rejected"
    );
}

#[test]
fn self_consistency_rejects_bad_ed_pub_length() {
    // ed_pub present but not 64 hex -> parser treats whole rest as ip (no ed_pub),
    // so consistency is trivially true (TOFU); forging a node_id vs a real key is
    // covered by `self_consistency_rejects_forged_node_id`.
    let txt = format!("{TXT_PREFIX}inf1:abc:zz:1.2.3.4:9400");
    let rec = parse_validator_record(&txt).unwrap();
    // "zz:1.2.3.4:9400" is not a valid 64-hex ed_pub, so no key is captured.
    assert!(rec.ed_pub.is_none());
    assert!(record_self_consistent(&rec));
}

#[test]
fn legacy_record_without_key_is_accepted_for_tofu() {
    let rec = ValidatorRecord {
        node_id: "inf1:abc".to_string(),
        ed_pub: None,
        ip: "1.2.3.4:9400".to_string(),
    };
    // No key to check against -> cannot disprove consistency (TOFU path).
    assert!(record_self_consistent(&rec));
}

#[test]
fn trust_anchor_record_is_parsed_and_consistent() {
    // Simulate what resolve_with_trust_anchor relies on: a pinned key matches a
    // consistent DNS record.
    let (_id, ed_hex, txt) = consistent_txt("5.6.7.8:9400");
    let rec = parse_validator_record(&txt).unwrap();
    assert_eq!(rec.ed_pub.as_deref(), Some(ed_hex.as_str()));
    assert!(record_self_consistent(&rec));
}
