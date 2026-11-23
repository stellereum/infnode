//! PERF S7: counting tests for the DHT lookup fan-out selector.
//!
//! `lookup_fanout` used to sort candidates with `sort_by_key(|a| xor_distance(a,
//! target))`, which recomputed a full 20-byte XOR for BOTH comparison operands
//! on every comparison (~n·log2(n) distance evaluations per inbound lookup).
//! It now measures each candidate exactly once (`lookup_fanout_counted` exposes
//! the counter). These tests pin the count and prove the selected set is
//! byte-identical to the old ordering rule.

use infnode::dht::{lookup_fanout, lookup_fanout_counted, xor_distance};
use infnode::proto::NODEID_LEN;

fn id(seed: u64) -> [u8; NODEID_LEN] {
    // Cheap deterministic spread; the exact values do not matter, only that
    // they are distinct and include ties-by-duplicate in the set tests.
    let h = blake3::hash(&seed.to_le_bytes());
    let mut out = [0u8; NODEID_LEN];
    out.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
    out
}

/// Reference implementation of the PREVIOUS selector: stable `sort_by_key`
/// recomputation, `dedup`, `truncate`. Used to prove the optimized version
/// returns exactly the same set in exactly the same order.
fn reference_fanout(
    peers: &[[u8; NODEID_LEN]],
    target: &[u8; NODEID_LEN],
    from: &[u8; NODEID_LEN],
    fanout: usize,
) -> Vec<[u8; NODEID_LEN]> {
    let mut candidates: Vec<[u8; NODEID_LEN]> =
        peers.iter().copied().filter(|p| p != from).collect();
    candidates.sort_by_key(|a| xor_distance(a, target));
    candidates.dedup();
    candidates.truncate(fanout);
    candidates
}

#[test]
fn perf_s7_lookup_fanout_measures_each_candidate_exactly_once() {
    let target = id(0);
    let from = id(u64::MAX);
    let mut peers = Vec::new();
    for i in 0..500u64 {
        peers.push(id(i));
    }

    let mut distances = 0usize;
    let selected = lookup_fanout_counted(peers.clone(), &target, &from, 3, &mut distances);
    let expected_measured = peers.iter().filter(|p| **p != from).count();
    assert_eq!(
        distances, expected_measured,
        "one XOR-distance per candidate; the old sort recomputed both operands per comparison"
    );
    assert_eq!(selected.len(), 3, "fan-out stays bounded by ALPHA");

    // The optimized selector and the plain wrapper agree (the wrapper only
    // discards the counter).
    assert_eq!(
        selected,
        lookup_fanout(peers.clone(), &target, &from, 3),
        "counted and plain selectors return the identical set"
    );
    // ... and both equal the pre-optimization ordering rule.
    assert_eq!(
        selected,
        reference_fanout(&peers, &target, &from, 3),
        "selected set/order must be unchanged (stable sort by precomputed key)"
    );
}

#[test]
fn perf_s7_lookup_fanout_ordering_is_stable_and_excludes_sender() {
    let target = id(7);
    let from = id(11);
    // Duplicates: `dedup` used to only collapse CONSECUTIVE equal ids after the
    // stable sort, so duplicates of the closest id must still collapse to one.
    let mut peers = vec![from, from, id(1), id(1), id(1), id(2), id(3)];
    peers.extend(peers.clone());

    let mut distances = 0usize;
    let counted = lookup_fanout_counted(peers.clone(), &target, &from, 10, &mut distances);
    let expected_measured = peers.iter().filter(|p| **p != from).count();
    assert_eq!(distances, expected_measured, "sender copies are skipped");
    assert_eq!(counted, reference_fanout(&peers, &target, &from, 10));
    assert!(!counted.contains(&from), "never reflect to the requester");
    assert_eq!(
        counted.len(),
        counted
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "dedup leaves no duplicate entries"
    );
    for w in counted.windows(2) {
        assert!(
            xor_distance(&w[0], &target) <= xor_distance(&w[1], &target),
            "fan-out set is XOR-ordered closest-first"
        );
    }

    // Empty input and a zero fan-out stay empty.
    assert!(lookup_fanout(Vec::new(), &target, &from, 3).is_empty());
    let mut d = 0usize;
    assert!(lookup_fanout_counted(peers, &target, &from, 0, &mut d).is_empty());
}
