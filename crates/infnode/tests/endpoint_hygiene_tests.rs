//! Endpoint hygiene (port-scan incident): dial order + per-cycle budgets.
//!
//! Pure dial-plan tests (no network): `build_dial_plan` is the exact function
//! `dial_peer` iterates, so bounds proven here bound the live dial path —
//! every `connect_with_auth` call comes from one plan entry, and the dial
//! loop additionally breaks at `MAX_DIAL_ENDPOINTS_PER_CYCLE` (defense in
//! depth). Sibling breaker / reputation state is only *observed* (parked
//! flag in); nothing here touches auth, reputation, DHT, or breaker code.

use infnode::node::{
    build_dial_plan, DialKind, MAX_DIAL_ENDPOINTS_PER_CYCLE, MAX_GOSSIP_DIAL_PER_CYCLE,
};
use std::net::SocketAddr;

fn ep(s: &str) -> String {
    s.to_string()
}

fn kinds(plan: &[infnode::node::DialPlanEntry]) -> Vec<DialKind> {
    plan.iter().map(|e| e.kind).collect()
}

#[test]
fn consts_sane() {
    // GATE: black_box defeats const-folding; pins must fail loudly if changed.
    assert_eq!(std::hint::black_box(MAX_DIAL_ENDPOINTS_PER_CYCLE), 3);
    assert_eq!(std::hint::black_box(MAX_GOSSIP_DIAL_PER_CYCLE), 1);
    assert!(std::hint::black_box(MAX_GOSSIP_DIAL_PER_CYCLE) <= MAX_DIAL_ENDPOINTS_PER_CYCLE);
}

#[test]
fn healthy_single_endpoint_is_single_configured() {
    // Healthy-peer path: one configured endpoint, nothing else — the dial
    // loop below runs exactly the legacy sequence (one `connect_with_auth`).
    let plan = build_dial_plan(&[ep("127.0.0.1:9001")], &[], None, false);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].endpoint, "127.0.0.1:9001");
    assert_eq!(plan[0].kind, DialKind::Configured);
}

#[test]
fn configured_first_stops_at_cap() {
    let cfg: Vec<String> = (1..=5).map(|i| format!("127.0.0.1:900{i}")).collect();
    let gossip: Vec<String> = (1..=3).map(|i| format!("10.0.0.1:800{i}")).collect();
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&cfg, &gossip, Some(punch), false);
    // Hard cap: never more than 3 dials per peer per cycle, all configured.
    assert_eq!(plan.len(), MAX_DIAL_ENDPOINTS_PER_CYCLE);
    assert_eq!(
        kinds(&plan),
        vec![
            DialKind::Configured,
            DialKind::Configured,
            DialKind::Configured
        ]
    );
    // Listed order preserved.
    assert_eq!(plan[0].endpoint, "127.0.0.1:9001");
    assert_eq!(plan[1].endpoint, "127.0.0.1:9002");
    assert_eq!(plan[2].endpoint, "127.0.0.1:9003");
    // No gossip, no punch once the cap is spent on configured.
    assert!(plan.iter().all(|e| e.kind == DialKind::Configured));
}

#[test]
fn gossip_deferred_to_spare_budget() {
    let cfg = vec![ep("127.0.0.1:9001"), ep("127.0.0.1:9002")];
    let gossip = vec![ep("10.0.0.1:8001"), ep("10.0.0.2:8002")];
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&cfg, &gossip, Some(punch), false);
    // 2 configured + 1 gossip = cap; punch has no budget left (no extra try).
    assert_eq!(plan.len(), 3);
    assert_eq!(
        kinds(&plan),
        vec![DialKind::Configured, DialKind::Configured, DialKind::Gossip]
    );
    assert_eq!(plan[2].endpoint, "10.0.0.1:8001");
}

#[test]
fn gossip_only_peer_gets_spare_budget() {
    // No configured endpoints: gossip may fill the gossip budget, punch the
    // rest — still within the single per-cycle cap.
    let gossip = vec![ep("10.0.0.1:8001"), ep("10.0.0.2:8002")];
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&[], &gossip, Some(punch), false);
    assert_eq!(plan.len(), 2);
    assert_eq!(kinds(&plan), vec![DialKind::Gossip, DialKind::Punch]);
    assert_eq!(plan[0].endpoint, "10.0.0.1:8001");
}

#[test]
fn punch_counted_in_budget_no_extra_tries() {
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    // Cap already spent on configured: punch must NOT add a 4th attempt.
    let cfg: Vec<String> = (1..=3).map(|i| format!("127.0.0.1:900{i}")).collect();
    let plan = build_dial_plan(&cfg, &[], Some(punch), false);
    assert_eq!(plan.len(), 3);
    assert!(plan.iter().all(|e| e.kind == DialKind::Configured));
    // Spare budget: punch fills it as the last attempt.
    let cfg2 = vec![ep("127.0.0.1:9001"), ep("127.0.0.1:9002")];
    let plan2 = build_dial_plan(&cfg2, &[], Some(punch), false);
    assert_eq!(plan2.len(), 3);
    assert_eq!(
        kinds(&plan2),
        vec![DialKind::Configured, DialKind::Configured, DialKind::Punch]
    );
    assert_eq!(plan2[2].endpoint, "10.9.9.9:7001");
}

#[test]
fn punch_duplicate_of_configured_skipped() {
    // Punch to an address already covered is not an extra try.
    let punch: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let plan = build_dial_plan(&[ep("127.0.0.1:9001")], &[], Some(punch), false);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].kind, DialKind::Configured);
}

#[test]
fn gossip_duplicate_of_configured_skipped_budget_kept() {
    // A gossip endpoint already listed in config must not consume the gossip
    // budget; the next fresh gossip address gets the single spare slot.
    let cfg = vec![ep("127.0.0.1:9001")];
    let gossip = vec![ep("127.0.0.1:9001"), ep("10.0.0.1:8001")];
    let plan = build_dial_plan(&cfg, &gossip, None, false);
    assert_eq!(plan.len(), 2);
    assert_eq!(kinds(&plan), vec![DialKind::Configured, DialKind::Gossip]);
    assert_eq!(plan[1].endpoint, "10.0.0.1:8001");
}

#[test]
fn parked_peer_gets_single_probe() {
    // Parked (sibling breaker signal: banned/throttled) — one configured
    // probe, never gossip, never punch.
    let cfg: Vec<String> = (1..=3).map(|i| format!("127.0.0.1:900{i}")).collect();
    let gossip = vec![ep("10.0.0.1:8001")];
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&cfg, &gossip, Some(punch), true);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].endpoint, "127.0.0.1:9001");
    assert_eq!(plan[0].kind, DialKind::Configured);
}

#[test]
fn parked_peer_without_configured_dials_nothing() {
    let gossip = vec![ep("10.0.0.1:8001")];
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&[], &gossip, Some(punch), true);
    assert!(plan.is_empty());
}

#[test]
fn exact_dupes_in_config_collapsed() {
    let cfg = vec![
        ep("127.0.0.1:9001"),
        ep("127.0.0.1:9001"),
        ep("127.0.0.1:9002"),
    ];
    let plan = build_dial_plan(&cfg, &[], None, false);
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].endpoint, "127.0.0.1:9001");
    assert_eq!(plan[1].endpoint, "127.0.0.1:9002");
}

#[test]
fn unparseable_kept_for_legacy_log_without_spending_budget() {
    // Bad strings stay in the plan in order (dial loop logs them exactly as
    // before); they never become `connect_with_auth` calls, so attempts stay
    // within the cap even when the plan holds them.
    let cfg = vec![ep("not-an-addr"), ep("127.0.0.1:9001")];
    let gossip = vec![ep("10.0.0.1:8001")];
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    let plan = build_dial_plan(&cfg, &gossip, Some(punch), false);
    assert_eq!(plan[0].endpoint, "not-an-addr");
    assert_eq!(plan[0].kind, DialKind::Configured);
    // Cap counts plan entries: bad + cfg + gossip = 3, punch excluded.
    assert_eq!(plan.len(), MAX_DIAL_ENDPOINTS_PER_CYCLE);
    let parseable: Vec<&str> = plan
        .iter()
        .filter(|e| e.endpoint.parse::<SocketAddr>().is_ok())
        .map(|e| e.endpoint.as_str())
        .collect();
    assert_eq!(parseable, vec!["127.0.0.1:9001", "10.0.0.1:8001"]);
    assert!(parseable.len() <= MAX_DIAL_ENDPOINTS_PER_CYCLE);
}

#[test]
fn sweep_never_exceeds_cap_regardless_of_table_growth() {
    // Route-table growth cannot widen a cycle: 8 configured + 8 gossip +
    // punch still yields at most 3 attempts, at most 1 of them gossip.
    let cfg: Vec<String> = (1..=8).map(|i| format!("127.0.0.1:900{i}")).collect();
    let gossip: Vec<String> = (1..=8).map(|i| format!("10.0.0.{}:8001", i)).collect();
    let punch: SocketAddr = "10.9.9.9:7001".parse().unwrap();
    for parked in [false, true] {
        let plan = build_dial_plan(&cfg, &gossip, Some(punch), parked);
        assert!(plan.len() <= MAX_DIAL_ENDPOINTS_PER_CYCLE);
        let gossip_n = plan.iter().filter(|e| e.kind == DialKind::Gossip).count();
        let punch_n = plan.iter().filter(|e| e.kind == DialKind::Punch).count();
        assert!(gossip_n <= MAX_GOSSIP_DIAL_PER_CYCLE);
        assert!(punch_n <= 1);
        if parked {
            assert_eq!(plan.len(), 1);
        }
    }
}
