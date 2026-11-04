//! Parity + never-slower gate for the `merge_index_union` HashSet optimization.
//!
//! Reference: verbatim copy of the pre-optimization nested-scan logic.
//! Differential: randomized local/incoming/tombs JSON (valid + malformed),
//! byte-identical merged value + identical `changed` flag.
//! Gate: optimized `KvStore::merge_replica` must not be slower than the
//! reference on fixed fixtures (fails on regression).

use infnode::dht::{now_ms, KvStore, StoredValue};
use infnode::proto::NODEID_LEN;
use std::collections::HashMap;
use std::time::Instant;

fn origin() -> [u8; NODEID_LEN] {
    [9u8; NODEID_LEN]
}

/// Verbatim pre-optimization logic of the `Some(local)` index-union branch
/// (plus the `stored_at <= 0` guard and the `None` branch), as a pure
/// function so the differential test does not depend on wall-clock `now`
/// inside the reference path either (caller passes `now` to both sides).
fn ref_merge_index(
    local: Option<&StoredValue>,
    tombs_json: Option<&str>,
    incoming_value: &str,
    ttl_ms: i64,
    origin: [u8; NODEID_LEN],
    stored_at: i64,
    now: i64,
) -> (Option<StoredValue>, bool) {
    if stored_at <= 0 {
        return (None, false);
    }
    let incoming: Vec<String> = serde_json::from_str(incoming_value).unwrap_or_default();
    match local {
        None => (
            Some(StoredValue {
                value: incoming_value.to_string(),
                expires: now + ttl_ms,
                origin,
                ttl_ms,
                stored_at,
            }),
            true,
        ),
        Some(local) => {
            let mut ids: Vec<String> = serde_json::from_str(&local.value).unwrap_or_default();
            let tombs: Vec<String> = match tombs_json {
                None => Vec::new(),
                Some(t) => {
                    let m: HashMap<String, i64> =
                        serde_json::from_str(t).unwrap_or_default();
                    m.into_keys().collect()
                }
            };
            ids.retain(|x| !tombs.iter().any(|t| t == x));
            let mut changed = false;
            for id in incoming {
                if tombs.iter().any(|t| t == &id) {
                    continue;
                }
                if !ids.iter().any(|x| x == &id) {
                    ids.push(id);
                    changed = true;
                }
            }
            if changed || stored_at > local.stored_at {
                let v = serde_json::to_string(&ids).unwrap_or_else(|_| local.value.clone());
                let newv = StoredValue {
                    value: v,
                    expires: now + ttl_ms.max(local.ttl_ms),
                    origin,
                    ttl_ms: ttl_ms.max(local.ttl_ms),
                    stored_at: stored_at.max(local.stored_at),
                };
                (Some(newv), changed)
            } else {
                (None, changed)
            }
        }
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

fn rand_id(rng: &mut Rng, pool: &[String]) -> String {
    match rng.below(10) {
        0 => String::new(),
        1 => "m\"quote\\slash\u{1f600}".to_string(),
        2 => format!("x{:x}", rng.next()),
        3 => "a".repeat(rng.below(300) as usize),
        _ => pool[rng.below(pool.len() as u64) as usize].clone(),
    }
}

fn rand_json_array(rng: &mut Rng, pool: &[String]) -> String {
    let n = rng.below(8) as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(rand_id(rng, pool));
    }
    serde_json::to_string(&v).unwrap()
}

fn rand_malformed(rng: &mut Rng, valid: &str) -> String {
    let corpus = [
        "",
        "{",
        "[",
        "[\"a\",]",
        "[\"a\" \"b\"]",
        "null",
        "123",
        "\"str\"",
        "{\"a\":1}",
        "{\"m1\":5}",
        "[1,2,3]",
        "[[[]]]",
    ];
    match rng.below(4) {
        0 => corpus[rng.below(corpus.len() as u64) as usize].to_string(),
        1 => {
            // truncation of a valid array
            let cut = rng.below(valid.len() as u64 + 1) as usize;
            valid[..cut.min(valid.len())].to_string()
        }
        2 => {
            // single-byte flip inside a valid array
            let mut b = valid.as_bytes().to_vec();
            if !b.is_empty() {
                let i = rng.below(b.len() as u64) as usize;
                b[i] = b[i].wrapping_add(1);
            }
            String::from_utf8_lossy(&b).into_owned()
        }
        _ => format!("{valid} trailing-garbage"),
    }
}

fn rand_tombs(rng: &mut Rng, pool: &[String]) -> Option<String> {
    match rng.below(5) {
        0 => None,
        1 => Some(rand_malformed(rng, "{\"m000001\":1}")),
        _ => {
            let n = rng.below(4) as usize;
            let mut m = HashMap::new();
            for _ in 0..n {
                m.insert(rand_id(rng, pool), rng.next() as i64);
            }
            Some(serde_json::to_string(&m).unwrap())
        }
    }
}

#[test]
fn opt_index_union_parity_randomized() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let pool: Vec<String> = (0..64).map(|i| format!("m{i:06}")).collect();
    for round in 0..3000 {
        let now = now_ms();
        let key = if round % 7 == 0 {
            "plain:key".to_string()
        } else {
            format!("box{}:index", rng.below(3))
        };
        let has_local = rng.below(4) != 0;
        let local: Option<StoredValue> = if has_local {
            let lv = match rng.below(5) {
                0 => rand_malformed(&mut rng, "[\"m000001\"]"),
                _ => rand_json_array(&mut rng, &pool),
            };
            Some(StoredValue {
                value: lv,
                expires: now + 86_400_000,
                origin: origin(),
                ttl_ms: 86_400_000,
                stored_at: now - rng.below(100_000) as i64,
            })
        } else {
            None
        };
        let tombs_json: Option<String> = rand_tombs(&mut rng, &pool);
        let incoming_value = match rng.below(5) {
            0 => rand_malformed(&mut rng, "[\"m000002\"]"),
            _ => rand_json_array(&mut rng, &pool),
        };
        let ttl_ms = match rng.below(4) {
            0 => -1_000,
            1 => 0,
            _ => rng.below(1_000_000) as i64,
        };
        let stored_at = match rng.below(6) {
            0 => 0,
            1 => -(rng.below(1000) as i64),
            2 => now + rng.below(1_000_000) as i64,
            _ => now - rng.below(1_000_000) as i64,
        };

        // Reference (index path only; LWW modeled inline below).
        let is_index = key.ends_with("index");
        let (ref_new, ref_changed) = if is_index {
            ref_merge_index(
                local.as_ref(),
                tombs_json.as_deref(),
                &incoming_value,
                ttl_ms,
                origin(),
                stored_at,
                now,
            )
        } else {
            (None, false)
        };

        // Production: identical starting map, one merge_replica call.
        let mut kv = KvStore::default();
        if let Some(l) = &local {
            kv.restore(key.clone(), l.clone());
        }
        let tkey = format!("{key}:tombs");
        if let Some(t) = &tombs_json {
            kv.restore(
                tkey.clone(),
                StoredValue {
                    value: t.clone(),
                    expires: now + 86_400_000,
                    origin: origin(),
                    ttl_ms: 86_400_000,
                    stored_at: now,
                },
            );
        }
        // restore() drops already-expired entries; mirror that for the
        // reference expectation (expired local == no local).
        let local_live = match &local {
            Some(l) if l.expires > now => Some(l.clone()),
            _ => None,
        };
        let prod_changed = kv.merge_replica(&key, incoming_value.clone(), ttl_ms, origin(), stored_at);
        if !is_index {
            // LWW path (unchanged code): apply iff strictly newer; the
            // `stored_at <= 0` guard sits above all paths.
            let expected = if stored_at <= 0 {
                false
            } else {
                match &local {
                    None => true,
                    Some(l) => stored_at > l.stored_at,
                }
            };
            assert_eq!(prod_changed, expected, "round {round}: LWW flag diverged");
            let got = kv.entries_clone();
            if expected {
                assert_eq!(got[&key].value, incoming_value, "round {round}: LWW value diverged");
                assert_eq!(got[&key].stored_at, stored_at, "round {round}: LWW stored_at diverged");
            } else if local.is_some() {
                assert_eq!(got[&key].value, local.as_ref().unwrap().value, "round {round}: LWW kept diverged");
            }
            continue;
        }
        assert_eq!(
            prod_changed, ref_changed,
            "round {round}: changed flag diverged"
        );
        // Compare STORED state (entries_clone keeps expired entries too),
        // so negative-TTL inserts — invisible to peek() on both sides —
        // still compare byte-identical with no clock involved.
        let prod_final: Option<String> =
            kv.entries_clone().get(&key).map(|s| s.value.clone());
        let ref_final: Option<String> = match &ref_new {
            Some(nv) => Some(nv.value.clone()),
            None => local_live.map(|l| l.value),
        };
        assert_eq!(prod_final, ref_final, "round {round}: merged value diverged");
        if let (Some(p), Some(r)) = (kv.peek(&key), ref_new) {
            assert!(
                (p.1 - r.expires).abs() <= 5_000,
                "round {round}: expires diverged beyond clock tolerance"
            );
            let got = kv.entries_clone();
            let st = &got[&key];
            assert_eq!(st.ttl_ms, r.ttl_ms, "round {round}: ttl diverged");
            assert_eq!(st.stored_at, r.stored_at, "round {round}: stored_at diverged");
        }
    }
}

#[test]
fn opt_index_union_tombs_key_parity_randomized() {
    // The sibling `:tombs` union path is untouched; differential guard that
    // the optimization did not alter its routing or results.
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    for round in 0..500 {
        let now = now_ms();
        let key = "box:idx:tombs".to_string();
        let mut kv = KvStore::default();
        if rng.below(2) == 0 {
            let mut m = HashMap::new();
            for _ in 0..rng.below(4) {
                m.insert(format!("m{:06}", rng.below(64)), rng.next() as i64);
            }
            kv.restore(
                key.clone(),
                StoredValue {
                    value: serde_json::to_string(&m).unwrap(),
                    expires: now + 86_400_000,
                    origin: origin(),
                    ttl_ms: 86_400_000,
                    stored_at: now - 1000,
                },
            );
        }
        let mut inc = HashMap::new();
        for _ in 0..rng.below(4) {
            inc.insert(format!("m{:06}", rng.below(64)), rng.next() as i64);
        }
        let iv = serde_json::to_string(&inc).unwrap();
        let before = kv.peek(&key).map(|(v, _)| v);
        let changed = kv.merge_replica(&key, iv.clone(), 86_400_000, origin(), now);
        let after = kv.peek(&key).map(|(v, _)| v);
        // Invariants of the max-per-id union: monotonic growth of known ids,
        // changed implies a strictly larger id set.
        let count = |s: &Option<String>| -> usize {
            s.as_ref()
                .and_then(|v| serde_json::from_str::<HashMap<String, i64>>(v).ok())
                .map(|m| m.len())
                .unwrap_or(0)
        };
        assert!(
            count(&after) >= count(&before),
            "round {round}: tombs union shrank"
        );
        if changed {
            assert!(
                count(&after) > count(&before) || after != before,
                "round {round}: changed without effect"
            );
        }
    }
}

fn bench_union_fixture(n: usize) -> (StoredValue, String, String) {
    let local_ids: Vec<String> = (0..n).map(|i| format!("m{i:06}")).collect();
    let incoming_ids: Vec<String> = (0..n).map(|i| format!("m{:06}", i + n / 2)).collect();
    let local = StoredValue {
        value: serde_json::to_string(&local_ids).unwrap(),
        expires: now_ms() + 86_400_000,
        origin: origin(),
        ttl_ms: 86_400_000,
        stored_at: now_ms() - 5000,
    };
    (
        local,
        serde_json::to_string(&incoming_ids).unwrap(),
        serde_json::to_string(&std::collections::HashMap::<String, i64>::new()).unwrap(),
    )
}

fn time_prod(n: usize, iters: usize) -> f64 {
    let (local, incoming, tombs) = bench_union_fixture(n);
    for _ in 0..2 {
        let mut kv = KvStore::default();
        kv.restore("b:index".to_string(), local.clone());
        kv.restore(
            "b:index:tombs".to_string(),
            StoredValue {
                value: tombs.clone(),
                expires: now_ms() + 86_400_000,
                origin: origin(),
                ttl_ms: 86_400_000,
                stored_at: now_ms(),
            },
        );
        std::hint::black_box(kv.merge_replica("b:index", incoming.clone(), 86_400_000, origin(), now_ms()));
    }
    let t = Instant::now();
    for _ in 0..iters {
        let mut kv = KvStore::default();
        kv.restore("b:index".to_string(), local.clone());
        kv.restore(
            "b:index:tombs".to_string(),
            StoredValue {
                value: tombs.clone(),
                expires: now_ms() + 86_400_000,
                origin: origin(),
                ttl_ms: 86_400_000,
                stored_at: now_ms(),
            },
        );
        std::hint::black_box(kv.merge_replica("b:index", incoming.clone(), 86_400_000, origin(), now_ms()));
    }
    t.elapsed().as_nanos() as f64 / iters as f64
}

fn time_ref(n: usize, iters: usize) -> f64 {
    let (local, incoming, tombs) = bench_union_fixture(n);
    for _ in 0..2 {
        std::hint::black_box(ref_merge_index(
            Some(&local),
            Some(&tombs),
            &incoming,
            86_400_000,
            origin(),
            now_ms(),
            now_ms(),
        ));
    }
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(ref_merge_index(
            Some(&local),
            Some(&tombs),
            &incoming,
            86_400_000,
            origin(),
            now_ms(),
            now_ms(),
        ));
    }
    t.elapsed().as_nanos() as f64 / iters as f64
}

#[test]
fn opt_index_union_never_slower() {
    // Fixed fixtures, same box/process. Fails on regression.
    for (n, iters) in [(200usize, 50usize), (2000usize, 5usize)] {
        let r = time_ref(n, iters);
        let p = time_prod(n, iters);
        println!("[opt-gate] index-union n={n}: ref {r:.0} ns/op prod {p:.0} ns/op ({:.2}x)", r / p.max(1.0));
        assert!(
            p <= r,
            "REGRESSION at n={n}: prod {p:.0} ns/op slower than ref {r:.0} ns/op"
        );
    }
}
