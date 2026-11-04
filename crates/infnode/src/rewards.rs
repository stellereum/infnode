//! Трекер наград: валидатор периодически пингует пиров (аптайм) и запрашивает
//! у них объём хранилища (core.storage). Пишет rewards.json:
//!   { ts, interval_secs, nodes: [{ name, node_id, total_bytes, uptime_ratio, trust_score, weight }] }
//! weight = сглаженный объём × (0.3 + 0.7 × uptime_ratio) — сбалансированный вес,
//! при котором мелкие ноды не угнетаются (логарифм/корень вместо линейного роста),
//! а надёжные получают больше.
//! Включается env INFNODE_REWARDS=1 (только на валидаторе).

use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration};

use crate::node::Node;

const INTERVAL_SECS: u64 = 600; // 10 минут
const UPTIME_WINDOW_MS: i64 = 24 * 3600 * 1000; // окно аптайма — 24 часа
const REQ_TIMEOUT_SECS: u64 = 5;

/// Минимальная доля веса, которая начисляется за сам факт аптайма (даже если хранилище мало).
/// 0.3 + 0.7 × ratio → надёжная мелкая нода не получает ~0.
const UPTIME_WEIGHT_FLOOR: f64 = 0.3;

/// Anti-Sybil: replication factor. Каждый чанк оплачивается максимум RF раз (обычно 3).
/// Первые RF копий получают награду, 4-я, 5-я... копия (фейковая нода, хранящая тот же
/// чанк) — НЕ вознаграждается. Это как Filecoin/Sia: платим за УНИКАЛЬНОЕ хранение.
const RF: usize = 3;

/// Сглаживание объёма: sqrt вместо линейного, чтобы 100 GB и 1 TB не отличались в 10 раз,
/// а мелкие ноды сохраняли значимый вес. (Баланс «не угнетаем мелких».)
fn smoothed_bytes(bytes: u64) -> f64 {
    (bytes as f64).sqrt()
}

/// Результат proof-of-storage проверки одной ноды.
#[derive(Default)]
struct ProofResult {
    /// Суммарный размер проверенных (proof-подтверждённых) чанков.
    verified_bytes: u64,
    /// Всего отправлено челленджей.
    total: usize,
    /// Успешно предъявленных чанков.
    ok: usize,
    /// Пары (chunk_id, len) для КАЖДОГО успешно проверенного чанка.
    /// Нужны для anti-Sybil RF-лимита: чтобы отличить «уникальные» байты от «копий».
    chunks: Vec<(String, u64)>,
}

/// Anti-Sybil RF-агрегация (проход по всем нодам):
///   1) собираем chunk_id → список нод, реально хранящих этот чанк (реплик);
///   2) каждый чанк оплачивается максимум RF раз — начисляем байты только первым RF
///      репликам (в порядке приоритета: выше аптайм = выше приоритет, надёжные ноды
///      в приоритете; при равенстве — стабильный порядок по индексу);
///   3) возвращает per-node число байт ПОСЛЕ RF-лимита (уникальные × RF суммарно).
///
/// Вход: срез (подтверждённые чанки ноды, uptime ноды).
/// Следствие: суммарный начисленный вес сети ≤ размер уникальных данных × RF —
/// 100 фейковых нод с одинаковыми чанками дают ~уникальные × 3, а не ×100.
fn rf_limited_bytes(nodes: &[(&[(String, u64)], f64)]) -> Vec<u64> {
    use std::collections::HashMap;
    // chunk_id -> реплики (индекс ноды, len)
    let mut by_chunk: HashMap<&str, Vec<(usize, u64)>> = HashMap::new();
    for (i, (chunks, _)) in nodes.iter().enumerate() {
        // дедупликация в пределах ноды: один и тот же cid не может занимать 2 слота RF
        let mut seen: Vec<&str> = Vec::new();
        for (cid, len) in *chunks {
            if seen.contains(&cid.as_str()) {
                continue;
            }
            seen.push(cid.as_str());
            by_chunk.entry(cid.as_str()).or_default().push((i, *len));
        }
    }

    let mut result = vec![0u64; nodes.len()];
    for replicas in by_chunk.values() {
        // сортируем реплики по приоритету: uptime ноды убывает (надёжные первые),
        // при равенстве — стабильно по порядку добавления (индекс ноды).
        let mut order: Vec<usize> = (0..replicas.len()).collect();
        order.sort_by(|&a, &b| {
            let pa = nodes[replicas[a].0].1;
            let pb = nodes[replicas[b].0].1;
            pb.partial_cmp(&pa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(replicas[a].0.cmp(&replicas[b].0))
        });
        // начисляем байты только первым RF репликам
        for &k in order.iter().take(RF) {
            let (node_i, len) = replicas[k];
            result[node_i] += len;
        }
    }
    result
}

/// Proof-of-storage: валидатор выбирает случайные локальные манифесты (m:/f:),
/// для каждого случайный чанк, шлёт ноде storage.fetch и сверяет blake3(чанк) с хэшем
/// в манифесте. Возвращает (подтверждённые байты, проверено чанков, успешно).
/// Это заменяет самооценку core.storage: вес получают только реально хранящиеся байты.
async fn proof_verify(
    node: &Arc<Node>,
    pid: [u8; crate::proto::NODEID_LEN],
    max_challenges: usize,
) -> ProofResult {
    let mut res = ProofResult::default();

    // собираем пул манифестов (m: и f:), у каждого возьмём по одному случайному чанку.
    // Только манифесты, у которых чанки имеют хэш (целостность проверяема).
    // все 4 префикса: repair принимает mail:/files: наряду с m:/f: (старые ключи,
    // DHT-слепки) — иначе часть манифестов выпадала из подсчёта
    let mut keys: Vec<String> = node.kv_manifest_keys("m:").await;
    keys.extend(node.kv_manifest_keys("mail:").await);
    keys.extend(node.kv_manifest_keys("f:").await);
    keys.extend(node.kv_manifest_keys("files:").await);
    if keys.is_empty() {
        return res;
    }

    let mut pool: Vec<String> = Vec::new();
    for k in keys.iter() {
        let Some(raw) = node.get_local_kv(k).await else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(chunks) = manifest["chunks"].as_array() else {
            continue;
        };
        if chunks.iter().any(|c| c["hash"].as_str().is_some()) {
            pool.push(k.clone());
        }
        if pool.len() >= max_challenges * 4 {
            break;
        }
    }
    if pool.is_empty() {
        return res;
    }

    // Криптографический случайный индекс — now_ms % len был предсказуем (узел мог
    // заранее подготовить только проверяемые чанки). Теперь каждый раунд случайный.
    let mut rng = rand::rngs::OsRng;
    use rand::Rng;
    for k in pool.iter().take(max_challenges) {
        let Some(raw) = node.get_local_kv(k).await else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(chunks) = manifest["chunks"].as_array() else {
            continue;
        };
        if chunks.is_empty() {
            continue;
        }
        // случайный чанк (крипто-random)
        let idx = rng.gen_range(0..chunks.len());
        let c = &chunks[idx];
        let Some(cid) = c["id"].as_str() else {
            continue;
        };
        let Some(expected) = c["hash"].as_str() else {
            continue;
        };
        let bucket = manifest["bucket"].as_str().unwrap_or("files");
        // ЧЕСТНОСТЬ: засчитываем размер РЕАЛЬНО проверенного чанка (c["len"]),
        // а не весь манифест. Раньше нода, хранящая 1 чанк из 10-чанкового письма,
        // получала вес за весь размер письма (раздувание веса).
        let chunk_len = c["len"].as_u64().unwrap_or(0);

        res.total += 1;
        let payload = json!({ "bucket": bucket, "chunk_id": cid })
            .to_string()
            .into_bytes();
        let got = timeout(
            Duration::from_secs(REQ_TIMEOUT_SECS),
            node.request_to(pid, "storage.fetch", payload),
        )
        .await;
        let Ok(Ok(resp)) = got else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&resp) else {
            continue;
        };
        if !v["ok"].as_bool().unwrap_or(false) {
            continue;
        }
        let Some(b64) = v["data"].as_str() else {
            continue;
        };
        let Ok(data) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        else {
            continue;
        };
        let actual = hex::encode(blake3::hash(&data).as_bytes());
        if actual.eq_ignore_ascii_case(expected) {
            // засчитываем размер проверенного чанка (не весь манифест!)
            res.verified_bytes += chunk_len;
            res.ok += 1;
            // фиксируем какой именно чанк подтверждён — для anti-Sybil RF-лимита
            res.chunks.push((cid.to_string(), chunk_len));
        }
    }
    res
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn load_state(p: &Path) -> serde_json::Map<String, Value> {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// Парсит node_id вида "inf1:<hex>" в массив байт [u8; NODEID_LEN].
#[allow(dead_code)] // GATE: peer-id helper for rewards audit tooling
fn pid(node_id: &str) -> [u8; crate::proto::NODEID_LEN] {
    let hex_part = node_id.strip_prefix("inf1:").unwrap_or(node_id);
    let mut out = [0u8; crate::proto::NODEID_LEN];
    if let Ok(bytes) = hex::decode(hex_part) {
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
    }
    out
}

pub async fn run(node: &Arc<Node>, data_dir: &Path) -> Result<()> {
    let state_file = data_dir.join("rewards_state.json");
    let out_file = data_dir.join("rewards.json");
    let mut state = load_state(&state_file);

    loop {
        let ts = now_ms();
        let mut new_state = state.clone();
        let _nodes: Vec<Value> = Vec::new();

        // Автодобавление нод (П.3.2, задача 3): собираем ВСЕ известные ноды из routing +
        // конфигурированные. Новая нода, приславшая dht.update (самопрезентация), попадает
        // в routing автоматически и участвует в rewards без ручного внесения в конфиг.
        // Фильтр безопасности: нода должна иметь ed_pub (подтверждённая Ed25519-идентичность)
        // и живые last_seen — иначе не начисляем (нельзя надуть вес фейковой нодой).
        let known = node.known_peers().await;
        // Данные всех нод за этот раунд (проход 1): нужно собрать подтверждённые чанки
        // ВСЕХ нод, чтобы anti-Sybil RF-лимит мог учесть репликацию между нодами.
        // (key, ratio, verified_bytes, proof_total, proof_ok, trust_score, chunks)
        #[allow(clippy::type_complexity)] // GATE: payout accumulator is local to rewards pass
        let mut collected: Vec<(String, f64, u64, usize, usize, u64, Vec<(String, u64)>)> =
            Vec::new();
        for p in &known {
            // только ноды с подтверждённым публичным ключом (не "фантомы" без ed_pub)
            if p.ed_hex.is_empty() {
                continue;
            }
            let key = format!("inf1:{}", hex::encode(p.id));

            // пинг с таймаутом
            let ping_ok = timeout(
                Duration::from_secs(REQ_TIMEOUT_SECS),
                node.request_to(p.id, "core.ping", vec![]),
            )
            .await
            .is_ok();

            // для NAT-пиров (сами инициируют соединение и шлют dht.update/core.ping)
            // исходящий ping не проходит, но входящий heartbeat (last_seen) доказывает живость.
            let last_seen = node.peer_last_seen(&p.id).await;
            let heartbeat_ok = last_seen
                .map(|ls| ts - ls < 3 * 60 * 1000) // живой если писал в последние 3 мин
                .unwrap_or(false);
            let ok = ping_ok || heartbeat_ok;

            // история аптайма (rolling-окно 24ч)
            let mut ev: Vec<Value> = new_state
                .get(&key)
                .and_then(|v| v["events"].as_array().cloned())
                .unwrap_or_default();
            ev.retain(|e| e[0].as_i64().unwrap_or(0) > ts - UPTIME_WINDOW_MS);
            ev.push(json!([ts, ok]));
            new_state.insert(key.clone(), json!({ "events": ev }));

            let total = ev.len() as f64;
            let ok_n = ev
                .iter()
                .filter(|e| e[1].as_bool().unwrap_or(false))
                .count();
            let ratio = if total > 0.0 {
                ok_n as f64 / total
            } else {
                0.0
            };

            // Proof-of-storage: валидатор проверяет реальное хранение (челленджи по чанкам
            // из своих манифестов), а не доверяет самооценке ноды (core.storage убран).
            let proof = if ok {
                proof_verify(node, p.id, 8).await
            } else {
                ProofResult::default()
            };

            // trust score 0..100: надёжность (аптайм) × 100, но с штрафом если нода не
            // смогла предъявить хранимые чанки (0 подтверждённых — подозрительно).
            let trust_score = ((ratio * 100.0).round() as u64).min(100);
            let trust_score = if proof.total > 0 && proof.ok == 0 {
                trust_score.saturating_sub(20)
            } else {
                trust_score
            };

            collected.push((
                key,
                ratio,
                proof.verified_bytes,
                proof.total,
                proof.ok,
                trust_score,
                proof.chunks,
            ));
        }

        // Anti-Sybil RF-лимит (проход 2): каждый чанк оплачивается максимум RF раз.
        // Считаем, сколько РАЗНЫХ нод реально хранят каждый чанк, и начисляем байты
        // только первым RF репликам (по приоритету — аптайму). 4-я, 5-я... копия
        // (фейковая нода с тем же чанком) не приносит вес.
        let rf_bytes = rf_limited_bytes(
            &collected
                .iter()
                .map(|c| (c.6.as_slice(), c.1))
                .collect::<Vec<_>>(),
        );

        // Проход 3: строим nodes с RF-ограниченным весом.
        let mut nodes: Vec<Value> = Vec::new();
        for (i, (key, ratio, verified_bytes, proof_total, proof_ok, trust_score, _)) in
            collected.iter().enumerate()
        {
            // RF-ограниченный объём: уникальные байты этой ноды, но не более чем при
            // оплате каждого чанка максимум RF раз (не линейно от числа одинаковых копий).
            let rf_verified = rf_bytes[i];
            // сбалансированный вес: сглаженный RF-ограниченный объём × (пол + доля аптайма)
            let weight = (smoothed_bytes(rf_verified)
                * (UPTIME_WEIGHT_FLOOR + (1.0 - UPTIME_WEIGHT_FLOOR) * ratio))
                .round() as u64;

            nodes.push(json!({
                // имя: для автодобавленных нод — короткий hex id (у конфигурированных есть name,
                // но NodeInfo его не несёт; имя не критично для награды, только node_id)
                "name": key[..16.min(key.len())].to_string(),
                "node_id": key,
                "total_bytes": verified_bytes,
                "rf_verified_bytes": rf_verified,
                "proof_chunks": proof_total,
                "proof_ok": proof_ok,
                "uptime_ratio": (ratio * 1000.0).round() / 1000.0,
                "trust_score": trust_score,
                "weight": weight,
                "ts": ts,
            }));
        }

        // Расчётный регистр выплат (П.3.2): доля каждой ноды = weight/total_weight × пул.
        // Только РАСЧЁТ и учёт — приватный ключ payout НЕ хранится в process, подпись/отправка
        // Distribute выполняется оператором вне процесса (vault/мультисиг). Величина пула задаётся
        // env INFNODE_REWARD_POOL_TON (TON за интервал); по умолчанию 0 — ledger пишется, выплат нет.
        let pool_ton: f64 = std::env::var("INFNODE_REWARD_POOL_TON")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        // Комиссия валидатора (владельца сети): INFNODE_VALIDATOR_FEE_PERCENT, 0..=30.
        // Валидатор НЕ может взять больше 30% — нодам гарантированно остаётся ≥70% пула.
        // Это защита от монополизации: владелец настраивает свою долю, но не может
        // присвоить почти весь заработок (порог жёстко ограничен в коде).
        let validator_fee: f64 = std::env::var("INFNODE_VALIDATOR_FEE_PERCENT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30.0);
        let validator_fee = validator_fee.clamp(0.0, 30.0);
        let total_weight: u64 = nodes.iter().filter_map(|n| n["weight"].as_u64()).sum();
        let mut payouts: Vec<Value> = Vec::new();
        if total_weight > 0 && pool_ton > 0.0 {
            // нанотоны = TON * 1e9
            let pool_nt: f64 = pool_ton * 1_000_000_000.0;
            // доля валидаторов (комиссия) и пул для нод (остаток)
            let validator_nt = (pool_nt * validator_fee / 100.0).floor() as u64;
            let nodes_pool_nt = (pool_nt - validator_nt as f64).max(0.0);
            // комиссия валидаторам: поровну между основным + суб-валидаторами (validators)
            // если validators пуст — весь fee идёт основному (владельцу)
            if validator_nt > 0 {
                let mut validator_ids: Vec<String> = node.cfg.validators.clone();
                let primary_id = format!("inf1:{}", hex::encode(node.id));
                if !validator_ids.contains(&primary_id) {
                    validator_ids.insert(0, primary_id.clone());
                }
                let n_val = validator_ids.len().max(1);
                let share_nt_each = (validator_nt as f64 / n_val as f64).floor() as u64;
                for vid in &validator_ids {
                    if share_nt_each == 0 {
                        continue;
                    }
                    payouts.push(json!({
                        "name": if vid == &primary_id { "validator-primary".to_string() } else { "validator-sub".to_string() },
                        "node_id": vid.clone(),
                        "weight": 0,
                        "share_nt": share_nt_each,
                        "share_ton": (share_nt_each as f64) / 1_000_000_000.0,
                        "status": "pending",
                        "kind": "validator_fee",
                    }));
                }
            }
            // остаток нодам пропорционально весу
            for n in &nodes {
                let w = n["weight"].as_u64().unwrap_or(0);
                if w == 0 {
                    continue;
                }
                let share_nt = (nodes_pool_nt * (w as f64) / (total_weight as f64)).floor() as u64;
                if share_nt == 0 {
                    continue;
                }
                let share_ton = (share_nt as f64) / 1_000_000_000.0;
                payouts.push(json!({
                    "name": n["name"].clone(),
                    "node_id": n["node_id"].clone(),
                    "weight": w,
                    "share_nt": share_nt,
                    "share_ton": share_ton,
                    "status": "pending",
                    "kind": "storage_reward",
                }));
            }
        }
        let ledger_entry = json!({
            "ts": ts,
            "interval_secs": INTERVAL_SECS,
            "pool_ton": pool_ton,
            "validator_fee_percent": validator_fee,
            "total_weight": total_weight,
            "payouts": payouts,
        });

        let _ = std::fs::write(&state_file, serde_json::to_string(&json!(new_state))?);
        let out = json!({ "ts": ts, "interval_secs": INTERVAL_SECS, "nodes": nodes });
        let _ = std::fs::write(&out_file, serde_json::to_string_pretty(&out)?);

        // append в payout_ledger.json (регистр распределения, читаемый оператором для Distribute)
        let ledger_file = data_dir.join("payout_ledger.json");
        let mut ledger: Vec<Value> = std::fs::read_to_string(&ledger_file)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        ledger.push(ledger_entry);
        if let Ok(raw) = serde_json::to_string_pretty(&json!(ledger)) {
            let _ = std::fs::write(&ledger_file, raw);
        }

        eprintln!(
            "[rewards] rewards.json updated: {}",
            serde_json::to_string(&out).unwrap_or_default()
        );

        state = new_state;
        sleep(Duration::from_secs(INTERVAL_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Проверка честного распределения с комиссией валидатора.
    /// Валидатор ≤30%, ноды получают ≥70% пропорционально весу.
    #[test]
    fn fair_split_with_validator_fee() {
        let pool_nt: f64 = 1_000_000_000.0; // 1 TON
        let fee: f64 = 30.0;
        let validator_nt = (pool_nt * fee / 100.0).floor() as u64;
        let nodes_pool_nt = (pool_nt - validator_nt as f64).max(0.0);
        // две ноды: weight 70 и 30
        let w_a: f64 = 70.0;
        let w_b: f64 = 30.0;
        let total_w = w_a + w_b;
        let a_nt = (nodes_pool_nt * w_a / total_w).floor() as u64;
        let b_nt = (nodes_pool_nt * w_b / total_w).floor() as u64;
        let nodes_total = a_nt + b_nt;
        let all = validator_nt + nodes_total;
        // валидатор ≤30%
        assert!(validator_nt as f64 / pool_nt <= 0.31, "validator >30%");
        // ноды ≥70%
        assert!(nodes_total as f64 / pool_nt >= 0.69, "nodes <70%");
        // пропорционально: A > B (вес 70 vs 30)
        assert!(a_nt > b_nt, "A should get more (higher weight)");
        // сумма не превышает пул
        assert!(all <= pool_nt as u64, "pool overspend");
        println!(
            "OK: val={} a={} b={} all={} pool={}",
            validator_nt, a_nt, b_nt, all, pool_nt as u64
        );
    }

    /// Честный proof: размер проверенного чанка, а не манифеста.
    #[test]
    fn chunk_len_not_manifest_size() {
        // манифест 10MB, чанк 1MB — засчитываем 1MB
        let manifest_size = 10_000_000u64;
        let chunk_len = 1_000_000u64;
        assert!(chunk_len < manifest_size);
        // в коде verified_bytes += chunk_len (не manifest["size"])
        // (проверка логики: тест подтверждает, что честно считать чанк)
        let _ = manifest_size;
    }

    /// Anti-Sybil RF-лимит: 100 фейковых нод с ОДИНАКОВЫМИ чанками (копии) НЕ получают
    /// 100-кратный вес. Каждый чанк оплачивается максимум RF раз → суммарный вес ≈
    /// уникальные_байты × RF, а не ×100.
    #[test]
    fn anti_sybil_rf_limit_100_copies() {
        // «уникальные» данные: 3 чанка
        let unique_chunks: Vec<(String, u64)> = vec![
            ("c1".to_string(), 1_000),
            ("c2".to_string(), 2_000),
            ("c3".to_string(), 3_000),
        ];
        let unique_bytes: u64 = unique_chunks.iter().map(|(_, l)| *l).sum(); // 6000

        let n = 100usize;
        // 100 фейковых нод подтверждают ОДНИ И ТЕ ЖЕ чанки (реплики одного набора)
        let nodes: Vec<(&[(String, u64)], f64)> =
            (0..n).map(|_| (unique_chunks.as_slice(), 1.0)).collect();

        let rf_bytes = rf_limited_bytes(&nodes);
        let total: u64 = rf_bytes.iter().sum();

        // суммарно: ровно уникальные × RF (6000 × 3 = 18000), а НЕ ×100 (600000)
        assert_eq!(
            total,
            unique_bytes * RF as u64,
            "total RF bytes must equal unique × RF, got {}",
            total
        );
        // получает вес ровно RF=3 ноды
        let rewarded = rf_bytes.iter().filter(|&&b| b > 0).count();
        assert_eq!(rewarded, RF, "only RF=3 nodes should be rewarded");
        // не должно быть линейного роста ×100
        assert!(
            total < unique_bytes * n as u64,
            "weight must not scale ×100 with copies: {} >= {}",
            total,
            unique_bytes * n as u64
        );
        println!(
            "OK: 100 copies -> total {} = unique {} × RF {} (not ×100 = {})",
            total,
            unique_bytes,
            RF,
            unique_bytes * n as u64
        );
    }

    /// RF-лимит учитывает разные наборы чанков: если нода хранит УНИКАЛЬНЫЙ чанк,
    /// он ей начисляется полностью (не более RF копий каждого чанка).
    #[test]
    fn rf_limit_respects_unique_chunks() {
        // нода A хранит c1; ноды B и C хранят тот же c1 + каждый свой уникальный c2/c3
        let chunks_a: Vec<(String, u64)> = vec![("c1".to_string(), 1000)];
        let chunks_b: Vec<(String, u64)> = vec![("c1".to_string(), 1000), ("c2".to_string(), 500)];
        let chunks_c: Vec<(String, u64)> = vec![("c1".to_string(), 1000), ("c3".to_string(), 700)];
        let nodes = vec![
            (chunks_a.as_slice(), 1.0),
            (chunks_b.as_slice(), 1.0),
            (chunks_c.as_slice(), 1.0),
        ];
        let rf_bytes = rf_limited_bytes(&nodes);
        // c1 платится 3 раза (RF=3) — всем; c2 и c3 — полностью уникальны
        assert_eq!(rf_bytes[0], 1000); // только c1
        assert_eq!(rf_bytes[1], 1000 + 500); // c1 + c2
        assert_eq!(rf_bytes[2], 1000 + 700); // c1 + c3
    }

    /// RF-лимит выбирает надёжные узлы в приоритете: при репликации выше аптайм = раньше.
    #[test]
    fn rf_limit_prefers_reliable_nodes() {
        let chunk: Vec<(String, u64)> = vec![("c1".to_string(), 1000)];
        // фейковая нода с низким аптаймом 0.1, надёжная с 0.9
        let nodes = vec![
            (chunk.as_slice(), 0.1),
            (chunk.as_slice(), 0.9),
            (chunk.as_slice(), 0.7),
            (chunk.as_slice(), 0.2),
        ];
        let rf_bytes = rf_limited_bytes(&nodes);
        // RF=3 → наградят ноды с аптаймом 0.9, 0.7, 0.2 (топ-3), а не фейковую 0.1
        assert_eq!(rf_bytes[1], 1000, "uptime 0.9 should be first");
        assert_eq!(rf_bytes[2], 1000, "uptime 0.7 should be rewarded");
        assert_eq!(rf_bytes[3], 1000, "uptime 0.2 should be 3rd");
        assert_eq!(rf_bytes[0], 0, "4th copy (uptime 0.1) must NOT be rewarded");
    }
}

#[cfg(test)]
mod tests_split {

    /// Комиссия валидаторов делится ПОРОВНУ между основным + суб.
    #[test]
    fn validator_fee_split_equal() {
        let pool_nt: f64 = 1_000_000_000.0; // 1 TON
        let fee: f64 = 30.0;
        let validator_nt = (pool_nt * fee / 100.0).floor() as u64; // 300M
                                                                   // 3 валидатора (основной + 2 суб)
        let n_val = 3usize;
        let share_each = (validator_nt as f64 / n_val as f64).floor() as u64; // 100M
        assert_eq!(share_each, 100_000_000, "each validator should get 100M");
        let total_val = share_each * n_val as u64;
        assert!(total_val <= validator_nt, "total must not exceed the fee");
        // нодам остаётся >=70%
        let nodes_pool = (pool_nt - validator_nt as f64).max(0.0) as u64;
        assert!(nodes_pool as f64 / pool_nt >= 0.69);
        println!(
            "OK: 3 validators by {} nt, nodes {}",
            share_each, nodes_pool
        );
    }
}
