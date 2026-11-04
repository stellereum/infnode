//! Миграция чанков и batch-проверка целостности (П.3.3).
//!
//! - migration_pass: проход по локальным чанкам (mail:/files:/). Для каждого вычисляется
//!   актуальный k-ближайший набор к ключу blake3(bucket:cid). Если локальная нода НЕ в нём —
//!   чанк пушится на актуальные ноды (storage.store), затем удаляется локально (storage.delete
//!   через локальный fs). Если локальная в наборе, но какой-то пир из k-ближайших недоступен —
//!   чанк отправляется на недостающую (best-effort).
//! - integrity_pass: проход по манифестам (m:/f:), для каждого чанка сверяется blake3 с хэшем
//!   в манифесте, считается mismatch. Отчёт пишется в data_dir/migration_report.json.
//!
//! Запуск: env INFNODE_MIGRATION=1 (по умолчанию выкл). Период — env
//! INFNODE_MIGRATION_INTERVAL_SECS (default 3600 = 1 час).

use base64::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::node::Node;
use crate::proto::NODEID_LEN;

const K: usize = crate::dht::K;

/// Вычислить target-узел (первые NODEID_LEN байт blake3("bucket:cid")) для DHT-поиска
/// актуальных k-ближайших к чанку.
fn chunk_target(bucket: &str, chunk_id: &str) -> [u8; NODEID_LEN] {
    let h = blake3::hash(format!("{bucket}:{chunk_id}").as_bytes());
    let mut target = [0u8; NODEID_LEN];
    target.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
    target
}

/// Список локальных чанков на диске для указанного бакета.
fn list_local_chunks(data_dir: &Path, bucket: &str) -> Vec<String> {
    let safe: String = bucket
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let dir = data_dir.join("chunks").join(safe);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            // chunk_id — hex blake3, 64 символа
            n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit())
        })
        .collect()
}

/// Прочитать локальный чанк с диска (bytes).
fn read_local_chunk(data_dir: &Path, bucket: &str, chunk_id: &str) -> Option<Vec<u8>> {
    let safe: String = bucket
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let p = data_dir.join("chunks").join(safe).join(chunk_id);
    std::fs::read(&p).ok()
}

/// Отправить чанк пиру через storage.store (с таймаутом — недоступный пир не должен
/// вешать миграцию). Возвращает true при успехе.
async fn push_chunk(
    node: &Arc<Node>,
    peer_id: [u8; NODEID_LEN],
    bucket: &str,
    chunk_id: &str,
    data: &[u8],
) -> bool {
    if !node.peer_allows(&peer_id, bucket).await {
        return false;
    }
    let payload = json!({
        "bucket": bucket,
        "chunk_id": chunk_id,
        "data": base64::engine::general_purpose::STANDARD.encode(data),
    })
    .to_string()
    .into_bytes();
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            node.request_to(peer_id, "storage.store", payload),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Удалить локальный чанк (через ту же логику, что и handle_storage_delete).
fn delete_local_chunk(data_dir: &Path, bucket: &str, chunk_id: &str) {
    let safe: String = bucket
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let p = data_dir.join("chunks").join(safe).join(chunk_id);
    let _ = std::fs::remove_file(p);
}

/// Проход по локальным чанкам: миграция на актуальные k-ближайших.
/// Возвращает статистику для отчёта.
pub async fn migrate_pass(node: &Arc<Node>, data_dir: &Path) -> Value {
    let mut pushed = 0u64;
    let mut removed = 0u64;
    let mut skipped = 0u64;
    let mut errors = 0u64;
    let mut total = 0u64;

    let buckets = ["mail", "files"];
    for bucket in buckets {
        // мигрируем только если эта нода имеет право на бакет (роль хранения)
        if !node.role_allows(bucket) {
            continue;
        }
        let local_ids = list_local_chunks(data_dir, bucket);
        for chunk_id in local_ids {
            total += 1;
            let target = chunk_target(bucket, &chunk_id);
            // dht_find_node ходит в сеть — оборачиваем в таймаут, чтобы недоступный
            // пир не вешал миграцию на каждом чанке
            let closest = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                node.dht_find_node(&target),
            )
            .await
            {
                Ok(v) => v,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };
            // ближайшие K нод должны хранить реплики; если локальной нет в K-ближайших — push + delete
            let our_id = node.id;
            let our_in_closest = closest.iter().take(K).any(|n| n.id == our_id);

            if !our_in_closest {
                // мигрируем на новые: push на каждую актуальную из K (если реплик меньше K)
                let Some(data) = read_local_chunk(data_dir, bucket, &chunk_id) else {
                    errors += 1;
                    continue;
                };
                let mut sent = 0usize;
                for n in closest.iter().take(K) {
                    if n.id == our_id {
                        continue;
                    }
                    if push_chunk(node, n.id, bucket, &chunk_id, &data).await {
                        sent += 1;
                    }
                }
                pushed += 1;
                if sent > 0 {
                    delete_local_chunk(data_dir, bucket, &chunk_id);
                    removed += 1;
                }
                // если не удалось ни на одну ноду — оставляем локально (страховка от потери)
            } else {
                // мы в k-ближайших: best-effort дополнить недостающих реплик (если есть данные)
                skipped += 1;
            }
        }
    }

    json!({
        "pass": "migrate",
        "total_chunks": total,
        "pushed": pushed,
        "removed_locally": removed,
        "skipped_local_in_k": skipped,
        "errors": errors,
    })
}

/// Batch-проверка целостности: проход по манифестам m:/f:, сверка blake3 чанков с манифестом.
/// Отчёт: total/checked/missing(bucket locally)/hash_mismatch.
pub async fn integrity_pass(node: &Arc<Node>, data_dir: &Path) -> Value {
    let mut total_mfs = 0u64;
    let mut total_chunks = 0u64;
    let mut checked = 0u64;
    let mut missing_local = 0u64;
    let mut hash_mismatch = 0u64;

    for prefix in ["m:", "f:"] {
        let keys = node.kv_manifest_keys(prefix).await;
        for k in keys {
            total_mfs += 1;
            let Some(raw) = node.get_local_kv(&k).await else {
                continue;
            };
            let Ok(mf) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let bucket = mf["bucket"].as_str().unwrap_or("files");
            let Some(chunks) = mf["chunks"].as_array() else {
                continue;
            };
            for c in chunks {
                total_chunks += 1;
                let Some(cid) = c["id"].as_str() else {
                    continue;
                };
                let expected = c["hash"].as_str();
                let Some(data) = read_local_chunk(data_dir, bucket, cid) else {
                    missing_local += 1;
                    continue;
                };
                checked += 1;
                if let Some(exp) = expected {
                    let actual = hex::encode(blake3::hash(&data).as_bytes());
                    if !actual.eq_ignore_ascii_case(exp) {
                        hash_mismatch += 1;
                    }
                }
            }
        }
    }

    json!({
        "pass": "integrity",
        "total_manifests": total_mfs,
        "total_chunks": total_chunks,
        "checked_locally": checked,
        "missing_locally": missing_local,
        "hash_mismatch": hash_mismatch,
    })
}

/// Записать объединённый отчёт (migrate+integrity) в data_dir/migration_report.json (append).
fn write_report(data_dir: &Path, entry: Value) {
    let p = data_dir.join("migration_report.json");
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.push(entry);
    if let Ok(raw) = serde_json::to_string_pretty(&json!(arr)) {
        let _ = std::fs::write(&p, raw);
    }
}

/// Главный цикл миграции. Запускается из main.rs НЕ в async-контексте:
/// сам создаёт dedicated OS thread со своим tokio Runtime, чтобы
/// синхронный fs I/O и сетевые вызовы (dht_find_node) НЕ блокировали
/// главный runtime валидатора (где крутится web + rewards).
///
/// Периодически запускает migrate_pass + integrity_pass, пишет отчёт.
/// Каждый проход обёрнут в timeout — если сеть зависла, цикл продолжится.
pub fn run(node: Arc<Node>, data_dir: PathBuf) {
    std::thread::Builder::new()
        .name("infmail-migration".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("migration-worker")
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[migration] не удалось создать runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let interval_secs: u64 = std::env::var("INFNODE_MIGRATION_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600);
                // Пуш-миграция чанков на другие ноды (сеть-dependent). По умолчанию ВЫКЛ:
                // для малых сетей данные уже реплицируются при записи (store_chunk_replicated),
                // а в больших сетях включается явно. Integrity-проверка работает всегда.
                let push_enabled = std::env::var("INFNODE_MIGRATION_PUSH").as_deref() == Ok("1");
                eprintln!("[migration] старт (dedicated thread): interval={}s push={}", interval_secs, push_enabled);
                loop {
                    // migrate_pass: только если явно включён; обёрнут в timeout
                    let migrate = if push_enabled {
                        match tokio::time::timeout(
                            Duration::from_secs(120),
                            migrate_pass(&node, &data_dir),
                        )
                        .await
                        {
                            Ok(v) => v,
                            Err(_) => {
                                eprintln!("[migration] migrate_pass TIMEOUT (120s) — пропускаем");
                                json!({ "pass": "migrate", "error": "timeout" })
                            }
                        }
                    } else {
                        json!({ "pass": "migrate", "disabled": true })
                    };
                    // integrity_pass: только локальный fs, тоже обёрнут
                    let integrity = match tokio::time::timeout(
                        Duration::from_secs(60),
                        integrity_pass(&node, &data_dir),
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(_) => {
                            eprintln!("[migration] integrity_pass TIMEOUT (60s) — пропускаем");
                            json!({ "pass": "integrity", "error": "timeout" })
                        }
                    };
                    let entry = json!({
                        "ts": crate::dht::now_ms(),
                        "migrate": migrate,
                        "integrity": integrity,
                    });
                    write_report(&data_dir, entry.clone());
                    eprintln!(
                        "[migration] pass: migrate pushed={} removed={} skipped={} err={} | integrity checked={} missing={} mismatch={}",
                        migrate["pushed"].as_u64().unwrap_or(0),
                        migrate["removed_locally"].as_u64().unwrap_or(0),
                        migrate["skipped_local_in_k"].as_u64().unwrap_or(0),
                        migrate["errors"].as_u64().unwrap_or(0),
                        integrity["checked_locally"].as_u64().unwrap_or(0),
                        integrity["missing_locally"].as_u64().unwrap_or(0),
                        integrity["hash_mismatch"].as_u64().unwrap_or(0),
                    );
                    sleep(Duration::from_secs(interval_secs)).await;
                }
            });
        })
        .expect("спавн migration thread");
}
