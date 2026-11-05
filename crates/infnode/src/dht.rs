//! Kademlia DHT: routing table (k-buckets) + KV-хранилище.

use crate::proto::NODEID_LEN;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub const K: usize = 20; // размер бакета
pub const ALPHA: usize = 3; // параллельность lookup

/// Окно жизни dedup-записей (`dedup:*` в KV) — и тот же TTL у pubsub-dedup
/// (`Node::mark_seen`): 5 минут. Раньше `dedup:*` жили 30 дней и ПРОДЛЯЛИСЬ при
/// каждой записи чанка: 113k из 158k ключей kv.json и ~31 МБ/сутки роста файла.
/// Длинное окно больше не нужно: chunk_id теперь содержимо-адресные
/// (см. `node::chunk_id_for`), повторная запись того же чанка идемпотентна —
/// дедуп защищает только от мгновенных дублей при репликации/починке.
pub const DEDUP_TTL_MS: i64 = 5 * 60 * 1000;

/// Horizon after which a routing-table entry counts as stale (no refresh seen).
/// 24 h matches the persistent-subscription horizon (`Node::prune_subs`): an
/// entry unseen for a full day is dead weight, not discovery memory. Applied
/// by `RoutingTable::prune_stale` from the 60 s `dht_refresh` loop; lookups
/// only ever ADD fresh entries, so this strictly shrinks the table.
pub const ROUTING_STALE_AFTER_MS: i64 = 24 * 3600 * 1000;

/// Узел в таблице маршрутизации (FULL-PQ: `id` is the PQ id via
/// `proto::pq_id_from_pub`; `ed_hex` is the frozen auth/TLS pin (NOT
/// identity); `pq_hex` is the pinned Falcon-512 key that MUST derive `id`).
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct NodeInfo {
    pub id: [u8; NODEID_LEN],
    pub endpoints: Vec<String>,
    pub ed_hex: String,
    pub pq_hex: String,
    pub last_seen: i64,
}

/// Fail-closed gate for gossip-fed routing records (audit 2026-11-01):
/// an endpoint is dialable only if it parses as a socket address.
pub fn endpoint_ok(ep: &str) -> bool {
    if ep.is_empty() || ep.len() > crate::proto::MAX_ENDPOINT_LEN {
        return false;
    }
    ep.parse::<std::net::SocketAddr>().is_ok()
}

/// Fail-closed gate for routing records arriving over the network
/// (`dht.update`, `dht.find_node` answers, `dht.find_value` hints):
/// FULL-PQ — `id` MUST equal `pq_id_from_pub(pq)` (otherwise anyone could
/// bind an honest PQ id to their own key and hijack discovery); `ed_hex`
/// must be a valid 32-byte hex key (frozen auth/TLS pin, NOT identity —
/// verified separately at handshake/TLS, never for identity); endpoints are
/// filtered to dialable ones.
pub fn node_info_valid(
    id: &[u8; NODEID_LEN],
    ed_hex: &str,
    pq_hex: &str,
    endpoints: &[String],
) -> bool {
    let ed: [u8; 32] = match hex::decode(ed_hex) {
        Ok(b) => match b.try_into() {
            Ok(k) => k,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    let _ = ed;
    let pq: Vec<u8> = match hex::decode(pq_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if pq.len() != crate::proto::PQ_FALCON_PK_LEN {
        return false;
    }
    if crate::proto::pq_id_from_pub(&pq) != *id {
        return false;
    }
    if endpoints.len() > crate::proto::MAX_ENDPOINTS_PER_NODE {
        return false;
    }
    true
}

/// XOR-дистанция между двумя ID (как big-endian 160-бит число).
pub fn xor_distance(a: &[u8; NODEID_LEN], b: &[u8; NODEID_LEN]) -> [u8; NODEID_LEN] {
    let mut d = [0u8; NODEID_LEN];
    for i in 0..NODEID_LEN {
        d[i] = a[i] ^ b[i];
    }
    d
}

fn leading_common_bits(a: &[u8; NODEID_LEN], b: &[u8; NODEID_LEN]) -> usize {
    let mut common = 0usize;
    for i in 0..NODEID_LEN {
        let x = a[i] ^ b[i];
        if x == 0 {
            common += 8;
            continue;
        }
        common += x.leading_zeros() as usize;
        break;
    }
    common
}

/// Kademlia routing table: 160 бакетов по XOR-расстоянию от нашего ID.
pub struct RoutingTable {
    own: [u8; NODEID_LEN],
    k: usize,
    buckets: Vec<VecDeque<NodeInfo>>,
}

impl RoutingTable {
    pub fn new(own: [u8; NODEID_LEN], k: usize) -> Self {
        Self {
            own,
            k,
            buckets: vec![VecDeque::new(); 160],
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn bucket_of(&self, id: &[u8; NODEID_LEN]) -> usize {
        let common = leading_common_bits(&self.own, id);
        common.min(159)
    }

    /// Вставка/обновление узла: самый свежий — в начало бакета; полный бакет — evict старого.
    pub fn insert(&mut self, node: NodeInfo) {
        let idx = self.bucket_of(&node.id);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            bucket.remove(pos);
            bucket.push_front(node);
            return;
        }
        if bucket.len() >= self.k {
            // полный бакет: вытесняем самого старого (LRU)
            bucket.pop_back();
        }
        bucket.push_front(node);
    }

    /// Удаление узла (мёртвый/сбойный).
    pub fn remove(&mut self, id: &[u8; NODEID_LEN]) {
        let idx = self.bucket_of(id);
        self.buckets[idx].retain(|n| n.id != *id);
    }

    /// Выселить протухшие записи (`last_seen` старше `max_age_ms`).
    /// Возвращает число выселенных. `closest`/`insert` не меняются, поэтому
    /// результаты lookup на свежих фикстурах бит-в-бит те же (см.
    /// `tests/dht_scale_tests.rs::routing_prune_stale_before_after`).
    pub fn prune_stale(&mut self, now_ms: i64, max_age_ms: i64) -> usize {
        let mut evicted = 0usize;
        for bucket in &mut self.buckets {
            let before = bucket.len();
            bucket.retain(|n| now_ms.saturating_sub(n.last_seen) <= max_age_ms);
            evicted += before - bucket.len();
        }
        evicted
    }

    /// Ближайшие n узлов к target (по XOR).
    pub fn closest(&self, target: &[u8; NODEID_LEN], n: usize) -> Vec<NodeInfo> {
        let mut all: Vec<(NodeInfo, [u8; NODEID_LEN])> = Vec::new();
        for b in &self.buckets {
            for node in b {
                let d = xor_distance(&node.id, target);
                all.push((node.clone(), d));
            }
        }
        all.sort_by(|a, b| a.1.cmp(&b.1));
        all.into_iter().take(n).map(|(n, _)| n).collect()
    }

    pub fn all(&self) -> Vec<NodeInfo> {
        let mut out = Vec::new();
        for b in &self.buckets {
            out.extend(b.iter().cloned());
        }
        out
    }

    /// Подсчёт заполненности (для мониторинга).
    pub fn bucket_stats(&self) -> Vec<usize> {
        self.buckets.iter().map(|b| b.len()).collect()
    }
}

/// KV-хранилище DHT (для метаданных сети, сервисов и т.п.).
///
/// R6: карта лежит под `Arc` (copy-on-write). Читателям (снапшот для
/// persist_kv, перебор манифестов в storage.store, LWW-проверка dht.store)
/// отдаётся `Arc::clone` — O(1) вместо клонирования всей карты (на стенде
/// это был полный копир 48–85 МБ на КАЖДЫЙ такой запрос прямо на
/// async-воркере). Мутации идут через `Arc::make_mut`: пока снапшот жив
/// (идёт serialize+запись в blocking-пуле), мутирующая запись оплачивает
/// один клон карты — это дешевле, чем клон на каждом чтении.
#[derive(Default)]
pub struct KvStore {
    entries: Arc<HashMap<String, StoredValue>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredValue {
    pub value: String,
    pub expires: i64,
    pub origin: [u8; NODEID_LEN],
    pub ttl_ms: i64,
    pub stored_at: i64,
}

impl KvStore {
    /// Единственная точка мутации карты (copy-on-write через `Arc::make_mut`).
    fn entries_mut(&mut self) -> &mut HashMap<String, StoredValue> {
        Arc::make_mut(&mut self.entries)
    }

    pub fn store(&mut self, key: &str, value: String, ttl_ms: i64, origin: [u8; NODEID_LEN]) {
        let now = now_ms();
        let expires = now + ttl_ms;
        self.entries_mut().insert(
            key.to_string(),
            StoredValue {
                value,
                expires,
                origin,
                ttl_ms,
                stored_at: now,
            },
        );
    }

    /// Store a replica keeping the ORIGINATOR's clock (see `keys_to_republish`):
    /// `expires` is recomputed from the original `stored_at`, so TTL fires on
    /// the original schedule no matter how many hops the value travelled.
    /// Clamped: a corrupt/future stored_at cannot extend past now+ttl, and a
    /// missing/ancient one cannot resurrect an already-dead entry.
    pub fn store_replica(
        &mut self,
        key: &str,
        value: String,
        ttl_ms: i64,
        origin: [u8; NODEID_LEN],
        stored_at: i64,
    ) {
        let now = now_ms();
        let sa = stored_at.clamp(now - ttl_ms, now);
        let expires = sa + ttl_ms;
        if expires <= now {
            return;
        }
        self.entries_mut().insert(
            key.to_string(),
            StoredValue {
                value,
                expires,
                origin,
                ttl_ms,
                stored_at: sa,
            },
        );
    }

    /// Репликация (LWW по stored_at): применить значение от пира ТОЛЬКО если оно новее
    /// локального (по stored_at), иначе оставить свежее локальное. Защищает от затирания
    /// свежих записей старыми слепками пиров (dht.sync / catch_up / dht.store).
    /// Возвращает true, если пировское значение применили.
    pub fn merge_replica(
        &mut self,
        key: &str,
        value: String,
        ttl_ms: i64,
        origin: [u8; NODEID_LEN],
        stored_at: i64,
    ) -> bool {
        let now = now_ms();
        if stored_at <= 0 {
            // пир не прислал stored_at — не затираем локальное, отдаём приоритет локальному
            return false;
        }
        // OR-set для индексов ящика: параллельные append'ы с двух нод при чистом LWW
        // теряли письма (выживал только более новый список целиком). Union по id —
        // оба письма выживают; удаления защищены tombstones (ключ "{index}:tombs").
        if Self::is_index_key(key) {
            return self.merge_index_union(key, value, ttl_ms, origin, stored_at, now);
        }
        if Self::is_tombs_key(key) {
            return self.merge_tombs_union(key, value, ttl_ms, origin, stored_at, now);
        }
        let expires = now + ttl_ms;
        let apply = match self.entries.get(key) {
            // локального нет — берём от пира
            None => true,
            // локальное новее — не затираем
            Some(local) => stored_at > local.stored_at,
        };
        if apply {
            self.entries_mut().insert(
                key.to_string(),
                StoredValue {
                    value,
                    expires,
                    origin,
                    ttl_ms,
                    stored_at,
                },
            );
        }
        apply
    }

    fn is_index_key(key: &str) -> bool {
        key.ends_with("index") && !key.ends_with(":tombs")
    }

    fn is_tombs_key(key: &str) -> bool {
        key.ends_with(":tombs")
    }

    /// Union слияния списков id (индексы ящика). Возвращает true если локальное изменилось.
    fn merge_index_union(
        &mut self,
        key: &str,
        value: String,
        ttl_ms: i64,
        origin: [u8; NODEID_LEN],
        stored_at: i64,
        now: i64,
    ) -> bool {
        let incoming: Vec<String> = serde_json::from_str(&value).unwrap_or_default();
        match self.entries.get(key) {
            None => {
                self.entries_mut().insert(
                    key.to_string(),
                    StoredValue {
                        value,
                        expires: now + ttl_ms,
                        origin,
                        ttl_ms,
                        stored_at,
                    },
                );
                true
            }
            Some(local) => {
                let mut ids: Vec<String> = serde_json::from_str(&local.value).unwrap_or_default();
                // чистим от tombstones при слиянии, чтобы удалённое не воскресало
                // от старых реплик (удаление реплицируется и списком, и tombstone)
                //
                // Perf: исходный тройной вложенный скан (`retain` × tombs +
                // цикл × (tombs + ids)) — O(n·m) строковых сравнений; на
                // индексе из тысяч id это миллисекунды под write-lock'ом на
                // КАЖДОЕ слияние. Множества дают ТЕ ЖЕ порядок/флаги/байты за
                // O(n+m): `ids` растёт только push'ами в исходном порядке
                // (сначала локальные, затем входящие по порядку), `changed` —
                // только при push'е, проверки tombstone — раньше dedup'а.
                let tombs = self.tombs_for(key);
                let tomb_set: HashSet<&str> = tombs.iter().map(String::as_str).collect();
                if !tomb_set.is_empty() {
                    ids.retain(|x| !tomb_set.contains(x.as_str()));
                }
                let mut known: HashSet<String> = ids.iter().cloned().collect();
                ids.reserve(incoming.len());
                let mut changed = false;
                for id in incoming {
                    if tomb_set.contains(id.as_str()) {
                        continue;
                    }
                    if !known.contains(id.as_str()) {
                        known.insert(id.clone());
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
                    self.entries_mut().insert(key.to_string(), newv);
                }
                changed
            }
        }
    }

    /// Union слияния tombstones {id: ts} — берём max ts по каждому id.
    fn merge_tombs_union(
        &mut self,
        key: &str,
        value: String,
        ttl_ms: i64,
        origin: [u8; NODEID_LEN],
        stored_at: i64,
        now: i64,
    ) -> bool {
        let incoming: std::collections::HashMap<String, i64> =
            serde_json::from_str(&value).unwrap_or_default();
        match self.entries.get(key) {
            None => {
                self.entries_mut().insert(
                    key.to_string(),
                    StoredValue {
                        value,
                        expires: now + ttl_ms,
                        origin,
                        ttl_ms,
                        stored_at,
                    },
                );
                true
            }
            Some(local) => {
                let mut tombs: std::collections::HashMap<String, i64> =
                    serde_json::from_str(&local.value).unwrap_or_default();
                let mut changed = false;
                for (id, ts) in incoming {
                    let e = tombs.entry(id).or_insert(0);
                    if ts > *e {
                        *e = ts;
                        changed = true;
                    }
                }
                if changed || stored_at > local.stored_at {
                    let v = serde_json::to_string(&tombs).unwrap_or_else(|_| local.value.clone());
                    let newv = StoredValue {
                        value: v,
                        expires: now + ttl_ms.max(local.ttl_ms),
                        origin,
                        ttl_ms: ttl_ms.max(local.ttl_ms),
                        stored_at: stored_at.max(local.stored_at),
                    };
                    self.entries_mut().insert(key.to_string(), newv);
                }
                changed
            }
        }
    }

    /// Локальные tombstones для индексного ключа (тихий OR-set).
    fn tombs_for(&self, index_key: &str) -> Vec<String> {
        let tkey = format!("{index_key}:tombs");
        match self.entries.get(&tkey) {
            None => Vec::new(),
            Some(st) => {
                let m: std::collections::HashMap<String, i64> =
                    serde_json::from_str(&st.value).unwrap_or_default();
                m.into_keys().collect()
            }
        }
    }

    /// Список ключей для republish (переиздание значений на k-ближайших).
    /// `dedup:*` исключены: это локальная подсказка «этот контент уже у нас»,
    /// а не DHT-значение. При 5-минутном окне они иначе републикуются каждые
    /// 2.5 минуты, и каждая репликация сбрасывает `stored_at` у соседа —
    /// запись живёт вечно и снова раздувает kv.json.
    /// (key, value, ttl_ms, origin, stored_at): the age rides along so a
    /// replica keeps the ORIGINAL clock instead of resetting it on every hop
    /// (audit 2026-10-06: without it mutual republish made TTL immortal).
    pub fn keys_to_republish(&self, now: i64) -> Vec<(String, String, i64, [u8; NODEID_LEN], i64)> {
        self.entries
            .iter()
            .filter(|(k, v)| {
                !k.starts_with("dedup:") && v.expires > now && now - v.stored_at > v.ttl_ms / 2
            })
            .map(|(k, v)| (k.clone(), v.value.clone(), v.ttl_ms, v.origin, v.stored_at))
            .collect()
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        let now = now_ms();
        let v = self.entries.get(key);
        match v {
            Some(v) if v.expires > now => Some(v.value.clone()),
            Some(_) => {
                self.entries_mut().remove(key);
                None
            }
            None => None,
        }
    }

    /// Read-only peek for hot paths (audit 2026-10-06): returns the live
    /// value without mutating (no lazy expiry), so callers can hold a READ
    /// lock. Expiry cleanup, if needed, is the caller's explicit remove.
    pub fn peek(&self, key: &str) -> Option<(String, i64)> {
        let now = now_ms();
        self.entries
            .get(key)
            .filter(|v| v.expires > now)
            .map(|v| (v.value.clone(), v.expires))
    }

    /// Удалить значение по строковому ключу.
    pub fn remove(&mut self, key: &str) {
        self.entries_mut().remove(key);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `stored_at` одной ключевой записи без клона карты (LWW-проверка
    /// dht.store раньше здесь клонировала ВСЮ карту — 48–85 МБ на запрос).
    pub fn stored_at(&self, key: &str) -> i64 {
        self.entries.get(key).map(|v| v.stored_at).unwrap_or(0)
    }

    pub fn prune(&mut self) {
        let now = now_ms();
        self.entries_mut().retain(|_, v| v.expires > now);
    }

    /// Выкинуть мёртвое ПЕРЕД сериализацией kv.json. Возвращает
    /// (удалено всего, из них dedup:*). Считаем, чтобы тесты/диагностика могли
    /// замерить «до/после».
    ///
    /// 1) записи с истёкшим `expires` — раньше просроченное только ПРОПУСКАЛОСЬ
    ///    при чтении (`get`/`kv_manifest_keys`), а в карте и в файле копилось
    ///    до ближайшего `prune` из 60-секундного цикла (а на путях
    ///    `handle_dht_store`/`catch_up_with` вообще без prune);
    /// 2) `dedup:*` старше `DEDUP_TTL_MS` по `stored_at` — включая легаси-записи
    ///    с 30-дневным TTL: их `expires` продлевается при каждой записи, т.е.
    ///    они не протухают сами и именно они давали основной рост файла.
    pub fn sweep(&mut self, now: i64) -> (usize, usize, Vec<(String, String)>) {
        let mut expired = 0usize;
        let mut dedup = 0usize;
        let mut removed: Vec<(String, String)> = Vec::new();
        self.entries_mut().retain(|k, v| {
            if v.expires <= now {
                expired += 1;
                removed.push((k.clone(), v.value.clone()));
                return false;
            }
            if k.starts_with("dedup:") && now.saturating_sub(v.stored_at) > DEDUP_TTL_MS {
                dedup += 1;
                removed.push((k.clone(), v.value.clone()));
                return false;
            }
            // Retention cap for heavy stell DHT manifests: blocks, headers, snapshots older than 2h
            // are pruned from kv.json so the file stays ~1 MB instead of growing to 50+ MB.
            let is_stell_blob = k.starts_with("stell_blocks:")
                || k.starts_with("stell_headers:")
                || k.starts_with("stell_state:");
            if is_stell_blob
                && (v.stored_at == 0 || now.saturating_sub(v.stored_at) > 2 * 3600 * 1000)
            {
                expired += 1;
                removed.push((k.clone(), v.value.clone()));
                return false;
            }
            true
        });
        (expired + dedup, dedup, removed)
    }

    /// Владеющая копия всей карты (тесты/диагностика). Горячие пути берут
    /// `entries_snapshot` — O(1) вместо клона десятков мегабайт.
    pub fn entries_clone(&self) -> HashMap<String, StoredValue> {
        (*self.entries).clone()
    }

    /// Дешёвый снапшот для чтения/сериализации: один `Arc::clone`,
    /// блокировка kv отпускается сразу, карта не копируется.
    pub fn entries_snapshot(&self) -> Arc<HashMap<String, StoredValue>> {
        Arc::clone(&self.entries)
    }

    pub fn restore(&mut self, key: String, v: StoredValue) {
        if v.expires > now_ms() {
            self.entries_mut().insert(key, v);
        }
    }
}

#[cfg(test)]
mod kv_sweep_tests {
    use super::*;

    fn origin() -> [u8; NODEID_LEN] {
        [0u8; NODEID_LEN]
    }

    fn value(now: i64, stored_at: i64, ttl_ms: i64) -> StoredValue {
        StoredValue {
            value: "{}".into(),
            expires: now + ttl_ms,
            origin: origin(),
            ttl_ms,
            stored_at,
        }
    }

    #[test]
    fn sweep_drops_expired_and_stale_dedup_keeps_live() {
        let now = now_ms();
        let mut kv = KvStore::default();
        // живые записи (манифест/индекс)
        kv.store(
            "mail:alice:index",
            "[\"m1\"]".into(),
            30 * 24 * 3600 * 1000,
            origin(),
        );
        kv.store("files:alice", "[]".into(), 30 * 24 * 3600 * 1000, origin());
        // уже просроченная запись (отрицательный TTL)
        kv.store("expired:key", "x".into(), -1_000, origin());
        // свежий dedup — записан только что
        kv.store(
            "dedup:fresh",
            "{\"nodes\":[]}".into(),
            DEDUP_TTL_MS,
            origin(),
        );
        // легаси-dedup: 30-дневный TTL, но последняя запись была 10 минут назад
        kv.restore(
            "dedup:stale".into(),
            value(now, now - 2 * DEDUP_TTL_MS, 30 * 24 * 3600 * 1000),
        );

        let before = kv.len();
        assert_eq!(
            before, 5,
            "before: 2 live + expired + fresh dedup + stale dedup"
        );

        let (removed, removed_dedup, _) = kv.sweep(now);
        let after = kv.len();

        assert_eq!(
            before - after,
            removed,
            "removed must match the entry delta"
        );
        assert_eq!(removed, 2, "expired + stale dedup");
        assert_eq!(removed_dedup, 1);
        assert_eq!(after, 3, "after: 2 live + fresh dedup");

        assert!(kv.get("mail:alice:index").is_some(), "live keys kept");
        assert!(kv.get("files:alice").is_some(), "live keys kept");
        assert!(kv.get("dedup:fresh").is_some(), "fresh dedup kept");
        assert!(kv.get("expired:key").is_none(), "expired dropped");
        assert!(kv.get("dedup:stale").is_none(), "stale dedup dropped");
    }

    #[test]
    fn sweep_drops_expired_stell_blobs_keeps_live_and_legacy() {
        // Retention окно publisher'а (stellereum: тела/заголовки ниже
        // finalized − KEEP + TTL-backstop): просроченные `stell_*` манифесты
        // вычищаются sweep'ом, живые и легаси (долгий TTL, без expiry-концепта
        // в старых данных — у них всегда есть далёкий `expires`) — никогда.
        let now = now_ms();
        let mut kv = KvStore::default();
        // живые stell-манифесты (окно retention)
        kv.store(
            "stell_blocks:abc_blk_deadbeef",
            "{}".into(),
            11 * 24 * 3600 * 1000,
            origin(),
        );
        kv.store(
            "stell_headers:abc_h_42000",
            "{}".into(),
            11 * 24 * 3600 * 1000,
            origin(),
        );
        kv.store(
            "stell_head:abc_shard_0_head",
            "{}".into(),
            30 * 24 * 3600 * 1000,
            origin(),
        );
        // просроченные stell-манифесты (окно вышло)
        kv.store("stell_blocks:abc_blk_ffff", "x".into(), -1_000, origin());
        kv.store("stell_headers:abc_h_7", "x".into(), -1_000, origin());
        // легаси-долгоживущие (реестр/индексы, 30 дней как раньше)
        kv.store(
            "mail:alice:index",
            "[\"m1\"]".into(),
            30 * 24 * 3600 * 1000,
            origin(),
        );

        assert_eq!(kv.len(), 6);
        let (removed, _, _) = kv.sweep(now);
        assert_eq!(removed, 2, "только два просроченных stell-ключа");
        assert_eq!(kv.len(), 4);
        assert!(
            kv.get("stell_blocks:abc_blk_deadbeef").is_some(),
            "живое тело kept"
        );
        assert!(
            kv.get("stell_headers:abc_h_42000").is_some(),
            "живой заголовок kept"
        );
        assert!(kv.get("stell_head:abc_shard_0_head").is_some(), "head kept");
        assert!(
            kv.get("mail:alice:index").is_some(),
            "долгоживущие без expiry-концепта kept"
        );
        assert!(
            kv.get("stell_blocks:abc_blk_ffff").is_none(),
            "просроченное тело dropped"
        );
        assert!(
            kv.get("stell_headers:abc_h_7").is_none(),
            "просроченный заголовок dropped"
        );
    }

    #[test]
    fn keys_to_republish_skips_dedup() {
        let now = now_ms();
        let mut kv = KvStore::default();
        // обе записи старше половины TTL => раньше обе бы ушли в republish
        kv.restore("dedup:old".into(), value(now, now - 600_000, 600_000));
        kv.restore(
            "mail:alice:index".into(),
            value(now, now - 600_000, 600_000),
        );

        let mut keys: Vec<String> = kv
            .keys_to_republish(now)
            .into_iter()
            .map(|(k, _, _, _, _)| k)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["mail:alice:index".to_string()],
            "dedup must not be republished"
        );
    }

    #[test]
    fn replica_preserves_original_age_so_ttl_fires() {
        // Regression (audit 2026-10-06): republish used to reset stored_at on
        // every hop, making entries immortal. A replica must die on the
        // originator's schedule.
        let mut kv = KvStore::default();
        let now = now_ms();
        let ttl = 600_000;
        let born = now - 500_000; // almost expired at origin
        kv.store_replica("mail:old:index", "v".into(), ttl, [7u8; 20], born);
        assert_eq!(kv.stored_at("mail:old:index"), born);
        // 100s left on the original clock: still served...
        assert!(kv.get("mail:old:index").is_some());
        // ...but a FRESH store (no age) would live 600s; the replica must not.
        let mut kv2 = KvStore::default();
        kv2.store("mail:fresh:index", "v".into(), ttl, [7u8; 20]);
        assert!(kv2.stored_at("mail:fresh:index") >= now);
        // Future stored_at cannot extend life past now+ttl...
        kv.store_replica(
            "mail:fut:index",
            "v".into(),
            ttl,
            [7u8; 20],
            now + 999_999_999,
        );
        // Fresh read, not the stale `now` above: `store_replica` clamps to
        // ITS OWN now_ms(), which can tick one ms past the captured value —
        // comparing against the stale one flakes on the millisecond boundary.
        // A +999M leak would still fail this by nine orders of magnitude.
        assert!(kv.stored_at("mail:fut:index") <= now_ms());
        // ...and an already-dead entry is not resurrected.
        kv.store_replica("mail:dead:index", "v".into(), ttl, [7u8; 20], now - ttl - 1);
        assert!(kv.get("mail:dead:index").is_none());
    }
}
