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

/// Minimum age of the least-recently-seen bucket entry before a NEWcomer may
/// displace it. A novel identity can otherwise mint enough valid keys to fill
/// a bucket and evict every honest entry (eclipse by churn). Recently seen
/// entries are kept; only idle ones are replaced, and `prune_stale` still
/// handles the 24 h horizon.
pub const ROUTING_EVICT_GRACE_MS: i64 = 10 * 60 * 1000;

/// Узел в таблице маршрутизации (FULL-PQ: `id` is the PQ id via
/// `proto::pq_id_from_pub`; `pq_hex` is the pinned Falcon-512 key that MUST
/// derive `id`. There is no classical identity field any more).
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct NodeInfo {
    pub id: [u8; NODEID_LEN],
    pub endpoints: Vec<String>,
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
/// bind an honest PQ id to their own key and hijack discovery); endpoints
/// are filtered to dialable ones.
pub fn node_info_valid(id: &[u8; NODEID_LEN], pq_hex: &str, endpoints: &[String]) -> bool {
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

/// Peers a `dht.lookup` handler may forward to.
///
/// A recursive lookup used to fan out to EVERY connected peer, so one inbound
/// request could become `deg^ttl` outbound requests (amplification). Kademlia
/// forwards to at most [`ALPHA`] closest candidates; this pure selector pins
/// that bound without touching the wire.
pub fn lookup_fanout(
    peers: impl IntoIterator<Item = [u8; NODEID_LEN]>,
    target: &[u8; NODEID_LEN],
    from: &[u8; NODEID_LEN],
    fanout: usize,
) -> Vec<[u8; NODEID_LEN]> {
    let mut distances = 0usize;
    lookup_fanout_counted(peers, target, from, fanout, &mut distances)
}

/// [`lookup_fanout`] with an operation counter (`distances` is incremented once
/// per XOR-distance evaluation) so a test can pin the cost model.
///
/// Every candidate's distance is computed EXACTLY ONCE and the (stable) sort
/// runs over the precomputed key. The previous `sort_by_key` recomputed
/// `xor_distance` for BOTH operands of every comparison — an O(n·log2 n) run
/// of full 20-byte XORs per forwarded lookup instead of O(n). Ordering is
/// identical: `sort_by_key` was stable, so equal distances keep their
/// candidate order here too, and `dedup` is now `dedup_by` on the same key.
pub fn lookup_fanout_counted(
    peers: impl IntoIterator<Item = [u8; NODEID_LEN]>,
    target: &[u8; NODEID_LEN],
    from: &[u8; NODEID_LEN],
    fanout: usize,
    distances: &mut usize,
) -> Vec<[u8; NODEID_LEN]> {
    let peers = peers.into_iter();
    // Pre-size from the iterator's lower bound (a `Vec` iterator reports its
    // exact length): one allocation instead of ~log2(n) growth re-copies.
    let mut candidates: Vec<([u8; NODEID_LEN], [u8; NODEID_LEN])> =
        Vec::with_capacity(peers.size_hint().0);
    for p in peers {
        if p == *from {
            continue;
        }
        *distances += 1;
        candidates.push((p, xor_distance(&p, target)));
    }
    candidates.sort_by(|a, b| a.1.cmp(&b.1));
    candidates.dedup_by(|a, b| a.0 == b.0);
    candidates.truncate(fanout);
    candidates.into_iter().map(|(p, _)| p).collect()
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

    /// Insert/update: newest at the front; a full bucket replaces only its
    /// least-recently-seen entry, and only once that entry is past
    /// [`ROUTING_EVICT_GRACE_MS`] (anti-eclipse; see the body).
    pub fn insert(&mut self, node: NodeInfo) {
        let idx = self.bucket_of(&node.id);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            bucket.remove(pos);
            bucket.push_front(node);
            return;
        }
        if bucket.len() >= self.k {
            // Full bucket: replace the LEAST-RECENTLY-SEEN entry, and only
            // when it has been idle past the grace window. A novel id is
            // dropped while every existing entry is still recent, so key
            // churn cannot eclipse honest routing entries.
            let oldest = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, n)| n.last_seen)
                .map(|(i, n)| (i, n.last_seen));
            match oldest {
                Some((idx, last_seen))
                    if node.last_seen.saturating_sub(last_seen) >= ROUTING_EVICT_GRACE_MS =>
                {
                    bucket.remove(idx);
                }
                _ => return,
            }
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
        if n == 0 {
            return Vec::new();
        }
        // One reservation for the whole table scan: `Vec::new()` grew (and
        // re-copied) the refs vector through ~log2(len) reallocations on every
        // lookup, and this runs per find_node/republish/replication pick.
        let mut refs: Vec<(&NodeInfo, [u8; NODEID_LEN])> = Vec::with_capacity(self.len());
        for b in &self.buckets {
            for node in b {
                refs.push((node, xor_distance(&node.id, target)));
            }
        }
        if refs.len() > n {
            refs.select_nth_unstable_by(n - 1, |a, b| a.1.cmp(&b.1));
            refs.truncate(n);
        }
        refs.sort_by(|a, b| a.1.cmp(&b.1));
        refs.into_iter().map(|(node, _)| node.clone()).collect()
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
/// Значения лежат в `Arc<StoredValue>`, а сама карта хранится напрямую (без
/// `Arc<HashMap<...>>` + `Arc::make_mut`):
/// - снапшот (`entries_snapshot`) копирует только ключи и инкрементирует
///   счётчики ссылок `Arc<StoredValue>` — 0 байт копирования `StoredValue.value`;
/// - мутация одного ключа (`store`/`store_replica`/`merge_replica`/`restore`)
///   меняет ровно один слот карты и никогда не клонирует всю карту, даже пока
///   предыдущий снапшот сериализуется в `spawn_blocking`.
pub const MAX_KV_ENTRIES: usize = 100_000;
pub const MAX_KV_BYTES: usize = 512 * 1024 * 1024;

#[derive(Default)]
pub struct KvStore {
    entries: HashMap<String, Arc<StoredValue>>,
    total_bytes: usize,
    chunk_hashes: HashMap<String, String>,
    manifest_chunks: HashMap<String, Vec<String>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredValue {
    pub value: String,
    pub expires: i64,
    pub origin: [u8; NODEID_LEN],
    pub ttl_ms: i64,
    pub stored_at: i64,
    #[serde(skip)]
    pub last_republished_ms: i64,
}

fn is_manifest_candidate(key: &str, val: &str) -> bool {
    if key.starts_with("dedup:")
        || key.starts_with("sealed-owner:")
        || key.starts_with("recovery:")
        || key.starts_with("blacklist:")
        || key.starts_with("share:")
        || key.starts_with("user:")
    {
        return false;
    }
    (key.starts_with("m:")
        || key.starts_with("mail:")
        || key.starts_with("f:")
        || key.starts_with("files:")
        || key.contains(':'))
        && val.trim_start().starts_with('{')
        && val.contains("chunks")
}

fn extract_manifest_chunk_hashes(key: &str, val: &str) -> Vec<(String, String)> {
    if !is_manifest_candidate(key, val) {
        return Vec::new();
    }
    let Ok(m) = serde_json::from_str::<serde_json::Value>(val) else {
        return Vec::new();
    };
    let Some(cs) = m["chunks"].as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in cs {
        if let (Some(cid), Some(hash)) = (c["id"].as_str(), c["hash"].as_str()) {
            if !cid.is_empty() && !hash.is_empty() {
                out.push((cid.to_string(), hash.to_string()));
            }
        }
    }
    out
}

fn is_pinned_kv_key(key: &str) -> bool {
    key.starts_with("sealed-owner:")
        || key.starts_with("recovery:")
        || key.starts_with("blacklist:")
        || key.starts_with("share:")
        || key.starts_with("user:")
}

impl KvStore {
    fn unindex_key(&mut self, key: &str) {
        if let Some(cids) = self.manifest_chunks.remove(key) {
            for cid in cids {
                self.chunk_hashes.remove(&cid);
            }
        }
    }

    fn index_key(&mut self, key: &str, val: &str) {
        self.unindex_key(key);
        let pairs = extract_manifest_chunk_hashes(key, val);
        if !pairs.is_empty() {
            let mut cids = Vec::with_capacity(pairs.len());
            for (cid, hash) in pairs {
                cids.push(cid.clone());
                self.chunk_hashes.insert(cid, hash);
            }
            self.manifest_chunks.insert(key.to_string(), cids);
        }
    }

    fn insert_entry(&mut self, key: String, v: StoredValue) {
        if let Some(old) = self.entries.get(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(key.len() + old.value.len());
        }
        self.total_bytes = self.total_bytes.saturating_add(key.len() + v.value.len());
        self.index_key(&key, &v.value);
        self.entries.insert(key, Arc::new(v));
    }

    fn remove_entry(&mut self, key: &str) {
        if let Some(old) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(key.len() + old.value.len());
            self.unindex_key(key);
        }
    }

    fn ensure_remote_capacity(&mut self, key: &str, incoming_val_len: usize, now: i64) -> bool {
        let existing_val_len = self.entries.get(key).map(|v| v.value.len());
        let is_new = existing_val_len.is_none();
        let added_bytes = match existing_val_len {
            Some(old_len) => incoming_val_len.saturating_sub(old_len),
            None => key.len().saturating_add(incoming_val_len),
        };
        if !(is_new && self.entries.len() >= MAX_KV_ENTRIES)
            && self.total_bytes.saturating_add(added_bytes) <= MAX_KV_BYTES
        {
            return true;
        }
        // Step 1: sweep expired / stale dedup / expired stell blobs first.
        self.sweep(now);
        let existing_val_len = self.entries.get(key).map(|v| v.value.len());
        let is_new = existing_val_len.is_none();
        let added_bytes = match existing_val_len {
            Some(old_len) => incoming_val_len.saturating_sub(old_len),
            None => key.len().saturating_add(incoming_val_len),
        };
        if !(is_new && self.entries.len() >= MAX_KV_ENTRIES)
            && self.total_bytes.saturating_add(added_bytes) <= MAX_KV_BYTES
        {
            return true;
        }
        // Step 2: evict oldest non-pinned entries (excluding `key` itself).
        let mut victims: Vec<(i64, String)> = self
            .entries
            .iter()
            .filter(|(k, _)| k.as_str() != key && !is_pinned_kv_key(k))
            .map(|(k, v)| (v.stored_at, k.clone()))
            .collect();
        victims.sort_unstable_by_key(|(sa, _)| *sa);
        for (_, vkey) in victims {
            self.remove_entry(&vkey);
            if !(is_new && self.entries.len() >= MAX_KV_ENTRIES)
                && self.total_bytes.saturating_add(added_bytes) <= MAX_KV_BYTES
            {
                return true;
            }
        }
        false
    }

    /// O(1) lookup of expected BLAKE3 chunk hash from live manifests.
    pub fn expected_chunk_hash(&self, chunk_id: &str) -> Option<&str> {
        self.chunk_hashes.get(chunk_id).map(|s| s.as_str())
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn keys_with_prefixes(&self, prefixes: &[&str], now: i64) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(k, v)| v.expires > now && prefixes.iter().any(|p| k.starts_with(p)))
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn store(&mut self, key: &str, value: String, ttl_ms: i64, origin: [u8; NODEID_LEN]) {
        let now = now_ms();
        let expires = now + ttl_ms;
        self.insert_entry(
            key.to_string(),
            StoredValue {
                value,
                expires,
                origin,
                ttl_ms,
                stored_at: now,
                last_republished_ms: 0,
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
    ) -> bool {
        let now = now_ms();
        let sa = stored_at.clamp(now - ttl_ms, now);
        let expires = sa + ttl_ms;
        if expires <= now {
            return false;
        }
        if !self.ensure_remote_capacity(key, value.len(), now) {
            return false;
        }
        self.insert_entry(
            key.to_string(),
            StoredValue {
                value,
                expires,
                origin,
                ttl_ms,
                stored_at: sa,
                last_republished_ms: 0,
            },
        );
        true
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
            if !self.ensure_remote_capacity(key, value.len(), now) {
                return false;
            }
            self.insert_entry(
                key.to_string(),
                StoredValue {
                    value,
                    expires,
                    origin,
                    ttl_ms,
                    stored_at,
                    last_republished_ms: 0,
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
        match self.entries.get(key).cloned() {
            None => {
                if !self.ensure_remote_capacity(key, value.len(), now) {
                    return false;
                }
                self.insert_entry(
                    key.to_string(),
                    StoredValue {
                        value,
                        expires: now + ttl_ms,
                        origin,
                        ttl_ms,
                        stored_at,
                        last_republished_ms: 0,
                    },
                );
                true
            }
            Some(local) => {
                let mut ids: Vec<String> = serde_json::from_str(&local.value).unwrap_or_default();
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
                    if !self.ensure_remote_capacity(key, v.len(), now) {
                        return false;
                    }
                    let newv = StoredValue {
                        value: v,
                        expires: now + ttl_ms.max(local.ttl_ms),
                        origin,
                        ttl_ms: ttl_ms.max(local.ttl_ms),
                        stored_at: stored_at.max(local.stored_at),
                        last_republished_ms: local.last_republished_ms,
                    };
                    self.insert_entry(key.to_string(), newv);
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
        match self.entries.get(key).cloned() {
            None => {
                if !self.ensure_remote_capacity(key, value.len(), now) {
                    return false;
                }
                self.insert_entry(
                    key.to_string(),
                    StoredValue {
                        value,
                        expires: now + ttl_ms,
                        origin,
                        ttl_ms,
                        stored_at,
                        last_republished_ms: 0,
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
                    if !self.ensure_remote_capacity(key, v.len(), now) {
                        return false;
                    }
                    let newv = StoredValue {
                        value: v,
                        expires: now + ttl_ms.max(local.ttl_ms),
                        origin,
                        ttl_ms: ttl_ms.max(local.ttl_ms),
                        stored_at: stored_at.max(local.stored_at),
                        last_republished_ms: local.last_republished_ms,
                    };
                    self.insert_entry(key.to_string(), newv);
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
    /// Возвращает `Vec<(String, Arc<StoredValue>)>` без глубокого копирования `value`,
    /// с троттлингом по `last_republished_ms`.
    pub fn keys_to_republish(&self, now: i64) -> Vec<(String, Arc<StoredValue>)> {
        self.entries
            .iter()
            .filter(|(k, v)| {
                !k.starts_with("dedup:")
                    // Local-authoritative sealed-manifest pins: a peer refuses
                    // them, so republishing is pure traffic.
                    && !k.starts_with("sealed-owner:")
                    && v.expires > now
                    && now - v.stored_at > v.ttl_ms / 2
                    && (v.last_republished_ms == 0
                        || now.saturating_sub(v.last_republished_ms)
                            >= (v.ttl_ms / 4).max(3_600_000))
            })
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect()
    }

    /// Пометить ключ как переизданный в момент `now`.
    pub fn mark_republished(&mut self, key: &str, now: i64) {
        if let Some(arc) = self.entries.get_mut(key) {
            Arc::make_mut(arc).last_republished_ms = now.max(1);
        }
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        let now = now_ms();
        let expired = match self.entries.get(key) {
            Some(v) if v.expires > now => return Some(v.value.clone()),
            Some(_) => true,
            None => return None,
        };
        if expired {
            self.remove_entry(key);
        }
        None
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
        self.remove_entry(key);
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
        let mut unindex = Vec::new();
        let mut bytes_sub = 0usize;
        let manifest_chunks = &self.manifest_chunks;
        self.entries.retain(|k, v| {
            if v.expires > now {
                true
            } else {
                bytes_sub = bytes_sub.saturating_add(k.len() + v.value.len());
                if manifest_chunks.contains_key(k.as_str()) {
                    unindex.push(k.clone());
                }
                false
            }
        });
        self.total_bytes = self.total_bytes.saturating_sub(bytes_sub);
        for k in unindex {
            self.unindex_key(&k);
        }
    }

    /// Выкинуть мёртвое ПЕРЕД сериализацией kv.json. Возвращает
    /// (удалено всего, из них dedup:*, удалённые Arc-значения без dedup:*).
    pub fn sweep(&mut self, now: i64) -> (usize, usize, Vec<(String, Arc<StoredValue>)>) {
        let mut expired = 0usize;
        let mut dedup = 0usize;
        let mut removed: Vec<(String, Arc<StoredValue>)> = Vec::new();
        let mut unindex = Vec::new();
        let mut bytes_sub = 0usize;
        let manifest_chunks = &self.manifest_chunks;
        self.entries.retain(|k, v| {
            if v.expires <= now {
                expired += 1;
                bytes_sub = bytes_sub.saturating_add(k.len() + v.value.len());
                if manifest_chunks.contains_key(k.as_str()) {
                    unindex.push(k.clone());
                }
                if !k.starts_with("dedup:") {
                    removed.push((k.clone(), Arc::clone(v)));
                }
                return false;
            }
            if k.starts_with("dedup:") && now.saturating_sub(v.stored_at) > DEDUP_TTL_MS {
                dedup += 1;
                bytes_sub = bytes_sub.saturating_add(k.len() + v.value.len());
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
                bytes_sub = bytes_sub.saturating_add(k.len() + v.value.len());
                if manifest_chunks.contains_key(k.as_str()) {
                    unindex.push(k.clone());
                }
                removed.push((k.clone(), Arc::clone(v)));
                return false;
            }
            true
        });
        self.total_bytes = self.total_bytes.saturating_sub(bytes_sub);
        for k in unindex {
            self.unindex_key(&k);
        }
        (expired + dedup, dedup, removed)
    }

    /// Владеющая копия всей карты (тесты/диагностика). Горячие пути берут
    /// `entries_snapshot` — вместо клона десятков мегабайт значений.
    pub fn entries_clone(&self) -> HashMap<String, StoredValue> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), (**v).clone()))
            .collect()
    }

    /// Дешёвый снапшот для чтения/сериализации: копируются только ключи и
    /// инкрементируются `Arc<StoredValue>` (0 байт копирования `StoredValue.value`),
    /// блокировка kv отпускается сразу, последующие мутации не клонируют карту.
    pub fn entries_snapshot(&self) -> Vec<(String, Arc<StoredValue>)> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect()
    }

    pub fn restore(&mut self, key: String, mut v: StoredValue) {
        if v.expires > now_ms() {
            v.last_republished_ms = 0;
            self.insert_entry(key, v);
        }
    }
}

/// Сериализовать снапшот `KvStore` в JSON-объект `{"key": StoredValue, ...}`
/// без выделения промежуточной `HashMap` и без копирования строк `StoredValue.value`
/// (формат совместим с `load_kv`: `serde_json::from_str::<HashMap<String, StoredValue>>`).
pub fn serialize_kv_snapshot(
    snapshot: &[(String, Arc<StoredValue>)],
) -> serde_json::Result<String> {
    struct SnapshotMap<'a>(&'a [(String, Arc<StoredValue>)]);
    impl serde::Serialize for SnapshotMap<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_map(self.0.iter().map(|(k, v)| (k.as_str(), v.as_ref())))
        }
    }
    serde_json::to_string(&SnapshotMap(snapshot))
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
            last_republished_ms: 0,
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
        kv.restore(
            "sealed-owner:files:doc.bin".into(),
            value(now, now - 600_000, 600_000),
        );

        let mut keys: Vec<String> = kv
            .keys_to_republish(now)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["mail:alice:index".to_string()],
            "dedup and local-only sealed-owner pins must not be republished"
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

    #[test]
    fn snapshot_and_concurrent_store_share_arc_without_deep_cloning_values() {
        let mut kv = KvStore::default();
        let ttl = 600_000;
        let org1 = [1u8; NODEID_LEN];
        let org2 = [2u8; NODEID_LEN];
        let big_v1 = "a".repeat(8192);
        kv.store("k1", big_v1.clone(), ttl, org1);
        kv.store("k2", "v2-old".into(), ttl, org1);

        // Держим первый снапшот живым (имитация in-flight spawn_blocking persist_kv)
        // и параллельно мутируем другой ключ + добавляем новые ключи.
        let snap1 = kv.entries_snapshot();
        kv.store("k2", "v2-new".into(), ttl, org2);
        kv.store("k3", "v3".into(), ttl, org2);
        kv.store_replica("k4", "v4-rep".into(), ttl, org2, now_ms() - 1_000);

        let snap2 = kv.entries_snapshot();

        let arc1_k1 = &snap1.iter().find(|(k, _)| k == "k1").unwrap().1;
        let arc2_k1 = &snap2.iter().find(|(k, _)| k == "k1").unwrap().1;
        assert!(
            Arc::ptr_eq(arc1_k1, arc2_k1),
            "неизменённая запись k1 должна разделять тот же Arc<StoredValue> без глубокого клона"
        );

        let arc1_k2 = &snap1.iter().find(|(k, _)| k == "k2").unwrap().1;
        let arc2_k2 = &snap2.iter().find(|(k, _)| k == "k2").unwrap().1;
        assert!(
            !Arc::ptr_eq(arc1_k2, arc2_k2),
            "перезаписанная запись k2 должна получить новый Arc<StoredValue>"
        );
        assert_eq!(arc1_k2.value, "v2-old");
        assert_eq!(arc2_k2.value, "v2-new");
        drop(snap1);

        // JSON round-trip (формат load_kv) должен быть 100% эквивалентен HashMap<String, StoredValue>.
        let json = serialize_kv_snapshot(&snap2).expect("serialize snapshot");
        let parsed_val: serde_json::Value = serde_json::from_str(&json).expect("json value");
        let direct_val: serde_json::Value =
            serde_json::to_value(kv.entries_clone()).expect("direct json");
        assert_eq!(
            parsed_val, direct_val,
            "JSON-формат снапшота должен совпадать 1:1"
        );

        let decoded: HashMap<String, StoredValue> =
            serde_json::from_str(&json).expect("load_kv decode");
        let mut reloaded = KvStore::default();
        for (k, v) in decoded {
            reloaded.restore(k, v);
        }
        let orig = kv.entries_clone();
        let back = reloaded.entries_clone();
        assert_eq!(back.len(), orig.len());
        for (k, ev) in &orig {
            let av = back.get(k).expect("restored key present");
            assert_eq!(av.value, ev.value);
            assert_eq!(av.expires, ev.expires);
            assert_eq!(av.origin, ev.origin);
            assert_eq!(av.ttl_ms, ev.ttl_ms);
            assert_eq!(av.stored_at, ev.stored_at);
        }
    }

    #[test]
    fn chunk_hashes_index_tracks_store_merge_remove_sweep_and_restore() {
        let mut kv = KvStore::default();
        let now = now_ms();
        let mf1 = serde_json::json!({
            "chunks": [
                {"id": "aa11", "hash": "deadbeef"},
                {"id": "bb22", "hash": "cafebabe"}
            ]
        })
        .to_string();
        kv.store("files:doc1", mf1, 60_000, origin());
        assert_eq!(kv.expected_chunk_hash("aa11"), Some("deadbeef"));
        assert_eq!(kv.expected_chunk_hash("bb22"), Some("cafebabe"));

        // Updating the manifest replaces its chunk hashes cleanly.
        let mf2 = serde_json::json!({
            "chunks": [{"id": "cc33", "hash": "feedface"}]
        })
        .to_string();
        // `store` stamps its own `now_ms()`; under load that can advance past a
        // 10 ms margin and make the replica look stale (LWW refuses it). Use a
        // deliberately generous future stamp so the test is deterministic.
        assert!(kv.merge_replica("files:doc1", mf2, 60_000, origin(), now + 60_000));
        assert_eq!(kv.expected_chunk_hash("aa11"), None);
        assert_eq!(kv.expected_chunk_hash("cc33"), Some("feedface"));

        // Restore rebuilds index; remove and sweep clean it up.
        let mf_m = serde_json::json!({
            "chunks": [{"id": "dd44", "hash": "12345678"}]
        })
        .to_string();
        kv.restore(
            "m:mail1".into(),
            StoredValue {
                value: mf_m,
                expires: now + 1_000,
                origin: origin(),
                ttl_ms: 1_000,
                stored_at: now,
                last_republished_ms: 0,
            },
        );
        assert_eq!(kv.expected_chunk_hash("dd44"), Some("12345678"));

        kv.remove("files:doc1");
        assert_eq!(kv.expected_chunk_hash("cc33"), None);

        let (removed, _, _) = kv.sweep(now + 2_000);
        assert_eq!(removed, 1);
        assert_eq!(kv.expected_chunk_hash("dd44"), None);
    }

    #[test]
    fn keys_to_republish_throttled_by_mark_republished() {
        let mut kv = KvStore::default();
        let now = now_ms();
        let ttl = 600_000;
        kv.store_replica("files:aged", "v".into(), ttl, origin(), now - 450_000);

        let first = kv.keys_to_republish(now);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, "files:aged");

        kv.mark_republished("files:aged", now);
        assert!(
            kv.keys_to_republish(now + 1_000).is_empty(),
            "must be throttled right after mark_republished"
        );
        // Interval is (ttl / 4).max(3_600_000) = 3_600_000 ms.
        kv.restore(
            "files:aged2".into(),
            StoredValue {
                value: "v".into(),
                expires: now + 10_000_000,
                origin: origin(),
                ttl_ms: ttl,
                stored_at: now - 450_000,
                last_republished_ms: 0,
            },
        );
        kv.mark_republished("files:aged2", now);
        assert!(kv.keys_to_republish(now + 3_599_999).is_empty());
        assert_eq!(kv.keys_to_republish(now + 3_600_000).len(), 1);
    }
}
