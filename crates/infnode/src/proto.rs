use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const NODEID_LEN: usize = 20;
pub const MAX_FRAME: usize = 32 * 1024 * 1024;
pub const MAX_AUTH_FRAME: usize = 64 * 1024;
pub const TS_WINDOW_MS: i64 = 600_000;

/// Fail-closed ingress caps (audit 2026-11-01). The 32 MiB `MAX_FRAME` is a
/// transport envelope: individual services accept far less, so one peer
/// cannot turn a single request into a multi-megabyte allocation or a
/// mesh-wide amplification.
pub const MAX_DHT_KEY_LEN: usize = 512;
pub const MAX_DHT_VALUE_LEN: usize = 1024 * 1024;
pub const MAX_PUBSUB_DATA_LEN: usize = 1024 * 1024;
pub const MAX_STORAGE_CHUNK_LEN: usize = 2 * 1024 * 1024;
pub const MAX_NONCE_LEN: usize = 1024;
pub const MAX_TOPIC_LEN: usize = 256;
pub const MAX_ENDPOINTS_PER_NODE: usize = 8;
pub const MAX_ENDPOINT_LEN: usize = 256;
pub const MAX_ROUTES_PER_UPDATE: usize = 512;
pub const MAX_DHT_LOOKUP_TTL: u64 = 8;
pub const MAX_PUBSUB_TTL: u64 = 16;
pub const MAX_DHT_SYNC_LIMIT: usize = 10_000;
pub const MAX_REMOTE_TTL_SECS: u64 = 30 * 24 * 3600;
pub const MAX_SEEN_IDS: usize = 200_000;
pub const MAX_OUTBOX_PER_PEER: usize = 1024;

pub fn topic_ok(topic: &str) -> bool {
    !topic.is_empty() && topic.len() <= MAX_TOPIC_LEN
}

pub fn dht_key_ok(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_DHT_KEY_LEN
}

pub fn dht_value_ok(value: &str) -> bool {
    value.len() <= MAX_DHT_VALUE_LEN
}

pub fn pubsub_data_ok(data: &str) -> bool {
    data.len() <= MAX_PUBSUB_DATA_LEN
}

/// Claim a handshake nonce: true = fresh (inserted), false = replayed or
/// malformed. Entries older than `TS_WINDOW_MS` are pruned; the map is
/// hard-bounded so a flood of distinct nonces cannot grow memory without
/// limit (at the cap the handshake is refused — fail closed).
pub fn claim_nonce(seen: &mut HashMap<String, i64>, nonce: &str, now: i64) -> bool {
    if nonce.len() < 8
        || nonce.len() > 128
        || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    // Prune on every claim: handshakes are rare (not per-request), so an O(n)
    // scan here never lands on a hot path, and the window stays exact.
    let cutoff = now.saturating_sub(TS_WINDOW_MS);
    seen.retain(|_, ts| *ts > cutoff);
    if seen.contains_key(nonce) {
        return false;
    }
    if seen.len() >= MAX_SEEN_IDS {
        return false;
    }
    seen.insert(nonce.to_string(), now);
    true
}

pub mod kind {
    pub const PING: u8 = 0;
    pub const PONG: u8 = 1;
    pub const CHALLENGE: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const REQ: u8 = 4;
    pub const RESP: u8 = 5;
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn ts_ok(ts: i64) -> bool {
    (now_ms() - ts).abs() <= TS_WINDOW_MS
}

pub fn svc_id(name: &str) -> u64 {
    let h = blake3::hash(name.as_bytes());
    u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap())
}

pub fn svc_name(id: u64) -> Option<&'static str> {
    crate::services::SERVICE_NAMES
        .iter()
        .find(|n| svc_id(n) == id)
        .copied()
}

/// E2E ключ: X25519(shared) + оба NodeID (канонически отсортированы), раздутый через blake3.
/// Симметричный для обеих сторон независимо от направления.
pub fn e2e_key_from_shared(shared: &[u8; 32], id_a: &[u8; 20], id_b: &[u8; 20]) -> [u8; 32] {
    let (lo, hi) = if id_a < id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(b"infnode-e2e-v1");
    h.update(shared);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

/// Сессионный ключ с forward secrecy (X3DH-подобный): смешиваем 4 shared-секрета —
/// ss(static-static), se(static-эфимерный), es(эфемерный-static), ee(эфемерный-эфемерный).
/// Каждое соединение использует свежие эфемерные ключи, поэтому компрометация
/// долгосрочных ключей позже не раскрывает прошлый трафик.
pub fn session_key(
    shared_ss: &[u8; 32],
    shared_se: &[u8; 32],
    shared_es: &[u8; 32],
    shared_ee: &[u8; 32],
    id_a: &[u8; 20],
    id_b: &[u8; 20],
) -> [u8; 32] {
    let (lo, hi) = if id_a < id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(b"infnode-session-v1");
    h.update(shared_ss);
    h.update(shared_se);
    h.update(shared_es);
    h.update(shared_ee);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: u8,
    pub seq: u32,
    pub ts: i64,
    pub src: [u8; NODEID_LEN],
    pub dst: [u8; NODEID_LEN],
    pub svc: u64,
    pub payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sig: [u8; 64],
}

const HDR: usize = 68;

impl Frame {
    /// Exact wire length of `encode()` output.
    pub fn encoded_len(&self) -> usize {
        HDR + self.payload.len() + self.nonce.len() + 64
    }

    /// Append the signed prefix (everything except the trailing 64-byte sig).
    /// Single pass, no return-alloc: `encode`, `encode_into` and `sign_data`
    /// all funnel here so the byte layout has exactly one definition.
    pub fn sign_data_into(&self, v: &mut Vec<u8>) {
        v.push(1); // version
        v.push(self.kind);
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.ts.to_le_bytes());
        v.extend_from_slice(&self.src);
        v.extend_from_slice(&self.dst);
        v.extend_from_slice(&self.svc.to_le_bytes());
        v.extend_from_slice(&(self.nonce.len() as u16).to_le_bytes());
        v.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.payload);
        v.extend_from_slice(&self.nonce);
    }

    pub fn sign_data(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HDR + self.payload.len() + self.nonce.len());
        self.sign_data_into(&mut v);
        v
    }

    /// Streaming digest of the signed prefix: byte-identical input to
    /// `blake3::hash(&self.sign_data())` with no intermediate Vec.
    fn sign_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&[1]); // version
        h.update(&[self.kind]);
        h.update(&self.seq.to_le_bytes());
        h.update(&self.ts.to_le_bytes());
        h.update(&self.src);
        h.update(&self.dst);
        h.update(&self.svc.to_le_bytes());
        h.update(&(self.nonce.len() as u16).to_le_bytes());
        h.update(&(self.payload.len() as u32).to_le_bytes());
        h.update(&self.payload);
        h.update(&self.nonce);
        *h.finalize().as_bytes()
    }

    /// Append one full frame (prefix + sig) with a single reserve.
    pub fn encode_into(&self, b: &mut Vec<u8>) {
        b.reserve(self.encoded_len());
        self.sign_data_into(b);
        b.extend_from_slice(&self.sig);
    }

    /// Batch encode: one reserve for the whole run, zero per-frame allocs.
    pub fn encode_many(frames: &[Frame], out: &mut Vec<u8>) {
        out.reserve(frames.iter().map(Frame::encoded_len).sum::<usize>());
        for f in frames {
            f.encode_into(out);
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        // Exact capacity: the trailing sig fits without a second alloc.
        let mut b = Vec::with_capacity(self.encoded_len());
        self.sign_data_into(&mut b);
        b.extend_from_slice(&self.sig);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Frame> {
        if b.len() < HDR + 64 {
            bail!("frame too short");
        }
        // Manual LE loads: slices are in-bounds (checked above), so no
        // fallible try_into on the hot path. Validation order and error
        // strings are unchanged from the original decoder.
        let nlen = u16::from_le_bytes([b[62], b[63]]) as usize;
        let plen = u32::from_le_bytes([b[64], b[65], b[66], b[67]]) as usize;
        // защита от переполнения usize и out-of-bounds при нечётких/злонамеренных пакетах
        if plen > MAX_FRAME {
            bail!("payload too large");
        }
        // Поле nonce легитимно несёт 24 байта (XChaCha nonce); 64 КиБ
        // злонамеренного nonce на каждом из 1024 стримов — десятки мегабайт.
        if nlen > MAX_NONCE_LEN {
            bail!("nonce too large");
        }
        // проверяем что сумма длин не переполняет usize и точно совпадает с длиной
        let total = HDR
            .checked_add(plen)
            .and_then(|x| x.checked_add(nlen))
            .and_then(|x| x.checked_add(64));
        let total = match total {
            Some(t) => t,
            None => bail!("frame length overflow"),
        };
        if total != b.len() {
            bail!("frame length mismatch");
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&b[b.len() - 64..]);
        let mut src = [0u8; NODEID_LEN];
        let mut dst = [0u8; NODEID_LEN];
        src.copy_from_slice(&b[14..34]);
        dst.copy_from_slice(&b[34..54]);
        let f = Frame {
            kind: b[1],
            seq: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
            ts: i64::from_le_bytes([b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13]]),
            src,
            dst,
            svc: u64::from_le_bytes([
                b[54], b[55], b[56], b[57], b[58], b[59], b[60], b[61],
            ]),
            payload: b[68..68 + plen].to_vec(),
            nonce: b[68 + plen..68 + plen + nlen].to_vec(),
            sig,
        };
        // version check
        if b[0] != 1 {
            bail!("unsupported version");
        }
        // не допускаем переполнения индексов для нечётких пакетов
        if f.nonce.len() != nlen || f.payload.len() != plen {
            bail!("internal mismatch");
        }
        Ok(f)
    }

    pub fn verify(&self, pk: &VerifyingKey) -> bool {
        // sign-then-hash: подпись над blake3-дайджестом всего фрейма (быстро для больших payload)
        let d = self.sign_digest();
        pk.verify_strict(&d, &Signature::from_bytes(&self.sig))
            .is_ok()
    }
}

// PQ HANDSHAKE (default-ON since PQ 9.1; opt-out `STELL_INF_PQ_HANDSHAKE=0` pre-H only;
// additive only — mirrors pq_transport.rs + docs/PQ_TRANSPORT_PLAN.md §3/§5).
// KEX ephemeral ML-KEM-768; auth INTERIM keyed-hash MAC (NOT Falcon, plan §7), verified BEFORE
// session derivation (fail closed); malformed PQ REFUSED (no silent downgrade); binding zeroed till exporter pinned.

/// Env gate for the PQ handshake (shared name for both reads below; no new
/// env knobs — the opt-out reuses this same variable, inverted).
pub const PQ_HANDSHAKE_ENV: &str = "STELL_INF_PQ_HANDSHAKE";

/// Legacy opt-in read: true exactly when `STELL_INF_PQ_HANDSHAKE=1`.
/// Kept byte-for-byte for compatibility (pinned by
/// `pq_flag_defaults_off_and_parses_only_exact_1`); live handshake paths
/// use `pq_handshake_active` (default-ON) instead.
pub fn pq_handshake_enabled() -> bool {
    std::env::var(PQ_HANDSHAKE_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Default-ON read (PQ 9.1): PQ is attempted first unless the operator
/// explicitly opts out with `STELL_INF_PQ_HANDSHAKE=0` (exact `"0"`).
/// Unset, empty, or any other value (including the legacy `"1"`) = PQ
/// active. There was no pre-existing classical opt-out flag — the same
/// variable is now read inverted, so old `=1` configs keep working and only
/// an explicit `=0` opts out. The opt-out is honored ONLY while
/// `!pq_classical_refused_at(height)`; at/after
/// [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused fail-closed
/// regardless of this flag.
pub fn pq_handshake_active() -> bool {
    pq_handshake_active_for(std::env::var(PQ_HANDSHAKE_ENV).ok().as_deref())
}

/// Pure core of [`pq_handshake_active`] (env-free so tests stay race-free:
/// only the legacy `pq_flag_defaults_off_...` test touches the process env).
/// `Some("0")` = explicit classical opt-out; anything else = PQ active.
pub fn pq_handshake_active_for(value: Option<&str>) -> bool {
    !matches!(value, Some("0"))
}

// HEIGHT-GATED CLASSICAL DEATH (PQ 9.1, default-ON).
//
// Shape mirrors the `STELL_VRF_ACTIVATION_HEIGHT` precedent
// (`stellereum/src/vrf.rs`: `VrfActivation::Disabled` default,
// `FromHeight(h)` arms refusal for heights `>= h` via `is_active_at`, same
// boundary carried + logged at startup): pre-H the mixed window tolerates
// classical (WARN + counter, fail-open with noise); at/after H classical is
// refused fail-closed (`pq_mixed_policy_at` / `pq_falcon_policy_at`).
// Unlike VRF there is NO env override here on purpose: a single binary-wide
// const keeps every node on the identical boundary with no per-node drift.
// To adjust, the lead changes the const below (one line) and redeploys
// uniformly — same rollout discipline as a VRF H change.
//
// H choice: infnode-observed heights are tens of thousands (kv fixtures pin
// `"stell:height:*" = "42000:..."`; `node.rs` cites live height 71587),
// VRF activation tests stage at `ACTIVATION_H = 1_000_000`. `300_000` is
// current-chain-scale (≈42k–72k) + ~200k headroom, rounded up — far future,
// comfortably pre-activation for every live/test height, far below any
// planned flag-day. Revisit well before the chain approaches H.
pub const PQ_CLASSICAL_REFUSE_AFTER_HEIGHT: u64 = 300_000;

/// True when a handshake at `height` must refuse classical (height `>= H`).
/// Pre-H (`false`) = legacy window behavior, byte-identical.
pub fn pq_classical_refused_at(height: u64) -> bool {
    height >= PQ_CLASSICAL_REFUSE_AFTER_HEIGHT
}

/// Monotonic count of classical fallbacks taken while PQ was active (pre-H
/// window only; post-H there are no fallbacks — only refusals). Lives here
/// (not `metrics.rs`) to keep the change inside the handshake zone; the
/// lead may mirror it into the Prometheus render as a follow-up.
static PQ_CLASSICAL_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Record one classical fallback; returns the new total.
pub fn pq_record_classical_fallback() -> u64 {
    PQ_CLASSICAL_FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed) + 1
}

/// Classical fallbacks so far (fail-closed counting, like `auth_bans_hit`).
pub fn pq_classical_fallback_total() -> u64 {
    PQ_CLASSICAL_FALLBACK_TOTAL.load(Ordering::Relaxed)
}

/// Loud WARN for a classical fallback (call on every pre-H fallback, dial
/// and accept sides). Never silent: prints the running fallback count and
/// the refusal height so operators see the window closing.
pub fn pq_warn_classical_fallback(side: &str) {
    let n = pq_record_classical_fallback();
    eprintln!(
        "[WARN] PQ handshake fell back to classical ({side}, fallback #{n}): peer is classical-only or offered no pq_* (pre-H window). Classical will be REFUSED at/after height {} — provision pq-identity.key on both ends.",
        PQ_CLASSICAL_REFUSE_AFTER_HEIGHT
    );
}

/// Wire version of the PQ handshake transcript.
pub const PQ_TRANSCRIPT_VERSION: u16 = 1;
/// Suite id for the interim ML-KEM-768-hybrid handshake. Distinct from the
/// reserved Falcon-512 production suite (`0xF1`) and the `pq_transport.rs`
/// test-only suite (`0xFF`); KAT vectors can never validate as either.
pub const PQ_SUITE_MLKEM768_HYBRID: u8 = 0x4D;
/// Domain string baked into every transcript digest (pins the channel-binding
/// label slot until the TLS exporter is wired).
pub const PQ_DOMAIN: &[u8] = b"infnode-pqhs-v1";
/// Domain for the hybrid session-key derivation.
pub const PQ_SESSION_DOMAIN: &[u8] = b"infnode-pq-session-v1";
/// Channel-binding placeholder (zeros) until the QUIC/TLS exporter output is
/// bound here. Follow-up; kept explicit rather than silently weak.
pub const PQ_CHAN_BIND_PLACEHOLDER: [u8; 32] = [0u8; 32];

/// Fixed-shape PQ handshake transcript (all fields 32 bytes, same field order
/// as `pq_transport.rs` `PqPlanTranscript` so the layout is shared):
/// long-term-PQ hashes, ephemeral KEX pubs, channel binding, frame bindings.
pub struct PqTranscript {
    /// `blake3` of the full initiator KEM encapsulation key (1184 B).
    pub pq_init: [u8; 32],
    /// `blake3` of the full responder KEM ciphertext (1088 B).
    pub pq_resp: [u8; 32],
    /// Initiator ephemeral X25519 pub.
    pub eph_init: [u8; 32],
    /// Responder ephemeral X25519 pub.
    pub eph_resp: [u8; 32],
    /// Channel binding (currently [`PQ_CHAN_BIND_PLACEHOLDER`]).
    pub chan_bind: [u8; 32],
    /// `blake3` of the CHALLENGE frame `sign_data` (binds the whole frame).
    pub nonce_init: [u8; 32],
    /// `blake3` of responder auth binding (`eph_resp || at_le || resp_id`).
    pub nonce_resp: [u8; 32],
}

impl PqTranscript {
    fn push(out: &mut Vec<u8>, f: &[u8; 32]) {
        out.extend_from_slice(&(f.len() as u16).to_le_bytes());
        out.extend_from_slice(f);
    }
    /// Canonical encoding: domain || `version` le16 || `suite` u8 ||
    /// length-prefixed fields.
    pub fn encode(&self, version: u16, suite: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(PQ_DOMAIN.len() + 3 + 7 * 34);
        v.extend_from_slice(PQ_DOMAIN);
        v.extend_from_slice(&version.to_le_bytes());
        v.push(suite);
        Self::push(&mut v, &self.pq_init);
        Self::push(&mut v, &self.pq_resp);
        Self::push(&mut v, &self.eph_init);
        Self::push(&mut v, &self.eph_resp);
        Self::push(&mut v, &self.chan_bind);
        Self::push(&mut v, &self.nonce_init);
        Self::push(&mut v, &self.nonce_resp);
        v
    }
    /// Digest both sides authenticate (production: same bytes Falcon signs).
    pub fn digest(&self, version: u16, suite: u8) -> [u8; 32] {
        *blake3::hash(&self.encode(version, suite)).as_bytes()
    }
}

/// Canonical 32-byte field hash for variable-length PQ inputs.
pub fn pq_hash_field(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Interim transcript authenticator: `blake3` keyed hash with the ML-KEM
/// shared secret as key over the transcript digest. See module docs: stand-in
/// for the Falcon-512 signature over the same digest (lead-gated).
pub fn pq_auth_tag(shared: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(shared, digest).as_bytes()
}

/// Constant-time tag comparison (no early exit).
pub fn pq_verify_tag(expected: &[u8; 32], got: &[u8; 32]) -> bool {
    let mut d: u8 = 0;
    for i in 0..32 {
        d |= expected[i] ^ got[i];
    }
    d == 0
}

/// Hybrid session key: breaks only if BOTH the classical X3DH key and the
/// ML-KEM shared secret break. Either input flipping changes the output.
pub fn pq_hybrid_session_key(
    classical: &[u8; 32],
    pq_shared: &[u8; 32],
    digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PQ_SESSION_DOMAIN);
    h.update(classical);
    h.update(pq_shared);
    h.update(digest);
    *h.finalize().as_bytes()
}

/// Negotiated handshake mode after applying the mixed-mode window policy.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PqMode {
    /// Classical X3DH handshake (peer offered no PQ, or local node is
    /// classical-only and ignores offered `pq_*` fields per plan §5).
    Classical,
    /// PQ-hybrid handshake (offer verified, hybrid session key).
    Pq,
}

/// Status of explicitly offered PQ fields, as observed by the verifier.
pub struct PqOfferCheck {
    /// Payload parses and all lengths/types are well-formed.
    pub wellformed: bool,
    /// `pq_ver`/`pq_suite` match [`PQ_TRANSCRIPT_VERSION`] /
    /// [`PQ_SUITE_MLKEM768_HYBRID`].
    pub suite_ok: bool,
    /// Transcript tag verifies against the recomputed digest.
    pub tag_ok: bool,
}

/// Mixed-mode window policy, exactly per `docs/PQ_TRANSPORT_PLAN.md` §5:
/// window builds verify dual-or-classical and route by classical id;
/// classical-only nodes NEVER see PQ fields as errors. Fails closed with a
/// clear error when PQ is explicitly offered but invalid (malformed fields,
/// unknown suite/version, bad tag) — this "refuse, never silently downgrade"
/// arm is the deliberate choice for the case the plan leaves implicit
/// (downgrade resistance during the window).
pub fn pq_mixed_policy(
    local_pq: bool,
    offer: Option<PqOfferCheck>,
) -> Result<PqMode, &'static str> {
    let Some(o) = offer else {
        return Ok(PqMode::Classical);
    };
    if !local_pq {
        // Classical-only node: PQ fields are additive JSON, ignored, never an error.
        return Ok(PqMode::Classical);
    }
    if !o.wellformed {
        return Err("pq fields malformed");
    }
    if !o.suite_ok {
        return Err("unsupported pq suite/version");
    }
    if !o.tag_ok {
        return Err("pq transcript auth failed");
    }
    Ok(PqMode::Pq)
}

// PQ FALCON TAG (default-ON since PQ 9.1 — same `pq_handshake_active` gate
// as the KEM path; explicit `STELL_INF_PQ_HANDSHAKE=0` opts out pre-H only).
// Additive only: nothing above is modified; opted-out (or PQ-identity
// absent) leaves the handshake byte-identical to the ML-KEM-hybrid/classical
// paths.
//
// Backend: `falcon-rust 0.3.1` (already vendored in `Cargo.toml` — no new
// crypto lineage). What the tag is: Falcon-512 over the FINALIZED transcript
// digest by the LONG-TERM PQ key (`keyring::PqKeys`), verified against the
// peer's pinned `pq_pub` BEFORE any session key is derived (fail closed,
// same ordering discipline as the classical sig-before-session gate).
//
// Blocker resolutions (see task report):
// (a) fixed vectors: Falcon signing is randomized (fresh 40-byte nonce per
//     signature), so byte pins are IMPOSSIBLE by construction. Tests pin
//     verification BEHAVIOR instead (real `falcon512::sign`: verify-passes,
//     tampered-digest-fails, cross-key-fails, truncated/malformed-fails).
//     Wycheproof-style byte pins stay where the primitive is deterministic
//     (KEM parts, transcript digest — see existing KATs, untouched).
// (b) framing: NEITHER vendored crate emits the chain-canonical 0x29/666
//     layout (`stellereum/src/post_quantum.rs:2260-2308` — verified
//     empirically: `falcon-rust` emits header 0x59, `pqcrypto-falcon`
//     padded emits 0x39; cross-crate verification FAILS both directions).
//     So both ends use `falcon-rust` verify (self-consistent, fail-closed),
//     and chain interop stays an OPEN follow-up (framing adapter, a
//     coordinated-change item per the chain comment — never a silent
//     verifier relaxation here). The public-key encoding IS shared (897
//     bytes, header 0x09, accepted by both crates), so pins and `pq_id`
//     derivation are framing-independent.

/// Wire suite id for the Falcon-512 tag. Equals the reserved production
/// suite (`pq_transport.rs` `PQPLAN_SUITE_FALCON512_RESERVED`); distinct from
/// the ML-KEM-hybrid suite (`0x4D`) and the test-only suite (`0xFF`).
pub const PQ_SUITE_FALCON512: u8 = 0xF1;
/// Falcon-512 raw public-key length (shared encoding, header 0x09).
pub const PQ_FALCON_PK_LEN: usize = 897;
/// Falcon-512 secret-key encoding length (`falcon-rust`).
pub const PQ_FALCON_SK_LEN: usize = 1281;
/// Falcon-512 signature length (`falcon-rust` fixed framing).
pub const PQ_FALCON_SIG_LEN: usize = 666;
/// Domain for the PQ long-term id (binding helper only — NOT `NodeId`).
pub const PQ_ID_DOMAIN: &[u8] = b"infnode-pqid-v1";

/// PQ binding id: `blake3("infnode-pqid-v1" || falcon_pk)[..20]`, announced
/// alongside the classical id with first-PQ-wins stickiness
/// (`node::PqIdentityRegistry`). Display/binding helper ONLY — promoting it
/// to canonical `NodeId` is a flag-day follow-up (would fork
/// DHT/pins/TLS/federation); see `keyring::NodeKeys::id`.
pub fn pq_id_from_pub(pk: &[u8]) -> [u8; NODEID_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(PQ_ID_DOMAIN);
    h.update(pk);
    let out = h.finalize();
    let mut id = [0u8; NODEID_LEN];
    id.copy_from_slice(&out.as_bytes()[..NODEID_LEN]);
    id
}

/// Finalized transcript digest bytes the Falcon tag covers (same canonical
/// `PqTranscript` encoding, Falcon suite id — so the suite byte is covered
/// and KEM-suite digests never validate as Falcon tags).
pub fn pq_falcon_digest(t: &PqTranscript) -> [u8; 32] {
    t.digest(PQ_TRANSCRIPT_VERSION, PQ_SUITE_FALCON512)
}

/// Falcon-512 tag over `digest` with a raw 1281-byte secret encoding.
/// Malformed secret = hard error (fail closed, never an empty tag).
pub fn pq_falcon_sign(sk_bytes: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>> {
    use falcon_rust::falcon512;
    let sk =
        falcon512::SecretKey::from_bytes(sk_bytes).map_err(|_| anyhow!("pq sk malformed"))?;
    Ok(falcon512::sign(digest, &sk).to_bytes())
}

/// Fail-closed Falcon-512 verification: any malformed key/signature
/// (length, parse, variant) returns false — never an error, never a panic.
pub fn pq_falcon_verify(pk_bytes: &[u8], digest: &[u8; 32], sig_bytes: &[u8]) -> bool {
    use falcon_rust::falcon512;
    let (Ok(pk), Ok(sig)) = (
        falcon512::PublicKey::from_bytes(pk_bytes),
        falcon512::Signature::from_bytes(sig_bytes),
    ) else {
        return false;
    };
    falcon512::verify(digest, &sig, &pk)
}

/// Falcon-tag window policy, mirroring `pq_mixed_policy` (plan §5):
/// identity-absent peers are classical-EXPLICIT (`Ok(Classical)` — the
/// `PeerConfig.pq_pub = None` case); a classical-only local node ignores
/// offered PQ identity (never an error); explicitly offered PQ identity that
/// is malformed or mistagged is REFUSED with a clear error (no silent
/// downgrade, same fail-closed arm as the KEM path).
pub fn pq_falcon_policy(
    local_has_pq: bool,
    peer_pq: Option<&[u8]>,
    digest: &[u8; 32],
    sig: Option<&[u8]>,
) -> Result<PqMode, &'static str> {
    let Some(pk) = peer_pq else {
        return Ok(PqMode::Classical);
    };
    if !local_has_pq {
        return Ok(PqMode::Classical);
    }
    if pk.len() != PQ_FALCON_PK_LEN {
        return Err("pq identity malformed");
    }
    let Some(s) = sig else {
        return Err("pq falcon tag failed");
    };
    if s.len() != PQ_FALCON_SIG_LEN {
        return Err("pq falcon tag failed");
    }
    if !pq_falcon_verify(pk, digest, s) {
        return Err("pq falcon tag failed");
    }
    Ok(PqMode::Pq)
}

/// Height-gated KEM policy (PQ 9.1): pre-H delegates to [`pq_mixed_policy`]
/// unchanged (window tolerance, classical-explicit); at/after
/// [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused fail-closed —
/// even peer-absent (`None`) and even for a classical-only local node. Only
/// a fully verified PQ offer negotiates `Pq` at/after H.
pub fn pq_mixed_policy_at(
    height: u64,
    local_pq: bool,
    offer: Option<PqOfferCheck>,
) -> Result<PqMode, &'static str> {
    if !pq_classical_refused_at(height) {
        return pq_mixed_policy(local_pq, offer);
    }
    let Some(o) = offer else {
        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
    };
    if !local_pq {
        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
    }
    if !o.wellformed {
        return Err("pq fields malformed");
    }
    if !o.suite_ok {
        return Err("unsupported pq suite/version");
    }
    if !o.tag_ok {
        return Err("pq transcript auth failed");
    }
    Ok(PqMode::Pq)
}

/// Height-gated Falcon-tag policy (PQ 9.1): pre-H delegates to
/// [`pq_falcon_policy`] unchanged (absent identity = classical-explicit);
/// at/after [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused
/// fail-closed — absent identity, classical-only local, malformed key, and
/// mistag ALL refuse. Only offered + verified PQ negotiates `Pq`.
pub fn pq_falcon_policy_at(
    height: u64,
    local_has_pq: bool,
    peer_pq: Option<&[u8]>,
    digest: &[u8; 32],
    sig: Option<&[u8]>,
) -> Result<PqMode, &'static str> {
    if !pq_classical_refused_at(height) {
        return pq_falcon_policy(local_has_pq, peer_pq, digest, sig);
    }
    let Some(pk) = peer_pq else {
        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
    };
    if !local_has_pq {
        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
    }
    if pk.len() != PQ_FALCON_PK_LEN {
        return Err("pq identity malformed");
    }
    let Some(s) = sig else {
        return Err("pq falcon tag failed");
    };
    if s.len() != PQ_FALCON_SIG_LEN {
        return Err("pq falcon tag failed");
    }
    if !pq_falcon_verify(pk, digest, s) {
        return Err("pq falcon tag failed");
    }
    Ok(PqMode::Pq)
}

// TRANSPORT-KEX FULL: AEAD frame bodies under the established hybrid
// session key when PQ is negotiated. Additive only: no existing function,
// layout, or domain above is modified, so classical sessions stay
// byte-identical (they never call these helpers; the classical wire path is
// `Frame::{encode,decode,verify}` + `session_key`/`e2e_key_from_shared`,
// pinned by existing KATs).
//
// Key: `pq_hybrid_session_key(classical, pq_shared, digest)` — same
// derivation and transcript shapes as the handshake (`PqTranscript::digest`
// with `PQ_SUITE_MLKEM768_HYBRID`). Cipher: XChaCha20-Poly1305, same idiom
// as `mailbox::seal`/`node::e2e_encrypt_det` (no new deps). Classical e2e
// uses empty AAD; PQ frames bind a canonical AAD
// (`KEX_FRAME_DOMAIN || header || session digest`) so a body sealed in one
// session never opens in another (key differs AND aad differs — both layers
// fail closed).
//
// Key rotation / epoch: the session key is fixed for the lifetime of one
// connection (`sessions: stable_id -> [u8;32]` in `node.rs`, read-only here).
// There is no mid-connection re-key in scope; re-key = reconnect (fresh
// ephemeral X25519 + fresh ML-KEM encap => fresh hybrid key). Wiring these
// helpers into `node.rs frame_loop` is the sibling's zone; this module only
// provides the fail-closed seal/open primitives + tests.
//
/// Domain separating PQ frame AAD from classical e2e (which uses empty AAD).
pub const KEX_FRAME_DOMAIN: &[u8] = b"infnode-frame-v1";
/// XChaCha nonce length for frame bodies (same 24 B as `Frame.nonce` legit use).
pub const KEX_FRAME_NONCE_LEN: usize = 24;

/// Canonical AAD binding a sealed body to its frame header + PQ session:
/// `KEX_FRAME_DOMAIN || kind u8 || seq le32 || ts le64 || src20 || dst20 ||
/// svc le64 || session_digest32`. Any header or session swap changes the AAD
/// and `kex_frame_open` refuses (no silent cross-frame/cross-session accept).
pub fn kex_frame_aad(
    kind: u8,
    seq: u32,
    ts: i64,
    src: &[u8; NODEID_LEN],
    dst: &[u8; NODEID_LEN],
    svc: u64,
    session_digest: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        KEX_FRAME_DOMAIN.len() + 1 + 4 + 8 + NODEID_LEN + NODEID_LEN + 8 + 32,
    );
    v.extend_from_slice(KEX_FRAME_DOMAIN);
    v.push(kind);
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(src);
    v.extend_from_slice(dst);
    v.extend_from_slice(&svc.to_le_bytes());
    v.extend_from_slice(session_digest);
    v
}

/// Seal a frame body under `session_key` (== `pq_hybrid_session_key(...)`
/// when PQ negotiated) with the given 24-byte nonce and AAD from
/// [`kex_frame_aad`]. Deterministic for fixed inputs (fixtures/KATs); use
/// [`kex_frame_seal_rand`] for live traffic.
pub fn kex_frame_seal(
    session_key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(session_key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload { msg: plaintext, aad },
        )
        .expect("kex frame seal")
}

/// Live-traffic seal: fresh OS-random 24-byte nonce, returns `(ct, nonce)`.
/// Same shape as `node::e2e_encrypt` so the call site swaps one line.
pub fn kex_frame_seal_rand(
    session_key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; KEX_FRAME_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = kex_frame_seal(session_key, &nonce, aad, plaintext);
    (ct, nonce.to_vec())
}

/// Open a PQ frame body: AEAD-verifies the Poly1305 tag over
/// (`aad`, `ct`) and returns the plaintext. Fail-closed: wrong key, tampered
/// body, swapped header/session (AAD mismatch), or bad nonce length all
/// error — never an empty/plaintext fallback.
pub fn kex_frame_open(
    session_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != KEX_FRAME_NONCE_LEN {
        bail!("invalid frame nonce length");
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(session_key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ct, aad },
        )
        .map_err(|_| anyhow!("kex frame open failed (tamper/wrong key/session?)"))
}

/// Decoder fuzz regressions (Agent 1, stellereum): Frame::decode is the
/// network entry point — it must never panic on peer bytes (plen/nlen abuse,
/// truncations, bit flips). Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn frame_adversarial_lengths_never_panic() {
        let f = Frame {
            kind: kind::REQ,
            seq: 1,
            ts: 1,
            src: [1u8; NODEID_LEN],
            dst: [2u8; NODEID_LEN],
            svc: 0,
            payload: b"ping".to_vec(),
            nonce: vec![0u8; 8],
            sig: [0u8; 64],
        };
        let enc = f.encode();
        let mut corpus = vec![vec![], enc.clone()];
        for n in 0..enc.len() {
            corpus.push(enc[..n].to_vec());
        }
        // plen/nlen length-confusion sweeps at the header offsets 62..68.
        for plen in [0u32, 1, u32::MAX, MAX_FRAME as u32 + 1] {
            for nlen in [0u16, 1, u16::MAX] {
                let mut m = enc.clone();
                m[62..64].copy_from_slice(&nlen.to_le_bytes());
                m[64..68].copy_from_slice(&plen.to_le_bytes());
                corpus.push(m);
            }
        }
        for input in &corpus {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = Frame::decode(input);
            }));
            assert!(r.is_ok(), "Frame::decode panicked on len {}", input.len());
        }
    }
}
