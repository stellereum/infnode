use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;
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
    if nonce.len() < 8 || nonce.len() > 128 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
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

/// O(1)-amortized handshake nonce replay window backed by a paired
/// `HashMap` + `VecDeque` expiry queue.
#[derive(Default)]
pub struct NonceWindow {
    seen: HashMap<String, i64>,
    order: VecDeque<(i64, String)>,
}

impl NonceWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim(&mut self, nonce: &str, now: i64) -> bool {
        if nonce.len() < 8 || nonce.len() > 128 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let cutoff = now.saturating_sub(TS_WINDOW_MS);
        while let Some((ts, _)) = self.order.front() {
            if *ts > cutoff {
                break;
            }
            if let Some((ts, old)) = self.order.pop_front() {
                if self.seen.get(&old).copied() == Some(ts) {
                    self.seen.remove(&old);
                }
            }
        }
        if self.seen.contains_key(nonce) {
            return false;
        }
        if self.seen.len() >= MAX_SEEN_IDS {
            // Fallback exact prune if non-monotonic timestamps kept older entries behind a newer head.
            self.seen.retain(|_, ts| *ts > cutoff);
            if self.seen.len() >= MAX_SEEN_IDS {
                return false;
            }
        }
        let key = nonce.to_string();
        self.seen.insert(key.clone(), now);
        self.order.push_back((now, key));
        true
    }
}

pub mod kind {
    pub const PING: u8 = 0;
    pub const PONG: u8 = 1;
    pub const CHALLENGE: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const REQ: u8 = 4;
    pub const RESP: u8 = 5;
    /// Post-handshake protocol-negotiation control frame.
    ///
    /// This is a CONTROL kind, not a new frame header: the v2 frame layout
    /// (version byte, header offsets, signature trailer) is byte-identical for
    /// every pre-existing kind, and peers that never send/receive `HELLO`
    /// keep the exact v2 wire behaviour. Frames are length-delimited by their
    /// own header, so a receiver that does not know `HELLO` simply ignores it
    /// (the `Node::handle` default arm) and the next frame parses normally.
    pub const HELLO: u8 = 6;
}

/// True for the control kinds this build understands. An UNKNOWN kind is
/// deliberately NOT an error (forward compatibility): `Node::handle` ignores
/// it and the stream stays usable.
pub const fn is_control_kind(k: u8) -> bool {
    k == kind::HELLO
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
    static NAMES: OnceLock<HashMap<u64, &'static str>> = OnceLock::new();
    NAMES
        .get_or_init(|| {
            crate::services::SERVICE_NAMES
                .iter()
                .map(|&n| (svc_id(n), n))
                .collect()
        })
        .get(&id)
        .copied()
}

/// KEM-only session key: `blake3(PQ_SESSION_DOMAIN || pq_shared || digest)`.
///
/// FULL-PQ: the classical X3DH leg is cut — no static/ephemeral ECDH input.
/// Forward secrecy comes from the fresh ephemeral ML-KEM-768 encap per
/// handshake; the transcript `digest` binds the session (KEX ek/ct + frame
/// bindings, including the exchanged eph pubs as freshness). Either input
/// flipping changes the output.
pub fn pq_session_key(pq_shared: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PQ_SESSION_DOMAIN);
    h.update(pq_shared);
    h.update(digest);
    *h.finalize().as_bytes()
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
    /// Falcon-512 tag over `blake3(sign_data)` (FULL-PQ: the Ed25519 trailer
    /// is gone; a 64-byte / empty value never verifies).
    pub sig: Vec<u8>,
}

/// Fixed prefix length through `payload_len` (version..payload_len).
const HDR: usize = 68;
/// Wire version. v1 carried a 64-byte Ed25519 trailer and is REFUSED: there
/// is no classical frame path in FULL-PQ.
pub const FRAME_VERSION: u8 = 2;

/// Frame versions this build can speak, as a closed range. Today the range is
/// exactly `[2, 2]` (FULL-PQ is a flag day), but the negotiation helper below
/// is written against a RANGE so widening it later is a constant change, not a
/// new handshake.
pub const FRAME_VERSION_MIN: u32 = FRAME_VERSION as u32;
/// See [`FRAME_VERSION_MIN`].
pub const FRAME_VERSION_MAX: u32 = FRAME_VERSION as u32;

/// Pure frame-version negotiation: highest version in
/// `[peer_min, peer_max] ∩ [FRAME_VERSION_MIN, FRAME_VERSION_MAX]`, or `None`
/// when the ranges are disjoint (no common version: the peers cannot talk).
///
/// Picking the HIGHEST common version is the conventional rule (newer wins
/// when both sides support it); because this build supports exactly one
/// version today, the result is `Some(2)` iff the peer's range contains 2.
pub fn negotiate_frame_version(peer_min: u32, peer_max: u32) -> Option<u32> {
    if peer_min > peer_max {
        return None;
    }
    let lo = peer_min.max(FRAME_VERSION_MIN);
    let hi = peer_max.min(FRAME_VERSION_MAX);
    (lo <= hi).then_some(hi)
}

// ---------------------------------------------------------------------------
// PROTOCOL VERSION / FORK ID / CAPABILITY NEGOTIATION (control plane).
//
// This block is deliberately transport-generic: `infnode` owns the wire
// mechanics of the control message and the pure negotiation state machine,
// while the CHAIN identity (its `PROTOCOL_VERSION`, `FORK_ID` and advertised
// capability set) is installed by the embedding binary through
// [`install_local_identity`]. `stellereum::protocol` is that installer for the
// chain; a standalone infnode uses [`DEFAULT_IDENTITY`].
//
// The control message is exchanged once per connection AFTER a successful
// PQ+AUTH handshake. It is NOT carried in the frame header, and it never
// changes the v2 frame encoding: a peer that never negotiates sends and
// receives exactly the same bytes as before.
// ---------------------------------------------------------------------------

/// Semver-ish protocol version: 16-bit major + 16-bit minor, packed into the
/// low/high halves of a `u32` so the wire form is one fixed 4-byte field.
///
/// Compatibility rule (see [`negotiate`]): the major must match; a minor
/// difference of one is accepted with the capability INTERSECTION and one
/// advisory log line; a difference of two or more is refused for consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    /// Build from `major.minor`.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self(((major as u32) << 16) | minor as u32)
    }

    pub const fn major(self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub const fn minor(self) -> u16 {
        (self.0 & 0xffff) as u16
    }

    pub const fn to_wire(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub const fn from_wire(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }

    /// Absolute minor distance within the same major (`u16::MAX` when the
    /// majors differ, which every caller treats as incompatible).
    pub const fn minor_distance(self, other: Self) -> u16 {
        if self.major() != other.major() {
            return u16::MAX;
        }
        self.minor().abs_diff(other.minor())
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major(), self.minor())
    }
}

/// Capability bitflags advertised in [`Hello`].
///
/// Unknown bits are preserved on the wire (forward compatibility) but never
/// enter an AGREED set: [`Self::intersection`] only keeps bits both sides
/// understand, so a future capability cannot be silently assumed active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Capabilities(pub u64);

impl Capabilities {
    /// Nothing: the safe value for a peer refused for consensus.
    pub const NONE: Self = Self(0);
    /// Compact proposal gossip (`CompactProposal` / `BodyPull` / `Body`).
    /// A peer that does not advertise this MUST receive the full `Proposal`.
    pub const COMPACT_GOSSIP_BIT: u64 = 1 << 0;
    /// Direct validator mesh delivery (warm links) instead of the overlay
    /// broadcast. Advisory: the overlay fallback always remains.
    pub const MESH_DIRECT_BIT: u64 = 1 << 1;
    pub const COMPACT_GOSSIP: Self = Self(Self::COMPACT_GOSSIP_BIT);
    pub const MESH_DIRECT: Self = Self(Self::MESH_DIRECT_BIT);
    /// Every capability this build implements.
    pub const ALL: Self = Self(Self::COMPACT_GOSSIP_BIT | Self::MESH_DIRECT_BIT);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Stable `FORK_ID` of the standalone infnode overlay, used only until the
/// embedding chain installs its own identity (see [`install_local_identity`]).
///
/// Derived from the transport ruleset constants, never from a binary hash:
/// the frame version, the PQ transcript version/suite and the frame caps.
/// Changing any of them changes this value; a rebuild does not.
pub const INFNODE_FORK_ID: u32 = fork_id_from_parts(&[
    FRAME_VERSION as u32,
    PQ_TRANSCRIPT_VERSION as u32,
    PQ_SUITE_MLKEM768_HYBRID as u32,
    MAX_AUTH_FRAME as u32,
    MAX_FRAME as u32,
]);

/// Standalone default identity (overridden by the chain at startup).
pub const DEFAULT_IDENTITY: ProtocolIdentity = ProtocolIdentity {
    protocol_version: ProtocolVersion::new(1, 0),
    fork_id: INFNODE_FORK_ID,
    capabilities: Capabilities::ALL,
};

/// Domain separation for the constant-only FNV fold used by [`INFNODE_FORK_ID`].
const FORK_ID_DOMAIN: &[u8] = b"infnode-fork-v1";
const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

/// FNV-1a 32 over `bytes`, seeded with `seed`. `const` so the fork id is a
/// compile-time constant derived only from the listed inputs.
pub const fn fnv1a32(seed: u32, bytes: &[u8]) -> u32 {
    let mut h = seed;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u32;
        h = h.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    h
}

/// Deterministic fork-id fold over the domain and a list of ruleset values.
pub const fn fork_id_from_parts(parts: &[u32]) -> u32 {
    let mut h = fnv1a32(FNV_OFFSET, FORK_ID_DOMAIN);
    let mut i = 0;
    while i < parts.len() {
        let b = parts[i].to_le_bytes();
        h = fnv1a32(h, &b);
        i += 1;
    }
    h
}

/// The local protocol identity advertised in [`Hello`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolIdentity {
    pub protocol_version: ProtocolVersion,
    pub fork_id: u32,
    pub capabilities: Capabilities,
}

impl ProtocolIdentity {
    pub const fn hello(self) -> Hello {
        Hello {
            protocol_version: self.protocol_version,
            fork_id: self.fork_id,
            capabilities: self.capabilities,
        }
    }
}

static LOCAL_IDENTITY: std::sync::OnceLock<ProtocolIdentity> = std::sync::OnceLock::new();

/// Install the local identity ONCE per process. Returns an error if a
/// DIFFERENT identity was already installed (the chain must not silently run
/// with a stale fork id); re-installing the exact same identity is a no-op.
pub fn install_local_identity(identity: ProtocolIdentity) -> Result<(), String> {
    match LOCAL_IDENTITY.set(identity) {
        Ok(()) => Ok(()),
        Err(rejected) if rejected == identity => Ok(()),
        Err(rejected) => Err(format!(
            "protocol identity already installed as v{} fork 0x{:08x}; refusing to replace it with v{} fork 0x{:08x}",
            rejected.protocol_version,
            rejected.fork_id,
            identity.protocol_version,
            identity.fork_id,
        )),
    }
}

/// The identity this process advertises (default until the chain installs).
pub fn local_identity() -> ProtocolIdentity {
    *LOCAL_IDENTITY.get_or_init(|| DEFAULT_IDENTITY)
}

/// Fixed magic of a [`Hello`] control payload (`IHL1`).
pub const HELLO_MAGIC: [u8; 4] = *b"IHL1";
/// Fixed prefix length of a Hello payload. Trailing bytes are ignored so a
/// future version can append fields without breaking this decoder.
pub const HELLO_WIRE_LEN: usize = 4 + 4 + 4 + 8;

/// `Hello { protocol_version, fork_id, capabilities }`.
///
/// It travels as the payload of a [`kind::HELLO`] control frame after the
/// PQ+AUTH handshake (so it is signed and identity-bound like every frame).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: ProtocolVersion,
    pub fork_id: u32,
    pub capabilities: Capabilities,
}

impl Hello {
    pub const fn new(
        protocol_version: ProtocolVersion,
        fork_id: u32,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            protocol_version,
            fork_id,
            capabilities,
        }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HELLO_WIRE_LEN);
        out.extend_from_slice(&HELLO_MAGIC);
        out.extend_from_slice(&self.protocol_version.to_wire());
        out.extend_from_slice(&self.fork_id.to_le_bytes());
        out.extend_from_slice(&self.capabilities.bits().to_le_bytes());
        out
    }

    /// Decode a control payload. `None` for a bad magic or a short payload;
    /// trailing bytes are ignored (forward-compatible extension space).
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < HELLO_WIRE_LEN || b[..4] != HELLO_MAGIC {
            return None;
        }
        let version = ProtocolVersion::from_wire([b[4], b[5], b[6], b[7]]);
        let fork_id = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let caps = u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
        Some(Self {
            protocol_version: version,
            fork_id,
            capabilities: Capabilities::from_bits(caps),
        })
    }
}

/// Why a peer was refused CONSENSUS participation. Every variant is loud and
/// specific; none of them drops the connection (DHT/storage services remain
/// available to a non-consensus peer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiationRefusal {
    /// The consensus rulesets differ. This is a hard fork boundary: accepting
    /// the peer would let two incompatible rule sets vote on one chain.
    ForkMismatch { local: u32, peer: u32 },
    /// Incomparable major versions (semver-ish integers).
    MajorMismatch {
        local: ProtocolVersion,
        peer: ProtocolVersion,
    },
    /// Peer is more than one minor version behind.
    VersionTooOld {
        local: ProtocolVersion,
        peer: ProtocolVersion,
    },
    /// Peer is more than one minor version ahead.
    VersionTooNew {
        local: ProtocolVersion,
        peer: ProtocolVersion,
    },
}

impl std::fmt::Display for NegotiationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForkMismatch { local, peer } => write!(
                f,
                "CONSENSUS REFUSED: fork_id mismatch (local 0x{local:08x}, peer 0x{peer:08x}) — \
                 peers with different consensus rules must never vote together; \
                 non-consensus services (DHT/blobs) remain available"
            ),
            Self::MajorMismatch { local, peer } => write!(
                f,
                "CONSENSUS REFUSED: incompatible protocol major (local v{local}, peer v{peer})"
            ),
            Self::VersionTooOld { local, peer } => write!(
                f,
                "CONSENSUS REFUSED: peer protocol v{peer} is more than one minor behind local v{local}"
            ),
            Self::VersionTooNew { local, peer } => write!(
                f,
                "CONSENSUS REFUSED: peer protocol v{peer} is more than one minor ahead of local v{local}"
            ),
        }
    }
}

impl std::error::Error for NegotiationRefusal {}

/// Result of a successful negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agreement {
    /// Version of the agreed common protocol (the lower of the two on N-1).
    pub protocol_version: ProtocolVersion,
    /// Intersection of the advertised capability sets.
    pub capabilities: Capabilities,
    /// True when the peers differ by exactly one minor version (accepted, but
    /// a coarse upgrade is in progress and a full-capability peer would see
    /// the intersection instead).
    pub advisory: bool,
}

/// Pure negotiation state machine (no I/O, no globals): the whole rule set.
///
/// * different `fork_id` -> [`NegotiationRefusal::ForkMismatch`];
/// * same major and same minor -> full intersection, `advisory == false`;
/// * same major, one minor apart -> intersection, `advisory == true`;
/// * same major, two or more minors apart -> `VersionTooOld`/`VersionTooNew`;
/// * different major -> `MajorMismatch`.
pub fn negotiate(local: ProtocolIdentity, peer: Hello) -> Result<Agreement, NegotiationRefusal> {
    if local.fork_id != peer.fork_id {
        return Err(NegotiationRefusal::ForkMismatch {
            local: local.fork_id,
            peer: peer.fork_id,
        });
    }
    let lv = local.protocol_version;
    let pv = peer.protocol_version;
    if lv.major() != pv.major() {
        return Err(NegotiationRefusal::MajorMismatch {
            local: lv,
            peer: pv,
        });
    }
    let distance = lv.minor_distance(pv);
    match distance {
        0 => Ok(Agreement {
            protocol_version: lv,
            capabilities: local.capabilities.intersection(peer.capabilities),
            advisory: false,
        }),
        1 => Ok(Agreement {
            protocol_version: if pv < lv { pv } else { lv },
            capabilities: local.capabilities.intersection(peer.capabilities),
            advisory: true,
        }),
        _ => {
            if pv < lv {
                Err(NegotiationRefusal::VersionTooOld {
                    local: lv,
                    peer: pv,
                })
            } else {
                Err(NegotiationRefusal::VersionTooNew {
                    local: lv,
                    peer: pv,
                })
            }
        }
    }
}

/// Per-peer negotiated state, stored by the transport after a Hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerProtocolState {
    pub hello: Hello,
    pub agreement: Option<Agreement>,
    pub refusal: Option<NegotiationRefusal>,
}

impl PeerProtocolState {
    /// Consensus traffic may be exchanged only with an accepted peer.
    pub const fn consensus_eligible(&self) -> bool {
        self.agreement.is_some()
    }

    /// Agreed capabilities (`NONE` for a refused peer).
    pub const fn capabilities(&self) -> Capabilities {
        match self.agreement {
            Some(a) => a.capabilities,
            None => Capabilities::NONE,
        }
    }

    /// A refused peer may still serve non-consensus services (DHT/blobs).
    pub const fn may_serve_non_consensus(&self) -> bool {
        true
    }
}

/// Classify a peer's Hello against the local identity.
pub fn classify_peer(local: ProtocolIdentity, hello: Hello) -> PeerProtocolState {
    match negotiate(local, hello) {
        Ok(agreement) => PeerProtocolState {
            hello,
            agreement: Some(agreement),
            refusal: None,
        },
        Err(refusal) => PeerProtocolState {
            hello,
            agreement: None,
            refusal: Some(refusal),
        },
    }
}

/// One decoded control-plane message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    Hello(Hello),
}

/// Decode a control frame payload by kind.
///
/// An UNKNOWN kind or an undecodable known payload returns `None`, which every
/// caller MUST treat as "ignore this frame and keep the stream" — never as a
/// protocol error, disconnect or desync. Frames are self-delimiting, so
/// ignoring one cannot shift the next one.
pub fn decode_control(kind: u8, payload: &[u8]) -> Option<ControlMessage> {
    match kind {
        self::kind::HELLO => Hello::decode(payload).map(ControlMessage::Hello),
        _ => None,
    }
}

/// Operator-facing diagnosis for a frame whose version byte is not ours:
/// "peer speaks vX, we speak vY — coordinated upgrade required".
///
/// A mixed-version cluster fails closed FRAME BY FRAME (`Frame::decode`
/// refuses any byte other than [`FRAME_VERSION`]) with no other
/// operator-visible signal, so the decoder emits exactly one of these lines
/// per process (see [`report_frame_version_mismatch`]).
pub fn frame_version_mismatch_line(peer_version: u8) -> String {
    let common = negotiate_frame_version(u32::from(peer_version), u32::from(peer_version))
        .map(|v| format!("v{v}"))
        .unwrap_or_else(|| "none".to_string());
    format!(
        "[infnode] frame version mismatch: peer speaks v{peer_version}, we speak v{FRAME_VERSION} \
         — coordinated upgrade required (supported range v{FRAME_VERSION_MIN}..=v{FRAME_VERSION_MAX}, \
         common version: {common})"
    )
}

/// Print [`frame_version_mismatch_line`] at most ONCE per process and return
/// it. `Frame::decode` calls this from the version-mismatch branch; the
/// `Once` is what keeps a mixed-version peer from flooding the log with one
/// line per rejected frame (a busy node rejects thousands per second).
///
/// Side effect in a decoder is deliberate: the decode error itself carries the
/// stable string callers already match on, and without this line the operator
/// sees only silent fail-closed isolation.
pub fn report_frame_version_mismatch(peer_version: u8) -> String {
    static REPORTED: std::sync::Once = std::sync::Once::new();
    let line = frame_version_mismatch_line(peer_version);
    REPORTED.call_once(|| eprintln!("{line}"));
    line
}

impl Frame {
    /// Exact wire length of `encode()` output: prefix + payload + nonce +
    /// `sig_len` u16 + Falcon tag.
    pub fn encoded_len(&self) -> usize {
        HDR + self.payload.len() + self.nonce.len() + 2 + self.sig.len()
    }

    /// Append the signed prefix (everything except `sig_len || sig`).
    /// Single pass, no return-alloc: `encode`, `encode_into` and `sign_data`
    /// all funnel here so the byte layout has exactly one definition.
    pub fn sign_data_into(&self, v: &mut Vec<u8>) {
        v.push(FRAME_VERSION);
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
    pub fn sign_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&[FRAME_VERSION]);
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

    /// Validate wire length invariants before encoding so oversized payloads
    /// fail cleanly instead of producing un-decodable frames.
    pub fn try_encode_into(&self, b: &mut Vec<u8>) -> Result<()> {
        if self.payload.len() > MAX_FRAME {
            bail!("payload too large");
        }
        if self.nonce.len() > MAX_NONCE_LEN {
            bail!("nonce too large");
        }
        if self.sig.len() > u16::MAX as usize {
            bail!("signature too large");
        }
        self.encode_into(b);
        Ok(())
    }

    /// Checked encode returning an error if lengths exceed frame bounds.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME {
            bail!("payload too large");
        }
        if self.nonce.len() > MAX_NONCE_LEN {
            bail!("nonce too large");
        }
        if self.sig.len() > u16::MAX as usize {
            bail!("signature too large");
        }
        Ok(self.encode())
    }

    /// Append one full frame (prefix + sig_len + sig) with a single reserve.
    pub fn encode_into(&self, b: &mut Vec<u8>) {
        b.reserve(self.encoded_len());
        self.sign_data_into(b);
        b.extend_from_slice(&(self.sig.len() as u16).to_le_bytes());
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
        b.extend_from_slice(&(self.sig.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.sig);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Frame> {
        // HDR + sig_len(2); the Falcon tag itself is variable-length on the
        // wire (a zero-length tag is decodable but never verifies).
        if b.len() < HDR + 2 {
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
        let sig_len_off = HDR
            .checked_add(plen)
            .and_then(|x| x.checked_add(nlen))
            .ok_or_else(|| anyhow!("frame length overflow"))?;
        if sig_len_off + 2 > b.len() {
            bail!("frame too short");
        }
        let sig_len = u16::from_le_bytes([b[sig_len_off], b[sig_len_off + 1]]) as usize;
        let total = sig_len_off
            .checked_add(2)
            .and_then(|x| x.checked_add(sig_len))
            .ok_or_else(|| anyhow!("frame length overflow"))?;
        if total != b.len() {
            bail!("frame length mismatch");
        }
        let sig = b[sig_len_off + 2..].to_vec();
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
            svc: u64::from_le_bytes([b[54], b[55], b[56], b[57], b[58], b[59], b[60], b[61]]),
            payload: b[68..68 + plen].to_vec(),
            nonce: b[68 + plen..68 + plen + nlen].to_vec(),
            sig,
        };
        // version check (v1 = classical Ed25519 trailer: refused, no fallback)
        if b[0] != FRAME_VERSION {
            // ONE operator-visible line per process (never one per frame);
            // the decode error string itself stays exactly what callers
            // already match on.
            report_frame_version_mismatch(b[0]);
            bail!("unsupported version (classical frame refused)");
        }
        // не допускаем переполнения индексов для нечётких пакетов
        if f.nonce.len() != nlen || f.payload.len() != plen {
            bail!("internal mismatch");
        }
        Ok(f)
    }

    /// FULL-PQ frame authentication: Falcon-512 over
    /// `blake3(sign_data)`, verified against the peer's PQ identity.
    /// Malformed keys/tags return false (fail closed, never a classical
    /// Ed25519 fallback).
    pub fn verify(&self, pq_pub: &[u8]) -> bool {
        if self.sig.len() != PQ_FALCON_SIG_LEN {
            return false;
        }
        pq_falcon_verify(pq_pub, &self.sign_digest(), &self.sig)
    }

    /// Fast path using a pre-parsed Falcon-512 public key.
    pub fn verify_parsed(&self, pk: &falcon_rust::falcon512::PublicKey) -> bool {
        if self.sig.len() != PQ_FALCON_SIG_LEN {
            return false;
        }
        pq_falcon_verify_parsed(pk, &self.sign_digest(), &self.sig)
    }
}

// PQ HANDSHAKE (MANDATORY, FULL-PQ wipe).
// KEX ephemeral ML-KEM-768; the transcript is authenticated by the long-term
// Falcon-512 key (see `pq_falcon_*` below) before any session key is derived
// (fail closed). Classical offers, absent PQ identity, malformed PQ and bad
// tags are REFUSED at every height — there is no mixed-mode window and no
// env opt-out.

/// Legacy env name kept for log/CLI text only. It is NOT read: an opt-out
/// would be a classical fallback, which FULL-PQ does not allow.
pub const PQ_HANDSHAKE_ENV: &str = "STELL_INF_PQ_HANDSHAKE";

/// Always true (FULL-PQ). Kept so call sites/tests that ask "is PQ active?"
/// still have a single answer; there is no classical mode.
pub fn pq_handshake_active() -> bool {
    true
}

/// Pure core of [`pq_handshake_active`]: PQ is mandatory regardless of the
/// (ignored) value, including the old `STELL_INF_PQ_HANDSHAKE=0` opt-out.
pub fn pq_handshake_active_for(_value: Option<&str>) -> bool {
    true
}

// CLASSICAL IS REFUSED AT EVERY HEIGHT (FULL-PQ wipe).
//
// The former height-gated mixed window (`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`,
// `pq_classical_refused_at`, fallback counter + WARN) is GONE: there is no
// pre-H tolerance and no counter, because no classical offer is ever
// accepted. `pq_mixed_policy` / `pq_falcon_policy` below refuse an absent or
// classical offer unconditionally.

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
    /// Initiator 32-byte hello freshness nonce (no ECDH; KEM provides FS).
    pub fresh_init: [u8; 32],
    /// Responder 32-byte hello freshness nonce (no ECDH).
    pub fresh_resp: [u8; 32],
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
        Self::push(&mut v, &self.fresh_init);
        Self::push(&mut v, &self.fresh_resp);
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

/// Negotiated handshake mode. FULL-PQ: the only possible outcome is `Pq`;
/// the enum is kept (single variant) so call sites/tests stay type-stable.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PqMode {
    /// PQ handshake (offer verified, KEM-only session key).
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

/// PQ-only KEM policy (FULL-PQ wipe): an absent offer, a local node without
/// a PQ identity, malformed fields, an unknown suite/version or a bad tag are
/// ALL refusals at every height. Nothing falls back to classical.
pub fn pq_mixed_policy(
    local_pq: bool,
    offer: Option<PqOfferCheck>,
) -> Result<PqMode, &'static str> {
    let Some(o) = offer else {
        return Err("pq offer required (classical refused)");
    };
    if !local_pq {
        return Err("pq identity required (classical refused)");
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

// PQ FALCON TAG (MANDATORY — FULL-PQ wipe; there is no opt-out).
// Every CHALLENGE/AUTH frame and the transcript itself are authenticated by
// the long-term Falcon-512 key; an absent PQ identity or a missing/bad tag is
// refused at every height.
//
// Backend: `falcon-rust 0.3.1` (already vendored in `Cargo.toml` — no new
// crypto lineage). What the tag is: Falcon-512 over the FINALIZED transcript
// digest by the LONG-TERM PQ key (`keyring::PqKeys`), verified against the
// peer's pinned `pq_pub` BEFORE any session key is derived (fail closed).
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

/// Canonical PQ `NodeId`: `blake3("infnode-pqid-v1" || falcon_pk)[..20]`.
/// This IS the only node identity (FULL-PQ wipe: no classical id exists);
/// DHT ids, TLS pins and federation records all bind to it.
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
    let sk = falcon512::SecretKey::from_bytes(sk_bytes).map_err(|_| anyhow!("pq sk malformed"))?;
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

/// Fail-closed Falcon-512 verification against an already-parsed public key.
pub fn pq_falcon_verify_parsed(
    pk: &falcon_rust::falcon512::PublicKey,
    digest: &[u8; 32],
    sig_bytes: &[u8],
) -> bool {
    use falcon_rust::falcon512;
    let Ok(sig) = falcon512::Signature::from_bytes(sig_bytes) else {
        return false;
    };
    falcon512::verify(digest, &sig, pk)
}

/// PQ-only Falcon-tag policy (FULL-PQ wipe): an absent peer identity, a local
/// node without a PQ identity, a malformed/mistagged Falcon key and a missing
/// tag are ALL refusals at every height.
pub fn pq_falcon_policy(
    local_has_pq: bool,
    peer_pq: Option<&[u8]>,
    digest: &[u8; 32],
    sig: Option<&[u8]>,
) -> Result<PqMode, &'static str> {
    let Some(pk) = peer_pq else {
        return Err("pq identity required (classical refused)");
    };
    if !local_has_pq {
        return Err("pq identity required (classical refused)");
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

// TRANSPORT-KEX FULL: AEAD frame bodies under the established KEM-only
// session key when PQ is negotiated (`pq_session_key(pq_shared, digest)`;
// the classical X3DH leg is cut — no hybrid derivation anymore). No
// existing layout or domain above is modified, so the classical wire path
// (`Frame::{encode,decode,verify}`, pinned by existing KATs) is untouched.
//
// Key: `pq_session_key(pq_shared, digest)` — same transcript shapes as the
// handshake (`PqTranscript::digest` with `PQ_SUITE_MLKEM768_HYBRID`). Cipher:
// XChaCha20-Poly1305, same idiom as `mailbox::seal`/`node::e2e_encrypt_det`
// (no new deps). Classical e2e uses empty AAD; PQ frames bind a canonical
// AAD (`KEX_FRAME_DOMAIN || header || session digest`) so a body sealed in
// one session never opens in another (key differs AND aad differs — both
// layers fail closed).
//
// Key rotation / epoch: the session key is fixed for the lifetime of one
// connection (`sessions: stable_id -> [u8;32]` in `node.rs`, read-only here).
// There is no mid-connection re-key in scope; re-key = reconnect (fresh
// ML-KEM encap => fresh KEM-only key). Wiring these helpers into
// `node.rs frame_loop` is the sibling's zone; this module only provides the
// fail-closed seal/open primitives + tests.
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
    let mut v =
        Vec::with_capacity(KEX_FRAME_DOMAIN.len() + 1 + 4 + 8 + NODEID_LEN + NODEID_LEN + 8 + 32);
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

/// Seal a frame body under `session_key` (== `pq_session_key(...)` when PQ
/// negotiated) with the given 24-byte nonce and AAD from
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
            Payload {
                msg: plaintext,
                aad,
            },
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
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
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
            sig: Vec::new(),
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
