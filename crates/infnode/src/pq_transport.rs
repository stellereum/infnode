//! PQ TRANSPORT MIGRATION — design doc + KAT-level prototype. UNWIRED BY DESIGN.
//!
//! STATUS: UNWIRED. This file is intentionally NOT referenced by `lib.rs`,
//! `node.rs`, or any build target. Proof: `grep -rn "pq_transport\|PqPlan"
//! crates/infnode/src/` returns hits ONLY inside this file (the `PqPlan`
//! prefix is grep-proof: zero hits existed before this file was created).
//! All executable content lives in `#[cfg(test)]` (see `#![cfg(test)]`
//! below), so even a future accidental `mod pq_transport;` compiles to an
//! empty module in production builds. Production behavior is byte-identical:
//! no existing file was modified.
//!
//! Signing backend honesty note: no PQ signature crate is vendored
//! (adding one needs lead approval), so the executable KATs use
//! `PqPlanTestOnlyMac` — a SHA-256/HMAC structural stand-in that models the
//! Falcon-512 call shape (sign/verify over a bound transcript) with ZERO PQ
//! security claims. It exists so transcript-binding logic executes TODAY.
//! Production backend: Falcon-512 (vendored crate, TBD by lead) implementing
//! the same `PqPlanSigner` interface. KAT vectors below use suite `0xFF`
//! (`PQPLAN_SUITE_TESTONLY`), which is asserted distinct from the reserved
//! production suite `0xF1`, so KAT vectors can never validate as production
//! signatures.
//!
//! =========================================================================
//! AUDIT — classical auth / KEX / identity / TLS primitives AS THEY WERE
//! pre-PQ (read-only; paths relative to infnode/, crate `infnode`).
//! HISTORICAL BASELINE: rows below describe the pre-wipe shapes
//! (`node_id`/`x_pub`/`x_bytes`, X3DH KEX, ed-derived NodeId) — all excised
//! by the FULL-PQ wipe (KEM-only sessions, PQ-only NodeId, no static X25519).
//! Live shapes: see `config.rs` (PeerConfig), `keyring.rs` (NodeKeys/PqKeys),
//! `dht.rs` (`node_info_valid`), `node.rs` (`register_dns_candidate`).
//! =========================================================================
//! | # | primitive | location |
//! |---|-----------|----------|
//! | A1 | NodeId = `blake3(ed_pub)[..20]`, `NodeKeys::id()` | crates/infnode/src/keyring.rs:178-183 |
//! | A2 | `NodeKeys::{generate,save,load}` (`identity.key` ed25519 seed, `e2e.key` x25519 seed, 0600/0700 perms) | crates/infnode/src/keyring.rs:163-267 |
//! | A3 | Frame sign-data layout + `Frame::verify` (ed25519 `verify_strict` over `blake3(sign_data)`) | crates/infnode/src/proto.rs:170-184,246-251 |
//! | A4 | `sign_frame` (node signing helper) | crates/infnode/src/node.rs:709-713 |
//! | A5 | Dial-side handshake: fresh ephemeral X25519 per conn, CHALLENGE `{nonce,at,eph,ed,x}` signed | crates/infnode/src/node.rs:1126-1149 |
//! | A6 | Dial-side AUTH check: kind/AUTH + src/pin + `verify` + `ts_ok` + payload `{at,node,eph}` binding | crates/infnode/src/node.rs:1166-1194 |
//! | A7 | Accept-side CHALLENGE gate: rep gate, `challenge_fields` strict parse, ts, peer-pin match, TOFU branch, sig, nonce replay claim | crates/infnode/src/node.rs:6153-6321 |
//! | A8 | `challenge_fields` (nonce hex/at fresh/eph+ed+x 32B) + `hex_fixed_32` | crates/infnode/src/node.rs:6944-6967 |
//! | A9 | TOFU unknown-node accept: `claimed == blake3(ed)[..20]`, MITM key-change refuse, dynamic pinned peer | crates/infnode/src/node.rs:6226-6291 |
//! | A10 | Server AUTH reply `{node,name,at,eph}` signed; session stored per `stable_id` | crates/infnode/src/node.rs:6346-6367 |
//! | K1 | X3DH session KDF `session_key(ss,se,es,ee,lo,hi)` domain `infnode-session-v1` | crates/infnode/src/proto.rs:127-152 |
//! | K2 | E2E key `e2e_key_from_shared` domain `infnode-e2e-v1` (sorted ids) | crates/infnode/src/proto.rs:106-121 |
//! | K3 | Initiator X3DH: S_AxS_B, S_AxE_B, E_AxS_B, E_AxE_B via `diffie_hellman` | crates/infnode/src/node.rs:6986-6994 |
//! | K4 | Responder X3DH: mirrored operand order, same 4 shared values | crates/infnode/src/node.rs:7013-7020 |
//! | K5 | Mailbox `box_key` ECDH + sorted pubs, domain `infmail-cryptobox-v1`; `seal`/`open` (XChaCha20-Poly1305) | crates/infnode/src/mailbox.rs:129-179 |
//! | T1 | `build_tls`: self-signed Ed25519 cert (`rcgen::PKCS_ED25519`), CN `infnode-<ed_hex>`, 10y validity | crates/infnode/src/node.rs:7080-7105 |
//! | T2 | `PinnedVerifier`: SPKI pin == peer ed_pub + CN cross-check + validity window + self-signature check | crates/infnode/src/node.rs:7112-7156 |
//! | T3 | TLS1.2 signatures hard-disabled; protocol = rustls safe defaults on `ring` provider (de-facto TLS1.3 for peer auth) | crates/infnode/src/node.rs:7158-7187 |
//! | T4 | QUIC server cert install + per-peer pinned `ClientConfig` (static peers at startup, TOFU via `add_dynamic_peer`) | crates/infnode/src/node.rs:516-519,531-540,1896-1908 |
//! | I1 | `PeerConfig {name,node_id,ed_pub,x_pub,endpoints,...}` + `node_id_raw`/`ed_bytes`/`x_bytes` | crates/infnode/src/config.rs:25-81 |
//! | I2 | `node_info_valid`: ed derives id via blake3, x optional-32B, dialable endpoints cap | crates/infnode/src/dht.rs:51-80 |
//! | I3 | DHT derived id `blake3(&ed)` (routing-record check) | crates/infnode/src/dht.rs:64-66 |
//! | I4 | Federation TXT `infnode-validator=inf1:{node}:{ed}:{ip}`, `record_self_consistent` (node_id==blake3(ed)) | crates/infnode/src/federation.rs:88-152 |
//! | I5 | `verify_domain_validator` (multi-DoH, skips inconsistent records) | crates/infnode/src/federation.rs:158-173 |
//!
//! Classical holes this plan closes (target): A3/A4/A6/A7 (Ed25519-only peer
//! auth), K1-K5 (X25519-only KEX — Shor-breakable), T1 (Ed25519 TLS certs),
//! A1/I1-I4 (NodeId bound to a classical key).
//!
//! =========================================================================
//! KEX VERDICT (verified 2026-11-02, offline)
//! =========================================================================
//! * `Cargo.lock` (304 crates) contains NO `ml-kem`/`mlkem`/`kyber`/
//!   `dilithium`/`sphincs`/`pqcrypto`/`oqs` package (grep: zero hits).
//! * `cargo metadata --offline` fails (registry unreachable; prior finding
//!   stands: ML-KEM unavailable offline).
//! * `~/.cargo` cache holds only stale `pqcrypto-falcon/internals/traits`
//!   + `falcon-rust/profiler` crates — NOT in the dependency graph, NOT
//!   usable without lead approval.
//! * VERDICT: full-PQ KEX needs ML-KEM vendoring by the lead. Until then the
//!   honest interim is Falcon-authenticated ephemeral X25519 — PQ peer auth
//!   over a still-classical KEX — modelled here as `PqPlanX25519Backend`
//!   with `PQPLAN_CLASSICAL = true`. `PQPLAN_KEX_OPTIONS` + the
//!   `pqplan_kex_verdict_is_honest` test encode this machine-checkably.
//! * REJECTED: hybrid X25519+symmetric-PSK bootstrap — pre-shared-key
//!   distribution across a permissionless overlay has no key-management
//!   story (TOFU peers are strangers); it adds operational fragility for
//!   zero PQ gain on the wire. NOT proposed.
//!
//! =========================================================================
//! DESIGN (what the lead wires later; this file only prototypes the shapes)
//! =========================================================================
//! 1. PQ peer auth: CHALLENGE/AUTH payloads gain `pq_pub` (Falcon-512
//!    long-term key) + `pq_sig` over the SAME `sign_data()` bytes the
//!    Ed25519 signature covers (dual-signature transition), OR — at flag day
//!    — a `PqPlanTranscript` (versioned, domain-separated, length-prefixed)
//!    binding {pq_init, pq_resp, eph_init, eph_resp, channel_binding,
//!    nonce_init, nonce_resp}. The responder MUST verify the Falcon
//!    signature before deriving any session key (fail closed, mirrors
//!    node.rs:6309-6312 ordering: sig BEFORE nonce-claim BEFORE session).
//! 2. Channel binding: 32 bytes from the QUIC/TLS exporter (rustls exporter
//!    output once `PinnedVerifier` is extended; until then the exporter
//!    label MUST be pinned in the transcript domain string). Any byte flip
//!    in the binding invalidates the signature (covered by KAT tamper test).
//! 3. PQ long-term id: `pq_id = SHAKE/BLAKE3(falcon_pub)[..20]`-family —
//!    concrete: `blake3("infnode-pqid-v1" || falcon_pk)[..20]`, rendered
//!    `inf1:`-compatible. Dual-announce window: peers gossip BOTH
//!    (classical_id, pq_id, cross-signature); first-PQ-wins sticky binding;
//!    key-change without rollback re-ceremony => Quarantined (fail closed,
//!    mirrors the classical MITM rule at node.rs:6246-6259).
//! 4. NodeId migration: see `pqplan_resolve` + docs/PQ_TRANSPORT_PLAN.md.
//!    Classical `NodeId=blake3(ed)` stays canonical until flag day; PQ id is
//!    carried alongside, bound, then promoted.
#![cfg(test)]

/// Prototype namespace. Every symbol carries the `PqPlan`/`pqplan_` prefix so
/// unwired-status is provable with one grep (see `pqplan_unwired_proof`).
mod pq_plan_proto {
    // ------------------------------------------------------------------
    // Minimal SHA-256 (public-domain algorithm, std-only) so the KATs run
    // with zero new dependencies. NOT a crypto recommendation: production
    // uses blake3 (already vendored) + Falcon-512 (lead-vendored later).
    // ------------------------------------------------------------------
    const PQPLAN_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    struct PqPlanSha256 {
        h: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        total: u64,
    }

    impl PqPlanSha256 {
        fn pqplan_new() -> Self {
            Self {
                h: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                    0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0u8; 64],
                buf_len: 0,
                total: 0,
            }
        }
        fn pqplan_block(&mut self) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    self.buf[4 * i],
                    self.buf[4 * i + 1],
                    self.buf[4 * i + 2],
                    self.buf[4 * i + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7)
                    ^ w[i - 15].rotate_right(18)
                    ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17)
                    ^ w[i - 2].rotate_right(19)
                    ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(PQPLAN_K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
            self.h[5] = self.h[5].wrapping_add(f);
            self.h[6] = self.h[6].wrapping_add(g);
            self.h[7] = self.h[7].wrapping_add(hh);
        }
        fn pqplan_update(&mut self, mut data: &[u8]) {
            self.total += data.len() as u64;
            while !data.is_empty() {
                let room = 64 - self.buf_len;
                let take = room.min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len == 64 {
                    self.pqplan_block();
                    self.buf_len = 0;
                }
            }
        }
        fn pqplan_final(mut self) -> [u8; 32] {
            let bit_len = self.total.wrapping_mul(8);
            self.pqplan_update(&[0x80]);
            while self.buf_len != 56 {
                if self.buf_len == 64 {
                    self.pqplan_block();
                    self.buf_len = 0;
                }
                // pad with zeros; 56 is reachable within one block here
                // because buf_len < 64 always holds at this point.
                let room = if self.buf_len < 56 { 56 - self.buf_len } else { 64 - self.buf_len + 56 };
                let zeros = [0u8; 64];
                let take = room.min(64 - self.buf_len);
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&zeros[..take]);
                self.buf_len += take;
                if self.buf_len == 64 && room > take {
                    self.pqplan_block();
                    self.buf_len = 0;
                }
                if self.buf_len == 56 {
                    break;
                }
            }
            self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.pqplan_block();
            let mut out = [0u8; 32];
            for (i, v) in self.h.iter().enumerate() {
                out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
            }
            out
        }
    }

    fn pqplan_sha256(data: &[u8]) -> [u8; 32] {
        let mut s = PqPlanSha256::pqplan_new();
        s.pqplan_update(data);
        s.pqplan_final()
    }

    fn pqplan_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..32 {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }
        let mut inner = PqPlanSha256::pqplan_new();
        inner.pqplan_update(&ipad);
        inner.pqplan_update(data);
        let ih = inner.pqplan_final();
        let mut outer = PqPlanSha256::pqplan_new();
        outer.pqplan_update(&opad);
        outer.pqplan_update(&ih);
        outer.pqplan_final()
    }

    /// Constant-time equality (no early exit) for signature comparison.
    fn pqplan_ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut d: u8 = 0;
        for i in 0..a.len() {
            d |= a[i] ^ b[i];
        }
        d == 0
    }

    fn pqplan_hex(b: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(2 * b.len());
        for v in b {
            s.push(H[(v >> 4) as usize] as char);
            s.push(H[(v & 15) as usize] as char);
        }
        s
    }

    // ------------------------------------------------------------------
    // Transcript: versioned, domain-separated, length-prefixed binding of
    // {pq long-term ids, ephemeral KEX pubs, channel binding, nonces}.
    // ------------------------------------------------------------------
    /// Wire version of the PQ handshake transcript.
    pub const PQPLAN_VERSION: u16 = 1;
    /// Reserved production suite id (Falcon-512). NEVER used by KATs.
    pub const PQPLAN_SUITE_FALCON512_RESERVED: u8 = 0xF1;
    /// Test-only suite id used by `PqPlanTestOnlyMac`. MUST stay distinct
    /// from every production suite so KAT vectors cannot validate as real.
    pub const PQPLAN_SUITE_TESTONLY: u8 = 0xFF;
    /// Domain string baked into every transcript digest.
    pub const PQPLAN_DOMAIN: &[u8] = b"infnode-pqhs-v1";

    /// Fixed-shape handshake transcript (all fields 32 bytes).
    pub struct PqPlanTranscript {
        pub version: u16,
        pub suite: u8,
        pub pq_init: [u8; 32],
        pub pq_resp: [u8; 32],
        pub eph_init: [u8; 32],
        pub eph_resp: [u8; 32],
        pub chan_bind: [u8; 32],
        pub nonce_init: [u8; 32],
        pub nonce_resp: [u8; 32],
    }

    impl PqPlanTranscript {
        fn pqplan_push(out: &mut Vec<u8>, f: &[u8; 32]) {
            out.extend_from_slice(&(f.len() as u16).to_le_bytes());
            out.extend_from_slice(f);
        }
        /// Canonical encoding: domain || version || suite || len-prefixed fields.
        pub fn pqplan_encode(&self) -> Vec<u8> {
            let mut v = Vec::with_capacity(16 + 3 + 7 * 34);
            v.extend_from_slice(PQPLAN_DOMAIN);
            v.extend_from_slice(&self.version.to_le_bytes());
            v.push(self.suite);
            Self::pqplan_push(&mut v, &self.pq_init);
            Self::pqplan_push(&mut v, &self.pq_resp);
            Self::pqplan_push(&mut v, &self.eph_init);
            Self::pqplan_push(&mut v, &self.eph_resp);
            Self::pqplan_push(&mut v, &self.chan_bind);
            Self::pqplan_push(&mut v, &self.nonce_init);
            Self::pqplan_push(&mut v, &self.nonce_resp);
            v
        }
        /// Digest that signatures cover (production: blake3; here SHA-256).
        pub fn pqplan_digest(&self) -> [u8; 32] {
            pqplan_sha256(&self.pqplan_encode())
        }
    }

    // ------------------------------------------------------------------
    // Signer interface (production: Falcon-512) + test-only MAC stand-in.
    // ------------------------------------------------------------------
    /// Interface the production Falcon-512 backend will implement.
    pub trait PqPlanSigner {
        fn pqplan_sign(&self, digest: &[u8; 32]) -> [u8; 64];
        fn pqplan_verify(&self, digest: &[u8; 32], sig: &[u8; 64]) -> bool;
    }

    /// TEST-ONLY structural stand-in. Models the sign/verify call shape with
    /// HMAC-SHA-256. ZERO PQ security — never ships, never wires.
    pub struct PqPlanTestOnlyMac {
        pub key: [u8; 32],
    }

    impl PqPlanSigner for PqPlanTestOnlyMac {
        fn pqplan_sign(&self, digest: &[u8; 32]) -> [u8; 64] {
            let mut m1 = Vec::with_capacity(16 + 1 + 32);
            m1.extend_from_slice(b"pqplan-sig-v1");
            m1.push(0x01);
            m1.extend_from_slice(digest);
            let mut m2 = Vec::with_capacity(16 + 1 + 32);
            m2.extend_from_slice(b"pqplan-sig-v1");
            m2.push(0x02);
            m2.extend_from_slice(digest);
            let h1 = pqplan_hmac(&self.key, &m1);
            let h2 = pqplan_hmac(&self.key, &m2);
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&h1);
            s[32..].copy_from_slice(&h2);
            s
        }
        fn pqplan_verify(&self, digest: &[u8; 32], sig: &[u8; 64]) -> bool {
            pqplan_ct_eq(&self.pqplan_sign(digest), sig)
        }
    }

    // ------------------------------------------------------------------
    // KEX ranking (design record, machine-checked by tests below).
    // ------------------------------------------------------------------
    pub struct PqPlanKexOption {
        pub label: &'static str,
        pub classical_only: bool,
        pub available_offline: bool,
        pub rank: u8, // 1 = first choice; u8::MAX = rejected
        pub note: &'static str,
    }

    /// Ranked KEX options. Rank 1 (ML-KEM-768) is UNAVAILABLE offline:
    /// full-PQ KEX needs lead vendoring. Until then only classical KEX
    /// backends exist — encoded honestly, not hidden.
    pub const PQPLAN_KEX_OPTIONS: [PqPlanKexOption; 4] = [
        PqPlanKexOption {
            label: "ml-kem-768 (FIPS 203)",
            classical_only: false,
            available_offline: false,
            rank: 1,
            note: "first choice for full-PQ KEX; NOT vendored — lead must vendor crate",
        },
        PqPlanKexOption {
            label: "falcon-auth + ephemeral-x25519 (signed-ephemeral interim)",
            classical_only: true,
            available_offline: true,
            rank: 2,
            note: "PQ peer auth over classical KEX; honest interim, mirrors node.rs X3DH shape",
        },
        PqPlanKexOption {
            label: "x25519 static+ephemeral X3DH (status quo)",
            classical_only: true,
            available_offline: true,
            rank: 3,
            note: "node.rs:6970-7021 + proto.rs:127-152; Shor-breakable, kept only pre-flag-day",
        },
        PqPlanKexOption {
            label: "x25519 + symmetric-PSK bootstrap",
            classical_only: true,
            available_offline: true,
            rank: u8::MAX,
            note: "REJECTED: no PSK distribution story for TOFU strangers; fragility for zero PQ gain",
        },
    ];

    /// KEX backend interface for the migration. The shipped backend stays
    /// classical until ML-KEM is vendored — the flag says so in the type.
    pub trait PqPlanKexMethod {
        /// True while the backend relies on classical assumptions (X25519).
        const PQPLAN_CLASSICAL: bool;
        fn pqplan_label(&self) -> &'static str;
    }

    /// Interim backend: ephemeral X25519 under Falcon peer auth.
    /// CLASSICAL KEX — the name and flag make that unmissable.
    pub struct PqPlanX25519ClassicalBackend;

    impl PqPlanKexMethod for PqPlanX25519ClassicalBackend {
        const PQPLAN_CLASSICAL: bool = true;
        fn pqplan_label(&self) -> &'static str {
            "falcon-auth + ephemeral-x25519 (CLASSICAL KEX interim)"
        }
    }

    // ------------------------------------------------------------------
    // NodeId migration rule: dual-announce window, first-PQ-wins, rollback.
    // Pure logic — the exact rule the flag-day plan executes.
    // ------------------------------------------------------------------
    /// What a peer presents during migration.
    pub struct PqPlanView {
        pub classical_id: [u8; 20],
        pub claimed_pq: Option<[u8; 32]>,
        pub pq_sig_ok: bool,
        pub in_window: bool,
        pub rollback: bool,
        /// Previously bound PQ id (sticky first-PQ-wins state).
        pub bound_pq: Option<[u8; 32]>,
    }

    /// Effective identity after applying the migration rule.
    #[derive(Debug, PartialEq, Eq)]
    pub enum PqPlanEffective {
        /// Classical `blake3(ed)[..20]` remains canonical.
        Classical,
        /// PQ identity promoted (bound or newly bindable).
        Pq,
        /// Conflicting PQ claim without rollback ceremony: fail closed.
        Quarantined,
    }

    /// Migration rule. Mirrors the classical MITM discipline
    /// (node.rs:6246-6259): a key change outside ceremony never silently wins.
    pub fn pqplan_resolve(v: &PqPlanView) -> PqPlanEffective {
        if v.rollback {
            return PqPlanEffective::Classical;
        }
        match (v.bound_pq, v.claimed_pq) {
            (None, None) => PqPlanEffective::Classical,
            (None, Some(_)) if !v.pq_sig_ok || !v.in_window => PqPlanEffective::Classical,
            (None, Some(_)) => PqPlanEffective::Pq,
            (Some(_), None) => PqPlanEffective::Pq,
            (Some(b), Some(c)) if c == b && v.pq_sig_ok => PqPlanEffective::Pq,
            (Some(_), Some(_)) => PqPlanEffective::Quarantined,
        }
    }

    // ------------------------------------------------------------------
    // KAT fixed vectors (generated by running this file; hardcoded below).
    // ------------------------------------------------------------------
    fn pqplan_kat_transcript() -> PqPlanTranscript {
        let mut pq_init = [0u8; 32];
        let mut pq_resp = [0u8; 32];
        let mut eph_init = [0u8; 32];
        let mut eph_resp = [0u8; 32];
        let mut chan = [0u8; 32];
        let mut n_init = [0u8; 32];
        let mut n_resp = [0u8; 32];
        for i in 0..32 {
            pq_init[i] = 0xA0u8.wrapping_add(i as u8);
            pq_resp[i] = 0xB0u8.wrapping_add(i as u8);
            eph_init[i] = 0xC0u8.wrapping_add(i as u8);
            eph_resp[i] = 0xD0u8.wrapping_add(i as u8);
            chan[i] = 0xE0u8.wrapping_add(i as u8);
            n_init[i] = 0x01u8.wrapping_add(i as u8);
            n_resp[i] = 0x21u8.wrapping_add(i as u8);
        }
        PqPlanTranscript {
            version: PQPLAN_VERSION,
            suite: PQPLAN_SUITE_TESTONLY,
            pq_init,
            pq_resp,
            eph_init,
            eph_resp,
            chan_bind: chan,
            nonce_init: n_init,
            nonce_resp: n_resp,
        }
    }

    fn pqplan_kat_key() -> [u8; 32] {
        [0x5Au8; 32]
    }

    #[cfg(test)]
    mod pq_plan_kats {
        use super::*;

        /// Fixed transcript digest vector (suite 0xFF, version 1).
        const EXPECTED_DIGEST: &str =
            "5450080b401cd23fd4438c7d03df4a8b9afe0071dd77fc122bce65073738f26a";
        /// Fixed signature vector for the test-only MAC key over that digest.
        const EXPECTED_SIG: &str = "983d0312a2587bd05d67bca62e07e70041b75522f544938847736df8bfac06e15b1deb1797835d7d2eab61a851e343ae02ede6332b19b042396520b52a76951e";

        #[test]
        fn pqplan_sha256_selftest() {
            // NIST-style sanity: SHA-256("abc") is a universal constant.
            assert_eq!(
                pqplan_hex(&pqplan_sha256(b"abc")),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert_eq!(
                pqplan_hex(&pqplan_sha256(b"")),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn pqplan_test_suite_is_not_production() {
            assert_ne!(
                PQPLAN_SUITE_TESTONLY, PQPLAN_SUITE_FALCON512_RESERVED,
                "KAT suite must never collide with the production Falcon suite"
            );
        }

        #[test]
        fn kat_transcript_vector() {
            let t = pqplan_kat_transcript();
            let enc = t.pqplan_encode();
            // domain || u16 version || u8 suite || 7 x (u16 len || 32B field)
            assert_eq!(enc.len(), PQPLAN_DOMAIN.len() + 2 + 1 + 7 * 34);
            assert!(enc.starts_with(PQPLAN_DOMAIN));
            assert_eq!(pqplan_hex(&t.pqplan_digest()), EXPECTED_DIGEST);
        }

        #[test]
        fn kat_sign_verify_vector() {
            let t = pqplan_kat_transcript();
            let d = t.pqplan_digest();
            let mac = PqPlanTestOnlyMac { key: pqplan_kat_key() };
            let sig = mac.pqplan_sign(&d);
            assert_eq!(pqplan_hex(&sig), EXPECTED_SIG);
            assert!(mac.pqplan_verify(&d, &sig));
        }

        #[test]
        fn tamper_anywhere_rejected() {
            let base = pqplan_kat_transcript();
            let d0 = base.pqplan_digest();
            let mac = PqPlanTestOnlyMac { key: pqplan_kat_key() };
            let sig0 = mac.pqplan_sign(&d0);
            // Flip one byte in every bound field + version + suite: each must
            // change the digest AND fail verification against the old sig.
            let mut cases: Vec<PqPlanTranscript> = Vec::new();
            let mut v_ver = pqplan_kat_transcript();
            v_ver.version ^= 0x01;
            cases.push(v_ver);
            let mut v_suite = pqplan_kat_transcript();
            v_suite.suite ^= 0x01;
            cases.push(v_suite);
            let mut v_pq = pqplan_kat_transcript();
            v_pq.pq_init[0] ^= 0x01;
            cases.push(v_pq);
            let mut v_pqr = pqplan_kat_transcript();
            v_pqr.pq_resp[31] ^= 0x80;
            cases.push(v_pqr);
            let mut v_ei = pqplan_kat_transcript();
            v_ei.eph_init[7] ^= 0x01;
            cases.push(v_ei);
            let mut v_er = pqplan_kat_transcript();
            v_er.eph_resp[0] ^= 0x01;
            cases.push(v_er);
            let mut v_cb = pqplan_kat_transcript();
            v_cb.chan_bind[15] ^= 0x01;
            cases.push(v_cb);
            let mut v_ni = pqplan_kat_transcript();
            v_ni.nonce_init[0] ^= 0x01;
            cases.push(v_ni);
            let mut v_nr = pqplan_kat_transcript();
            v_nr.nonce_resp[31] ^= 0x01;
            cases.push(v_nr);
            assert_eq!(cases.len(), 9);
            for c in &cases {
                let d = c.pqplan_digest();
                assert_ne!(d, d0, "tampered transcript must change digest");
                assert!(!mac.pqplan_verify(&d, &sig0), "old sig must fail on new digest");
                assert!(!mac.pqplan_verify(&d0, &mac.pqplan_sign(&d)), "cross sig must fail");
            }
        }

        #[test]
        fn wrong_key_and_truncation_rejected() {
            let d = pqplan_kat_transcript().pqplan_digest();
            let mac = PqPlanTestOnlyMac { key: pqplan_kat_key() };
            let sig = mac.pqplan_sign(&d);
            let mut bad_key = pqplan_kat_key();
            bad_key[0] ^= 0x01;
            let bad = PqPlanTestOnlyMac { key: bad_key };
            assert!(!bad.pqplan_verify(&d, &sig));
            let mut trunc = sig;
            trunc[63] ^= 0x01;
            assert!(!mac.pqplan_verify(&d, &trunc));
            assert!(!mac.pqplan_verify(&d, &[0u8; 64]));
        }

        #[test]
        fn kex_verdict_is_honest() {
            // Rank 1 (full-PQ) must be unavailable; every available backend
            // must advertise itself as classical-only.
            let top = PQPLAN_KEX_OPTIONS.iter().find(|o| o.rank == 1).expect("rank 1 exists");
            assert!(top.label.contains("ml-kem"), "rank 1 must be ML-KEM");
            assert!(!top.available_offline, "ML-KEM must be flagged unavailable offline");
            assert!(!top.classical_only, "ML-KEM must be flagged full-PQ");
            for o in PQPLAN_KEX_OPTIONS.iter().filter(|o| o.available_offline) {
                assert!(o.classical_only, "available backend '{}' must admit classical-only", o.label);
            }
            // The interim backend carries the classical flag in its type.
            assert!(PqPlanX25519ClassicalBackend::PQPLAN_CLASSICAL);
            assert!(
                PqPlanX25519ClassicalBackend
                    .pqplan_label()
                    .contains("CLASSICAL")
            );
            // Rejected option stays rejected (rank MAX, never selectable).
            let rej = PQPLAN_KEX_OPTIONS.iter().find(|o| o.rank == u8::MAX).expect("rejected exists");
            assert!(rej.label.contains("PSK"));
            // Every option carries a human-readable rationale (field is live).
            for o in PQPLAN_KEX_OPTIONS.iter() {
                assert!(!o.note.is_empty(), "option '{}' must document its rationale", o.label);
            }
        }

        fn pqplan_view(classical: u8, claimed: Option<u8>, bound: Option<u8>) -> PqPlanView {
            let mut c = [0u8; 20];
            c[0] = classical;
            let mk = |v: u8| {
                let mut k = [0u8; 32];
                k[0] = v;
                k
            };
            PqPlanView {
                classical_id: c,
                claimed_pq: claimed.map(mk),
                pq_sig_ok: true,
                in_window: true,
                rollback: false,
                bound_pq: bound.map(mk),
            }
        }

        #[test]
        fn migration_classical_stable() {
            let v = pqplan_view(1, None, None);
            assert_eq!(v.classical_id[0], 1, "view must carry the classical id through");
            assert_eq!(pqplan_resolve(&v), PqPlanEffective::Classical);
        }

        #[test]
        fn migration_first_pq_wins_in_window() {
            // No prior binding + valid in-window claim => promote.
            assert_eq!(pqplan_resolve(&pqplan_view(1, Some(7), None)), PqPlanEffective::Pq);
        }

        #[test]
        fn migration_invalid_claim_ignored() {
            // Bad signature => stay classical (never promote on garbage).
            let mut v = pqplan_view(1, Some(7), None);
            v.pq_sig_ok = false;
            assert_eq!(pqplan_resolve(&v), PqPlanEffective::Classical);
            // Outside the dual-announce window => stay classical.
            let mut w = pqplan_view(1, Some(7), None);
            w.in_window = false;
            assert_eq!(pqplan_resolve(&w), PqPlanEffective::Classical);
        }

        #[test]
        fn migration_sticky_and_key_change_quarantined() {
            // Known PQ peer, no claim in this message => stays PQ (sticky).
            assert_eq!(pqplan_resolve(&pqplan_view(1, None, Some(7))), PqPlanEffective::Pq);
            // Same key re-announced with valid sig => PQ.
            assert_eq!(pqplan_resolve(&pqplan_view(1, Some(7), Some(7))), PqPlanEffective::Pq);
            // DIFFERENT key without rollback => Quarantined (fail closed).
            assert_eq!(
                pqplan_resolve(&pqplan_view(1, Some(9), Some(7))),
                PqPlanEffective::Quarantined
            );
            // Same-key claim with BAD sig => Quarantined (not silent accept).
            let mut v = pqplan_view(1, Some(7), Some(7));
            v.pq_sig_ok = false;
            assert_eq!(pqplan_resolve(&v), PqPlanEffective::Quarantined);
        }

        #[test]
        fn migration_rollback_returns_classical() {
            // Operator-driven rollback ceremony always lands on classical,
            // even with a bound PQ key and a fresh claim.
            let mut v = pqplan_view(1, Some(7), Some(7));
            v.rollback = true;
            assert_eq!(pqplan_resolve(&v), PqPlanEffective::Classical);
            let mut w = pqplan_view(1, None, Some(7));
            w.rollback = true;
            assert_eq!(pqplan_resolve(&w), PqPlanEffective::Classical);
        }

        #[test]
        fn pqplan_unwired_proof() {
            // This prototype must never be referenced by production code.
            // Resolves lib.rs/node.rs from several candidate roots (standalone
            // rustc run vs future in-crate run) and fails closed if none match.
            let cands: [&str; 4] = [
                "crates/infnode/src/lib.rs",
                "src/lib.rs",
                "/home/imm/stellereum-project/infnode/crates/infnode/src/lib.rs",
                "./lib.rs",
            ];
            let lib = cands
                .iter()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .next()
                .expect("pqplan_unwired_proof: could not locate lib.rs — run from infnode/ workspace root");
            assert!(
                !lib.contains("pq_transport"),
                "production lib.rs must not reference pq_transport (unwired)"
            );
            assert!(
                !lib.contains("PqPlan"),
                "production lib.rs must not reference PqPlan symbols (unwired)"
            );
            let node_cands: [&str; 4] = [
                "crates/infnode/src/node.rs",
                "src/node.rs",
                "/home/imm/stellereum-project/infnode/crates/infnode/src/node.rs",
                "./node.rs",
            ];
            let node = node_cands
                .iter()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .next()
                .expect("pqplan_unwired_proof: could not locate node.rs — run from infnode/ workspace root");
            assert!(
                !node.contains("pq_transport") && !node.contains("PqPlan"),
                "production node.rs must not reference pq_transport/PqPlan (unwired)"
            );
        }
    }
}
