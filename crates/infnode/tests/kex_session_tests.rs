//! Transport-KEX full: AEAD frame bodies under the established hybrid
//! session key when PQ is negotiated.
//!
//! Scope: `proto.rs` seal/open primitives only (`kex_frame_*` +
//! `pq_hybrid_session_key` + `PqTranscript` shapes). No `node.rs` wiring is
//! touched here (sibling owns handshake/identity); the session keys below
//! are derived exactly as `node.rs` derives them
//! (`pq_hybrid_session_key(&classical, &shared, &digest)`), so the vectors
//! transfer 1:1 to the wire path.
//!
//! Key rotation / epoch: the session key is fixed per connection
//! (`stable_id -> [u8;32]`); re-key = reconnect (fresh ephemeral + fresh
//! ML-KEM encap). No mid-connection rotation is in scope.

use ed25519_dalek::{Signer, SigningKey};
use infnode::node::{e2e_decrypt, e2e_encrypt};
use infnode::proto::{
    self, Frame, PqTranscript, PQ_SUITE_MLKEM768_HYBRID, PQ_TRANSCRIPT_VERSION, NODEID_LEN,
};

// ---------------------------------------------------------------------------
// Fixed fixtures (deterministic, no RNG on the asserted paths).
// ---------------------------------------------------------------------------

fn transcript_a() -> PqTranscript {
    let f = |b: u8| {
        let mut x = [0u8; 32];
        for (i, v) in x.iter_mut().enumerate() {
            *v = b.wrapping_add(i as u8);
        }
        x
    };
    PqTranscript {
        pq_init: f(0xA0),
        pq_resp: f(0xB0),
        eph_init: f(0xC0),
        eph_resp: f(0xD0),
        chan_bind: f(0xE0),
        nonce_init: f(0x01),
        nonce_resp: f(0x21),
    }
}

fn transcript_b() -> PqTranscript {
    // Same shape, different session: two bindings flipped => new digest.
    let mut t = transcript_a();
    t.pq_resp[31] ^= 0x80;
    t.nonce_resp[0] ^= 0x01;
    t
}

const CLASSICAL: [u8; 32] = [0xCCu8; 32];
const SHARED_A: [u8; 32] = [0xDDu8; 32];
const SHARED_B: [u8; 32] = [0xEEu8; 32];

fn session_a() -> ([u8; 32], [u8; 32]) {
    let digest = transcript_a().digest(PQ_TRANSCRIPT_VERSION, PQ_SUITE_MLKEM768_HYBRID);
    let key = proto::pq_hybrid_session_key(&CLASSICAL, &SHARED_A, &digest);
    (key, digest)
}

fn session_b() -> ([u8; 32], [u8; 32]) {
    let digest = transcript_b().digest(PQ_TRANSCRIPT_VERSION, PQ_SUITE_MLKEM768_HYBRID);
    let key = proto::pq_hybrid_session_key(&CLASSICAL, &SHARED_B, &digest);
    (key, digest)
}

const KIND: u8 = proto::kind::REQ;
const SEQ: u32 = 7;
const TS: i64 = 1_700_000_000_000;
const SVC: u64 = 42;
const NONCE24: [u8; 24] = [0x24u8; 24];
const PLAIN: &[u8] = b"pq-secret-body";

fn src_dst() -> ([u8; NODEID_LEN], [u8; NODEID_LEN]) {
    ([1u8; NODEID_LEN], [2u8; NODEID_LEN])
}

// ---------------------------------------------------------------------------
// 1. PQ-session bodies decrypt+verify (AEAD open + ed25519 Frame verify +
//    codec round-trip).
// ---------------------------------------------------------------------------

#[test]
fn pq_session_bodies_decrypt_verify() {
    let (key, digest) = session_a();
    let (src, dst) = src_dst();
    let aad = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    let ct = proto::kex_frame_seal(&key, &NONCE24, &aad, PLAIN);
    assert_ne!(ct, PLAIN, "sealed body must differ from plaintext");
    // Tag appended: ct is plaintext + 16-byte Poly1305 tag.
    assert_eq!(ct.len(), PLAIN.len() + 16);

    // Full frame: sealed body rides as payload, signed like every frame.
    let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
    let vk = sk.verifying_key();
    let mut f = Frame {
        kind: KIND,
        seq: SEQ,
        ts: TS,
        src,
        dst,
        svc: SVC,
        payload: ct.clone(),
        nonce: NONCE24.to_vec(),
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    assert!(f.verify(&vk), "sealed frame must verify");

    // Wire round-trip preserves the sealed body.
    let enc = f.encode();
    let dec = Frame::decode(&enc).expect("decode sealed frame");
    assert!(dec.verify(&vk), "decoded sealed frame must verify");
    assert_eq!(dec.payload, ct);
    assert_eq!(dec.nonce, NONCE24.to_vec());

    // AEAD open recovers the body under the same session.
    let aad2 = proto::kex_frame_aad(dec.kind, dec.seq, dec.ts, &dec.src, &dec.dst, dec.svc, &digest);
    assert_eq!(aad2, aad, "AAD must rebuild byte-identical from the frame");
    let back = proto::kex_frame_open(&key, &dec.nonce, &aad2, &dec.payload).expect("open");
    assert_eq!(back, PLAIN);

    // Live-traffic (random-nonce) path round-trips too.
    let (ct2, n2) = proto::kex_frame_seal_rand(&key, &aad, PLAIN);
    let back2 = proto::kex_frame_open(&key, &n2, &aad, &ct2).expect("rand open");
    assert_eq!(back2, PLAIN);
}

// ---------------------------------------------------------------------------
// 2. Tampered body refused (AEAD tag + AAD + Frame sig layers).
// ---------------------------------------------------------------------------

#[test]
fn pq_tampered_body_refused() {
    let (key, digest) = session_a();
    let (src, dst) = src_dst();
    let aad = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    let ct = proto::kex_frame_seal(&key, &NONCE24, &aad, PLAIN);

    // Flip each of first/middle/last ct bytes: Poly1305 tag must refuse.
    for at in [0usize, ct.len() / 2, ct.len() - 1] {
        let mut bad = ct.clone();
        bad[at] ^= 0x01;
        assert!(
            proto::kex_frame_open(&key, &NONCE24, &aad, &bad).is_err(),
            "tampered ct at {at} must fail"
        );
    }
    // Truncated / extended ct refuses (never a panic, never plaintext).
    assert!(proto::kex_frame_open(&key, &NONCE24, &aad, &[]).is_err());
    assert!(proto::kex_frame_open(&key, &NONCE24, &aad, &ct[..ct.len() - 1]).is_err());
    let mut long = ct.clone();
    long.push(0x00);
    assert!(proto::kex_frame_open(&key, &NONCE24, &aad, &long).is_err());

    // AAD binding: header or session swap refuses even with the right key+ct.
    let mut bad_aad = aad.clone();
    let last = bad_aad.len() - 1;
    bad_aad[last] ^= 0x01;
    assert!(proto::kex_frame_open(&key, &NONCE24, &bad_aad, &ct).is_err());
    let other_aad = proto::kex_frame_aad(KIND, SEQ + 1, TS, &src, &dst, SVC, &digest);
    assert!(proto::kex_frame_open(&key, &NONCE24, &other_aad, &ct).is_err());

    // Nonce swap / bad length refuses.
    let mut bad_nonce = NONCE24.to_vec();
    bad_nonce[0] ^= 0x01;
    assert!(proto::kex_frame_open(&key, &bad_nonce, &aad, &ct).is_err());
    assert!(proto::kex_frame_open(&key, &[0u8; 8], &aad, &ct).is_err());

    // Frame-sig layer: retagging the sealed payload breaks ed25519 verify.
    let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
    let vk = sk.verifying_key();
    let mut f = Frame {
        kind: KIND,
        seq: SEQ,
        ts: TS,
        src,
        dst,
        svc: SVC,
        payload: ct.clone(),
        nonce: NONCE24.to_vec(),
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    assert!(f.verify(&vk));
    let mut tampered = f.clone();
    tampered.payload[0] ^= 0x01;
    assert!(!tampered.verify(&vk), "retagged body must break the frame sig");
}

// ---------------------------------------------------------------------------
// 3. Classical session unchanged: differential pre/post on fixed fixtures.
//    New helpers are additive — these pins break if the classical path moves.
// ---------------------------------------------------------------------------

#[test]
fn classical_session_unchanged() {
    // Pinned KDF vectors (same inputs as `pq_handshake_tests` classical pins).
    let e2e = proto::e2e_key_from_shared(&[0x11u8; 32], &[1u8; 20], &[2u8; 20]);
    assert_eq!(
        hex::encode(e2e),
        "223572ada7ec7d5a660706223197bf472d691c5b848e5df0187e01b98751baeb"
    );
    let sess = proto::session_key(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
        &[1u8; 20],
        &[2u8; 20],
    );
    assert_eq!(
        hex::encode(sess),
        "4e6ad0085408c0a66a43ad427f6865d0ea4efc462fbf9707c1af9597627cee5a"
    );
    // Pinned classical wire bytes: kind=REQ seq=7 ts=1700000000000
    // src=01*20 dst=02*20 svc=0 payload="ping" nonce=8x00 sig=64x00.
    let f = Frame {
        kind: proto::kind::REQ,
        seq: 7,
        ts: 1_700_000_000_000,
        src: [1u8; NODEID_LEN],
        dst: [2u8; NODEID_LEN],
        svc: 0,
        payload: b"ping".to_vec(),
        nonce: vec![0u8; 8],
        sig: [0u8; 64],
    };
    assert_eq!(
        hex::encode(f.encode()),
        "0104070000000068e5cf8b01000001010101010101010101010101010101010101010202020202020202020202020202020202020202000000000000000008000400000070696e67000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    // Codec round-trip still exact (length formula + decode invert encode).
    assert_eq!(f.encoded_len(), 68 + 4 + 8 + 64);
    let back = Frame::decode(&f.encode()).expect("decode");
    assert_eq!(back.payload, b"ping");
    assert_eq!(back.nonce, vec![0u8; 8]);
    // AAD shape pin: domain-prefixed, fixed length, distinct from empty
    // classical e2e AAD (domain separation is structural, not wire churn).
    let (src, dst) = src_dst();
    let digest = [0xEEu8; 32];
    let aad = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    assert!(aad.starts_with(proto::KEX_FRAME_DOMAIN));
    assert_eq!(
        aad.len(),
        proto::KEX_FRAME_DOMAIN.len() + 1 + 4 + 8 + NODEID_LEN + NODEID_LEN + 8 + 32
    );
}

// ---------------------------------------------------------------------------
// 4. Wrong key fails.
// ---------------------------------------------------------------------------

#[test]
fn pq_wrong_key_fails() {
    let (key_a, digest) = session_a();
    let (key_b, _) = session_b();
    assert_ne!(key_a, key_b, "fixture sessions must differ");
    let (src, dst) = src_dst();
    let aad = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    let ct = proto::kex_frame_seal(&key_a, &NONCE24, &aad, PLAIN);
    // Cross-key open refuses...
    assert!(proto::kex_frame_open(&key_b, &NONCE24, &aad, &ct).is_err());
    // ...while the right key still opens (control).
    assert_eq!(
        proto::kex_frame_open(&key_a, &NONCE24, &aad, &ct).expect("control"),
        PLAIN
    );
    // One-bit key flip also refuses.
    let mut near = key_a;
    near[0] ^= 0x01;
    assert!(proto::kex_frame_open(&near, &NONCE24, &aad, &ct).is_err());
}

// ---------------------------------------------------------------------------
// 5. Replay across sessions refused (key layer AND AAD layer).
// ---------------------------------------------------------------------------

#[test]
fn pq_replay_across_sessions_refused() {
    let (key_a, digest_a) = session_a();
    let (key_b, digest_b) = session_b();
    assert_ne!(digest_a, digest_b, "fixture digests must differ");
    let (src, dst) = src_dst();
    let aad_a = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest_a);
    let aad_b = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest_b);
    assert_ne!(aad_a, aad_b);
    let ct_a = proto::kex_frame_seal(&key_a, &NONCE24, &aad_a, PLAIN);

    // Full cross-session replay (key B + AAD B) refuses.
    assert!(proto::kex_frame_open(&key_b, &NONCE24, &aad_b, &ct_a).is_err());
    // Key-only swap refuses (attacker reuses the original AAD bytes).
    assert!(proto::kex_frame_open(&key_b, &NONCE24, &aad_a, &ct_a).is_err());
    // AAD-only swap refuses even under the ORIGINAL key (session binding).
    assert!(proto::kex_frame_open(&key_a, &NONCE24, &aad_b, &ct_a).is_err());
    // Control: original session still opens.
    assert_eq!(
        proto::kex_frame_open(&key_a, &NONCE24, &aad_a, &ct_a).expect("control"),
        PLAIN
    );
    // Reverse direction is symmetric.
    let ct_b = proto::kex_frame_seal(&key_b, &NONCE24, &aad_b, PLAIN);
    assert!(proto::kex_frame_open(&key_a, &NONCE24, &aad_a, &ct_b).is_err());
}

// ---------------------------------------------------------------------------
// 6. frame_loop paths: PQ REQ+RESP round-trip through the exact seal/open
//    sequence `handle_stream` runs (seal_rand -> Frame -> sign -> encode ->
//    decode -> verify -> AAD rebuild -> open), both directions.
// ---------------------------------------------------------------------------

#[test]
fn pq_frame_loop_req_resp_round_trip() {
    let (key, digest) = session_a();
    let (src, dst) = src_dst();
    let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
    let vk = sk.verifying_key();

    // REQ direction (dialer seals, frame_loop opens).
    let aad_req = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    let (ct_req, n_req) = proto::kex_frame_seal_rand(&key, &aad_req, PLAIN);
    assert_eq!(n_req.len(), proto::KEX_FRAME_NONCE_LEN);
    assert_eq!(ct_req.len(), PLAIN.len() + 16);
    assert_ne!(ct_req, PLAIN);
    let mut freq = Frame {
        kind: KIND,
        seq: SEQ,
        ts: TS,
        src,
        dst,
        svc: SVC,
        payload: ct_req.clone(),
        nonce: n_req.clone(),
        sig: [0u8; 64],
    };
    freq.sig = sk.sign(blake3::hash(&freq.sign_data()).as_bytes()).to_bytes();
    let wire = freq.encode();
    let got = Frame::decode(&wire).expect("decode req");
    assert!(got.verify(&vk), "sealed REQ must verify");
    let aad_req2 = proto::kex_frame_aad(
        got.kind, got.seq, got.ts, &got.src, &got.dst, got.svc, &digest,
    );
    assert_eq!(aad_req2, aad_req, "REQ AAD must rebuild from the frame");
    assert_eq!(
        proto::kex_frame_open(&key, &got.nonce, &aad_req2, &got.payload).expect("open req"),
        PLAIN
    );

    // RESP direction (frame_loop seals, dialer opens): kind=RESP, echo seq,
    // swapped src/dst, fresh ts — a distinct AAD from the REQ above.
    let ts_resp = TS + 1;
    let aad_resp = proto::kex_frame_aad(
        proto::kind::RESP,
        SEQ,
        ts_resp,
        &dst,
        &src,
        SVC,
        &digest,
    );
    assert_ne!(aad_resp, aad_req, "directions must bind distinct AADs");
    let (ct_resp, n_resp) = proto::kex_frame_seal_rand(&key, &aad_resp, PLAIN);
    let mut fresp = Frame {
        kind: proto::kind::RESP,
        seq: SEQ,
        ts: ts_resp,
        src: dst,
        dst: src,
        svc: SVC,
        payload: ct_resp,
        nonce: n_resp,
        sig: [0u8; 64],
    };
    fresp.sig = sk
        .sign(blake3::hash(&fresp.sign_data()).as_bytes())
        .to_bytes();
    let wire2 = fresp.encode();
    let got2 = Frame::decode(&wire2).expect("decode resp");
    assert!(got2.verify(&vk), "sealed RESP must verify");
    let aad_resp2 = proto::kex_frame_aad(
        got2.kind, got2.seq, got2.ts, &got2.src, &got2.dst, got2.svc, &digest,
    );
    assert_eq!(aad_resp2, aad_resp, "RESP AAD must rebuild from the frame");
    assert_eq!(
        proto::kex_frame_open(&key, &got2.nonce, &aad_resp2, &got2.payload)
            .expect("open resp"),
        PLAIN
    );

    // Cross-direction replay refuses: REQ body never opens as RESP and back.
    assert!(proto::kex_frame_open(&key, &got.nonce, &aad_resp, &got.payload).is_err());
    assert!(proto::kex_frame_open(&key, &got2.nonce, &aad_req, &got2.payload).is_err());
}

// ---------------------------------------------------------------------------
// 7. frame_loop drop path: every tamper shape fails the open (fail-closed,
//    never an empty/plaintext fallback); the control still opens.
// ---------------------------------------------------------------------------

#[test]
fn pq_frame_loop_tampered_dropped_no_fallback() {
    let (key, digest) = session_a();
    let (_, other_digest) = session_b();
    let (src, dst) = src_dst();
    let aad = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest);
    let (ct, nonce) = proto::kex_frame_seal_rand(&key, &aad, PLAIN);

    // Body tamper shapes: flips, truncations, extensions, empty.
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &bad).is_err());
    let mut bad = ct.clone();
    bad[ct.len() / 2] ^= 0x80;
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &bad).is_err());
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &bad).is_err());
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &[]).is_err());
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &ct[..ct.len() - 1]).is_err());
    let mut long = ct.clone();
    long.extend_from_slice(&[0x00, 0x01]);
    assert!(proto::kex_frame_open(&key, &nonce, &aad, &long).is_err());

    // Header-swap shapes: each changes the rebuilt AAD, so open refuses.
    let swap_aads = [
        proto::kex_frame_aad(proto::kind::RESP, SEQ, TS, &src, &dst, SVC, &digest),
        proto::kex_frame_aad(KIND, SEQ + 1, TS, &src, &dst, SVC, &digest),
        proto::kex_frame_aad(KIND, SEQ, TS + 1, &src, &dst, SVC, &digest),
        proto::kex_frame_aad(KIND, SEQ, TS, &dst, &src, SVC, &digest),
        proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC + 1, &digest),
        proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &other_digest),
    ];
    for (i, bad_aad) in swap_aads.iter().enumerate() {
        assert_ne!(*bad_aad, aad, "swap {i} must change the AAD");
        assert!(
            proto::kex_frame_open(&key, &nonce, bad_aad, &ct).is_err(),
            "header/session swap {i} must drop"
        );
    }

    // Nonce shapes: flip, short, empty, long.
    let mut bad_nonce = nonce.clone();
    bad_nonce[0] ^= 0x01;
    assert!(proto::kex_frame_open(&key, &bad_nonce, &aad, &ct).is_err());
    assert!(proto::kex_frame_open(&key, &[0u8; 8], &aad, &ct).is_err());
    assert!(proto::kex_frame_open(&key, &[], &aad, &ct).is_err());
    assert!(proto::kex_frame_open(&key, &[0u8; 25], &aad, &ct).is_err());

    // Wrong key refuses; the error is never a silent plaintext/empty accept.
    let mut near = key;
    near[0] ^= 0x01;
    let err = proto::kex_frame_open(&near, &nonce, &aad, &ct).expect_err("near key");
    assert!(format!("{err}").contains("kex frame open failed"));

    // Control: the untampered frame still opens (drop path is tamper-only).
    assert_eq!(
        proto::kex_frame_open(&key, &nonce, &aad, &ct).expect("control"),
        PLAIN
    );
}

// ---------------------------------------------------------------------------
// 8. Mixed sessions coexist: two PQ sessions interleave without cross-open,
//    and the classical e2e path works alongside them, byte-distinct.
// ---------------------------------------------------------------------------

#[test]
fn pq_mixed_sessions_coexist_and_classical_untouched() {
    let (key_a, digest_a) = session_a();
    let (key_b, digest_b) = session_b();
    assert_ne!(key_a, key_b);
    assert_ne!(digest_a, digest_b);
    let (src, dst) = src_dst();
    let aad_a = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest_a);
    let aad_b = proto::kex_frame_aad(KIND, SEQ, TS, &src, &dst, SVC, &digest_b);

    // Interleaved seal/open in either order (no cross-talk, no ordering need).
    let (ct_a, n_a) = proto::kex_frame_seal_rand(&key_a, &aad_a, PLAIN);
    let (ct_b, n_b) = proto::kex_frame_seal_rand(&key_b, &aad_b, PLAIN);
    assert_eq!(
        proto::kex_frame_open(&key_b, &n_b, &aad_b, &ct_b).expect("open b first"),
        PLAIN
    );
    assert_eq!(
        proto::kex_frame_open(&key_a, &n_a, &aad_a, &ct_a).expect("open a second"),
        PLAIN
    );
    // Cross-opens refuse in every combination.
    assert!(proto::kex_frame_open(&key_b, &n_a, &aad_a, &ct_a).is_err());
    assert!(proto::kex_frame_open(&key_a, &n_b, &aad_b, &ct_b).is_err());
    assert!(proto::kex_frame_open(&key_a, &n_a, &aad_b, &ct_a).is_err());
    assert!(proto::kex_frame_open(&key_b, &n_b, &aad_a, &ct_b).is_err());

    // Classical e2e path alongside: same plaintext, distinct ciphertext shape,
    // legacy open recovers it (proves the untouched classical arm coexists).
    let (ct_c, n_c) = e2e_encrypt(&CLASSICAL, PLAIN);
    assert_eq!(n_c.len(), 24);
    assert_eq!(ct_c.len(), PLAIN.len() + 16);
    assert_ne!(ct_c, ct_a, "classical and PQ arms must differ on the wire");
    assert_ne!(ct_c, ct_b, "classical and PQ arms must differ on the wire");
    assert_eq!(e2e_decrypt(&CLASSICAL, &n_c, &ct_c).expect("classical open"), PLAIN);
    // Classical ct never opens under a PQ session (and back): no silent cross.
    assert!(proto::kex_frame_open(&key_a, &n_c, &aad_a, &ct_c).is_err());
    assert!(e2e_decrypt(&CLASSICAL, &n_a, &ct_a).is_err());
}
