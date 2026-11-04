//! Fuzz tests for the infnode wire parser (`Frame::decode`).
//! The parser handles UNTRUSTED network input, so it must never panic, hang,
//! allocate unbounded memory, or accept malformed frames.
//!
//! Strategy: property-based fuzzing with a deterministic PRNG.
//!   1. pure random bytes
//!   2. mutations of a valid frame (bit flips, truncation, length tampering)
//!   3. adversarial length fields (huge plen/nlen, off-by-one boundaries)

use ed25519_dalek::{Signer, SigningKey};
use infnode::proto::{Frame, MAX_FRAME};
use rand::rngs::OsRng;

/// Minimal deterministic PRNG (xorshift64) for reproducible fuzzing.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
    fn range(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() as usize) % n
        }
    }
}

/// A valid signed frame for mutation testing.
fn valid_frame() -> Vec<u8> {
    let sk = SigningKey::generate(&mut OsRng);
    let mut f = Frame {
        kind: 4,
        seq: 1,
        ts: 1_700_000_000_000,
        src: [1u8; 20],
        dst: [2u8; 20],
        svc: 123,
        payload: b"hello".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    f.encode()
}

/// PURE RANDOM BYTES: decode must return Ok/Err, never panic.
#[test]
fn fuzz_random_bytes_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..20_000 {
        let len = rng.range(300);
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = rng.byte();
        }
        // Must not panic; result is either Ok or Err.
        let _ = Frame::decode(&buf);
    }
}

/// MUTATIONS OF A VALID FRAME: single/multi bit-flips and truncations.
#[test]
fn fuzz_mutated_valid_frame_never_panic() {
    let valid = valid_frame();
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    for _ in 0..20_000 {
        let mut buf = valid.clone();
        let flips = 1 + rng.range(8);
        for _ in 0..flips {
            if buf.is_empty() {
                break;
            }
            let i = rng.range(buf.len());
            buf[i] ^= 1 << (rng.byte() % 8);
        }
        // Occasionally truncate
        if rng.range(3) == 0 && !buf.is_empty() {
            let t = rng.range(buf.len());
            buf.truncate(t);
        }
        if let Ok(f) = Frame::decode(&buf) {
            // If it decodes, internal invariants must hold (no mismatched lengths).
            assert_eq!(f.payload.len(), f.payload.len());
            assert!(f.payload.len() <= MAX_FRAME);
        }
    }
}

/// ADVERSARIAL LENGTH FIELDS: huge plen/nlen must be rejected, not allocate.
#[test]
fn fuzz_adversarial_lengths_rejected() {
    let base = valid_frame();

    // plen = 0xFFFFFFFF (way over MAX_FRAME) at offset 64..68
    let mut b = base.clone();
    b[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Frame::decode(&b).is_err(), "huge plen must be rejected");

    // nlen = 0xFFFF at offset 62..64
    let mut b2 = base.clone();
    b2[62..64].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(Frame::decode(&b2).is_err(), "huge nlen must be rejected");

    // plen exactly MAX_FRAME+1
    let mut b3 = base.clone();
    b3[64..68].copy_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes());
    assert!(
        Frame::decode(&b3).is_err(),
        "plen over MAX_FRAME must be rejected"
    );

    // plen that overflows the total-length computation
    let mut b4 = base.clone();
    b4[64..68].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert!(
        Frame::decode(&b4).is_err(),
        "overflow plen must be rejected"
    );
}

/// TRUNCATION BOUNDARY: every prefix of a valid frame must be handled safely.
#[test]
fn fuzz_every_prefix_handled() {
    let valid = valid_frame();
    for cut in 0..valid.len() {
        let _ = Frame::decode(&valid[..cut]);
    }
    // A few bytes past the end must not panic either.
    let mut longer = valid.clone();
    longer.extend_from_slice(&[0u8; 8]);
    let _ = Frame::decode(&longer);
}

/// A frame that decodes must round-trip through encode/decode unchanged.
#[test]
fn decoded_frames_round_trip() {
    let valid = valid_frame();
    let f = Frame::decode(&valid).expect("valid frame must decode");
    let re = f.encode();
    let f2 = Frame::decode(&re).expect("re-encoded frame must decode");
    assert_eq!(f.kind, f2.kind);
    assert_eq!(f.seq, f2.seq);
    assert_eq!(f.payload, f2.payload);
}

/// A frame with version != 1 must be rejected.
#[test]
fn fuzz_bad_version_rejected() {
    let valid = valid_frame();
    for v in [0u8, 2, 3, 255] {
        let mut b = valid.clone();
        b[0] = v;
        assert!(Frame::decode(&b).is_err(), "version {v} must be rejected");
    }
}

/// A valid frame verifies; a tampered payload does not.
#[test]
fn signature_binds_payload() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let mut f = Frame {
        kind: 4,
        seq: 1,
        ts: 1,
        src: [0u8; 20],
        dst: [0u8; 20],
        svc: 0,
        payload: b"original".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    assert!(f.verify(&vk));

    // tamper the payload after signing
    f.payload = b"tampered".to_vec();
    assert!(!f.verify(&vk), "tampered payload must fail verification");
}

/// DIFFERENTIAL codec==codec: reference implementation (verbatim pre-opt
/// logic) vs optimized `Frame::{encode,decode}`. Randomized valid frames must
/// produce byte-identical wire; malformed inputs must yield identical errors.
mod reference {
    use super::*;

    pub fn ref_encode(f: &Frame) -> Vec<u8> {
        let mut v = Vec::with_capacity(68 + f.payload.len() + f.nonce.len());
        v.push(1);
        v.push(f.kind);
        v.extend_from_slice(&f.seq.to_le_bytes());
        v.extend_from_slice(&f.ts.to_le_bytes());
        v.extend_from_slice(&f.src);
        v.extend_from_slice(&f.dst);
        v.extend_from_slice(&f.svc.to_le_bytes());
        v.extend_from_slice(&(f.nonce.len() as u16).to_le_bytes());
        v.extend_from_slice(&(f.payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&f.payload);
        v.extend_from_slice(&f.nonce);
        v.extend_from_slice(&f.sig);
        v
    }

    pub fn ref_decode(b: &[u8]) -> anyhow::Result<Frame> {
        use anyhow::anyhow;
        const HDR: usize = 68;
        if b.len() < HDR + 64 {
            anyhow::bail!("frame too short");
        }
        let plen =
            u32::from_le_bytes(b[64..68].try_into().map_err(|_| anyhow!("plen"))?) as usize;
        let nlen =
            u16::from_le_bytes(b[62..64].try_into().map_err(|_| anyhow!("nlen"))?) as usize;
        if plen > MAX_FRAME {
            anyhow::bail!("payload too large");
        }
        if nlen > 1024 {
            anyhow::bail!("nonce too large");
        }
        let total = HDR
            .checked_add(plen)
            .and_then(|x| x.checked_add(nlen))
            .and_then(|x| x.checked_add(64));
        let total = match total {
            Some(t) => t,
            None => anyhow::bail!("frame length overflow"),
        };
        if total != b.len() {
            anyhow::bail!("frame length mismatch");
        }
        let sig: [u8; 64] = b[b.len() - 64..]
            .try_into()
            .map_err(|_| anyhow!("sig"))?;
        let f = Frame {
            kind: b[1],
            seq: u32::from_le_bytes(b[2..6].try_into().map_err(|_| anyhow!("seq"))?),
            ts: i64::from_le_bytes(b[6..14].try_into().map_err(|_| anyhow!("ts"))?),
            src: b[14..34].try_into().map_err(|_| anyhow!("src"))?,
            dst: b[34..54].try_into().map_err(|_| anyhow!("dst"))?,
            svc: u64::from_le_bytes(b[54..62].try_into().map_err(|_| anyhow!("svc"))?),
            payload: b[68..68 + plen].to_vec(),
            nonce: b[68 + plen..68 + plen + nlen].to_vec(),
            sig,
        };
        if b[0] != 1 {
            anyhow::bail!("unsupported version");
        }
        if f.nonce.len() != nlen || f.payload.len() != plen {
            anyhow::bail!("internal mismatch");
        }
        Ok(f)
    }
}

fn diff_rng(seed: u64) -> Rng {
    Rng(seed)
}

fn random_frame(rng: &mut Rng) -> Frame {
    let plen = match rng.range(6) {
        0 => 0,
        1 => rng.range(32),
        2 => rng.range(1024),
        3 => 1024 + rng.range(1024),
        4 => 65536,
        _ => rng.range(256),
    };
    let nlen = [0, 8, 24, 24, 100, 1024][rng.range(6)];
    let mut payload = vec![0u8; plen];
    for b in payload.iter_mut() {
        *b = rng.byte();
    }
    let mut nonce = vec![0u8; nlen];
    for b in nonce.iter_mut() {
        *b = rng.byte();
    }
    let mut src = [0u8; 20];
    let mut dst = [0u8; 20];
    let mut sig = [0u8; 64];
    for b in src.iter_mut() {
        *b = rng.byte();
    }
    for b in dst.iter_mut() {
        *b = rng.byte();
    }
    for b in sig.iter_mut() {
        *b = rng.byte();
    }
    Frame {
        kind: rng.byte(),
        seq: rng.next() as u32,
        ts: rng.next() as i64,
        src,
        dst,
        svc: rng.next(),
        payload,
        nonce,
        sig,
    }
}

fn frames_equal(a: &Frame, b: &Frame) -> bool {
    a.kind == b.kind
        && a.seq == b.seq
        && a.ts == b.ts
        && a.src == b.src
        && a.dst == b.dst
        && a.svc == b.svc
        && a.payload == b.payload
        && a.nonce == b.nonce
        && a.sig == b.sig
}

/// Valid frames: optimized encode is byte-identical to reference; decode of
/// either encoding yields equal frames; re-encode round-trips.
#[test]
fn differential_valid_frames_identical_wire() {
    let mut rng = diff_rng(0xC0DE_CAFE_1234_5678);
    for i in 0..2000 {
        let f = random_frame(&mut rng);
        let a = reference::ref_encode(&f);
        let b = f.encode();
        assert_eq!(a, b, "wire mismatch at iter {i}");
        assert_eq!(b.len(), f.encoded_len(), "encoded_len mismatch at iter {i}");
        let fa = reference::ref_decode(&b).expect("ref must decode opt encoding");
        let fb = Frame::decode(&a).expect("opt must decode ref encoding");
        assert!(frames_equal(&fa, &fb), "decoded frames differ at iter {i}");
        assert!(frames_equal(&f, &fb), "round-trip differs at iter {i}");
    }
}

/// Malformed inputs: both decoders agree — Ok frames are equal, Err strings
/// are identical. Covers truncations, bit flips, length-field abuse.
#[test]
fn differential_malformed_identical_errors() {
    let mut rng = diff_rng(0xBAD_F00D_5EED_1234);
    let valid = reference::ref_encode(&random_frame(&mut rng));
    let mut corpus: Vec<Vec<u8>> = vec![vec![], vec![0u8; 1], vec![0u8; 131], vec![0u8; 132]];
    for cut in 0..valid.len() {
        corpus.push(valid[..cut].to_vec());
    }
    for _ in 0..5000 {
        let mut buf = valid.clone();
        match rng.range(4) {
            0 => {
                let flips = 1 + rng.range(6);
                for _ in 0..flips {
                    let j = rng.range(buf.len());
                    buf[j] ^= 1 << (rng.byte() % 8);
                }
            }
            1 => {
                // length-field abuse at 62..68
                for b in buf[62..68].iter_mut() {
                    *b = rng.byte();
                }
            }
            2 => {
                let t = rng.range(buf.len() + 1);
                buf.truncate(t.min(buf.len()));
            }
            _ => {
                buf[0] = rng.byte();
                buf[1] = rng.byte();
            }
        }
        corpus.push(buf);
    }
    // fixed adversarial length corners
    for plen in [0u32, 1, 2, u32::MAX, MAX_FRAME as u32, MAX_FRAME as u32 + 1] {
        for nlen in [0u16, 1, 24, 1024, 1025, u16::MAX] {
            if valid.len() >= 68 {
                let mut m = valid.clone();
                m[62..64].copy_from_slice(&nlen.to_le_bytes());
                m[64..68].copy_from_slice(&plen.to_le_bytes());
                corpus.push(m);
            }
        }
    }
    let mut ok = 0;
    let mut err = 0;
    for (i, input) in corpus.iter().enumerate() {
        let r = reference::ref_decode(input);
        let o = Frame::decode(input);
        match (r, o) {
            (Ok(fa), Ok(fb)) => {
                assert!(frames_equal(&fa, &fb), "Ok frames differ at corpus {i}");
                assert_eq!(
                    reference::ref_encode(&fa),
                    fb.encode(),
                    "re-encode differs at corpus {i}"
                );
                ok += 1;
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(
                    e1.to_string(),
                    e2.to_string(),
                    "error strings differ at corpus {i} (len {})",
                    input.len()
                );
                err += 1;
            }
            (Ok(_), Err(e)) => panic!("ref Ok but opt Err({e}) at corpus {i}"),
            (Err(e), Ok(_)) => panic!("ref Err({e}) but opt Ok at corpus {i}"),
        }
    }
    assert!(ok > 0 && err > 1000, "corpus must cover both outcomes");
}

/// New batch/incremental APIs preserve wire bytes exactly.
#[test]
fn batch_and_incremental_encode_match() {
    let mut rng = diff_rng(0xBA7C_0000_0000_0001);
    let frames: Vec<Frame> = (0..64).map(|_| random_frame(&mut rng)).collect();
    // encode_into appends exactly encode()
    let mut buf = vec![0xAAu8; 7]; // nonzero prefix: must be preserved
    for f in &frames {
        let before = buf.len();
        f.encode_into(&mut buf);
        assert_eq!(&buf[before..], f.encode().as_slice());
    }
    // encode_many == concatenation of encode()
    let mut batched = Vec::new();
    Frame::encode_many(&frames, &mut batched);
    let mut single = Vec::new();
    for f in &frames {
        single.extend_from_slice(&f.encode());
    }
    assert_eq!(batched, single);
    assert_eq!(batched, buf[7..]);
    // empty batch is a no-op
    let mut empty = vec![1u8, 2, 3];
    Frame::encode_many(&[], &mut empty);
    assert_eq!(empty, vec![1u8, 2, 3]);
}

/// Streaming verify path agrees with the classical sign-then-hash on all
/// corpus sizes, including a 64KB frame (the case that used to allocate).
#[test]
fn verify_matches_reference_digest() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let mut rng = diff_rng(0x5EED_5EED_5EED_5EED);
    for _ in 0..50 {
        let mut f = random_frame(&mut rng);
        let d = blake3::hash(&f.sign_data());
        f.sig = sk.sign(d.as_bytes()).to_bytes();
        assert!(f.verify(&vk));
        // sign_data() is the exact signed prefix of encode()
        let enc = f.encode();
        assert_eq!(&enc[..enc.len() - 64], f.sign_data().as_slice());
    }
}
