//! Codec perf bench (std-only, no new deps): fixed fixtures small/1KB/64KB.
//! Run single-threaded so the counting allocator attributes cleanly:
//!   cargo test -p infnode --bench codec_perf -- --nocapture --test-threads=1
//! Reports ns/op + allocs/op + bytes/op per case.

use infnode::proto::{Frame, NODEID_LEN};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

struct Counting;

static ALLOC_ON: AtomicBool = AtomicBool::new(false);
static ALLOC_N: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ALLOC_ON.load(Ordering::Relaxed) {
            ALLOC_N.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(l.size(), Ordering::Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn fixture(plen: usize, nlen: usize) -> Frame {
    let mut payload = vec![0u8; plen];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i.wrapping_mul(31).wrapping_add(7)) as u8;
    }
    let mut nonce = vec![0u8; nlen];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = (i.wrapping_mul(17).wrapping_add(3)) as u8;
    }
    Frame {
        kind: 4,
        seq: 0x1234_5678,
        ts: 1_700_000_000_000,
        src: [0x11u8; NODEID_LEN],
        dst: [0x22u8; NODEID_LEN],
        svc: 0xDEAD_BEEF_CAFE_0001,
        payload,
        nonce,
        sig: [0x5Au8; 64],
    }
}

fn iters_for(plen: usize) -> usize {
    if plen <= 64 {
        20_000
    } else if plen <= 1024 {
        5_000
    } else {
        500
    }
}

fn bench_case(name: &str, plen: usize, nlen: usize) {
    let f = fixture(plen, nlen);
    let enc = f.encode();
    let n = iters_for(plen);

    // warmup
    for _ in 0..n.min(200) {
        let b = std::hint::black_box(&f).encode();
        std::hint::black_box(b);
    }

    // encode timing
    let t = Instant::now();
    for _ in 0..n {
        let b = std::hint::black_box(&f).encode();
        std::hint::black_box(b);
    }
    let enc_ns = t.elapsed().as_nanos() as f64 / n as f64;

    // decode timing
    let t = Instant::now();
    for _ in 0..n {
        let fr = Frame::decode(std::hint::black_box(&enc)).unwrap();
        std::hint::black_box(fr);
    }
    let dec_ns = t.elapsed().as_nanos() as f64 / n as f64;

    // allocs: encode
    ALLOC_N.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    ALLOC_ON.store(true, Ordering::Relaxed);
    for _ in 0..n {
        let b = std::hint::black_box(&f).encode();
        std::hint::black_box(b);
    }
    ALLOC_ON.store(false, Ordering::Relaxed);
    let enc_allocs = ALLOC_N.load(Ordering::Relaxed) as f64 / n as f64;
    let enc_bytes = ALLOC_BYTES.load(Ordering::Relaxed) as f64 / n as f64;

    // allocs: decode
    ALLOC_N.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    ALLOC_ON.store(true, Ordering::Relaxed);
    for _ in 0..n {
        let fr = Frame::decode(std::hint::black_box(&enc)).unwrap();
        std::hint::black_box(fr);
    }
    ALLOC_ON.store(false, Ordering::Relaxed);
    let dec_allocs = ALLOC_N.load(Ordering::Relaxed) as f64 / n as f64;
    let dec_bytes = ALLOC_BYTES.load(Ordering::Relaxed) as f64 / n as f64;

    println!(
        "[codec_perf] {name}: wire={}B iters={n} | encode {enc_ns:.0} ns/op {enc_allocs:.1} allocs/op {enc_bytes:.0} B/op | decode {dec_ns:.0} ns/op {dec_allocs:.1} allocs/op {dec_bytes:.0} B/op",
        enc.len(),
    );
}

#[test]
fn perf_small() {
    bench_case("small", 32, 24);
}

#[test]
fn perf_1k() {
    bench_case("1KB", 1024, 24);
}

#[test]
fn perf_64k() {
    bench_case("64KB", 65536, 24);
}

/// Frozen pre-optimization logic (verbatim copy of the original
/// `Frame::{encode,decode}`) for an apples-to-apples before/after in the
/// same binary/profile. Correctness equivalence is proven by the
/// differential tests in `tests/frame_fuzz_tests.rs`.
mod reference {
    use infnode::proto::{Frame, MAX_FRAME, MAX_NONCE_LEN};

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
        let mut b = v;
        b.extend_from_slice(&f.sig);
        b
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
        if nlen > MAX_NONCE_LEN {
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
        let sig: [u8; 64] = b[b.len() - 64..].try_into().map_err(|_| anyhow!("sig"))?;
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

fn timeit<R>(n: usize, mut f: impl FnMut() -> R) -> f64 {
    for _ in 0..n.min(200) {
        f();
    }
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_nanos() as f64 / n as f64
}

/// Before (reference) vs after (optimized) in one process/profile.
#[test]
fn perf_before_after() {
    for (name, plen, nlen) in [("small", 32usize, 24usize), ("1KB", 1024, 24), ("64KB", 65536, 24)]
    {
        let f = fixture(plen, nlen);
        let enc = f.encode();
        let n = iters_for(plen) * 4;
        let ref_enc = timeit(n, || std::hint::black_box(reference::ref_encode(std::hint::black_box(&f))));
        let opt_enc = timeit(n, || std::hint::black_box(std::hint::black_box(&f).encode()));
        let ref_dec = timeit(n, || {
            std::hint::black_box(reference::ref_decode(std::hint::black_box(&enc)).unwrap())
        });
        let opt_dec = timeit(n, || {
            std::hint::black_box(Frame::decode(std::hint::black_box(&enc)).unwrap())
        });
        println!(
            "[codec_perf] {name}: encode before={ref_enc:.0} after={opt_enc:.0} ns/op ({:.2}x) | decode before={ref_dec:.0} after={opt_dec:.0} ns/op ({:.2}x)",
            ref_enc / opt_enc,
            ref_dec / opt_dec,
        );
    }
}
