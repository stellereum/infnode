#![cfg(target_os = "linux")]

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Parser;
use infnode::node::{box_unwrap_key, e2e_decrypt};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde_json::Value;
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const MANIFEST_LIMIT: usize = 1024 * 1024;
const SEED_FILE_LIMIT: usize = 256;

/// Offline EC mail recovery. The BLAKE3 digest pins exact manifest bytes; it
/// does not prove who authored them. Output is the outer mail blob, which may
/// itself contain encrypted body/attachments. Never point this at live data.
#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    chunks: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// BLAKE3 of the EXACT manifest bytes, obtained through a trusted channel.
    #[arg(long)]
    trusted_manifest_blake3: String,
    /// Optional file containing the 64-byte ML-KEM seed as hex (not a CLI secret).
    #[arg(long)]
    owner_seed_file: Option<PathBuf>,
    /// Maximum ciphertext bytes, including the AEAD tag.
    #[arg(long)]
    max_ciphertext_bytes: usize,
    /// Maximum size of one shard.
    #[arg(long)]
    max_shard_bytes: usize,
    /// Maximum total virtual address space in bytes (Linux RLIMIT_AS).
    #[arg(long)]
    max_memory_bytes: u64,
}

// Walk from / or cwd without following symlinks in ANY component. Reject ..
// rather than trying to resolve it. FDs anchor every lookup against renames.
fn directory(path: &Path) -> Result<File> {
    let mut fd = if path.is_absolute() {
        File::open("/")?
    } else {
        File::open(".")?
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                fd = open_at(&fd, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            }
            _ => bail!("path contains unsupported component: {}", path.display()),
        }
    }
    Ok(fd)
}

fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name.as_bytes()).context("NUL in filename")?;
    // O_NONBLOCK prevents an attacker-controlled FIFO from blocking the process.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn parent_and_name(path: &Path) -> Result<(File, &OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("missing filename"))?;
    let parent = path.parent().ok_or_else(|| anyhow!("missing parent"))?;
    Ok((directory(parent)?, name))
}

fn read_file_at(dir: &File, name: &OsStr, limit: usize) -> Result<Vec<u8>> {
    let mut file = open_at(dir, name, libc::O_RDONLY, 0)?;
    ensure!(file.metadata()?.is_file(), "input is not a regular file");
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let count = file.read(&mut buf)?;
        if count == 0 {
            break;
        }
        ensure!(
            count <= limit.saturating_sub(data.len()),
            "input exceeds limit"
        );
        data.try_reserve(count).context("input allocation failed")?;
        data.extend_from_slice(&buf[..count]);
    }
    Ok(data)
}

fn read_path(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let (dir, name) = parent_and_name(path)?;
    read_file_at(&dir, name, limit).with_context(|| format!("read {}", path.display()))
}

fn integer(v: &Value, name: &str) -> Result<usize> {
    usize::try_from(v[name].as_u64().ok_or_else(|| anyhow!("invalid {name}"))?)
        .context("integer exceeds platform limits")
}

fn hex_bytes(v: &Value, name: &str, len: usize) -> Result<Vec<u8>> {
    let text = v[name].as_str().ok_or_else(|| anyhow!("missing {name}"))?;
    ensure!(text.len() == len * 2, "invalid {name} length");
    hex::decode(text).with_context(|| format!("invalid {name} hex"))
}

fn recover(args: &Args) -> Result<Vec<u8>> {
    ensure!(
        args.max_ciphertext_bytes >= 16,
        "ciphertext limit must be at least 16"
    );
    ensure!(args.max_shard_bytes > 0, "shard limit must be positive");
    let expected = hex::decode(&args.trusted_manifest_blake3).context("invalid trusted digest")?;
    ensure!(expected.len() == 32, "trusted digest must be 32 bytes");
    let raw = read_path(&args.manifest, MANIFEST_LIMIT)?;
    ensure!(
        blake3::hash(&raw).as_bytes() == expected.as_slice(),
        "trusted manifest digest mismatch"
    );
    let manifest: Value = serde_json::from_slice(&raw).context("invalid manifest JSON")?;
    ensure!(
        manifest["bucket"].as_str() == Some("mail"),
        "not a mail manifest"
    );
    ensure!(manifest["name"].as_str().is_some(), "missing mail name");
    let ec = &manifest["ec"];
    let k = integer(ec, "k")?;
    let n = integer(ec, "n")?;
    let ct_len = integer(ec, "ct_len")?;
    ensure!(k > 0 && k < n && n <= 256, "unsupported EC geometry");
    ensure!(
        ct_len >= 16 && ct_len <= args.max_ciphertext_bytes,
        "ciphertext exceeds limit or is too short"
    );
    let shard_len = ct_len
        .checked_add(k - 1)
        .ok_or_else(|| anyhow!("shard size overflow"))?
        / k;
    ensure!(
        shard_len > 0 && shard_len <= args.max_shard_bytes,
        "shard exceeds limit"
    );
    ensure!(
        integer(ec, "shard_len")? == shard_len,
        "manifest shard length mismatch"
    );
    ensure!(
        integer(&manifest, "size")?.checked_add(16) == Some(ct_len),
        "manifest plaintext size mismatch"
    );
    // Fail before allocating when the declared working set cannot fit. RLIMIT_AS
    // is the actual hard bound, including JSON, allocator and library overhead.
    let encoded = shard_len
        .checked_mul(n)
        .ok_or_else(|| anyhow!("encoded size overflow"))?;
    let estimate = encoded
        .checked_mul(2)
        .and_then(|x| ct_len.checked_mul(2).and_then(|y| x.checked_add(y)))
        .and_then(|x| x.checked_add(16 * 1024 * 1024))
        .ok_or_else(|| anyhow!("working set overflow"))?;
    ensure!(
        (estimate as u128) <= u128::from(args.max_memory_bytes),
        "estimated working set exceeds memory limit"
    );
    let nonce = hex_bytes(&manifest, "nonce", 24)?;
    let key = Zeroizing::new(if let Some(kb) = manifest.get("key_box") {
        ensure!(manifest.get("key").is_none(), "ambiguous key and key_box");
        if kb.get("eph").is_some() {
            bail!("unsupported legacy X25519 key_box");
        }
        // Bound every field before calling the public unwrapping API.
        hex_bytes(kb, "ct", 1088)
            .context("unsupported or invalid ML-KEM key_box ct (legacy X25519 is unsupported)")?;
        hex_bytes(kb, "nonce", 24)?;
        hex_bytes(kb, "ct2", 48)?;
        let seed_path = args
            .owner_seed_file
            .as_ref()
            .ok_or_else(|| anyhow!("ML-KEM key_box requires --owner-seed-file"))?;
        let seed = Zeroizing::new(read_path(seed_path, SEED_FILE_LIMIT)?);
        let seed_hex = std::str::from_utf8(&seed)
            .context("seed file must be UTF-8 hex")?
            .trim();
        ensure!(
            seed_hex.len() == 128 && seed_hex.bytes().all(|c| c.is_ascii_hexdigit()),
            "ML-KEM seed must be 64 bytes of hex; legacy X25519 is unsupported"
        );
        box_unwrap_key(kb, seed_hex).context("ML-KEM key_box unwrap failed")?
    } else {
        ensure!(
            args.owner_seed_file.is_none(),
            "owner seed supplied for public-key manifest"
        );
        hex_bytes(&manifest, "key", 32)?
            .try_into()
            .map_err(|_| anyhow!("invalid key"))?
    });
    let chunks = manifest["chunks"]
        .as_array()
        .ok_or_else(|| anyhow!("missing chunks"))?;
    ensure!(
        chunks.len() >= k && chunks.len() <= n,
        "invalid chunk count"
    );
    let mut seen = vec![false; n];
    let mut descriptors = Vec::with_capacity(chunks.len());
    for c in chunks {
        let idx = integer(c, "shard")?;
        ensure!(
            idx < n && !seen[idx],
            "duplicate or out-of-range shard index"
        );
        seen[idx] = true;
        ensure!(integer(c, "len")? == shard_len, "chunk length mismatch");
        let id = c["id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing chunk id"))?;
        ensure!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid chunk id"
        );
        let hash = hex_bytes(c, "hash", 32)?;
        descriptors.push((idx, id, hash));
    }
    let dir = directory(&args.chunks).context("open chunks directory")?;
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut have = 0;
    let mut last_err: Option<String> = None;
    for (idx, id, hash) in descriptors {
        let bytes = match read_file_at(&dir, OsStr::new(id), shard_len) {
            Ok(bytes) => bytes,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue
            }
            Err(e) => {
                let msg = format!("read shard {idx}: {e:#}");
                eprintln!("warning: skipping {msg}");
                last_err = Some(msg);
                continue;
            }
        };
        if bytes.len() != shard_len {
            let msg = format!("shard {idx} size mismatch ({} != {shard_len})", bytes.len());
            eprintln!("warning: skipping {msg}");
            last_err = Some(msg);
            continue;
        }
        if blake3::hash(&bytes).as_bytes() != hash.as_slice() {
            let msg = format!("shard {idx} hash mismatch");
            eprintln!("warning: skipping {msg}");
            last_err = Some(msg);
            continue;
        }
        slots[idx] = Some(bytes);
        have += 1;
        if have == k {
            break;
        }
    }
    if have < k {
        match last_err {
            Some(err) => bail!("insufficient shards: {have}/{k} (last error: {err})"),
            None => bail!("insufficient shards: {have}/{k}"),
        }
    }
    let rs = ReedSolomon::new(k, n - k).map_err(|e| anyhow!("unsupported EC geometry: {e}"))?;
    rs.reconstruct_data(&mut slots)
        .map_err(|e| anyhow!("EC reconstruction failed: {e}"))?;
    let mut ct = Vec::new();
    ct.try_reserve_exact(ct_len)
        .context("ciphertext allocation failed")?;
    for shard in slots.iter().take(k) {
        let data = shard
            .as_ref()
            .ok_or_else(|| anyhow!("missing reconstructed shard"))?;
        let take = (ct_len - ct.len()).min(data.len());
        ct.extend_from_slice(&data[..take]);
    }
    ensure!(
        ct.len() == ct_len,
        "reconstructed ciphertext length mismatch"
    );
    drop(slots);
    e2e_decrypt(&key, &nonce, &ct).context("mail AEAD verification failed")
}

fn publish(path: &Path, plain: &[u8]) -> Result<()> {
    let (dir, name) = parent_and_name(path)?;
    let mut file = open_at(
        &dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )
    .context("create output exclusively (existing paths are never overwritten)")?;
    file.write_all(plain)
        .context("write output (partial file may remain)")?;
    file.sync_all().context("sync output")?;
    Ok(())
}

fn set_memory_limit(bytes: u64) -> Result<()> {
    ensure!(bytes > 0, "memory limit must be positive");
    let value = libc::rlim_t::try_from(bytes).context("memory limit out of range")?;
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut old) } == 0,
        "getrlimit failed"
    );
    let limit = libc::rlimit {
        rlim_cur: value.min(old.rlim_cur),
        rlim_max: old.rlim_max,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } == 0,
        "setrlimit failed"
    );
    Ok(())
}

fn main() {
    let args = Args::parse();
    eprintln!("Trust notice: manifest BLAKE3 pins exact supplied bytes; it does NOT authenticate their author. Oversized mail may be refused. Output is the outer mail blob.");
    let result = set_memory_limit(args.max_memory_bytes)
        .and_then(|_| recover(&args))
        .and_then(|plain| publish(&args.output, &plain));
    if let Err(error) = result {
        eprintln!("recovery refused: {error:#}");
        std::process::exit(1);
    }
    eprintln!("AEAD verified; recovered outer mail blob exported without overwrite.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use infnode::node::{
        blob_content_hash, blob_key_nonce, box_wrap_key, e2e_encrypt_det, ec_chunk_id_for,
    };
    use serde_json::json;
    use std::fs;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ec-mail-recovery-test-{}-{nanos}-{n}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _tmp: TempDir,
        args: Args,
        manifest: Value,
        plain: Vec<u8>,
    }

    impl Fixture {
        // Reproduce the pre-limit writer layout independently of ec_encode.
        fn new(plain: Vec<u8>) -> Self {
            let tmp = TempDir::new();
            let chunks_dir = tmp.path().join("chunks");
            fs::create_dir(&chunks_dir).unwrap();
            let name = "legacy-fixture";
            let hash = blob_content_hash(&plain);
            let (key, nonce) = blob_key_nonce("mail", name, &hash);
            let ct = e2e_encrypt_det(&key, &nonce, &plain);
            let (k, n) = (3, 5);
            let shard_len = ct.len().div_ceil(k);
            let mut shards = vec![vec![0; shard_len]; n];
            for (i, part) in ct.chunks(shard_len).enumerate() {
                shards[i][..part.len()].copy_from_slice(part);
            }
            ReedSolomon::new(k, n - k)
                .unwrap()
                .encode(&mut shards)
                .unwrap();
            let chunks: Vec<Value> = shards.iter().enumerate().map(|(i, shard)| {
                let id = ec_chunk_id_for("mail", name, i, &hash);
                fs::write(chunks_dir.join(&id), shard).unwrap();
                json!({"id": id, "shard": i, "len": shard_len, "hash": blake3::hash(shard).to_hex().to_string()})
            }).collect();
            let manifest = json!({
                "bucket": "mail", "name": name, "size": plain.len(),
                "key": hex::encode(key), "nonce": hex::encode(nonce),
                "ec": {"k": k, "n": n, "ct_len": ct.len(), "shard_len": shard_len},
                "chunks": chunks
            });
            let args = Args {
                manifest: tmp.path().join("manifest.json"),
                chunks: chunks_dir,
                output: tmp.path().join("out"),
                trusted_manifest_blake3: String::new(),
                owner_seed_file: None,
                max_ciphertext_bytes: 64 * 1024 * 1024,
                max_shard_bytes: 32 * 1024 * 1024,
                max_memory_bytes: 512 * 1024 * 1024,
            };
            let mut fixture = Self {
                _tmp: tmp,
                args,
                manifest,
                plain,
            };
            fixture.save_manifest();
            fixture
        }

        fn save_manifest(&mut self) {
            let raw = serde_json::to_vec(&self.manifest).unwrap();
            self.args.trusted_manifest_blake3 = blake3::hash(&raw).to_hex().to_string();
            fs::write(&self.args.manifest, raw).unwrap();
        }

        fn chunk(&self, idx: usize) -> PathBuf {
            self.args
                .chunks
                .join(self.manifest["chunks"][idx]["id"].as_str().unwrap())
        }
    }

    #[test]
    fn legacy_writer_with_missing_data_shard() {
        let f = Fixture::new(b"legacy outer mail blob".to_vec());
        fs::remove_file(f.chunk(0)).unwrap();
        let plain = recover(&f.args).unwrap();
        assert_eq!(plain, f.plain);
        publish(&f.args.output, &plain).unwrap();
        assert_eq!(fs::read(&f.args.output).unwrap(), f.plain);
    }

    #[test]
    fn oversized_legacy_and_explicit_limits() {
        let mut f = Fixture::new(vec![0x5a; 32 * 1024 * 1024 + 1]);
        assert_eq!(recover(&f.args).unwrap(), f.plain);
        f.args.max_ciphertext_bytes = 32 * 1024 * 1024;
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("ciphertext"));
        f.args.max_ciphertext_bytes = 64 * 1024 * 1024;
        f.args.max_shard_bytes = 2 * 1024 * 1024;
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("shard exceeds"));
        f.args.max_shard_bytes = 32 * 1024 * 1024;
        f.args.max_memory_bytes = 32 * 1024 * 1024;
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("working set"));
    }

    #[test]
    fn manifest_digest_rejects_substitution_and_byte_changes() {
        let f = Fixture::new(b"mail".to_vec());
        let mut raw = fs::read(&f.args.manifest).unwrap();
        raw.push(b' ');
        fs::write(&f.args.manifest, raw).unwrap();
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("digest mismatch"));
        assert!(!f.args.output.exists());
    }

    #[test]
    fn corrupt_shard_recovers_from_remaining_valid_shards() {
        let f = Fixture::new(b"ec mail recovery with one corrupt shard and parity".to_vec());
        // Corrupt shard 0 (hash mismatch); remaining 4 >= k=3 shards recover.
        let path0 = f.chunk(0);
        let mut bytes0 = fs::read(&path0).unwrap();
        bytes0[0] ^= 1;
        fs::write(&path0, &bytes0).unwrap();
        assert_eq!(recover(&f.args).unwrap(), f.plain);

        // Also truncate shard 1 (size mismatch); remaining 3 == k shards still recover.
        fs::write(f.chunk(1), [0u8]).unwrap();
        assert_eq!(recover(&f.args).unwrap(), f.plain);
    }

    #[test]
    fn corrupt_shard_and_aead_are_refused() {
        let mut f = Fixture::new(b"mail payload".to_vec());
        fs::remove_file(f.chunk(3)).unwrap();
        fs::remove_file(f.chunk(4)).unwrap();
        let path = f.chunk(0);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("hash mismatch"));
        // Even a trusted manifest describing altered bytes cannot bypass AEAD.
        f.manifest["chunks"][0]["hash"] = json!(blake3::hash(&bytes).to_hex().to_string());
        f.save_manifest();
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("AEAD verification failed"));
        assert!(!f.args.output.exists());
    }

    #[test]
    fn invalid_geometry_and_duplicate_indices_are_refused() {
        let mut f = Fixture::new(b"mail".to_vec());
        f.manifest["ec"]["shard_len"] = json!(100);
        f.save_manifest();
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("shard length mismatch"));
        let len = f.manifest["chunks"][0]["len"].clone();
        f.manifest["ec"]["shard_len"] = len;
        f.manifest["chunks"][1]["shard"] = json!(0);
        f.save_manifest();
        assert!(format!("{:#}", recover(&f.args).unwrap_err()).contains("duplicate"));
    }

    #[test]
    fn refuses_existing_output_and_symlinks() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new(b"mail".to_vec());
        fs::write(&f.args.output, b"keep").unwrap();
        assert!(publish(&f.args.output, b"overwrite").is_err());
        assert_eq!(fs::read(&f.args.output).unwrap(), b"keep");
        fs::remove_file(f.chunk(3)).unwrap();
        fs::remove_file(f.chunk(4)).unwrap();
        let target = f.chunk(0);
        let original = fs::read(&target).unwrap();
        fs::remove_file(&target).unwrap();
        let outside = f._tmp.path().join("outside");
        fs::write(&outside, original).unwrap();
        symlink(&outside, &target).unwrap();
        assert!(recover(&f.args).is_err());
        assert_eq!(fs::read(&f.args.output).unwrap(), b"keep");
    }

    #[test]
    fn refuses_symlink_in_directory_path() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new(b"mail".to_vec());
        let alias = f._tmp.path().join("alias");
        symlink(&f.args.chunks, &alias).unwrap();
        f.args.chunks = alias;
        assert!(recover(&f.args).is_err());
        assert!(!f.args.output.exists());
    }

    #[test]
    fn ml_kem_box_and_legacy_x25519_refusal() {
        let mut f = Fixture::new(b"boxed mail".to_vec());
        let owner = infnode::mailbox::MailKeys::generate();
        let key: [u8; 32] = hex::decode(f.manifest["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let boxed = box_wrap_key(&hex::encode(&owner.kem_ek), &key).unwrap();
        f.manifest.as_object_mut().unwrap().remove("key");
        f.manifest["key_box"] = boxed;
        let seed_path = f._tmp.path().join("seed");
        fs::write(&seed_path, hex::encode(owner.kem_seed)).unwrap();
        f.args.owner_seed_file = Some(seed_path);
        f.save_manifest();
        assert_eq!(recover(&f.args).unwrap(), f.plain);
        f.manifest["key_box"] = json!({"eph": "00"});
        f.save_manifest();
        assert!(
            format!("{:#}", recover(&f.args).unwrap_err()).contains("unsupported legacy X25519")
        );
    }
}
