use crate::proto::NODEID_LEN;
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use falcon_rust::falcon512;
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroize;

/// Параметры KDF (memory-hard Argon2id): 64 MiB, 3 прохода, 4 линии.
const KDF_MEM_KIB: u32 = 65_536;
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 4;

/// Вывести 32-байтовый ключ шифрования из пассфразы через Argon2id (memory-hard).
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(KDF_MEM_KIB, KDF_ITERS, KDF_LANES, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 kdf: {e}"))?;
    Ok(key)
}

fn get_passphrase() -> Option<String> {
    std::env::var("STELL_NODE_PASSPHRASE")
        .ok()
        .or_else(|| std::env::var("INFNODE_KEY_PASSPHRASE").ok())
        .filter(|p| !p.is_empty())
}

/// LEGACY KDF (iterated blake3) — только для чтения старых `enc:` файлов.
fn legacy_passphrase_key() -> Option<[u8; 32]> {
    let p = get_passphrase()?;
    let mut h = blake3::hash(format!("infnode-key-v1:{p}").as_bytes());
    for _ in 0..65536 {
        h = blake3::hash(h.as_bytes());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.as_bytes()[..32]);
    Some(k)
}

/// Шифрует данные, если задана STELL_NODE_PASSPHRASE или INFNODE_KEY_PASSPHRASE; иначе возвращает как есть с предупреждением.
/// Формат: `enc2:<salt_hex>:<nonce_hex>:<ct_hex>` (Argon2id + XChaCha20-Poly1305).
pub fn protect(data: &[u8]) -> String {
    let Some(pass) = get_passphrase() else {
        eprintln!("[WARN] STELL_NODE_PASSPHRASE не задан: сохранение ключей в открытом виде");
        return String::from_utf8_lossy(data).to_string();
    };
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = derive_key(&pass, &salt).expect("argon2 kdf");
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), data)
        .expect("key encrypt");
    key.zeroize();
    format!(
        "enc2:{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce),
        hex::encode(&ct)
    )
}

/// Дешифрует строку. Поддерживает `enc2:` (Argon2id), legacy `enc:` и plaintext.
pub fn unprotect(data: &str) -> Result<String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    if let Some(rest) = data.strip_prefix("enc2:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() != 3 {
            bail!("bad enc2 blob");
        }
        let salt = hex::decode(parts[0])?;
        let nonce = hex::decode(parts[1])?;
        let ct = hex::decode(parts[2])?;
        let pass = get_passphrase()
            .ok_or_else(|| anyhow!("ключи зашифрованы, но STELL_NODE_PASSPHRASE не задан"))?;
        let mut key = derive_key(&pass, &salt)?;
        let c = XChaCha20Poly1305::new(Key::from_slice(&key));
        let plain = c
            .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| anyhow!("неверная пассфраза"));
        key.zeroize();
        let plain = plain?;
        Ok(String::from_utf8_lossy(&plain).to_string())
    } else if let Some(b64) = data.strip_prefix("enc:") {
        // Legacy iterated-blake3 формат (обратная совместимость)
        let key = legacy_passphrase_key()
            .ok_or_else(|| anyhow!("ключи зашифрованы, но STELL_NODE_PASSPHRASE не задан"))?;
        let blob = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)?;
        if blob.len() < 24 {
            bail!("bad enc blob");
        }
        let (nonce, ct) = blob.split_at(24);
        let c = XChaCha20Poly1305::new(Key::from_slice(&key));
        let plain = c
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("неверная пассфраза"))?;
        Ok(String::from_utf8_lossy(&plain).to_string())
    } else {
        if get_passphrase().is_none() {
            eprintln!("[WARN] STELL_NODE_PASSPHRASE не задан: загрузка ключей в открытом виде");
        }
        Ok(data.to_string())
    }
}

/// Записать приватный файл с правами 0600 (только владелец).
#[cfg(unix)]
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

/// Каталог для секретов — только владелец (0700).
#[cfg(unix)]
pub fn secure_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[derive(Clone)]
pub struct NodeKeys {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    /// Long-term ML-KEM-768 seed (64 bytes, `d || z`); the sole secret input
    /// for the KEM encapsulation key below.
    /// FULL-PQ: replaces the X25519 static secret (wipe — no ECDH material
    /// remains on disk; old 32-byte `e2e.key` files are refused, see `load`).
    pub kem_seed: [u8; crate::mailbox::KEM_SEED_LEN],
    /// ML-KEM-768 encapsulation key (1184 bytes) derived from `kem_seed`.
    pub kem_ek: Vec<u8>,
}

impl NodeKeys {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verifying = signing.verifying_key();
        let mut kem_seed = [0u8; crate::mailbox::KEM_SEED_LEN];
        OsRng.fill_bytes(&mut kem_seed);
        let kem_ek = crate::mailbox::kem_ek_from_seed(&kem_seed);
        Self {
            signing,
            verifying,
            kem_seed,
            kem_ek,
        }
    }

    pub fn id(&self) -> [u8; NODEID_LEN] {
        // NON-CANONICAL helper: classical `blake3(ed_pub)[..20]`.
        // FULL-PQ: this is NOT a NodeId and is never honored as one.
        // Canonical NodeId is PQ-only (`resolve_node_id`, `PqKeys::pq_id`).
        // Retained only for pre-existing route/TLS-pin call sites outside
        // this zone (handshake-auth policy frozen); new code must not use it
        // for identity.
        let h = blake3::hash(self.verifying.as_bytes());
        let mut id = [0u8; NODEID_LEN];
        id.copy_from_slice(&h.as_bytes()[..NODEID_LEN]);
        id
    }

    pub fn id_hex(&self) -> String {
        format!("inf1:{}", hex::encode(self.id()))
    }

    pub fn ed_hex(&self) -> String {
        hex::encode(self.verifying.as_bytes())
    }

    /// Hex of the ML-KEM-768 encapsulation key (1184 bytes).
    pub fn kem_ek_hex(&self) -> String {
        hex::encode(&self.kem_ek)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        secure_dir(dir)?;
        // Шифруем (если задана пассфраза) и пишем с правами 0600.
        let mut id_hex = hex::encode(self.signing.to_bytes());
        let mut kem_hex = hex::encode(self.kem_seed);
        write_private(&dir.join("identity.key"), &protect(id_hex.as_bytes()))?;
        write_private(&dir.join("e2e.key"), &protect(kem_hex.as_bytes()))?;
        id_hex.zeroize();
        kem_hex.zeroize();
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_meta = std::fs::metadata(dir)
                .map_err(|e| anyhow!("keystore dir {}: {e}", dir.display()))?;
            let dir_mode = dir_meta.permissions().mode() & 0o777;
            if dir_mode != 0o700 {
                bail!(
                    "keystore dir {} has insecure permissions 0o{:03o}, expected 0o700",
                    dir.display(),
                    dir_mode
                );
            }
            let id_path = dir.join("identity.key");
            let id_meta = std::fs::metadata(&id_path).map_err(|e| anyhow!("identity.key: {e}"))?;
            let id_mode = id_meta.permissions().mode() & 0o777;
            if id_mode != 0o600 {
                bail!(
                    "identity.key has insecure permissions 0o{:03o}, expected 0o600",
                    id_mode
                );
            }
            let e2e_path = dir.join("e2e.key");
            let e2e_meta = std::fs::metadata(&e2e_path).map_err(|e| anyhow!("e2e.key: {e}"))?;
            let e2e_mode = e2e_meta.permissions().mode() & 0o777;
            if e2e_mode != 0o600 {
                bail!(
                    "e2e.key has insecure permissions 0o{:03o}, expected 0o600",
                    e2e_mode
                );
            }
        }
        let id = std::fs::read_to_string(dir.join("identity.key"))
            .map_err(|e| anyhow!("identity.key: {e}"))?;
        let e2e =
            std::fs::read_to_string(dir.join("e2e.key")).map_err(|e| anyhow!("e2e.key: {e}"))?;
        let mut id_plain = unprotect(id.trim())?;
        let mut kem_plain = unprotect(e2e.trim())?;
        let id_bytes: [u8; 32] = hex::decode(id_plain.trim())?
            .try_into()
            .map_err(|_| anyhow!("identity seed должен быть 32 байта"))?;
        let kem_bytes = hex::decode(kem_plain.trim())?;
        if kem_bytes.len() == 32 {
            // Wipe-compat: a 32-byte seed is the pre-PQ X25519 static secret —
            // refused loudly, never silently accepted as KEM material.
            kem_plain.zeroize();
            bail!(
                "e2e.key: legacy x25519 key refused (FULL-PQ wipe: delete e2e.key and restart to generate a KEM key)"
            );
        }
        let kem_seed: [u8; crate::mailbox::KEM_SEED_LEN] = kem_bytes
            .try_into()
            .map_err(|_| anyhow!("e2e kem seed должен быть 64 байта"))?;
        // Стереть промежуточные plaintext-строки из памяти
        id_plain.zeroize();
        kem_plain.zeroize();
        let signing = SigningKey::from_bytes(&id_bytes);
        let verifying = signing.verifying_key();
        let kem_ek = crate::mailbox::kem_ek_from_seed(&kem_seed);
        Ok(Self {
            signing,
            verifying,
            kem_seed,
            kem_ek,
        })
    }
}

/// PQ long-term identity (Falcon-512), landed PQ 9.0, default-ON since 9.1
/// (first boot auto-generates via [`PqKeys::load_or_generate`]).
///
/// File convention — mirrors the `identity.key` precedent exactly:
/// - file: `<keys-dir>/pq-identity.key` (constant [`PQ_IDENTITY_FILE`]);
/// - contents: `protect()` envelope over the hex-encoded 32-byte Falcon
///   seed (same Argon2id+XChaCha20-Poly1305 envelope + 0600 file / 0700 dir
///   discipline as the classical keys; see `NodeKeys::save`);
/// - absent file = no PQ identity yet, explicit (see [`PqKeys::load_opt`];
///   first boot enrols via [`PqKeys::load_or_generate`]); corrupt content
///   or insecure permissions = hard error, never a silent classical
///   fallback (fail closed, FULL-PQ wipe — no classical-only mode).
///
/// The seed is the sole secret input: `falcon_rust::falcon512::keygen` is
/// deterministic, so the keypair regenerates byte-identically from it
/// (pinned by test). Storing the seed (not the 1281-byte secret encoding)
/// keeps the file small; secrecy is equivalent — guard it like a key.
///
/// FULL-PQ: [`PqKeys::pq_id`] IS the canonical `NodeId`
/// (`blake3("infnode-pqid-v1" || falcon_pk)[..20]`, `inf1:`-rendered via
/// [`PqKeys::pq_id_hex` / `keyring::resolve_node_id`]); there is no
/// classical fallback.
pub const PQ_IDENTITY_FILE: &str = "pq-identity.key";

#[derive(Clone)]
pub struct PqKeys {
    seed: [u8; 32],
    secret: falcon512::SecretKey,
    pub public: falcon512::PublicKey,
}

impl PqKeys {
    /// Deterministic keygen from a 32-byte seed (tests, offline ceremony).
    /// The seed is retained (guarded like the key) so `save` persists it.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (secret, public) = falcon512::keygen(seed);
        Self { seed, secret, public }
    }

    /// Fresh keygen from OS randomness (production path).
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keys = Self::from_seed(seed);
        seed.zeroize();
        keys
    }

    /// Raw 897-byte Falcon-512 public key (chain pubkey layout: header 0x09).
    pub fn pq_pub(&self) -> Vec<u8> {
        self.public.to_bytes()
    }

    /// Hex of the raw public key (wire/`PeerConfig.pq_pub` form).
    pub fn pq_pub_hex(&self) -> String {
        hex::encode(self.pq_pub())
    }

    /// Raw 1281-byte secret-key encoding (for `proto::pq_falcon_sign`).
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes()
    }

    /// Canonical PQ `NodeId`: `blake3("infnode-pqid-v1" || falcon_pk)[..20]`
    /// (FULL-PQ wipe — the ONLY `NodeId`; see `resolve_node_id`).
    pub fn pq_id(&self) -> [u8; NODEID_LEN] {
        crate::proto::pq_id_from_pub(&self.pq_pub())
    }

    /// `inf1:`-rendered canonical PQ `NodeId` (same alphabet as legacy ids).
    pub fn pq_id_hex(&self) -> String {
        format!("inf1:{}", hex::encode(self.pq_id()))
    }

    /// Falcon-512 tag over a finalized transcript digest with the long-term
    /// PQ key (666-byte framing, randomized nonce — see `proto` PQ docs).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        falcon512::sign(digest, &self.secret).to_bytes()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        secure_dir(dir)?;
        let mut seed_hex = hex::encode(self.seed);
        write_private(&dir.join(PQ_IDENTITY_FILE), &protect(seed_hex.as_bytes()))?;
        seed_hex.zeroize();
        Ok(())
    }

    /// Load if present, `Ok(None)` if the file is absent (classical-only,
    /// explicit). Corrupt content or insecure permissions are hard errors —
    /// a broken PQ key must never silently become "classical".
    pub fn load_opt(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(PQ_IDENTITY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        // Recover the seed deterministically: falcon-rust keygen is a pure
        // function of it, so round-trip regenerates the identical keypair.
        let stored = Self::load_seed(dir)?;
        Ok(Some(Self::from_seed(stored)))
    }

    /// First-boot ensure (PQ 9.1, default-ON): load if present, else generate
    /// fresh (OS randomness) and save with 0600/0700 discipline, returning
    /// the new identity. Mirrors the `identity.key` precedent exactly: the
    /// `main.rs` key-load sites do `if exists { load } else { generate +
    /// save }` for the classical keys — this is the same shape for
    /// `pq-identity.key`, so every booting node picks up PQ with no
    /// ceremony. Corrupt/unreadable content propagates as a hard error via
    /// `load_opt` (fail closed — never a silent classical downgrade), as do
    /// insecure permissions and save failures.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        if let Some(keys) = Self::load_opt(dir)? {
            return Ok(keys);
        }
        let keys = Self::generate();
        keys.save(dir)?;
        eprintln!(
            "[PQ] generated new {} in {} (0600, Falcon-512) — first boot, no ceremony needed",
            PQ_IDENTITY_FILE,
            dir.display()
        );
        Ok(keys)
    }

    /// The seed cannot be recovered from the keypair encodings, so `save`
    /// persists it — and `load_opt` must read the same file. Kept private:
    /// callers use `save`/`load_opt`, never raw seeds.
    fn load_seed(dir: &Path) -> Result<[u8; 32]> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_meta = std::fs::metadata(dir)
                .map_err(|e| anyhow!("keystore dir {}: {e}", dir.display()))?;
            let dir_mode = dir_meta.permissions().mode() & 0o777;
            if dir_mode != 0o700 {
                bail!(
                    "keystore dir {} has insecure permissions 0o{:03o}, expected 0o700",
                    dir.display(),
                    dir_mode
                );
            }
            let path = dir.join(PQ_IDENTITY_FILE);
            let meta = std::fs::metadata(&path).map_err(|e| anyhow!("{PQ_IDENTITY_FILE}: {e}"))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                bail!(
                    "{PQ_IDENTITY_FILE} has insecure permissions 0o{mode:03o}, expected 0o600"
                );
            }
        }
        let raw = std::fs::read_to_string(dir.join(PQ_IDENTITY_FILE))
            .map_err(|e| anyhow!("{PQ_IDENTITY_FILE}: {e}"))?;
        let mut plain = unprotect(raw.trim())?;
        let seed: [u8; 32] = hex::decode(plain.trim())?
            .try_into()
            .map_err(|_| anyhow!("pq seed должен быть 32 байта"))?;
        plain.zeroize();
        Ok(seed)
    }
}

// ---------------------------------------------------------------------------
// NodeId re-ceremony: PQ identity is PRIMARY and MANDATORY (FULL-PQ wipe).
//
// Derivation rule (one line): `NodeId = blake3("infnode-pqid-v1"||falcon_pk)[..20]`
// via `PqKeys::pq_id` (which reuses `proto::pq_id_from_pub` — no duplicate
// hashing logic lives here).
//
// No migration window, no legacy alias: the classical `blake3(ed_pub)[..20]`
// (`NodeKeys::id`) is NOT a NodeId and is never honored as one. Callers
// requiring the canonical id use `resolve_node_id` (PQ-only) or
// `ceremony_local_id`. `NodeKeys::id` remains only as a non-canonical
// helper for pre-existing route/TLS-pin call sites outside this zone
// (handshake-auth policy is frozen); it must NOT be used for new identity
// logic.
// ---------------------------------------------------------------------------

/// Which arm of the re-ceremony derivation produced a `NodeId`.
/// FULL-PQ: only the PQ arm exists. Kept as an enum (single variant) so
/// log/telemetry call sites (`node_id_kind`) keep a stable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIdKind {
    Pq,
}

impl NodeIdKind {
    /// Short label for logs and `node_id_kind` telemetry (`"PQ"`).
    pub fn label(self) -> &'static str {
        match self {
            NodeIdKind::Pq => "PQ",
        }
    }
}

/// A derived `NodeId` with its ceremony arm attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedNodeId {
    pub id: [u8; NODEID_LEN],
    pub kind: NodeIdKind,
}

impl ResolvedNodeId {
    /// Always false post-excision (no legacy arm exists). Kept for call-site
    /// compat so `is_legacy()` checks fail closed without rewiring.
    pub fn is_legacy(self) -> bool {
        false
    }

    /// `"PQ"` (log/telemetry mark).
    pub fn kind_label(self) -> &'static str {
        self.kind.label()
    }

    /// `inf1:`-rendered id (same alphabet as the classical id).
    pub fn id_hex(self) -> String {
        format!("inf1:{}", hex::encode(self.id))
    }
}

/// Canonical NodeId derivation: PQ-only. Requires a PQ identity;
/// there is no classical fallback (FULL-PQ wipe, no compat).
pub fn resolve_node_id(_ed: &NodeKeys, pq: &PqKeys) -> ResolvedNodeId {
    ResolvedNodeId {
        id: pq.pq_id(),
        kind: NodeIdKind::Pq,
    }
}

/// PQ-only announce: the single PQ id. No legacy alias is announced.
/// Wire encoding stays out of scope — see `parse_dual_announce`.
pub fn dual_announce_ids(_ed: &NodeKeys, pq: &PqKeys) -> Vec<[u8; NODEID_LEN]> {
    vec![pq.pq_id()]
}

/// `inf1:`-rendered PQ announce (same order as `dual_announce_ids`).
pub fn dual_announce_hex(_ed: &NodeKeys, pq: &PqKeys) -> Vec<String> {
    dual_announce_ids(_ed, pq)
        .iter()
        .map(|id| format!("inf1:{}", hex::encode(id)))
        .collect()
}

/// Parse an advertised PQ announce: exactly 1 `inf1:` id, fail-closed.
/// Malformed entries and wrong lengths are refused (never silently
/// truncated). Kept name for call-site compat.
pub fn parse_dual_announce(ids: &[String]) -> Result<Vec<[u8; NODEID_LEN]>> {
    if ids.len() != 1 {
        bail!("pq announce must carry exactly 1 id");
    }
    ids.iter()
        .map(|s| {
            let b = hex::decode(s.strip_prefix(crate::config::NODEID_PREFIX).unwrap_or(s))?;
            b.try_into()
                .map_err(|_| anyhow!("announced id must be 20 bytes"))
        })
        .collect()
}
