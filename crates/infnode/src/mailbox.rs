//! Почтовый ящик InfMail: E2E-шифрование (ML-KEM-768 + XChaCha20),
//! реестр пользователей и индексы ящиков в DHT-KV.
//!
//! FULL-PQ: X25519 ECDH removed. E2E is ML-KEM-768 encapsulation to the
//! recipient's long-term KEM key + XChaCha20-Poly1305 of the plaintext.
//! Old `x:` (X25519) key files are refused (wipe, no compat).

use crate::keyring::{protect, secure_dir, unprotect, write_private};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use zeroize::Zeroize;

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const KEM_CT_LEN: usize = 1088;
/// ML-KEM seed (`d || z`) length.
pub const KEM_SEED_LEN: usize = 64;

/// Пара ящика: ML-KEM-768 (E2E) + Ed25519 (подпись отправителя/владельца).
pub struct MailKeys {
    pub kem_seed: [u8; KEM_SEED_LEN],
    pub kem_ek: Vec<u8>,
    pub ed_sig: SigningKey,
    pub ed_ver: VerifyingKey,
}

impl MailKeys {
    pub fn generate() -> Self {
        let mut kem_seed = [0u8; KEM_SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut kem_seed);
        let kem_ek = kem_ek_from_seed(&kem_seed);
        let ed_sig = SigningKey::generate(&mut rand::rngs::OsRng);
        let ed_ver = ed_sig.verifying_key();
        Self {
            kem_seed,
            kem_ek,
            ed_sig,
            ed_ver,
        }
    }

    pub fn save(&self, dir: &std::path::Path, email: &str) -> Result<()> {
        secure_dir(dir)?;
        let mut kem_hex = hex::encode(self.kem_seed);
        let mut ed_hex = hex::encode(self.ed_sig.to_bytes());
        let mut contents = format!("kem:{}\ned:{}", kem_hex, ed_hex);
        // Шифруем (если задана INFNODE_KEY_PASSPHRASE) и пишем с правами 0600.
        write_private(
            &dir.join(format!("{email}.key")),
            &protect(contents.as_bytes()),
        )?;
        kem_hex.zeroize();
        ed_hex.zeroize();
        contents.zeroize();
        Ok(())
    }

    pub fn load(dir: &std::path::Path, email: &str) -> Result<Self> {
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
            let key_path = dir.join(format!("{email}.key"));
            let key_meta = std::fs::metadata(&key_path).map_err(|e| anyhow!("{email}.key: {e}"))?;
            let key_mode = key_meta.permissions().mode() & 0o777;
            if key_mode != 0o600 {
                bail!(
                    "{email}.key has insecure permissions 0o{:03o}, expected 0o600",
                    key_mode
                );
            }
        }
        let raw = std::fs::read_to_string(dir.join(format!("{email}.key")))?;
        let mut plain = unprotect(raw.trim())?;
        let mut kem_hex = None;
        let mut ed_hex = None;
        for line in plain.lines() {
            if let Some(v) = line.strip_prefix("kem:") {
                kem_hex = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("ed:") {
                ed_hex = Some(v.to_string());
            } else if line.strip_prefix("x:").is_some() {
                plain.zeroize();
                bail!("legacy x25519 mailbox key refused (FULL-PQ wipe: re-register mailbox)");
            }
        }
        let kem_bytes = hex::decode(kem_hex.ok_or_else(|| anyhow!("kem seed отсутствует"))?.trim())?;
        let kb: [u8; KEM_SEED_LEN] = kem_bytes
            .try_into()
            .map_err(|_| anyhow!("kem seed 64"))?;
        let eb: [u8; 32] =
            hex::decode(ed_hex.ok_or_else(|| anyhow!("ed seed отсутствует"))?.trim())?
                .try_into()
                .map_err(|_| anyhow!("ed seed 32"))?;
        plain.zeroize();
        let kem_ek = kem_ek_from_seed(&kb);
        let ed_sig = SigningKey::from_bytes(&eb);
        let ed_ver = ed_sig.verifying_key();
        Ok(Self {
            kem_seed: kb,
            kem_ek,
            ed_sig,
            ed_ver,
        })
    }

    /// Hex of the ML-KEM-768 encapsulation key (1184 bytes).
    pub fn x_hex(&self) -> String {
        hex::encode(&self.kem_ek)
    }

    pub fn ed_hex(&self) -> String {
        hex::encode(self.ed_ver.as_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed_sig.sign(msg).to_bytes()
    }

    pub fn verify(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(ed_pub)
            .map(|k| {
                k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
                    .is_ok()
            })
            .unwrap_or(false)
    }
}

/// Derive the ML-KEM-768 encapsulation key from a 64-byte seed.
pub fn kem_ek_from_seed(kem_seed: &[u8; KEM_SEED_LEN]) -> Vec<u8> {
    use ml_kem::kem::{FromSeed, KeyExport};
    let seed: ml_kem::Seed = (*kem_seed).into();
    let (_, ek) = ml_kem::MlKem768::from_seed(&seed);
    ek.to_bytes().as_slice().to_vec()
}

/// KEM shared-secret KDF: `blake3("infmail-kem-box-v1" || shared)`.
fn kem_box_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"infmail-kem-box-v1");
    h.update(shared);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

/// Encapsulate to a recipient's ML-KEM-768 key with explicit randomness
/// (same `encapsulate_deterministic`-with-`OsRng`-bytes idiom as
/// `node::pq_encapsulate`: `ml-kem` is built without its `getrandom`
/// feature).
fn kem_encapsulate(recipient_ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if recipient_ek.len() != KEM_EK_LEN {
        bail!("kem ek malformed");
    }
    let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey768>::try_from(recipient_ek)
        .map_err(|_| anyhow!("kem ek malformed"))?;
    let ek = ml_kem::EncapsulationKey768::new(&key).map_err(|_| anyhow!("kem ek malformed"))?;
    let mut m = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut m);
    let (ct, ss) = ek.encapsulate_deterministic(&m.into());
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), shared))
}

/// Decapsulate with the recipient's 64-byte KEM seed (FIPS 203 implicit
/// rejection: tampered ct yields fallback key, never an error — the AEAD
/// open then fails fail-closed).
fn kem_decapsulate(kem_seed: &[u8; KEM_SEED_LEN], ct: &[u8]) -> Result<[u8; 32]> {
    use ml_kem::kem::FromSeed;
    if ct.len() != KEM_CT_LEN {
        bail!("kem ct malformed");
    }
    let seed: ml_kem::Seed = (*kem_seed).into();
    let (dk, _) = ml_kem::MlKem768::from_seed(&seed);
    let kem_ct: ml_kem::kem::Ciphertext<ml_kem::MlKem768> =
        ct.try_into().map_err(|_| anyhow!("kem ct malformed"))?;
    use ml_kem::kem::Decapsulate;
    let ss = dk.decapsulate(&kem_ct);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Ok(shared)
}

/// Зашифровать для получателя (KEM-encap + XChaCha).
/// Формат: [24 nonce][1088 kem_ct][ciphertext+tag].
pub fn seal(recipient_ek: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let (kem_ct, shared) = kem_encapsulate(recipient_ek)?;
    let key = kem_box_key(&shared);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| anyhow!("encrypt"))?;
    let mut out = Vec::with_capacity(24 + KEM_CT_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Расшифровать своей парой.
pub fn open(recipient: &MailKeys, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + KEM_CT_LEN {
        bail!("blob слишком короткий");
    }
    let (nonce, rest) = blob.split_at(24);
    let (kem_ct, ct) = rest.split_at(KEM_CT_LEN);
    let shared = kem_decapsulate(&recipient.kem_seed, kem_ct)?;
    let key = kem_box_key(&shared);
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    c.decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("decrypt (не та пара или повреждено)"))
}
