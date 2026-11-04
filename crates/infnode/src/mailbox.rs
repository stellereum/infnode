//! Почтовый ящик InfMail: E2E-шифрование (crypto_box: X25519 + XChaCha20),
//! реестр пользователей и индексы ящиков в DHT-KV.

use crate::keyring::{protect, secure_dir, unprotect, write_private};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Пара ящика: X25519 (E2E) + Ed25519 (подпись отправителя/владельца).
pub struct MailKeys {
    pub secret: StaticSecret,
    pub public: PublicKey,
    pub ed_sig: SigningKey,
    pub ed_ver: VerifyingKey,
}

impl MailKeys {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        let ed_sig = SigningKey::generate(&mut rand::rngs::OsRng);
        let ed_ver = ed_sig.verifying_key();
        Self {
            secret,
            public,
            ed_sig,
            ed_ver,
        }
    }

    pub fn save(&self, dir: &std::path::Path, email: &str) -> Result<()> {
        secure_dir(dir)?;
        let mut x_hex = hex::encode(self.secret.to_bytes());
        let mut ed_hex = hex::encode(self.ed_sig.to_bytes());
        let mut contents = format!("x:{}\ned:{}", x_hex, ed_hex);
        // Шифруем (если задана INFNODE_KEY_PASSPHRASE) и пишем с правами 0600.
        write_private(
            &dir.join(format!("{email}.key")),
            &protect(contents.as_bytes()),
        )?;
        x_hex.zeroize();
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
        let mut x_hex = None;
        let mut ed_hex = None;
        for line in plain.lines() {
            if let Some(v) = line.strip_prefix("x:") {
                x_hex = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("ed:") {
                ed_hex = Some(v.to_string());
            }
        }
        let xb: [u8; 32] = hex::decode(x_hex.ok_or_else(|| anyhow!("x seed отсутствует"))?.trim())?
            .try_into()
            .map_err(|_| anyhow!("x seed 32"))?;
        let eb: [u8; 32] =
            hex::decode(ed_hex.ok_or_else(|| anyhow!("ed seed отсутствует"))?.trim())?
                .try_into()
                .map_err(|_| anyhow!("ed seed 32"))?;
        plain.zeroize();
        let secret = StaticSecret::from(xb);
        let public = PublicKey::from(&secret);
        let ed_sig = SigningKey::from_bytes(&eb);
        let ed_ver = ed_sig.verifying_key();
        Ok(Self {
            secret,
            public,
            ed_sig,
            ed_ver,
        })
    }

    pub fn x_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
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

/// Сессионный ключ из ECDH(приват, публичный) + оба публичных (канонически отсортированы).
fn box_key(priv_k: &StaticSecret, pub_a: &PublicKey, pub_b: &PublicKey) -> [u8; 32] {
    let shared = priv_k.diffie_hellman(pub_a);
    let (lo, hi) = if pub_a.as_bytes() < pub_b.as_bytes() {
        (pub_a.as_bytes(), pub_b.as_bytes())
    } else {
        (pub_b.as_bytes(), pub_a.as_bytes())
    };
    let mut h = blake3::Hasher::new();
    h.update(b"infmail-cryptobox-v1");
    h.update(shared.as_bytes());
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out.as_bytes()[..32]);
    k
}

/// Зашифровать для получателя (sender генерит эфемерный ключ).
/// Формат: [24 nonce][32 eph_pub][ciphertext+tag].
pub fn seal(recipient_pub: &PublicKey, plain: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let key = box_key(&eph, recipient_pub, &eph_pub);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| anyhow!("encrypt"))?;
    let mut out = Vec::with_capacity(24 + 32 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Расшифровать своей парой.
pub fn open(recipient: &MailKeys, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + 32 {
        bail!("blob слишком короткий");
    }
    let (nonce, rest) = blob.split_at(24);
    let (eph_bytes, ct) = rest.split_at(32);
    let eph_pub: [u8; 32] = eph_bytes.try_into().unwrap();
    let eph_pub = PublicKey::from(eph_pub);
    let key = box_key(&recipient.secret, &eph_pub, &recipient.public);
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    c.decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("decrypt (не та пара или повреждено)"))
}
