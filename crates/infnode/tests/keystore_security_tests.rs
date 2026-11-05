//! Security hardening tests for the infnode keystore (keyring + mailbox).
//! Verifies: POSIX 0600/0700 permissions, Argon2id-encrypted `enc2:` format,
//! wrong-passphrase rejection, and save/load roundtrips.
//!
//! NOTE: env vars are process-global, so all passphrase-dependent checks live in
//! a single test to avoid cross-test races.

use std::os::unix::fs::PermissionsExt;

/// Serializes tests that mutate the process-global INFNODE_KEY_PASSPHRASE.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn keystore_hardening_roundtrip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("infnode_sec_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");

    // ---- 1. Plaintext mode: still must enforce 0600 / 0700 ----
    let keys = infnode::keyring::NodeKeys::generate();
    let id_hex = keys.id_hex();
    keys.save(&dir).unwrap();

    let file_mode = std::fs::metadata(dir.join("identity.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600, "identity.key must be owner-only (0600)");
    let e2e_mode = std::fs::metadata(dir.join("e2e.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(e2e_mode, 0o600, "e2e.key must be owner-only (0600)");
    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "keystore dir must be owner-only (0700)");

    let loaded = infnode::keyring::NodeKeys::load(&dir).unwrap();
    assert_eq!(loaded.id_hex(), id_hex, "identity must round-trip");

    // ---- 2. Encrypted mode: Argon2id `enc2:` format + wrong-passphrase rejection ----
    std::env::set_var("INFNODE_KEY_PASSPHRASE", "correct-horse-battery");
    let keys2 = infnode::keyring::NodeKeys::generate();
    let id2 = keys2.id_hex();
    keys2.save(&dir).unwrap();

    let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
    assert!(
        raw.starts_with("enc2:"),
        "encrypted key must use the Argon2id enc2 format"
    );
    assert!(
        !raw.contains(&id2),
        "plaintext must never leak into the encrypted file"
    );

    let loaded2 = infnode::keyring::NodeKeys::load(&dir).unwrap();
    assert_eq!(loaded2.id_hex(), id2, "encrypted identity must round-trip");

    std::env::set_var("INFNODE_KEY_PASSPHRASE", "wrong-password");
    assert!(
        infnode::keyring::NodeKeys::load(&dir).is_err(),
        "wrong passphrase must be rejected (AEAD integrity)"
    );

    // ---- 3. Mailbox keys: encrypted + 0600 ----
    std::env::set_var("INFNODE_KEY_PASSPHRASE", "mail-passphrase");
    let mk = infnode::mailbox::MailKeys::generate();
    let ed = mk.ed_hex();
    mk.save(&dir, "alice@example.com").unwrap();

    let mk_path = dir.join("alice@example.com.key");
    let mk_mode = std::fs::metadata(&mk_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mk_mode, 0o600, "mailbox key must be owner-only (0600)");
    let mk_raw = std::fs::read_to_string(&mk_path).unwrap();
    assert!(mk_raw.starts_with("enc2:"), "mailbox key must be encrypted");
    assert!(!mk_raw.contains(&ed), "mailbox plaintext key must not leak");

    let mk2 = infnode::mailbox::MailKeys::load(&dir, "alice@example.com").unwrap();
    assert_eq!(mk2.ed_hex(), ed, "mailbox identity must round-trip");
    // FULL-PQ: KEM seal/open round-trip (X25519 removed).
    let msg = b"pq mailbox round-trip";
    let blob = infnode::mailbox::seal(&mk2.kem_ek, msg).expect("kem seal");
    let back = infnode::mailbox::open(&mk2, &blob).expect("kem open");
    assert_eq!(back, msg);

    std::env::remove_var("INFNODE_KEY_PASSPHRASE");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FULL-PQ wipe-compat: a fresh save round-trips the KEM encapsulation key,
/// and a legacy 32-byte (x25519) `e2e.key` is refused with a clear migration
/// error — never silently accepted as KEM material.
#[test]
fn keystore_kem_roundtrip_and_legacy_x25519_refused() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("INFNODE_KEY_PASSPHRASE");
    let dir = std::env::temp_dir().join(format!("infnode_kem_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let keys = infnode::keyring::NodeKeys::generate();
    assert_eq!(
        keys.kem_ek.len(),
        infnode::mailbox::KEM_EK_LEN,
        "KEM ek is 1184 bytes"
    );
    keys.save(&dir).unwrap();
    let back = infnode::keyring::NodeKeys::load(&dir).unwrap();
    assert_eq!(back.kem_ek, keys.kem_ek, "KEM ek must round-trip");
    assert_eq!(back.kem_seed, keys.kem_seed, "KEM seed must round-trip");
    // Legacy: 32-byte x25519 seed hex in e2e.key => loud migration refusal.
    std::fs::write(dir.join("e2e.key"), hex::encode([0x11u8; 32])).unwrap();
    let err = match infnode::keyring::NodeKeys::load(&dir) {
        Ok(_) => panic!("legacy x25519 e2e.key must fail"),
        Err(e) => format!("{e}"),
    };
    assert!(
        err.contains("legacy x25519 key refused"),
        "clear migration error, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A legacy `enc:` file (old iterated-blake3 format) must still be readable.
#[test]
fn legacy_enc_format_still_readable() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Build a legacy blob the same way the old code did.
    std::env::set_var("INFNODE_KEY_PASSPHRASE", "legacy-pass");

    let p = "legacy-pass";
    let mut h = blake3::hash(format!("infnode-key-v1:{p}").as_bytes());
    for _ in 0..65536 {
        h = blake3::hash(h.as_bytes());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&h.as_bytes()[..32]);

    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    let nonce = [7u8; 24];
    let c = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), b"deadbeef".as_ref())
        .unwrap();
    let mut blob = Vec::new();
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    let legacy = format!(
        "enc:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    );

    let out = infnode::keyring::unprotect(&legacy).unwrap();
    assert_eq!(out, "deadbeef", "legacy enc: files must remain readable");

    std::env::remove_var("INFNODE_KEY_PASSPHRASE");
}
