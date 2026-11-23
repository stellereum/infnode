//! Storage confidentiality pinning (`docs/REVIEW_QUALITY.md` 1.1).
//!
//! The old bucket path derived its XChaCha20 key+nonce from PUBLIC data
//! (`bucket:name:H(plaintext)`), so anyone holding the manifest and the chunks
//! could decrypt. These tests pin the two guarantees we now claim:
//!
//! 1. `store_blob_boxed(.., Some(owner_ek), Some(owner_seed))` seals the
//!    payload to the owner's ML-KEM-768 key and MACs the manifest: a non-owner
//!    with the FULL stored blob (manifest + every chunk) cannot decrypt it,
//!    cannot forge/replace the manifest, and the owner can (`fetch_blob_owner`).
//! 2. `store_blob` (no owner key) remains at-rest OBFUSCATION, not encryption:
//!    its key is publicly derivable and a third party CAN decrypt it. That test
//!    exists so nobody re-labels the legacy path as E2E confidentiality.

use infnode::config::NodeConfig;
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::mailbox::MailKeys;
use infnode::node::{
    blob_content_hash, blob_key_nonce, blob_seal_aad, box_unwrap_key, e2e_decrypt, e2e_decrypt_aad,
    Node, StoreMailError, BLOB_SEAL_V1,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn cfg() -> NodeConfig {
    NodeConfig {
        name: "storage-seal-test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-seal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let dir = tmpdir(tag);
    let node = Node::new(
        cfg(),
        NodeKeys::generate(),
        PqKeys::generate(),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, dir)
}

fn sample_blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// Everything a storage node / DHT peer can see: manifest JSON + the ciphertext
/// bytes of every chunk referenced by it.
async fn stored_blob(
    node: &Arc<Node>,
    data_dir: &Path,
    bucket: &str,
    name: &str,
) -> (Value, Vec<u8>) {
    let mkey = Node::blob_manifest_key(bucket, name);
    let raw = node
        .get_local_kv(&mkey)
        .await
        .expect("manifest in local KV");
    let manifest: Value = serde_json::from_str(&raw).expect("manifest");
    let dir = data_dir.join("chunks").join(bucket);
    let mut ct = Vec::new();
    for c in manifest["chunks"].as_array().expect("chunks") {
        let id = c["id"].as_str().expect("chunk id");
        ct.extend_from_slice(&std::fs::read(dir.join(id)).expect("chunk on disk"));
    }
    (manifest, ct)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_sealed_blob_is_not_decryptable_by_a_non_owner() {
    let (node, dir) = test_node("owner-seal").await;
    let owner = MailKeys::generate();
    let attacker = MailKeys::generate();
    let blob = sample_blob(3000);

    let owner_ek_hex = hex::encode(&owner.kem_ek);
    let owner_seed_hex = hex::encode(owner.kem_seed);
    let attacker_seed_hex = hex::encode(attacker.kem_seed);

    let stored = node
        .store_blob_boxed(
            "files",
            "secret.bin",
            &blob,
            Some(&owner_ek_hex),
            Some(&owner_seed_hex),
        )
        .await;
    assert!(stored.chunks > 0, "owner-sealed store must persist chunks");
    assert!(stored.replicas > 0, "the local node keeps one replica");

    let (manifest, ct) = stored_blob(&node, &dir, "files", "secret.bin").await;
    assert_eq!(
        manifest["seal"].as_str(),
        Some(BLOB_SEAL_V1),
        "owner-sealed manifest must be marked"
    );
    assert!(
        manifest.get("key").is_none(),
        "owner-sealed manifest must NEVER carry a plaintext data key"
    );
    assert!(
        manifest["key_box"].is_object(),
        "data key must be wrapped to the owner's KEM key"
    );
    assert!(!ct.is_empty(), "full ciphertext is on disk");

    let content_hash = blob_content_hash(&blob);

    // 1. The exact break from the review: key derived from public data.
    let (public_key, public_nonce) = blob_key_nonce("files", "secret.bin", &content_hash);
    assert!(
        e2e_decrypt(&public_key, &public_nonce, &ct).is_err(),
        "publicly derived key must NOT open an owner-sealed blob"
    );

    // 2. A third party with their own ML-KEM key cannot unwrap key_box.
    assert!(
        box_unwrap_key(&manifest["key_box"], &attacker_seed_hex).is_err(),
        "key_box must only open with the owner's KEM seed"
    );

    // 3. Even the OWNER's data key fails on a different AAD (bucket/name/content
    //    binding): a blob moved to another bucket is not confidential material
    //    that decrypts elsewhere.
    let owner_data_key = box_unwrap_key(&manifest["key_box"], &owner_seed_hex).expect("owner box");
    let nonce = hex::decode(manifest["nonce"].as_str().expect("nonce")).expect("hex nonce");
    assert!(
        e2e_decrypt(&owner_data_key, &nonce, &ct).is_err(),
        "sealed blob must not open with empty AAD"
    );
    assert!(
        e2e_decrypt_aad(
            &owner_data_key,
            &nonce,
            &blob_seal_aad("other-bucket", "secret.bin", &content_hash),
            &ct
        )
        .is_err(),
        "sealed blob must not open under a different bucket/name/content AAD"
    );

    // 4. The public fetch API refuses to guess: no owner key => None.
    assert!(
        node.fetch_blob("files", "secret.bin").await.is_none(),
        "fetch_blob must not return owner-sealed data without the owner key"
    );
    // 5. A non-owner using the owner API is refused too.
    assert!(
        node.fetch_blob_owner("files", "secret.bin", &attacker_seed_hex)
            .await
            .is_none(),
        "a non-owner must not decrypt even with the full blob"
    );
    // 6. The owner (possessor of the ML-KEM seed) reads it back intact.
    assert_eq!(
        node.fetch_blob_owner("files", "secret.bin", &owner_seed_hex)
            .await
            .expect("owner fetch"),
        blob
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_public_key_path_is_obfuscation_not_encryption() {
    let (node, dir) = test_node("legacy-obfuscation").await;
    let blob = sample_blob(2500);

    let stored = node.store_blob("files", "public.bin", &blob).await;
    assert!(stored > 0);

    let (manifest, ct) = stored_blob(&node, &dir, "files", "public.bin").await;
    assert!(
        manifest.get("seal").is_none(),
        "unboxed store_blob is the legacy format"
    );

    // The manifest publishes the data key...
    let published = hex::decode(manifest["key"].as_str().expect("legacy key")).expect("hex key");
    assert_eq!(published.len(), 32);

    // ...and that key is reproducible from public inputs alone, i.e. a third
    // party decrypts the full stored blob. This is the documented guarantee:
    // at-rest obfuscation, NOT confidentiality/E2E.
    let (derived_key, derived_nonce) =
        blob_key_nonce("files", "public.bin", &blob_content_hash(&blob));
    assert_eq!(published, derived_key, "legacy key is public derivation");
    assert_eq!(
        e2e_decrypt(&derived_key, &derived_nonce, &ct).expect("third party decrypts"),
        blob,
        "legacy path is obfuscation only; never advertise it as encryption"
    );

    // It still round-trips for existing data.
    assert_eq!(
        node.fetch_blob("files", "public.bin").await.expect("fetch"),
        blob
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_owner_key_fails_closed_instead_of_storing_a_plaintext_key() {
    let (node, dir) = test_node("invalid-owner").await;
    let blob = b"must not be stored under a downgraded key".to_vec();

    let owner = MailKeys::generate();
    let stored = node
        .store_blob_boxed(
            "files",
            "downgrade.bin",
            &blob,
            Some("deadbeef"),
            Some(&hex::encode(owner.kem_seed)),
        )
        .await;
    assert_eq!(stored.chunks, 0, "invalid owner ek must be refused");
    assert!(
        node.get_local_kv(&Node::blob_manifest_key("files", "downgrade.bin"))
            .await
            .is_none(),
        "no manifest may be written on a refused owner-sealed store"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// PENTEST2 L2: `store_mail(_boxed|_ec)` used to fall back to writing the
/// plaintext data key when the owner ek could not be boxed. Pin the new
/// fail-closed contract: a typed error, no manifest, and no chunk written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_mail_with_unboxable_owner_key_fails_closed() {
    let (node, dir) = test_node("mail-invalid-owner").await;
    let blob = b"mail body that must never be stored unsealed".to_vec();

    let err = node
        .store_mail_boxed("mail:bad", &blob, Some("deadbeef"))
        .await
        .expect_err("an unboxable owner ek must be refused");
    assert_eq!(
        err,
        StoreMailError::InvalidOwnerKey,
        "the refusal must name the owner key, not degrade to a plaintext key"
    );
    assert!(
        node.get_local_kv("m:mail:bad").await.is_none(),
        "no mail manifest may be written on a refused owner-sealed store"
    );
    let chunk_dir = dir.join("chunks").join("mail");
    let chunks = std::fs::read_dir(&chunk_dir)
        .map(|it| it.count())
        .unwrap_or(0);
    assert_eq!(
        chunks, 0,
        "the key must be boxed (fail closed) BEFORE any chunk is written"
    );

    // The EC path has the same contract.
    let err = node
        .store_mail_ec("mail:bad-ec", &blob, Some("not-hex"), 3, 5)
        .await
        .expect_err("an unboxable owner ek must be refused on the EC path too");
    assert_eq!(err, StoreMailError::InvalidOwnerKey);
    assert!(node.get_local_kv("m:mail:bad-ec").await.is_none());

    // A valid owner key still produces a key_box and never a plaintext key.
    let owner = MailKeys::generate();
    let n = node
        .store_mail_boxed("mail:good", &blob, Some(&hex::encode(owner.kem_ek)))
        .await
        .expect("a valid owner ek must be accepted");
    assert!(n > 0, "stored chunks must be counted");
    let manifest = node
        .get_local_kv("m:mail:good")
        .await
        .expect("manifest written");
    assert!(
        manifest.contains("key_box"),
        "owner-sealed mail must wrap the data key"
    );
    assert!(
        !manifest.contains("\"key\":\""),
        "owner-sealed mail must never publish the plaintext data key"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_sealed_fetch_rejects_tampered_chunk() {
    let (node, dir) = test_node("seal-tamper").await;
    let owner = MailKeys::generate();
    let owner_ek_hex = hex::encode(&owner.kem_ek);
    let owner_seed_hex = hex::encode(owner.kem_seed);
    let blob = sample_blob(1800);

    node.store_blob_boxed(
        "files",
        "tamper.bin",
        &blob,
        Some(&owner_ek_hex),
        Some(&owner_seed_hex),
    )
    .await;
    let (mut manifest, _) = stored_blob(&node, &dir, "files", "tamper.bin").await;
    let first_id = manifest["chunks"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = dir.join("chunks").join("files").join(&first_id);
    let mut raw = std::fs::read(&path).expect("chunk");
    raw[0] ^= 0x80;
    std::fs::write(&path, &raw).expect("tamper write");

    // Make the manifest agree with the tampered bytes, so the refusal below is
    // the AEAD layer (not merely the plaintext-chunk-hash check). The background
    // replication task may restore the original chunk in parallel; then the
    // (patched) manifest hash mismatches instead. Both outcomes are fail-closed,
    // which is exactly the property this test pins.
    manifest["chunks"][0]["hash"] = serde_json::json!(hex::encode(blake3::hash(&raw).as_bytes()));
    node.kv_store_local_with_ttl(
        &Node::blob_manifest_key("files", "tamper.bin"),
        &manifest.to_string(),
        30 * 24 * 3600 * 1000,
    )
    .await;

    assert!(
        node.fetch_blob_owner("files", "tamper.bin", &owner_seed_hex)
            .await
            .is_none(),
        "tampered ciphertext must fail closed (chunk hash / AEAD)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// H2: a storage peer cannot downgrade a sealed manifest to the legacy
/// (plaintext-key) format, even if it replaces BOTH the manifest and the
/// chunk file on the victim's disk/DHT cache. The owner can still re-publish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealed_manifest_cannot_be_downgraded_by_a_peer() {
    let (node, dir) = test_node("seal-downgrade").await;
    let owner = MailKeys::generate();
    let owner_ek_hex = hex::encode(&owner.kem_ek);
    let owner_seed_hex = hex::encode(owner.kem_seed);
    let original = sample_blob(2600);
    let attacker_blob = b"attacker-controlled replacement".repeat(40);

    let report = node
        .store_blob_boxed(
            "files",
            "secret.bin",
            &original,
            Some(&owner_ek_hex),
            Some(&owner_seed_hex),
        )
        .await;
    assert!(report.chunks > 0 && report.replicas > 0);
    assert_eq!(
        node.fetch_blob_owner("files", "secret.bin", &owner_seed_hex)
            .await
            .expect("owner reads the sealed blob"),
        original
    );

    // A second node produces a self-consistent LEGACY manifest + chunks (the
    // exact bytes a malicious storage peer can serve).
    let (attacker, attacker_dir) = test_node("seal-downgrade-attacker").await;
    attacker
        .store_blob("files", "secret.bin", &attacker_blob)
        .await;
    let (legacy_manifest, legacy_ct) =
        stored_blob(&attacker, &attacker_dir, "files", "secret.bin").await;
    assert!(legacy_manifest.get("seal").is_none());
    assert!(legacy_manifest.get("key").is_some());

    // Overwrite the victim's local manifest AND every referenced chunk.
    node.kv_store_local_with_ttl(
        &Node::blob_manifest_key("files", "secret.bin"),
        &legacy_manifest.to_string(),
        30 * 24 * 3600 * 1000,
    )
    .await;
    let chunk_dir = dir.join("chunks").join("files");
    std::fs::create_dir_all(&chunk_dir).expect("chunk dir");
    for c in legacy_manifest["chunks"].as_array().expect("chunks") {
        let id = c["id"].as_str().expect("chunk id");
        let off = c["off"].as_u64().expect("off") as usize;
        let len = c["len"].as_u64().expect("len") as usize;
        std::fs::write(chunk_dir.join(id), &legacy_ct[off..off + len]).expect("inject chunk");
    }

    // Downgrade refused: the pin says this name is sealed, and an owner fetch
    // never falls back to an unauthenticated format.
    assert!(
        node.fetch_blob_owner("files", "secret.bin", &owner_seed_hex)
            .await
            .is_none(),
        "a legacy manifest must not downgrade a sealed blob"
    );
    assert!(
        node.fetch_blob("files", "secret.bin").await.is_none(),
        "a pinned sealed name must not be served through the legacy reader"
    );

    // The owner (same key) can re-publish and read again.
    let replacement = b"owner replacement v2".repeat(60);
    let report = node
        .store_blob_boxed(
            "files",
            "secret.bin",
            &replacement,
            Some(&owner_ek_hex),
            Some(&owner_seed_hex),
        )
        .await;
    assert!(report.chunks > 0, "owner re-publish must be accepted");
    assert_eq!(
        node.fetch_blob_owner("files", "secret.bin", &owner_seed_hex)
            .await
            .expect("owner reads the replacement"),
        replacement
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&attacker_dir);
}

/// H2: a DIFFERENT owner cannot replace (re-seal) a pinned sealed manifest;
/// the owner's bytes and manifest stay intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealed_manifest_replacement_requires_the_same_owner_key() {
    let (node, dir) = test_node("seal-replace").await;
    let owner = MailKeys::generate();
    let attacker = MailKeys::generate();
    let original = sample_blob(1900);

    let report = node
        .store_blob_boxed(
            "files",
            "owned.bin",
            &original,
            Some(&hex::encode(&owner.kem_ek)),
            Some(&hex::encode(owner.kem_seed)),
        )
        .await;
    assert!(report.chunks > 0);
    let mkey = Node::blob_manifest_key("files", "owned.bin");
    let before = node.get_local_kv(&mkey).await.expect("manifest");

    let stolen = node
        .store_blob_boxed(
            "files",
            "owned.bin",
            b"attacker bytes",
            Some(&hex::encode(&attacker.kem_ek)),
            Some(&hex::encode(attacker.kem_seed)),
        )
        .await;
    assert_eq!(
        stolen.chunks, 0,
        "another owner must not replace the manifest"
    );
    assert_eq!(
        node.get_local_kv(&mkey).await.expect("manifest"),
        before,
        "a refused replacement must not touch the stored manifest"
    );
    assert_eq!(
        node.fetch_blob_owner("files", "owned.bin", &hex::encode(owner.kem_seed))
            .await
            .expect("owner still reads"),
        original
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// M4: the manifest chunk table is bounded/validated before any network
/// lookup. An inconsistent `size`, a non-contiguous `off`, or a chunk count
/// beyond the hard cap is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_chunk_table_is_bounded_and_consistent() {
    let (node, dir) = test_node("seal-bounds").await;
    let blob = sample_blob(4096);
    node.store_blob("files", "bounds.bin", &blob).await;
    let mkey = Node::blob_manifest_key("files", "bounds.bin");
    let (good, _) = stored_blob(&node, &dir, "files", "bounds.bin").await;
    assert_eq!(
        node.fetch_blob("files", "bounds.bin").await.expect("fetch"),
        blob
    );

    // Declared size disagrees with the ciphertext length.
    let mut bad = good.clone();
    bad["size"] = serde_json::json!(blob.len() as u64 - 1);
    node.kv_store_local_with_ttl(&mkey, &bad.to_string(), 30 * 24 * 3600 * 1000)
        .await;
    assert!(
        node.fetch_blob("files", "bounds.bin").await.is_none(),
        "size/content-length mismatch must be refused"
    );

    // Non-contiguous offsets.
    let mut bad = good.clone();
    bad["chunks"][0]["off"] = serde_json::json!(1u64);
    node.kv_store_local_with_ttl(&mkey, &bad.to_string(), 30 * 24 * 3600 * 1000)
        .await;
    assert!(
        node.fetch_blob("files", "bounds.bin").await.is_none(),
        "non-contiguous chunk table must be refused"
    );

    // Chunk count beyond the hard cap (count alone is enough; no lookups).
    let mut bad = good.clone();
    let one = bad["chunks"][0].clone();
    let many: Vec<serde_json::Value> = (0..infnode::node::MAX_BLOB_CHUNKS + 1)
        .map(|i| {
            let mut c = one.clone();
            c["off"] = serde_json::json!((i * 1024 * 1024) as u64);
            c["len"] = serde_json::json!(1024 * 1024u64);
            c
        })
        .collect();
    bad["chunks"] = serde_json::json!(many);
    node.kv_store_local_with_ttl(&mkey, &bad.to_string(), 30 * 24 * 3600 * 1000)
        .await;
    assert!(
        node.fetch_blob("files", "bounds.bin").await.is_none(),
        "an over-cap chunk array must be refused"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
