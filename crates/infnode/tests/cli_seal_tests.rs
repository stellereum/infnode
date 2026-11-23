//! CLI owner-sealed storage wiring (W9-3 leftover).
//!
//! `infnode storage-put` / `storage-get` used to write the public
//! content-derived-key format (data key in the manifest). This suite pins the
//! new contract: `storage-put` seals to an owner ML-KEM-768 ek (flag, or the
//! node's own key when omitted), the manifest carries `seal` + `key_box` and
//! NEVER a plaintext `key`, and only the matching owner seed can read it back.

use infnode::config::{self, NodeConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::mailbox::MailKeys;
use infnode::node::BLOB_SEAL_V1;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-cli-seal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

fn cfg(name: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
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

fn setup(tag: &str) -> PathBuf {
    let dir = tmpdir(tag);
    NodeKeys::generate().save(&dir.join("keys")).expect("keys");
    let _ = PqKeys::load_or_generate(&dir.join("keys")).expect("pq keys");
    config::save(&dir.join("node.yaml"), &cfg(tag)).expect("config");
    dir
}

fn infnode_bin() -> &'static str {
    env!("CARGO_BIN_EXE_infnode")
}

fn run(args: &[&str]) -> (bool, String, String) {
    run_full(args, &[], None)
}

/// Run the binary with a clean owner-key environment and optional env/stdin.
/// Removes `INFNODE_OWNER_KEY` so an ambient value cannot make a negative
/// test accidentally pass (or a positive one use a foreign key).
fn run_full(args: &[&str], envs: &[(&str, &str)], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(infnode_bin());
    cmd.args(args).env_remove("INFNODE_OWNER_KEY");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if let Some(input) = stdin {
        use std::io::Write;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn infnode");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .expect("write owner key to stdin");
        let out = child.wait_with_output().expect("wait infnode");
        return (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        );
    }
    let out = cmd.output().expect("spawn infnode");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn cli_storage_put_seals_to_the_owner_key_and_get_requires_it() {
    let dir = setup("roundtrip");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("plain.txt");
    let payload = b"owner-sealed CLI payload -- not decryptable by storage peers";
    std::fs::write(&src, payload).expect("input");

    let owner = MailKeys::generate();
    let owner_ek = hex::encode(&owner.kem_ek);
    let owner_seed = hex::encode(owner.kem_seed);

    let (ok, stdout, stderr) = run(&[
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--file",
        src.to_str().unwrap(),
        "--owner-ek",
        &owner_ek,
        "--owner-key",
        &owner_seed,
    ]);
    assert!(ok, "storage-put failed: {stdout}\n{stderr}");
    assert!(
        stderr.contains("--owner-key is DEPRECATED"),
        "the argv form must warn loudly: {stderr}"
    );
    assert!(
        stdout.contains("sealed=owner"),
        "put must report owner sealing: {stdout}"
    );
    assert!(
        stdout.contains("replicas=1"),
        "put must report the real replica count (this node stores the bucket): {stdout}"
    );

    // The manifest on disk must be owner-sealed: seal marker + key_box, and
    // no plaintext data key.
    let kv_path = dir.join("kv.json");
    let kv = std::fs::read_to_string(&kv_path).expect("kv.json flushed by CLI");
    assert!(
        kv.contains(BLOB_SEAL_V1),
        "manifest must carry the {BLOB_SEAL_V1} seal marker"
    );
    assert!(
        kv.contains("key_box"),
        "data key must be wrapped to the owner key"
    );
    assert!(
        !kv.contains("\"key\":\""),
        "owner-sealed manifest must not contain a plaintext data key"
    );

    // Owner can read it back.
    let out = dir.join("out.txt");
    let (ok, stdout, stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--out",
        out.to_str().unwrap(),
        "--owner-key",
        &owner_seed,
    ]);
    assert!(ok, "storage-get failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    // A different owner key cannot open it (and the plain fallback must not
    // silently return the sealed bytes).
    let attacker = MailKeys::generate();
    let attacker_seed = hex::encode(attacker.kem_seed);
    let out2 = dir.join("attacker.txt");
    let (_ok, stdout, _stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--out",
        out2.to_str().unwrap(),
        "--owner-key",
        &attacker_seed,
    ]);
    assert!(
        stdout.contains("owner key refused") || stdout.contains("blob not found"),
        "non-owner get must refuse, got: {stdout}"
    );
    assert!(!Path::new(&out2).exists(), "non-owner must write no output");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_storage_put_defaults_to_the_node_owner_key() {
    let dir = setup("default-key");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("payload.bin");
    let payload = vec![0xA5u8; 4096];
    std::fs::write(&src, &payload).expect("input");

    let (ok, stdout, stderr) = run(&[
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "default.bin",
        "--file",
        src.to_str().unwrap(),
    ]);
    assert!(ok, "storage-put failed: {stdout}\n{stderr}");
    assert!(stdout.contains("sealed=owner"), "{stdout}");
    assert!(
        stdout.contains("replicas=1"),
        "default owner path must report its local replica: {stdout}"
    );

    // Even without --owner-key the CLI uses the node's own KEM seed, which
    // matches the default owner ek, so the round trip succeeds.
    let out = dir.join("out.bin");
    let (ok, stdout, stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "default.bin",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "storage-get failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

/// L1: the owner seed must be usable from a 0600 file and from stdin, never
/// only from argv.
#[test]
fn cli_owner_key_file_and_stdin_round_trip() {
    let dir = setup("owner-key-file");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("plain.txt");
    let payload = b"owner key from a 0600 file, not from ps";
    std::fs::write(&src, payload).expect("input");

    let owner = MailKeys::generate();
    let owner_ek = hex::encode(&owner.kem_ek);
    let owner_seed = hex::encode(owner.kem_seed);
    let key_file = dir.join("owner.seed");
    // Trailing whitespace must be tolerated (editors add a newline).
    std::fs::write(&key_file, format!("{owner_seed}\n")).expect("key file");
    #[cfg(unix)]
    set_mode(&key_file, 0o600);

    let (ok, stdout, stderr) = run(&[
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "file-key.txt",
        "--file",
        src.to_str().unwrap(),
        "--owner-ek",
        &owner_ek,
        "--owner-key-file",
        key_file.to_str().unwrap(),
    ]);
    assert!(
        ok,
        "storage-put via --owner-key-file failed: {stdout}\n{stderr}"
    );
    assert!(
        !stderr.contains("DEPRECATED"),
        "the file form must not emit the argv deprecation: {stderr}"
    );

    // Read it back with the seed on stdin (`--owner-key-file -`).
    let out = dir.join("out.txt");
    let (ok, stdout, stderr) = run_full(
        &[
            "storage-get",
            "--config",
            cfg_path.to_str().unwrap(),
            "--to",
            "test",
            "--name",
            "file-key.txt",
            "--out",
            out.to_str().unwrap(),
            "--owner-key-file",
            "-",
        ],
        &[],
        Some(&format!("{owner_seed}\n")),
    );
    assert!(ok, "storage-get via stdin failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

/// L1: `$INFNODE_OWNER_KEY` is the fallback when no file flag is given.
#[test]
fn cli_owner_key_env_round_trip() {
    let dir = setup("owner-key-env");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("plain.txt");
    let payload = b"owner key from the environment";
    std::fs::write(&src, payload).expect("input");

    let owner = MailKeys::generate();
    let owner_ek = hex::encode(&owner.kem_ek);
    let owner_seed = hex::encode(owner.kem_seed);

    let put_args = [
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "env-key.txt",
        "--file",
        src.to_str().unwrap(),
        "--owner-ek",
        &owner_ek,
    ];
    let (ok, stdout, stderr) = run_full(&put_args, &[("INFNODE_OWNER_KEY", &owner_seed)], None);
    assert!(ok, "storage-put via env failed: {stdout}\n{stderr}");

    let out = dir.join("out.txt");
    let (ok, stdout, stderr) = run_full(
        &[
            "storage-get",
            "--config",
            cfg_path.to_str().unwrap(),
            "--to",
            "test",
            "--name",
            "env-key.txt",
            "--out",
            out.to_str().unwrap(),
        ],
        &[("INFNODE_OWNER_KEY", &owner_seed)],
        None,
    );
    assert!(ok, "storage-get via env failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

/// L1: a missing, empty or group/world-readable key file must fail BEFORE
/// anything is stored, and must say why.
#[test]
fn cli_owner_key_file_fails_closed() {
    let dir = setup("owner-key-fail");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("plain.txt");
    std::fs::write(&src, b"must not be stored without a usable key").expect("input");
    let owner = MailKeys::generate();
    let owner_ek = hex::encode(&owner.kem_ek);
    let owner_seed = hex::encode(owner.kem_seed);

    let put = |key_file: &Path| {
        run(&[
            "storage-put",
            "--config",
            cfg_path.to_str().unwrap(),
            "--to",
            "test",
            "--name",
            "refused.txt",
            "--file",
            src.to_str().unwrap(),
            "--owner-ek",
            &owner_ek,
            "--owner-key-file",
            key_file.to_str().unwrap(),
        ])
    };

    // Missing file.
    let (ok, stdout, stderr) = put(&dir.join("does-not-exist"));
    assert!(!ok, "a missing owner key file must fail closed: {stdout}");
    assert!(
        stderr.contains("owner key file"),
        "the refusal must name the key file: {stderr}"
    );
    assert!(!stdout.contains("put ok"), "no success may be reported");

    // Empty file.
    let empty = dir.join("empty.seed");
    std::fs::write(&empty, "\n").expect("empty key file");
    #[cfg(unix)]
    set_mode(&empty, 0o600);
    let (ok, stdout, stderr) = put(&empty);
    assert!(!ok, "an empty owner key must fail closed: {stdout}");
    assert!(
        stderr.contains("empty"),
        "the refusal must say the key was empty: {stderr}"
    );
    assert!(!stdout.contains("put ok"));

    // Wrong length (not an ML-KEM-768 seed).
    let short = dir.join("short.seed");
    std::fs::write(&short, "deadbeef\n").expect("short key file");
    #[cfg(unix)]
    set_mode(&short, 0o600);
    let (ok, stdout, stderr) = put(&short);
    assert!(!ok, "a wrong-length owner key must fail closed: {stdout}");
    assert!(
        stderr.contains("64-byte ML-KEM-768 seed"),
        "the refusal must state the expected size: {stderr}"
    );
    assert!(!stdout.contains("put ok"));

    // Group/world-readable file (Unix only; mode bits are meaningless elsewhere).
    #[cfg(unix)]
    {
        let open = dir.join("open.seed");
        std::fs::write(&open, format!("{owner_seed}\n")).expect("open key file");
        set_mode(&open, 0o644);
        let (ok, stdout, stderr) = put(&open);
        assert!(!ok, "a 0644 owner key file must fail closed: {stdout}");
        assert!(
            stderr.contains("chmod 600"),
            "the refusal must tell the operator how to fix it: {stderr}"
        );
        assert!(!stdout.contains("put ok"));
    }

    // Nothing was stored by any of the refused attempts.
    let kv = std::fs::read_to_string(dir.join("kv.json")).unwrap_or_default();
    assert!(
        !kv.contains("refused.txt"),
        "fail-closed attempts must not write a manifest: {kv}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
