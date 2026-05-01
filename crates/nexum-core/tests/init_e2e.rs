//! End-to-end integration tests for `nexum init`.
//!
//! Each test generates an ephemeral ed25519 keypair via `ssh-key` (no committed
//! credentials), invokes `init::run`, and asserts the full artifact set.

mod common;

use nexum_core::{
    init::{InitOpts, run},
    trust::events::load_events_yml,
};
use ssh_key::{Algorithm, PrivateKey};
use std::path::{Path, PathBuf};

fn write_ephemeral_keypair(dir: &Path) -> PathBuf {
    use ssh_key::rand_core::OsRng;
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let pub_line = private.public_key().to_openssh().unwrap();
    let priv_path = dir.join("id_ed25519");
    let pub_path = dir.join("id_ed25519.pub");
    std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&pub_path, pub_line).unwrap();
    priv_path
}

fn do_init(home: &common::NexumTestHome) -> nexum_core::init::InitOutcome {
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init must succeed in e2e test")
}

#[test]
fn e2e_full_success_all_artifacts_exist() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);
    let root = outcome.root.clone();
    let nb = root.join("notebook.git");

    assert_eq!(outcome.bootstrap_commit_sha.len(), 40);
    assert!(outcome.fingerprint.starts_with("SHA256:"));

    // Trust files.
    assert!(nb.join(".trust").join("events.yml").exists());
    assert!(nb.join(".trust").join("historical_signers").exists());
    assert!(nb.join(".trust").join("allowed_signers").exists());
    assert!(nb.join(".trust").join("revoked_signers").exists());

    // Other artifacts.
    assert!(nb.join("META.yml").exists());
    assert!(root.join("config.toml").exists());
    assert!(root.join(".bootstrap-fingerprint").exists());
    assert!(root.join("models").is_dir());
    assert!(root.join("projects").is_dir());
    assert!(root.join("logs").is_dir());
}

#[test]
fn e2e_events_yml_has_one_bootstrap_key_event() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);
    let events_path = outcome
        .root
        .join("notebook.git")
        .join(".trust")
        .join("events.yml");
    let log = load_events_yml(&events_path).unwrap();
    assert_eq!(log.schema_version, 1);
    assert_eq!(log.events.len(), 1);
    assert!(matches!(
        log.events[0].payload,
        nexum_core::trust::events::EventKind::BootstrapKey { .. }
    ));
}

#[test]
fn e2e_bootstrap_commit_verifies_via_historical_signers() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);
    let nb = outcome.root.join("notebook.git");
    let historical = nb.join(".trust").join("historical_signers");

    // Run git verify-commit via shell to double-check the end-to-end path.
    let status = std::process::Command::new("git")
        .current_dir(&nb)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", historical.display()),
            "verify-commit",
            "HEAD",
        ])
        .status()
        .expect("git verify-commit must run");
    assert!(status.success(), "bootstrap commit must verify clean");
}

#[test]
fn e2e_rerun_without_force_returns_already_initialized() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);

    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let err = run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(outcome.root.clone()),
        force: false,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        nexum_core::init::InitError::AlreadyInitialized { .. }
    ));
}

#[test]
fn e2e_rerun_with_force_succeeds() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);

    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let second = run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(outcome.root),
        force: true,
    });
    assert!(second.is_ok(), "force rerun must succeed");
}

#[test]
fn e2e_missing_key_returns_error() {
    let home = common::NexumTestHome::new().unwrap();
    // No key files anywhere; no override path.
    let err = run(InitOpts {
        ssh_key: None,
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .unwrap_err();
    assert!(
        matches!(err, nexum_core::init::InitError::SshKey(_)),
        "expected SshKey error, got: {err}"
    );
}
