//! End-to-end integration tests for `nexum init`.
//!
//! Each test generates an ephemeral ed25519 keypair via `ssh-key` (no committed
//! credentials), invokes `init::run`, and asserts the full artifact set.

mod common;

use common::write_ephemeral_keypair;
use nexum_core::{
    config::types::Config,
    init::{InitOpts, run},
    trust::events::load_events_yml,
};

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

#[test]
fn bad_override_key_path_returns_ssh_key_error() {
    let home = common::NexumTestHome::new().unwrap();
    let root = home.path().join(".nexum");
    // Private key file exists but no .pub file.
    let fake_key = home.path().join("fake_key");
    std::fs::write(&fake_key, "PLACEHOLDER").unwrap();
    let err = run(InitOpts {
        ssh_key: Some(fake_key),
        root: Some(root),
        force: false,
    })
    .unwrap_err();
    assert!(
        matches!(err, nexum_core::init::InitError::SshKey(_)),
        "expected SshKey error for missing .pub file"
    );
}

#[test]
fn rollback_removes_partial_tree_on_ssh_error() {
    let home = common::NexumTestHome::new().unwrap();
    let root = home.path().join(".nexum");
    let fake_key = home.path().join("fake_key");
    std::fs::write(&fake_key, "PLACEHOLDER").unwrap();
    let _err = run(InitOpts {
        ssh_key: Some(fake_key),
        root: Some(root.clone()),
        force: false,
    });
    assert!(
        !root.exists(),
        "rollback must remove partial ~/.nexum on failure"
    );
}

#[test]
fn e2e_refused_rerun_leaves_existing_artifacts_intact() {
    let home = common::NexumTestHome::new().unwrap();
    let outcome = do_init(&home);

    // Read the commit SHA and fingerprint from the first run.
    let first_sha = outcome.bootstrap_commit_sha.clone();
    let first_fp = outcome.fingerprint.clone();

    // Attempt a second run — must fail.
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let _err = run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(outcome.root.clone()),
        force: false,
    });

    // First run's artifacts must still be present and unchanged.
    let pin = std::fs::read_to_string(outcome.root.join(".bootstrap-fingerprint")).unwrap();
    assert_eq!(
        pin.trim(),
        first_fp,
        "bootstrap pin must be unchanged after refused rerun"
    );

    let cfg_raw = std::fs::read_to_string(outcome.root.join("config.toml")).unwrap();
    let cfg: Config = toml::from_str(&cfg_raw).unwrap();
    assert_eq!(cfg.trust.bootstrap.fingerprint, first_fp);

    let log_raw = std::fs::read_to_string(
        outcome
            .root
            .join("notebook.git")
            .join(".trust")
            .join("events.yml"),
    )
    .unwrap();
    // Commit SHA is in git history, not events.yml — just confirm events.yml still readable.
    let _log: nexum_core::trust::events::EventLog = serde_yaml::from_str(&log_raw).unwrap();

    let _ = first_sha; // Referenced for clarity.
}
