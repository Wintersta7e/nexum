//! Integration tests for `api::keys_recover`.
//!
//! Each test calls the real production path through `api::keys_recover`,
//! which exercises: preflight guards (sentinel, merge-head, chain-break ack,
//! Case A pin check, new-key-already-known check), the trust-file mutation +
//! signed-commit + verify loop, sentinel state machine, and pin update.
//!
//! All tests that sign commits run under a real notebook.git created by
//! `init_run`, with ephemeral SSH keypairs so no host key material is
//! required.

mod common;

use std::path::{Path, PathBuf};

use common::{write_ephemeral_keypair, NexumTestHome};
use nexum_core::{
    api::{self, RecoverCase},
    config::types::Config,
    init::{run as init_run, InitOpts},
    paths::Paths,
    trust::events::{load_events_yml, EventKind},
    trust::reanchor_pending::read_sentinel,
};

// ─── Fixture helpers ─────────────────────────────────────────────────────────

struct Fixture {
    _home: NexumTestHome,
    _key_dir: tempfile::TempDir,
    paths: Paths,
    cfg: Config,
    k1_path: PathBuf,
}

fn make_fixture() -> Fixture {
    let home = NexumTestHome::new().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let k1_path = write_ephemeral_keypair(key_dir.path());

    let outcome = init_run(InitOpts {
        ssh_key: Some(k1_path.clone()),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init succeeds");

    let paths = Paths::with_home(outcome.root);
    let cfg = Config::seed();

    Fixture {
        _home: home,
        _key_dir: key_dir,
        paths,
        cfg,
        k1_path,
    }
}

/// Write a second ephemeral keypair alongside K1. Returns the private-key path.
fn add_k2_keypair(key_dir: &Path) -> PathBuf {
    // Write a keypair with a different name so K1's files are not overwritten.
    use ssh_key::{rand_core::OsRng, Algorithm, PrivateKey};
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let pub_line = private.public_key().to_openssh().unwrap();
    let priv_path = key_dir.join("k2_ed25519");
    let pub_path = key_dir.join("k2_ed25519.pub");
    std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
    std::fs::write(&pub_path, pub_line.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    priv_path
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn recover_refused_when_acknowledge_chain_break_false() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    let result = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "lost key",
        false, // acknowledge_chain_break = false
    );
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::KeysRecoverChainBreakNotAcknowledged)
        ),
        "expected ChainBreakNotAcknowledged, got {result:?}"
    );
}

#[test]
fn recover_refused_when_sentinel_already_present() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    // Plant a sentinel before calling keys_recover.
    let sentinel_path = fix.paths.home.join(".reanchor_pending");
    std::fs::write(
        &sentinel_path,
        r#"{"case":"A","old_pin_fp":"SHA256:old","new_pin_fp":"SHA256:new",
           "new_pubkey":"ssh-ed25519 AAAA","started_at":"2026-05-01T00:00:00Z",
           "phase_completed":"init"}"#,
    )
    .unwrap();

    let result = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "lost key",
        true,
    );
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::KeysRecoverInProgress { .. })
        ),
        "expected InProgress, got {result:?}"
    );
    // Sentinel must still be present (not deleted by the preflight guard).
    assert!(
        sentinel_path.exists(),
        "sentinel must survive a refused call"
    );
}

#[test]
fn recover_refused_when_new_key_already_known() {
    let fix = make_fixture();

    // The K1 private key is already the bootstrap key — its fingerprint is in
    // events.yml. Passing K1 as the "new" key triggers the already-known check.
    let result = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &fix.k1_path,
        RecoverCase::B,
        "lost key",
        true,
    );
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::KeysRecoverNewKeyAlreadyKnown { .. })
        ),
        "expected NewKeyAlreadyKnown, got {result:?}"
    );
}

#[test]
fn recover_case_a_refused_when_pin_file_missing() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    // Delete the bootstrap-pin cache file so the Case A pin check fires.
    let pin_path = fix.paths.home.join(".bootstrap-fingerprint");
    if pin_path.exists() {
        std::fs::remove_file(&pin_path).unwrap();
    }

    let result = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::A,
        "rotating bootstrap",
        true,
    );
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::KeysRecoverPinMissingForCaseA { .. })
        ),
        "expected PinMissingForCaseA, got {result:?}"
    );
}

#[test]
fn recover_case_a_refused_when_pin_fp_mismatches_bootstrap() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    // Overwrite the pin cache with a stale/wrong fingerprint.
    let pin_path = fix.paths.home.join(".bootstrap-fingerprint");
    std::fs::write(&pin_path, "SHA256:wrong_fingerprint_abcdef").unwrap();

    let result = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::A,
        "rotating bootstrap",
        true,
    );
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::KeysRecoverPinMismatchForCaseA { .. })
        ),
        "expected PinMismatchForCaseA, got {result:?}"
    );
}

#[test]
fn recover_case_b_succeeds_and_rewrites_events_yml() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    let outcome = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "bootstrap key lost",
        true,
    )
    .expect("Case B recovery succeeds");

    // Outcome fields are populated.
    assert!(!outcome.old_fingerprint.is_empty());
    assert!(!outcome.new_fingerprint.is_empty());
    assert_ne!(outcome.old_fingerprint, outcome.new_fingerprint);
    assert!(!outcome.commit.is_empty());
    assert!(!outcome.regenerated_files.is_empty());
    assert!(outcome.regenerated_files.contains(&"events.yml".to_owned()));

    // events.yml must contain a BootstrapReanchor event.
    let events_yml = fix.paths.notebook_git.join(".trust/events.yml");
    let log = load_events_yml(&events_yml).expect("load events.yml");
    let has_reanchor = log.events.iter().any(|e| {
        matches!(
            &e.payload,
            EventKind::BootstrapReanchor {
                new_fingerprint,
                ..
            } if new_fingerprint == &outcome.new_fingerprint
        )
    });
    assert!(
        has_reanchor,
        "events.yml must contain a BootstrapReanchor event"
    );
}

#[test]
fn recover_case_b_updates_bootstrap_pin_in_config_and_cache() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    let old_fp = nexum_core::trust::pin::read_pin(&fix.paths.home)
        .expect("read initial pin")
        .fingerprint;

    let outcome = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "bootstrap key lost",
        true,
    )
    .expect("Case B recovery succeeds");

    // config.toml and the cache file must both carry the new fingerprint.
    let pin = nexum_core::trust::pin::read_pin(&fix.paths.home).expect("read updated pin");
    assert_eq!(pin.fingerprint, outcome.new_fingerprint);
    assert_ne!(pin.fingerprint, old_fp, "pin must have changed");
    assert!(
        !pin.cache_inconsistent,
        "cache must be consistent after recovery"
    );
}

#[test]
fn recover_case_b_deletes_sentinel_on_success() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "bootstrap key lost",
        true,
    )
    .expect("Case B recovery succeeds");

    // The sentinel must be gone after a successful recovery.
    let sentinel = read_sentinel(&fix.paths.home).expect("read_sentinel");
    assert!(
        sentinel.is_none(),
        "sentinel must be deleted after successful recovery"
    );
}

#[test]
fn recover_case_a_succeeds_with_matching_pin() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    // Ensure the pin cache file matches the actual bootstrap fp (init_run
    // writes it; verify it's consistent before the test).
    let pin_before =
        nexum_core::trust::pin::read_pin(&fix.paths.home).expect("read pin before Case A recovery");
    assert!(
        !pin_before.cache_inconsistent,
        "pin cache must be consistent before Case A recovery"
    );

    let outcome = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::A,
        "rotating bootstrap to new key",
        true,
    )
    .expect("Case A recovery succeeds");

    assert_eq!(outcome.case, RecoverCase::A);
    assert!(!outcome.commit.is_empty());
    assert!(outcome.regenerated_files.contains(&"events.yml".to_owned()));
}

#[test]
fn recover_case_a_updates_user_signingkey_to_new_key() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::A,
        "rotating bootstrap",
        true,
    )
    .expect("Case A recovery succeeds");

    // After Case A recovery, user.signingkey must point at K2.
    let out = std::process::Command::new("git")
        .args(["-C", fix.paths.notebook_git.to_str().unwrap()])
        .args(["config", "--local", "user.signingkey"])
        .output()
        .expect("git config");
    let current_signingkey = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert_eq!(
        current_signingkey,
        k2_path.display().to_string(),
        "user.signingkey must be updated to K2 after Case A recovery"
    );
}

#[test]
fn recover_case_b_idempotent_error_when_same_new_key_presented_twice() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    // First recovery succeeds.
    api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "bootstrap key lost",
        true,
    )
    .expect("first recovery succeeds");

    // Second attempt with the same new key must fail with NewKeyAlreadyKnown.
    let key_dir2 = tempfile::tempdir().unwrap();
    let k2_path2 = {
        // Copy K2's pub key to a new dir so the path is different but
        // fingerprint is the same.
        let pub_src = nexum_core::ssh_key::pub_path_for(&k2_path);
        let pub_dst = key_dir2.path().join("k2_ed25519.pub");
        std::fs::copy(&pub_src, &pub_dst).unwrap();
        let priv_dst = key_dir2.path().join("k2_ed25519");
        std::fs::copy(&k2_path, &priv_dst).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_dst, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        priv_dst
    };

    let result2 = api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path2,
        RecoverCase::B,
        "second attempt",
        true,
    );
    assert!(
        matches!(
            result2,
            Err(nexum_core::api::ApiError::KeysRecoverNewKeyAlreadyKnown { .. })
        ),
        "expected NewKeyAlreadyKnown on second attempt, got {result2:?}"
    );
}

#[test]
fn recover_sets_acknowledge_chain_anchor_lost_in_event() {
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::B,
        "bootstrap key lost",
        true,
    )
    .expect("recovery succeeds");

    let events_yml = fix.paths.notebook_git.join(".trust/events.yml");
    let log = load_events_yml(&events_yml).expect("load events.yml");
    let reanchor_event = log
        .events
        .iter()
        .find(|e| matches!(&e.payload, EventKind::BootstrapReanchor { .. }));
    let Some(ev) = reanchor_event else {
        panic!("BootstrapReanchor event not found in events.yml");
    };
    let EventKind::BootstrapReanchor {
        acknowledge_chain_anchor_lost,
        ..
    } = &ev.payload
    else {
        unreachable!()
    };
    assert!(
        acknowledge_chain_anchor_lost,
        "acknowledge_chain_anchor_lost must be true when the flag is passed"
    );
}

#[test]
fn recover_case_a_records_acknowledge_chain_anchor_lost_false() {
    // Case A preserves the bootstrap pin; pre-reanchor records remain
    // verifiable historicals (TrustBasis::PreReanchor + `pre-recovery-record`).
    // The event payload must therefore carry `acknowledge_chain_anchor_lost: false`
    // regardless of any operator acknowledgement passed at the API boundary.
    let fix = make_fixture();
    let key_dir = tempfile::tempdir().unwrap();
    let k2_path = add_k2_keypair(key_dir.path());

    api::keys_recover(
        &fix.paths,
        &fix.cfg,
        &k2_path,
        RecoverCase::A,
        "rotating bootstrap to new key",
        true,
    )
    .expect("Case A recovery succeeds");

    let events_yml = fix.paths.notebook_git.join(".trust/events.yml");
    let log = load_events_yml(&events_yml).expect("load events.yml");
    let Some(ev) = log
        .events
        .iter()
        .find(|e| matches!(&e.payload, EventKind::BootstrapReanchor { .. }))
    else {
        panic!("BootstrapReanchor event not found in events.yml");
    };
    let EventKind::BootstrapReanchor {
        acknowledge_chain_anchor_lost,
        ..
    } = &ev.payload
    else {
        unreachable!()
    };
    assert!(
        !acknowledge_chain_anchor_lost,
        "Case A must record acknowledge_chain_anchor_lost: false"
    );
}
