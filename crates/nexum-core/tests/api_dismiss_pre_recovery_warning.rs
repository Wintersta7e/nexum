//! Unit tests for `api::dismiss_pre_recovery_warning` and `api::list_pre_recovery_acks`.

use std::fs;
use tempfile::TempDir;

use nexum_core::api;
use nexum_core::paths::Paths;

/// Build a minimal Paths rooted in `home`.
fn make_paths(home: &std::path::Path) -> Paths {
    Paths::with_home(home.to_path_buf())
}

#[test]
fn dismiss_creates_state_dir_on_first_write() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    let result =
        api::dismiss_pre_recovery_warning(&paths, &["pre-recovery-record".to_owned()]).unwrap();

    assert_eq!(result.added, vec!["pre-recovery-record"]);
    assert!(result.already_present.is_empty());
    assert!(result.total.contains(&"pre-recovery-record".to_owned()));
    assert!(paths.trust_warnings_acked.exists(), "state file created");
    assert!(
        paths.trust_warnings_acked.parent().unwrap().is_dir(),
        "state directory created"
    );
}

#[test]
fn dismiss_with_two_codes_returns_added_and_already_present_correctly() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    // First call acks one code.
    api::dismiss_pre_recovery_warning(&paths, &["pre-recovery-record".to_owned()]).unwrap();

    // Second call: tries to ack both, one already present.
    let result = api::dismiss_pre_recovery_warning(
        &paths,
        &[
            "pre-recovery-record".to_owned(),
            "chain-anchor-lost".to_owned(),
        ],
    )
    .unwrap();

    assert_eq!(result.added, vec!["chain-anchor-lost"]);
    assert_eq!(result.already_present, vec!["pre-recovery-record"]);
    assert!(result.total.contains(&"pre-recovery-record".to_owned()));
    assert!(result.total.contains(&"chain-anchor-lost".to_owned()));
}

#[test]
fn dismiss_is_idempotent_for_already_acked_codes() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    let codes = vec!["pre-recovery-record".to_owned()];
    api::dismiss_pre_recovery_warning(&paths, &codes).unwrap();

    let raw_first = fs::read_to_string(&paths.trust_warnings_acked).unwrap();
    let result = api::dismiss_pre_recovery_warning(&paths, &codes).unwrap();
    let raw_second = fs::read_to_string(&paths.trust_warnings_acked).unwrap();

    assert!(result.added.is_empty());
    assert_eq!(result.already_present, vec!["pre-recovery-record"]);
    assert_eq!(raw_first, raw_second, "file unchanged on idempotent ack");
}

#[test]
fn list_acks_returns_empty_when_file_absent() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    let acks = api::list_pre_recovery_acks(&paths).unwrap();
    assert!(acks.is_empty());
}

#[test]
fn list_acks_round_trips_through_dismiss() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    api::dismiss_pre_recovery_warning(
        &paths,
        &[
            "pre-recovery-record".to_owned(),
            "chain-anchor-lost".to_owned(),
        ],
    )
    .unwrap();

    let mut acks = api::list_pre_recovery_acks(&paths).unwrap();
    acks.sort();
    assert_eq!(acks, vec!["chain-anchor-lost", "pre-recovery-record"]);
}

#[test]
fn dismiss_with_malformed_existing_file_refuses() {
    let tmp = TempDir::new().unwrap();
    let paths = make_paths(tmp.path());

    // Pre-create a malformed file.
    fs::create_dir_all(paths.trust_warnings_acked.parent().unwrap()).unwrap();
    fs::write(&paths.trust_warnings_acked, "{not json").unwrap();

    let result = api::dismiss_pre_recovery_warning(&paths, &["pre-recovery-record".to_owned()]);

    match result {
        Err(api::ApiError::PreRecoveryAckFileMalformed { path, .. }) => {
            assert_eq!(path, paths.trust_warnings_acked);
        }
        other => panic!("expected PreRecoveryAckFileMalformed, got {other:?}"),
    }

    // File NOT overwritten on refusal.
    let raw = fs::read_to_string(&paths.trust_warnings_acked).unwrap();
    assert_eq!(raw, "{not json");
}
