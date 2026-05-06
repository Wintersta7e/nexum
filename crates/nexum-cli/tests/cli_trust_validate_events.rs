//! CLI subprocess tests for `nexum trust validate-events`.

use tempfile::TempDir;

mod common;

#[test]
fn validate_events_clean_install_exits_zero() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let priv_key = common::write_ephemeral_keypair(&ssh_home);

    // init via subprocess so the bootstrap commit is signed and `events.yml`
    // is present; validate-events then walks zero tampering rows and exits 0.
    let init = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &[
            "init",
            "-y",
            "--ssh-key",
            priv_key.to_str().unwrap(),
            "--root",
            nexum_home.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        String::from_utf8_lossy(&init.stderr)
    );

    let out = common::run_nexum(&nexum_home, &ssh_home, &["trust", "validate-events"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 on clean install; stdout={}; stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("clean"),
        "expected 'clean' in human output; got: {stdout}"
    );
}

#[test]
fn validate_events_json_clean_install_emits_empty_array() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let priv_key = common::write_ephemeral_keypair(&ssh_home);

    let init = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &[
            "init",
            "-y",
            "--ssh-key",
            priv_key.to_str().unwrap(),
            "--root",
            nexum_home.to_str().unwrap(),
        ],
    );
    assert!(init.status.success());

    let out = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &["trust", "validate-events", "--json"],
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "[]");
}
