//! Integration tests for `nexum keys recover --reanchor` /
//! `--reanchor-without-pin`. Builds on the existing `TestHome` harness.

mod common;
use common::{write_named_keypair, TestHome};

/// Generate a fresh ed25519 keypair inside the test home's `.ssh` dir and
/// return the private-key path. The tag becomes the filename basename so
/// callers can place multiple keypairs alongside each other.
fn fresh_keypair(home: &TestHome, tag: &str) -> std::path::PathBuf {
    let ssh_dir = home.ssh_home().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).expect("mkdir ssh-home/.ssh");
    write_named_keypair(&ssh_dir, tag)
}

/// Read the bootstrap signing key path from the notebook.git config.
/// Mirrors the pattern in `keys_rotate.rs`.
fn bootstrap_signing_key_path(home: &TestHome) -> std::path::PathBuf {
    let notebook_git_config = home.path().join("notebook.git/.git/config");
    let config_text = std::fs::read_to_string(&notebook_git_config).unwrap();
    let path_str = config_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("signingkey = "))
        .expect("signingkey in git config")
        .trim()
        .to_owned();
    std::path::PathBuf::from(path_str)
}

#[test]
fn recover_case_a_happy_path_with_yes() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);

    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["kind"], "keys.recover.completed");
    assert_eq!(payload["case"], "A");
    assert_eq!(payload["pin_updated"], true);
    assert_eq!(payload["sentinel_state"], "removed");
    assert!(!home.path().join(".reanchor_pending").exists());
}

#[test]
fn recover_case_b_happy_path_with_yes() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Delete the pin cache to simulate Case B (pin lost).
    std::fs::remove_file(home.path().join(".bootstrap-fingerprint")).ok();

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor-without-pin",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-anchor-lost",
        "--yes",
        "--json",
    ]);

    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["case"], "B");
    assert_eq!(payload["pin_updated"], true);
    assert_eq!(payload["sentinel_state"], "removed");
}

#[test]
fn recover_case_a_without_ack_flag_refuses() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Missing --acknowledge-chain-break — clap requires it alongside --reanchor.
    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--yes",
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "clap requires should refuse missing --acknowledge-chain-break"
    );
}

#[test]
fn recover_case_b_without_ack_flag_refuses() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Missing --acknowledge-chain-anchor-lost — clap requires it alongside --reanchor-without-pin.
    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor-without-pin",
        k2_path.to_str().unwrap(),
        "--yes",
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "clap requires should refuse missing --acknowledge-chain-anchor-lost"
    );
}

#[test]
fn recover_case_a_with_missing_pin_emits_pin_missing_envelope() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Remove the bootstrap-fingerprint pin cache to trigger KEYS_RECOVER_PIN_MISSING_FOR_CASE_A.
    std::fs::remove_file(home.path().join(".bootstrap-fingerprint")).ok();

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected USAGE (exit 2)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["error_code"], "KEYS_RECOVER_PIN_MISSING_FOR_CASE_A");
}

#[test]
fn recover_case_a_with_pin_mismatch_emits_pin_mismatch_envelope() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Overwrite the pin cache with a bogus value to trigger KEYS_RECOVER_PIN_MISMATCH_FOR_CASE_A.
    std::fs::write(home.path().join(".bootstrap-fingerprint"), "SHA256:fake").unwrap();

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected STORE_INTEGRITY (exit 4)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        payload["error_code"],
        "KEYS_RECOVER_PIN_MISMATCH_FOR_CASE_A"
    );
}

#[test]
fn recover_refuses_when_sentinel_already_exists() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // Plant a reanchor_pending sentinel — the startup pre-check should fire
    // before recover-specific logic, yielding exit 8 (REANCHOR_PENDING).
    std::fs::write(
        home.path().join(".reanchor_pending"),
        r#"{"case":"A","old_pin_fp":"SHA256:x","new_pubkey":"ssh-ed25519 AAAA","started_at":"2026-05-20T12:00:00Z","phase_completed":"init"}"#,
    )
    .unwrap();

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(8),
        "expected REANCHOR_PENDING (exit 8)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn recover_refuses_when_new_key_already_known() {
    let home = TestHome::initialized_no_index();
    // Use the bootstrap key as the "new" key — it is already in events.yml.
    let bootstrap_path = bootstrap_signing_key_path(&home);

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        bootstrap_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected USAGE (exit 2)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["error_code"], "KEYS_RECOVER_NEW_KEY_ALREADY_KNOWN");
}

#[test]
fn recover_json_without_yes_refuses_usage() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    // --json but no --yes — CLI refuses before touching the api.
    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--json",
        // no --yes
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected USAGE (exit 2)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["error_code"], "USAGE");
}

#[test]
fn recover_clap_rejects_both_case_flags() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");
    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--reanchor-without-pin",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--acknowledge-chain-anchor-lost",
        "--yes",
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "clap mutex group must refuse both --reanchor and --reanchor-without-pin"
    );
}

#[test]
fn recover_case_a_success_envelope_contains_fingerprints_and_commit() {
    let home = TestHome::initialized_no_index();
    let k2_path = fresh_keypair(&home, "k2");

    let out = home.run(&[
        "keys",
        "recover",
        "--reanchor",
        k2_path.to_str().unwrap(),
        "--acknowledge-chain-break",
        "--yes",
        "--json",
    ]);

    assert!(out.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        payload["old_fingerprint"].as_str().is_some(),
        "old_fingerprint must be present"
    );
    assert!(
        payload["new_fingerprint"].as_str().is_some(),
        "new_fingerprint must be present"
    );
    assert!(
        payload["commit"].as_str().is_some(),
        "commit must be present"
    );
    assert!(
        payload["regenerated_files"].is_array(),
        "regenerated_files must be an array"
    );
    // old and new fingerprints must differ.
    assert_ne!(
        payload["old_fingerprint"], payload["new_fingerprint"],
        "old and new fingerprints must differ"
    );
}
