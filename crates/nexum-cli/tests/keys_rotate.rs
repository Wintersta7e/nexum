//! End-to-end: nexum keys rotate appends a `KeyAdded` event, regenerates signer
//! files, signs the commit with the OLD (still-trusted) key, verifies
//! post-commit, and only then updates git config's user.signingkey.

mod common;

#[test]
fn rotate_adds_a_keyadded_event_with_old_key_signing() {
    let home = common::TestHome::initialized_no_index();

    // Generate a fresh ed25519 keypair to rotate in. Place it under the
    // nexum home dir so we have a stable path that is inside the tempdir.
    let new_key = home.path().join("rotation-1");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&new_key)
        .status()
        .expect("ssh-keygen available");
    assert!(status.success(), "ssh-keygen did not generate a keypair");

    let notebook_git_config = home.path().join("notebook.git/.git/config");
    let signingkey_before = std::fs::read_to_string(&notebook_git_config).unwrap();

    let out = home.run(&[
        "keys",
        "rotate",
        "--new-key",
        new_key.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        out.status.success(),
        "exited non-zero:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "keys.rotate.completed");

    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let events = std::fs::read_to_string(events_yml).unwrap();
    assert!(
        events.contains("KeyAdded"),
        "events.yml must contain KeyAdded"
    );

    let signingkey_after = std::fs::read_to_string(&notebook_git_config).unwrap();
    assert_ne!(
        signingkey_before, signingkey_after,
        "user.signingkey must have been updated to the new key"
    );
}

#[test]
fn rotate_duplicate_fingerprint_returns_error() {
    let home = common::TestHome::initialized_no_index();

    // The bootstrap key's public key lives in events.yml. Extract it via
    // parsing so we can attempt to rotate in the same key.
    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let _raw = std::fs::read_to_string(&events_yml).unwrap();

    // Extract the public_key value from the YAML (it is the bootstrap key).
    // Rather than parsing YAML in the test, write the public key to a temp
    // file and pass it as `--new-key`. We just need any key that already
    // appears in events.yml — the bootstrap key's pub file is at the path
    // git config recorded in user.signingkey.
    let notebook_git_config = home.path().join("notebook.git/.git/config");
    let config_text = std::fs::read_to_string(&notebook_git_config).unwrap();
    // Extract `signingkey = <path>` from the config.
    let signing_key_path = config_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("signingkey = "))
        .expect("signingkey in git config")
        .trim()
        .to_owned();

    // Attempt to rotate with the same key that is already in events.yml.
    let out = home.run(&["keys", "rotate", "--new-key", &signing_key_path, "--json"]);
    assert!(
        !out.status.success(),
        "expected failure for duplicate key:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    // ErrorEnvelope carries error_code / message / context — no `ok` field
    // (that's only on the inline JSON envelopes some handlers emit). A
    // duplicate-key error surfaces under STORE_INTEGRITY with the trust
    // discriminator + DuplicateKey subkind.
    assert_eq!(payload["error_code"], "STORE_INTEGRITY");
    assert_eq!(payload["context"]["kind"], "trust");
    assert!(
        payload["message"]
            .as_str()
            .is_some_and(|m| m.contains("duplicate") || m.contains("Duplicate")),
        "message should mention duplicate: {payload:#}"
    );
}

/// Generate a fresh ed25519 keypair at `<home>/<name>` and return the path
/// to the private key file. `<name>.pub` ends up alongside it.
fn fresh_keypair(home_path: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = home_path.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&path)
        .status()
        .expect("ssh-keygen available");
    assert!(status.success(), "ssh-keygen did not generate a keypair");
    path
}

#[test]
fn rotate_refuses_during_in_progress_merge() {
    let home = common::TestHome::initialized_no_index();
    let new_key = fresh_keypair(home.path(), "rotation-2");

    // Stage a fake in-progress merge by writing notebook.git/.git/MERGE_HEAD.
    // The verb must refuse before any trust-state mutation.
    let merge_head = home.path().join("notebook.git/.git/MERGE_HEAD");
    std::fs::write(&merge_head, "deadbeef\n").unwrap();

    let out = home.run(&[
        "keys",
        "rotate",
        "--new-key",
        new_key.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "expected non-zero with MERGE_HEAD present:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    // Operator-fixable refusal (commit/abort the merge first) → USAGE,
    // not STORE_INTEGRITY (which the spec reserves for actual store damage).
    assert_eq!(payload["error_code"], "USAGE");
    let msg = payload["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("merge") || msg.contains("MERGE_HEAD"),
        "message should flag the in-progress merge: {msg}"
    );

    // Trust state untouched.
    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let events = std::fs::read_to_string(&events_yml).unwrap();
    assert!(
        !events.contains("KeyAdded"),
        "events.yml must NOT carry a KeyAdded after a refused rotation"
    );
}

#[test]
fn rotate_refuses_when_bootstrap_key_already_revoked() {
    let home = common::TestHome::initialized_no_index();
    let new_key = fresh_keypair(home.path(), "rotation-3");

    // Read the bootstrap fingerprint from config.toml and append a
    // KeyRotatedOut event for it to events.yml in the worktree. This
    // simulates the operator having already revoked the current bootstrap
    // key via some other path; rotation would commit-then-fail-verify, so
    // the pre-flight refuses up-front.
    let cfg_raw = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    let bootstrap_fp = cfg_raw
        .lines()
        .find_map(|l| l.trim().strip_prefix("fingerprint ="))
        .expect("[trust.bootstrap].fingerprint in config.toml")
        .trim()
        .trim_matches('"')
        .to_owned();
    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let original = std::fs::read_to_string(&events_yml).unwrap();
    let appended = format!(
        "{original}\n- event_id: 0192f000-0000-7000-a000-000000000099\n  kind: KeyRotatedOut\n  fingerprint: \"{bootstrap_fp}\"\n  reason: \"test pre-revocation\"\n"
    );
    std::fs::write(&events_yml, appended).unwrap();

    let out = home.run(&[
        "keys",
        "rotate",
        "--new-key",
        new_key.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "expected non-zero when bootstrap key is revoked:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    // Pre-flight refusal (operator recovers via `keys recover --reanchor`)
    // → USAGE, not STORE_INTEGRITY.
    assert_eq!(payload["error_code"], "USAGE");
    let msg = payload["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("no longer trusted") || msg.contains("recover"),
        "message should point at the recovery path: {msg}"
    );
}

#[test]
fn rotate_succeeds_after_bootstrap_pin_revoked_when_distinct_active_signer_exists() {
    // After a successor key has been rotated in and the operator legitimately
    // revokes the original bootstrap key, `keys rotate` must still let them
    // add further keys — the preflight checks the CURRENT git signer, not the
    // bootstrap pin. Regression test for the keys_rotate preflight that used
    // to refuse on bootstrap-pin revocation regardless of signer state.
    //
    // initialized_clean (not _no_index) — the revoke verb's KeyStateView
    // projection needs the index DB.
    let home = common::TestHome::initialized_clean();

    // Rotate K2 in. After this, user.signingkey points at K2 and both K1+K2
    // are Active.
    let k2 = fresh_keypair(home.path(), "rotation-k2");
    let out = home.run(&[
        "keys",
        "rotate",
        "--new-key",
        k2.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        out.status.success(),
        "rotate K2 failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Read K1's fingerprint from the bootstrap pin and revoke it via the
    // public CLI surface (NOT a hand-edit of events.yml — the test exercises
    // the real revoke path that the operator would use).
    let cfg_raw = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    let k1_fp = cfg_raw
        .lines()
        .find_map(|l| l.trim().strip_prefix("fingerprint ="))
        .expect("[trust.bootstrap].fingerprint in config.toml")
        .trim()
        .trim_matches('"')
        .to_owned();
    let out = home.run(&["keys", "revoke", &k1_fp, "--rotation", "--json"]);
    assert!(
        out.status.success(),
        "revoke K1 failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Now rotate K3 in. Pre-fix this would refuse with USAGE because the
    // preflight saw the revoked bootstrap pin; post-fix it sees the CURRENT
    // signer (K2, still Active) and proceeds.
    let k3 = fresh_keypair(home.path(), "rotation-k3");
    let out = home.run(&[
        "keys",
        "rotate",
        "--new-key",
        k3.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        out.status.success(),
        "rotate K3 after bootstrap-pin revoke should succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "keys.rotate.completed");
}

// TODO: rotate verify-failure rollback path is not yet covered end-to-end.
// Triggering a verify failure deterministically from a test requires either
// a stubbed git_verify_commit_with_signers or constructing a commit signed
// by a key absent from historical_signers — both need harness work outside
// the scope of these tests. The rollback helpers themselves
// (`rollback_last_commit`, `restore_paths_from_head`, `surface_rollback_err`)
// are exercised on the commit-failure path (the duplicate-fingerprint test)
// and on the regenerate-failure path; only the verify-failure branch is
// uncovered by an integration test.
