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
