//! End-to-end: trust regenerate-files on an init-fresh store is a no-op
//! and exits 0; after tampering with a derived signer file, the command
//! re-derives and signs a commit.

mod common;

#[test]
fn regenerate_files_on_a_fresh_init_is_a_noop() {
    let home = common::TestHome::initialized_no_index();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        out.status.success(),
        "exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "trust.regenerate.noop");
}

#[test]
fn regenerate_files_after_worktree_tamper_restores_without_commit() {
    let home = common::TestHome::initialized_no_index();

    // Tamper: truncate allowed_signers so the worktree diverges from
    // events.yml. Since events.yml itself hasn't changed, the re-derived
    // content matches HEAD's committed copy of allowed_signers exactly,
    // so per spec the regeneration restores the worktree but emits no
    // commit ("no derived file actually changed" relative to HEAD).
    let allowed = home.path().join("notebook.git/.trust/allowed_signers");
    std::fs::write(&allowed, "").unwrap();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        out.status.success(),
        "exited non-zero: stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "trust.regenerate.noop");
    let regenerated = std::fs::read_to_string(&allowed).unwrap();
    assert!(
        !regenerated.is_empty(),
        "allowed_signers was restored to canonical content"
    );
}

#[test]
fn regenerate_files_refuses_during_in_progress_merge() {
    let home = common::TestHome::initialized_no_index();
    // Stage a fake in-progress merge by writing notebook.git/.git/MERGE_HEAD.
    let merge_head = home.path().join("notebook.git/.git/MERGE_HEAD");
    std::fs::write(&merge_head, "deadbeef\n").unwrap();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        !out.status.success(),
        "expected non-zero with MERGE_HEAD present:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["error_code"], "STORE_INTEGRITY");
    let msg = payload["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("merge") || msg.contains("MERGE_HEAD"),
        "message should flag the in-progress merge: {msg}"
    );
}

#[test]
fn regenerate_files_refuses_when_reanchor_pending() {
    let home = common::TestHome::initialized_no_index();
    // Write a `.reanchor_pending` sentinel — any phase will do for this
    // refusal test.
    let sentinel = home.path().join(".reanchor_pending");
    std::fs::write(
        &sentinel,
        r#"{
            "case": "A",
            "old_pin_fp": "SHA256:old",
            "new_pin_fp": "SHA256:new",
            "new_pubkey": "ssh-ed25519 AAAA",
            "started_at": "2026-05-16T00:00:00Z",
            "pid": null,
            "phase_completed": "init"
        }"#,
    )
    .unwrap();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        !out.status.success(),
        "expected non-zero with reanchor sentinel present"
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    // The reanchor sentinel surfaces as a Trust error (REANCHOR_PENDING
    // exit code 8).
    assert_eq!(payload["error_code"], "REANCHOR_PENDING");
}

#[test]
fn regenerate_files_after_uncommitted_events_emits_a_signed_commit() {
    let home = common::TestHome::initialized_no_index();

    // Append a new event to events.yml in the worktree (uncommitted). The
    // re-derived signer files will differ from HEAD (which was derived from
    // events.yml WITHOUT the new event), so regenerate-files lands a signed
    // commit covering the signer files. events.yml itself stays uncommitted
    // in the worktree — out of scope here; the spec covers signer-file
    // regeneration only.
    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let original = std::fs::read_to_string(&events_yml).unwrap();
    // Use a synthetic event_id distinct from any init-time one. We don't
    // need the event to be semantically realistic — just to alter the
    // events.yml-derived signer content.
    let appended = format!(
        "{original}\n- event_id: 0192f000-0000-7000-a000-0000000000aa\n  kind: KeyAdded\n  fingerprint: \"SHA256:test-fp-for-regenerate-coverage\"\n  public_key: \"ssh-ed25519 AAAAFakeKeyForTest test@example.invalid\"\n  reason: \"test setup for regenerate Committed-arm coverage\"\n"
    );
    std::fs::write(&events_yml, appended).unwrap();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0 for Committed arm:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "trust.regenerate.committed");
    assert!(
        payload["commit"].as_str().is_some_and(|s| !s.is_empty()),
        "Committed envelope must carry a commit sha: {payload:#}"
    );
    let files = payload["files"].as_array().expect("files array");
    assert!(
        files.iter().any(|f| f == "historical_signers")
            || files.iter().any(|f| f == "allowed_signers"),
        "Committed envelope should list the regenerated signer files: {payload:#}"
    );
}
