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
    // Operator-fixable refusal (commit/abort the merge first) → USAGE,
    // not STORE_INTEGRITY (which the spec reserves for actual store damage).
    assert_eq!(payload["error_code"], "USAGE");
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
fn regenerate_files_refuses_when_events_yml_is_dirty() {
    let home = common::TestHome::initialized_no_index();

    // Append a new event to events.yml in the worktree without committing.
    // Deriving signer files from this uncommitted source and signing a
    // commit over the projections would land a non-self-contained mutation
    // — the commit would reference content (the new event) that is not
    // part of any commit. The operator must commit events.yml first.
    let events_yml = home.path().join("notebook.git/.trust/events.yml");
    let original = std::fs::read_to_string(&events_yml).unwrap();
    let appended = format!(
        "{original}\n- event_id: 0192f000-0000-7000-a000-0000000000aa\n  kind: KeyAdded\n  fingerprint: \"SHA256:test-fp-for-regenerate-coverage\"\n  public_key: \"ssh-ed25519 AAAAFakeKeyForTest test@example.invalid\"\n  reason: \"test setup\"\n"
    );
    std::fs::write(&events_yml, appended).unwrap();

    let out = home.run(&["trust", "regenerate-files", "--json"]);
    assert!(
        !out.status.success(),
        "expected non-zero exit when events.yml is dirty:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["context"]["subkind"], "regenerate_refused");
    let reason = payload["context"]["reason"]
        .as_str()
        .expect("reason field present");
    assert!(
        reason.contains("events.yml") || reason.contains("uncommitted"),
        "refusal reason should mention events.yml or uncommitted state: {reason}",
    );
}
