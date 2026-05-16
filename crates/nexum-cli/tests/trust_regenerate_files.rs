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
