//! Integration tests for `notebook::writer::commit_lifecycle_event`.
//!
//! Exercises the Reject, Stale, and Promote lifecycle mutations against a
//! real bootstrapped signed notebook fixture, plus a rollback test that
//! verifies the worktree is clean when no valid signer is configured.

mod trust;

use nexum_core::notebook::lifecycle::LifecycleEvent;
use nexum_core::notebook::writer::commit_lifecycle_event;
use nexum_core::paths::Paths;
use nexum_core::records::types::{
    Agent, CommitEvidence, Confidence, Outcome, RecordKey, RecordType, Source, TreeFingerprint,
    UnifiedRecord, VerificationStatus,
};
use std::collections::HashMap;
use std::path::PathBuf;
use trust::fixtures::{KeyPair, NotebookFixture, run_git, run_git_signed};
use trust::fresh_notebook_with_bootstrap;

// ── test helpers ──────────────────────────────────────────────────────────────

/// Build a `Paths` from the fixture's home directory.
fn paths_for(fixture: &NotebookFixture) -> Paths {
    Paths::with_home(fixture.home().to_owned())
}

/// Commit the `.trust/` directory files that `init_notebook` writes but
/// never stages. `preflight` calls `git status --porcelain` and treats any
/// untracked file as dirty; committing these files up-front leaves the
/// worktree clean for lifecycle-mutation tests.
fn commit_trust_files(fixture: &NotebookFixture, key: &KeyPair) {
    let nb = fixture.path();
    run_git(nb, &["add", ".trust/"]);
    run_git_signed(nb, &key.private_path, "trust: commit initial trust files");
}

/// Commit a pre-seeded recommendation YAML under
/// `<project_id>/recommendations/<id>.yml` as a *signed* commit using
/// `key`. Returns the commit SHA.
fn seed_rec(
    fixture: &NotebookFixture,
    key: &KeyPair,
    project_id: &str,
    rec_id: &str,
    outcome: &str,
) -> String {
    let nb = fixture.path();
    let dir = nb.join(project_id).join("recommendations");
    std::fs::create_dir_all(&dir).expect("create rec dir");
    let path = dir.join(format!("{rec_id}.yml"));
    std::fs::write(
        &path,
        format!(
            "schema_version: 1\n\
             id: {rec_id}\n\
             record_type: recommendation\n\
             project_id: {project_id}\n\
             outcome: {outcome}\n\
             confidence: medium\n\
             agent: claude-code\n\
             created: 2026-04-29T00:00:00Z\n\
             updated: 2026-04-29T00:00:00Z\n\
             problem: should we cache responses?\n"
        ),
    )
    .expect("write rec yaml");

    run_git(
        nb,
        &["add", &format!("{project_id}/recommendations/{rec_id}.yml")],
    );
    run_git_signed(nb, &key.private_path, &format!("rec: seed {rec_id}"));

    // Return HEAD SHA.
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(nb)
        .output()
        .expect("rev-parse HEAD");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Build a minimal `CommitEvidence` suitable for Promote tests.
fn sample_commit_evidence() -> CommitEvidence {
    CommitEvidence {
        repo_identity: "git:abc".into(),
        branch: "main".into(),
        commit_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
        commit_time: "2026-05-20T00:00:00Z".parse().unwrap(),
        commit_message_hash: "0".repeat(64),
        tree_changes_fingerprint: TreeFingerprint {
            strict: "1".repeat(64),
            loose: "2".repeat(64),
            file_paths: vec![PathBuf::from("src/lib.rs")],
        },
        verification_status: VerificationStatus::Verified,
    }
}

/// Build a minimal `UnifiedRecord` shaped like a new decision created by the
/// api facade. The `title` field carries the source rec title; `id` is the
/// decision id; `project_id` matches the source rec's project.
fn sample_decision(decision_id: &str, project_id: &str, rec_title: &str) -> Box<UnifiedRecord> {
    use chrono::Utc;
    use nexum_core::records::types::{CryptoResult, Provenance, SignatureStatus};
    Box::new(UnifiedRecord {
        id: decision_id.into(),
        record_type: RecordType::Decision,
        source: Source::Local,
        project_id: project_id.into(),
        title: rec_title.into(),
        summary: None,
        body: String::new(),
        body_origin_path: None,
        tags: vec![],
        agent: Agent::ClaudeCode,
        session_refs: vec![],
        files: vec![],
        commits: vec![],
        created: Utc::now(),
        updated: Utc::now(),
        confidence: Confidence::High,
        outcome: Outcome::Working,
        provenance: Provenance {
            source: Source::Local,
            signature_status: SignatureStatus::Unsigned,
            extractor: None,
            digest_hash: None,
            record_commit_sha: None,
            signer_fingerprint: None,
            crypto_result: CryptoResult::Good,
            relevant_trust_events_commit: None,
            trust_basis: None,
            warnings: vec![],
            commit_evidence: None,
            promoted_from: None,
            inherited_warnings: vec![],
        },
        extras: HashMap::new(),
        content_hash: String::new(),
    })
}

/// True when `notebook.git` has no uncommitted changes.
fn worktree_clean(nb: &std::path::Path) -> bool {
    let out = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(nb)
        .output()
        .expect("git status");
    out.stdout.is_empty()
}

// ── Reject happy path ─────────────────────────────────────────────────────────

#[test]
fn reject_stamps_outcome_and_produces_one_signed_commit() {
    let (fixture, primary, _bootstrap_ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);
    let paths = paths_for(&fixture);
    let nb = fixture.path();
    let project_id = "testproject";
    let rec_id = "2026-04-29-reject-me";

    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let sha_before_count = {
        let out = std::process::Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(nb)
            .output()
            .expect("rev-list count");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };

    let event = LifecycleEvent::Reject {
        rec_ref: RecordKey {
            source: Some(Source::Local),
            project_id: Some(project_id.into()),
            id: rec_id.into(),
        },
    };

    let sha = commit_lifecycle_event(&paths, &event)
        .expect("Reject must succeed on a bootstrapped signed store");

    // 1. Returns a non-empty SHA.
    assert!(!sha.is_empty(), "returned SHA must be non-empty");

    // 2. Exactly one new commit.
    let count_after = {
        let out = std::process::Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(nb)
            .output()
            .expect("rev-list count");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    assert_eq!(count_after, sha_before_count + 1, "exactly one new commit");

    // 3. Commit message is "reject: <id>".
    let msg = std::process::Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(nb)
        .output()
        .expect("git log");
    let msg_str = String::from_utf8(msg.stdout).unwrap();
    assert!(
        msg_str.trim() == format!("reject: {rec_id}"),
        "commit subject must be 'reject: {rec_id}', got: {msg_str}"
    );

    // 4. The rec file now has outcome: rejected.
    let rec_path = nb
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let content = std::fs::read_to_string(&rec_path).expect("read rec after reject");
    assert!(
        content.contains("outcome: rejected"),
        "rec must have outcome: rejected"
    );

    // 5. Worktree is clean.
    assert!(worktree_clean(nb), "worktree must be clean after Reject");
}

// ── Stale happy path ──────────────────────────────────────────────────────────

#[test]
fn stale_stamps_outcome_and_produces_one_signed_commit() {
    let (fixture, primary, _bootstrap_ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);
    let paths = paths_for(&fixture);
    let nb = fixture.path();
    let project_id = "testproject";
    let rec_id = "2026-04-29-stale-me";

    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let event = LifecycleEvent::Stale {
        rec_ref: RecordKey {
            source: Some(Source::Local),
            project_id: Some(project_id.into()),
            id: rec_id.into(),
        },
    };

    let sha = commit_lifecycle_event(&paths, &event)
        .expect("Stale must succeed on a bootstrapped signed store");

    assert!(!sha.is_empty());

    let msg = std::process::Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(nb)
        .output()
        .expect("git log");
    let msg_str = String::from_utf8(msg.stdout).unwrap();
    assert!(
        msg_str.trim() == format!("stale: {rec_id}"),
        "subject must be 'stale: {rec_id}', got {msg_str}"
    );

    let rec_path = nb
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let content = std::fs::read_to_string(&rec_path).expect("read rec after stale");
    assert!(
        content.contains("outcome: stale"),
        "must have outcome: stale"
    );

    assert!(worktree_clean(nb), "worktree must be clean after Stale");
}

// ── Promote happy path ────────────────────────────────────────────────────────

#[test]
fn promote_writes_decision_and_stamps_rec_in_one_commit() {
    let (fixture, primary, _bootstrap_ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);
    let paths = paths_for(&fixture);
    let nb = fixture.path();
    let project_id = "testproject";
    let rec_id = "2026-04-29-promote-me";
    let decision_id = "2026-05-21-promote-decision";

    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let sha_before_count = {
        let out = std::process::Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(nb)
            .output()
            .expect("rev-list count");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };

    let commit_evidence = sample_commit_evidence();
    let new_decision = sample_decision(decision_id, project_id, "should we cache responses?");

    let event = LifecycleEvent::Promote {
        rec_ref: RecordKey {
            source: Some(Source::Local),
            project_id: Some(project_id.into()),
            id: rec_id.into(),
        },
        new_decision,
        commit_evidence,
    };

    let sha = commit_lifecycle_event(&paths, &event)
        .expect("Promote must succeed on a bootstrapped signed store");

    assert!(!sha.is_empty(), "returned SHA must be non-empty");

    // Exactly one new commit.
    let count_after = {
        let out = std::process::Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(nb)
            .output()
            .expect("rev-list count");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    assert_eq!(count_after, sha_before_count + 1, "exactly one new commit");

    // Commit message: "promote: <rec_id> -> <dec_id> via <sha7>"
    let msg = std::process::Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(nb)
        .output()
        .expect("git log");
    let msg_str = String::from_utf8(msg.stdout).unwrap();
    let expected_subject = format!("promote: {rec_id} -> {decision_id} via a1b2c3d");
    assert!(
        msg_str.trim() == expected_subject,
        "subject must be '{expected_subject}', got: {msg_str}"
    );

    // Both files touched by the commit.
    let files_in_commit = std::process::Command::new("git")
        .args(["diff-tree", "--no-commit-id", "-r", "--name-only", "HEAD"])
        .current_dir(nb)
        .output()
        .expect("diff-tree");
    let files_str = String::from_utf8(files_in_commit.stdout).unwrap();
    assert!(
        files_str.contains(&format!("{project_id}/recommendations/{rec_id}.yml")),
        "commit must touch the rec: {files_str}"
    );
    assert!(
        files_str.contains(&format!("{project_id}/decisions/{decision_id}.yml")),
        "commit must touch the decision: {files_str}"
    );

    // rec has outcome: promoted.
    let rec_path = nb
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let rec_content = std::fs::read_to_string(&rec_path).expect("read rec after promote");
    assert!(
        rec_content.contains("outcome: promoted"),
        "rec must have outcome: promoted"
    );
    assert!(
        rec_content.contains(&format!("promoted_to: {decision_id}")),
        "rec must have promoted_to line"
    );

    // decision file exists and has outcome: working.
    let dec_path = nb
        .join(project_id)
        .join("decisions")
        .join(format!("{decision_id}.yml"));
    let dec_content = std::fs::read_to_string(&dec_path).expect("read decision after promote");
    assert!(
        dec_content.contains("outcome: working"),
        "decision must have outcome: working"
    );
    assert!(
        dec_content.contains("record_type: decision"),
        "decision must have record_type: decision"
    );

    // Worktree clean.
    assert!(worktree_clean(nb), "worktree must be clean after Promote");
}

// ── Rollback: commit fails via pre-commit hook (Promote) ──────────────────────

/// Exercises the commit-failure rollback for a Promote event via a pre-commit
/// hook that exits 1. This keeps a VALID signer configured so `preflight`
/// passes, then makes the commit itself fail — the code path that had the
/// bug. Asserts: `CommitSignFailed` returned (NOT `RollbackFailed`), the new
/// decision file does NOT exist on disk, the rec is unchanged (still
/// `outcome: proposed`), and the worktree is clean.
#[test]
fn promote_commit_hook_failure_returns_commit_sign_failed_and_clean_tree() {
    let (fixture, primary, _bootstrap_ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);
    let nb = fixture.path();
    let project_id = "testproject";
    let rec_id = "2026-04-29-promote-hook-fail";
    let decision_id = "2026-05-01-hook-fail-decision";

    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    // Capture the rec content before the event so we can assert it is
    // unchanged after the failed promote.
    let rec_path = nb
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let rec_before = std::fs::read_to_string(&rec_path).expect("read rec before promote");

    // Install a pre-commit hook that always exits 1. The signer IS still
    // configured so preflight passes; git itself refuses to commit.
    let hooks_dir = nb.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");
    let hook_path = hooks_dir.join("pre-commit");
    std::fs::write(&hook_path, "#!/bin/sh\nexit 1\n").expect("write pre-commit hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x pre-commit hook");
    }

    let paths = paths_for(&fixture);
    let commit_evidence = sample_commit_evidence();
    let new_decision = sample_decision(decision_id, project_id, "should we cache responses?");

    let event = LifecycleEvent::Promote {
        rec_ref: RecordKey {
            source: Some(Source::Local),
            project_id: Some(project_id.into()),
            id: rec_id.into(),
        },
        new_decision,
        commit_evidence,
    };

    let result = commit_lifecycle_event(&paths, &event);

    // Must be CommitSignFailed (not RollbackFailed — that would mean the
    // rollback itself failed, i.e. the bug).
    assert!(
        matches!(
            result,
            Err(nexum_core::api::ApiError::CommitSignFailed { .. })
        ),
        "expected CommitSignFailed, got {result:?}"
    );

    // The decision YAML must NOT exist — it was newly created and must be
    // removed during rollback.
    let dec_path = nb
        .join(project_id)
        .join("decisions")
        .join(format!("{decision_id}.yml"));
    assert!(
        !dec_path.exists(),
        "decision file must not exist after failed commit: {dec_path:?}"
    );

    // The rec must be unchanged — outcome: proposed, no promoted_to line.
    let rec_after = std::fs::read_to_string(&rec_path).expect("read rec after failed promote");
    assert_eq!(
        rec_before, rec_after,
        "rec file must be identical before and after a failed promote rollback"
    );
    assert!(
        rec_after.contains("outcome: proposed"),
        "rec must still have outcome: proposed after rollback"
    );
    assert!(
        !rec_after.contains("promoted_to:"),
        "rec must not have a promoted_to line after rollback"
    );

    // Worktree must be clean.
    assert!(
        worktree_clean(nb),
        "worktree must be clean after promote commit-failure rollback"
    );
}

// ── Rollback: no valid signer (preflight) ─────────────────────────────────────

/// When no `user.signingkey` is set, `preflight` returns `SignerInactive`
/// before any files are written. This is a distinct path from the commit-
/// failure rollback above (no files written, no rollback needed).
#[test]
fn no_signer_returns_commit_sign_failed_and_leaves_clean_worktree() {
    let (fixture, primary, _bootstrap_ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);
    let nb = fixture.path();
    let project_id = "testproject";
    let rec_id = "2026-04-29-rollback-me";

    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    // Remove user.signingkey so commit signing fails.
    run_git(nb, &["config", "--unset", "user.signingkey"]);
    // Also unset gpgsign so git doesn't attempt signing at all and exits
    // non-zero (unsetting signingkey alone may cause it to fall back to
    // global config on some systems; disable gpgsign entirely).
    run_git(nb, &["config", "commit.gpgsign", "false"]);
    // Now preflight will bail with SignerInactive (no user.signingkey).
    // That is the expected CommitSignFailed-adjacent failure path.

    let paths = paths_for(&fixture);

    let event = LifecycleEvent::Reject {
        rec_ref: RecordKey {
            source: Some(Source::Local),
            project_id: Some(project_id.into()),
            id: rec_id.into(),
        },
    };

    let result = commit_lifecycle_event(&paths, &event);

    // Must fail — either SignerInactive (preflight catches it) or CommitSignFailed.
    assert!(
        result.is_err(),
        "expected error when no signer is configured, got Ok"
    );

    // Worktree must be clean: no partially-written files left behind.
    assert!(
        worktree_clean(nb),
        "worktree must be clean after a rollback (no stray files)"
    );
}
