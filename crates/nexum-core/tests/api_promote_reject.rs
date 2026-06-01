//! Integration tests for `api::promote` and `api::reject`.
//!
//! Uses a real bootstrapped signed notebook fixture plus a freshly-indexed
//! `SQLite` store so the full promote/reject call path exercises the facade,
//! writer, and index in concert.

mod trust;

use nexum_core::api::{PromoteParams, promote, reject};
use nexum_core::indexer::db::open_or_create;
use nexum_core::indexer::run::run as indexer_run;
use nexum_core::paths::Paths;
use std::process::Command;
use trust::fixtures::{KeyPair, NotebookFixture, run_git, run_git_signed};
use trust::fresh_notebook_with_bootstrap;

// ── helpers shared across tests ──────────────────────────────────────────────

fn paths_for(fixture: &NotebookFixture) -> Paths {
    Paths::with_home(fixture.home().to_owned())
}

/// Config with cc+codex disabled; local enabled. Matches the local adapter
/// path derived from `Paths::with_home`.
fn local_cfg() -> nexum_core::config::types::Config {
    let mut cfg = nexum_core::config::types::Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = true;
    cfg
}

/// Commit the `.trust/` files (untracked after `init_notebook`) so preflight
/// sees a clean worktree.
fn commit_trust_files(fixture: &NotebookFixture, key: &KeyPair) {
    let nb = fixture.path();
    run_git(nb, &["add", ".trust/"]);
    run_git_signed(nb, &key.private_path, "trust: commit initial trust files");
}

/// Seed a recommendation YAML to notebook.git and return its commit SHA.
fn seed_rec(
    fixture: &NotebookFixture,
    key: &KeyPair,
    project_id: &str,
    rec_id: &str,
    outcome: &str,
) {
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
             problem: should we cache responses?\n\
             title: Cache Responses\n"
        ),
    )
    .expect("write rec yaml");

    run_git(
        nb,
        &["add", &format!("{project_id}/recommendations/{rec_id}.yml")],
    );
    run_git_signed(nb, &key.private_path, &format!("rec: seed {rec_id}"));
}

/// Run the incremental indexer over the fixture's notebook, populating the
/// `SQLite` index so `api::get` can resolve records.
fn index_fixture(fixture: &NotebookFixture, cfg: &nexum_core::config::types::Config) {
    let paths = paths_for(fixture);
    let mut conn = open_or_create(&paths.index_db).expect("open index db");
    indexer_run(&mut conn, cfg, &paths).expect("index_run must succeed");
}

/// Build a throwaway unsigned git repo with two commits on `main`.
/// Returns `(sha1, sha2)` where sha2 is HEAD.
fn init_project_repo(dir: &std::path::Path) -> (String, String) {
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(args)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-b", "main"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Test"]);
    std::fs::write(dir.join("a.txt"), "hello").unwrap();
    run(&["add", "a.txt"]);
    run(&["commit", "--no-gpg-sign", "-m", "first commit"]);
    let sha1 = sha_of(dir, "HEAD");
    std::fs::write(dir.join("b.txt"), "world").unwrap();
    run(&["add", "b.txt"]);
    run(&["commit", "--no-gpg-sign", "-m", "second commit"]);
    let sha2 = sha_of(dir, "HEAD");
    (sha1, sha2)
}

fn sha_of(dir: &std::path::Path, rev: &str) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(["rev-parse", rev])
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

// ── tests ────────────────────────────────────────────────────────────────────

/// `--skip-fingerprint` promote works even when the project repo is unreachable
/// (dummy path). Produces `Unknown` evidence. A decision is created and the rec
/// is stamped as `promoted`.
#[test]
fn skip_fingerprint_promote_succeeds_with_dummy_repo() {
    let (fixture, primary, _ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);

    let project_id = "name:testproject";
    let rec_id = "2026-04-29-cache-recs";
    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let cfg = local_cfg();
    index_fixture(&fixture, &cfg);

    let paths = paths_for(&fixture);
    let params = PromoteParams {
        rec: rec_id,
        commit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        repo: None, // not consulted under skip_fingerprint
        branch: Some("main"),
        skip_fingerprint: true,
        force_untrusted: true, // rec is unsigned in this test store
    };

    let outcome = promote(&paths, &cfg, &params).expect("skip_fingerprint promote must succeed");

    assert!(!outcome.decision_id.is_empty(), "decision_id must be set");
    assert!(
        !outcome.notebook_commit.is_empty(),
        "notebook_commit must be set"
    );
    assert_eq!(
        outcome.commit_evidence_status, "unknown",
        "skip_fingerprint must produce Unknown evidence"
    );

    // Verify the rec was stamped as promoted in notebook.git.
    let rec_path = fixture
        .path()
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let rec_content = std::fs::read_to_string(&rec_path).expect("read rec after promote");
    assert!(
        rec_content.contains("outcome: promoted"),
        "rec must have outcome: promoted after skip_fingerprint promote"
    );
    assert!(
        rec_content.contains(&format!("promoted_to: {}", outcome.decision_id)),
        "rec must carry promoted_to: <decision_id>"
    );

    // Decision file must exist with outcome: working.
    let dec_path = fixture
        .path()
        .join(project_id)
        .join("decisions")
        .join(format!("{}.yml", outcome.decision_id));
    let dec_content = std::fs::read_to_string(&dec_path).expect("read decision after promote");
    assert!(
        dec_content.contains("outcome: working"),
        "decision must have outcome: working"
    );
    assert!(
        dec_content.contains("record_type: decision"),
        "decision must have record_type: decision"
    );
}

/// Online promote with a reachable commit returns Verified evidence and creates
/// the decision.
#[test]
fn online_promote_reachable_commit_creates_decision() {
    let (fixture, primary, _ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);

    let project_id = "name:testproject2";
    let rec_id = "2026-04-29-online-promote";
    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let cfg = local_cfg();
    index_fixture(&fixture, &cfg);

    // Build a real project repo with a reachable commit.
    let repo_dir = tempfile::tempdir().expect("create repo tempdir");
    let (_sha1, sha2) = init_project_repo(repo_dir.path());

    let paths = paths_for(&fixture);
    let params = PromoteParams {
        rec: rec_id,
        commit: &sha2,
        repo: Some(repo_dir.path()),
        branch: Some("main"),
        skip_fingerprint: false,
        force_untrusted: true,
    };

    let outcome = promote(&paths, &cfg, &params).expect("online promote must succeed");

    assert_eq!(
        outcome.commit_evidence_status, "verified",
        "online promote must produce Verified evidence"
    );
    assert!(!outcome.decision_id.is_empty());
    assert!(!outcome.notebook_commit.is_empty());
}

/// Online promote with an unreachable commit (sha1 is parent, not reachable
/// from sha1 itself as branch tip) returns `CommitUnreachableFromDefault`.
#[test]
fn online_promote_unreachable_commit_returns_error() {
    let (fixture, primary, _ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);

    let project_id = "name:testproject3";
    let rec_id = "2026-04-29-unreachable-promote";
    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let cfg = local_cfg();
    index_fixture(&fixture, &cfg);

    let repo_dir = tempfile::tempdir().expect("create repo tempdir");
    let (_sha1, sha2) = init_project_repo(repo_dir.path());

    // sha2 is HEAD; sha1_again is parent of HEAD. sha2 is NOT an ancestor of
    // sha1_again (sha1_again is the parent, not the other way round).
    let sha1_parent = sha_of(repo_dir.path(), "HEAD~1");

    let paths = paths_for(&fixture);
    let params = PromoteParams {
        rec: rec_id,
        commit: &sha2,
        repo: Some(repo_dir.path()),
        // Use sha1_parent as the "branch" tip; sha2 is HEAD and is NOT an
        // ancestor of sha1_parent.
        branch: Some(&sha1_parent),
        skip_fingerprint: false,
        force_untrusted: true,
    };

    let err = promote(&paths, &cfg, &params).expect_err("unreachable commit must return an error");

    assert!(
        matches!(
            err,
            nexum_core::api::ApiError::CommitUnreachableFromDefault { .. }
        ),
        "expected CommitUnreachableFromDefault, got: {err:?}"
    );
}

/// `reject` stamps the recommendation as `rejected` and returns a
/// `RejectOutcome` with the commit SHA.
#[test]
fn reject_stamps_rec_as_rejected_and_returns_outcome() {
    let (fixture, primary, _ev, _key_dir) = fresh_notebook_with_bootstrap();
    commit_trust_files(&fixture, &primary);

    let project_id = "name:testproject4";
    let rec_id = "2026-04-29-reject-me";
    seed_rec(&fixture, &primary, project_id, rec_id, "proposed");

    let cfg = local_cfg();
    index_fixture(&fixture, &cfg);

    let paths = paths_for(&fixture);
    let outcome = reject(&paths, &cfg, rec_id).expect("reject must succeed");

    assert!(
        !outcome.notebook_commit.is_empty(),
        "notebook_commit must be set"
    );

    // Rec must now have outcome: rejected.
    let rec_path = fixture
        .path()
        .join(project_id)
        .join("recommendations")
        .join(format!("{rec_id}.yml"));
    let rec_content = std::fs::read_to_string(&rec_path).expect("read rec after reject");
    assert!(
        rec_content.contains("outcome: rejected"),
        "rec must have outcome: rejected after reject call"
    );
}
