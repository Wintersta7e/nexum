//! End-to-end test for `nexum_core::project::normalize_inbox`.

mod common;

use common::{NexumTestHome, write_ephemeral_keypair};
use nexum_core::init::{InitOpts, run as init_run};
use nexum_core::paths::Paths;
use nexum_core::project::normalize_inbox::normalize_inbox;
use rusqlite::Connection;
use std::fs;
use tempfile::tempdir;

#[test]
fn normalize_inbox_moves_record_when_resolution_succeeds() {
    let home = NexumTestHome::new().unwrap();
    let key_dir = tempdir().unwrap();
    let key_path = write_ephemeral_keypair(key_dir.path());

    let outcome = init_run(InitOpts {
        ssh_key: Some(key_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init succeeds");
    let paths = Paths::with_home(outcome.root);

    // Drop an _inbox record with a CodexThread ref. Commit it so the
    // worktree is clean before normalize_inbox runs.
    let rec_yaml = r"
schema_version: 1
id: 2026-04-29-test
record_type: recommendation
project_id: _inbox
session_refs:
  - kind: codex_thread
    thread_id: t-1
    rollout_path: /tmp/rollouts/r1.jsonl
";
    let inbox_dir = paths.notebook_git.join("_inbox/recommendations");
    fs::create_dir_all(&inbox_dir).unwrap();
    let inbox_path = inbox_dir.join("2026-04-29-test.yml");
    fs::write(&inbox_path, rec_yaml).unwrap();

    // Stage + signed-commit the inbox file so worktree is clean.
    let rel = std::path::Path::new("_inbox/recommendations/2026-04-29-test.yml");
    nexum_core::init::git_ops::git_commit_signed(
        &paths.notebook_git,
        &[rel],
        "inbox: seed 2026-04-29-test",
    )
    .expect("seed commit");

    // state_5.sqlite with a threads row.
    let state_db = home.path().join("state_5.sqlite");
    let conn = Connection::open(&state_db).unwrap();
    conn.execute_batch(
        "CREATE TABLE threads (id TEXT, rollout_path TEXT, cwd TEXT, \
         git_origin_url TEXT, created_at TEXT, updated_at TEXT, title TEXT); \
         INSERT INTO threads (id, git_origin_url, cwd) \
         VALUES ('t-1', 'https://github.com/example/foo.git', '/home/u/foo');",
    )
    .unwrap();

    let result = normalize_inbox(&paths, Some(&state_db)).expect("normalize failed");

    assert_eq!(result.moved_ids.len(), 1, "exactly one record moved");
    assert_eq!(result.moved_ids[0], "2026-04-29-test");
    assert_eq!(result.ambiguous, 0);
    assert_eq!(result.unresolved, 0);

    let inbox_path = paths
        .notebook_git
        .join("_inbox/recommendations/2026-04-29-test.yml");
    assert!(!inbox_path.exists(), "inbox copy was removed");

    // Find the moved record under <project_id>/recommendations/<id>.yml.
    let mut found_under: Option<String> = None;
    for entry in fs::read_dir(&paths.notebook_git).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name == "_inbox" || name.starts_with('.') {
            continue;
        }
        let target = entry.path().join("recommendations/2026-04-29-test.yml");
        if target.exists() {
            let body = fs::read_to_string(&target).unwrap();
            assert!(
                body.contains(&format!("project_id: {name}")),
                "project_id line should reflect the new id"
            );
            assert!(
                body.contains("schema_version: 1"),
                "preserve byte-level rest of the YAML"
            );
            assert!(body.contains("kind: codex_thread"), "preserve session_refs");
            found_under = Some(name);
            break;
        }
    }
    assert!(
        found_under.is_some(),
        "moved record not found under any project subdir"
    );
    // Sanity: the project_id derived from git:example/foo via git_url_hint
    // begins with `git:`.
    assert!(
        found_under.unwrap().starts_with("git:"),
        "expected git: identity from the example.com origin url"
    );
}
