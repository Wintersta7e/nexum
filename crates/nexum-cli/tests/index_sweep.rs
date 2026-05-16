//! End-to-end: `nexum index --sweep --aggressive` deletes records whose
//! source files no longer exist, in a single pass.

use std::path::Path;
use std::process::Command;

mod common;
use common::{TestHome, write_local_yaml};

/// Count records in the index db directly.
fn count_records(home: &Path) -> i64 {
    let db = home.join("index.db");
    let conn = rusqlite::Connection::open(&db).expect("open index.db");
    conn.query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .expect("count records")
}

/// Remove a local YAML record file from the notebook.
fn remove_local_record(home: &Path, sub: &str, id: &str) {
    let path = home
        .join("notebook.git")
        .join(sub)
        .join(format!("{id}.yml"));
    std::fs::remove_file(&path).unwrap_or_else(|e| panic!("remove {}: {e}", path.display()));
}

#[test]
fn aggressive_sweep_deletes_gone_records_immediately() {
    let home = TestHome::initialized_no_index();
    write_local_yaml(home.path(), "decisions", "alpha", "alpha body");
    write_local_yaml(home.path(), "decisions", "bravo", "bravo body");

    let out = home.run(&["index"]);
    assert!(
        out.status.success(),
        "initial index failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(count_records(home.path()), 2, "both records indexed");

    // Remove alpha; one plain index pass must NOT delete it (threshold = 3).
    remove_local_record(home.path(), "decisions", "alpha");
    let out = home.run(&["index"]);
    assert!(
        out.status.success(),
        "second index failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_records(home.path()),
        2,
        "default threshold defers delete"
    );

    // --sweep --aggressive must delete in one pass (threshold = 1).
    let ssh_home = home.path().parent().unwrap().join("ssh-home");
    let out = Command::new(common::nexum_bin())
        .env("NEXUM_HOME", home.path())
        .env("HOME", &ssh_home)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .args(["index", "--sweep", "--aggressive", "--json"])
        .output()
        .expect("CLI invocation");
    assert!(
        out.status.success(),
        "--sweep --aggressive exited non-zero:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_records(home.path()),
        1,
        "--aggressive must delete the gone record in one pass"
    );
}

#[test]
fn sweep_without_aggressive_still_defers_under_threshold() {
    let home = TestHome::initialized_no_index();
    write_local_yaml(home.path(), "decisions", "gamma", "gamma body");

    let out = home.run(&["index"]);
    assert!(
        out.status.success(),
        "initial index failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(count_records(home.path()), 1);

    remove_local_record(home.path(), "decisions", "gamma");

    // A single --sweep (no --aggressive) is one Authoritative pass;
    // counter goes to 1, below threshold of 3, so the row stays.
    let out = home.run(&["index", "--sweep"]);
    assert!(
        out.status.success(),
        "--sweep exited non-zero:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_records(home.path()),
        1,
        "--sweep alone must not delete below the threshold"
    );
}

#[test]
fn aggressive_requires_sweep() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["index", "--aggressive"]);
    // clap must reject --aggressive without --sweep
    assert!(
        !out.status.success(),
        "--aggressive without --sweep should fail"
    );
}

#[test]
fn sweep_conflicts_with_force() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["index", "--sweep", "--force"]);
    assert!(
        !out.status.success(),
        "--sweep and --force must be mutually exclusive"
    );
}
