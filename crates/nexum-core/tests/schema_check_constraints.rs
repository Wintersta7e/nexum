//! Verify `SQLite` CHECK constraints on the `records` table reject out-of-range
//! enum values and that NULL `trust_basis` is still permitted.

use nexum_core::indexer::db::open_or_create;
use rusqlite::Connection;
use tempfile::TempDir;

fn open() -> (TempDir, Connection) {
    let dir = TempDir::new().unwrap();
    let conn = open_or_create(&dir.path().join("index.db")).unwrap();
    (dir, conn)
}

/// Insert a row using a fully-valid baseline, then substitute `bad_value` into
/// `column`. Returns the rusqlite Result so callers can assert on it.
fn insert_with_field(conn: &Connection, column: &str, bad_value: &str) -> rusqlite::Result<usize> {
    let mut cols: Vec<(&str, &str)> = vec![
        ("id", "x"),
        ("record_type", "decision"),
        ("title", "t"),
        ("body", "b"),
        ("source", "local"),
        ("project_id", "git:test"),
        ("agent", "codex"),
        ("confidence", "medium"),
        ("outcome", "working"),
        ("signature_status", "unsigned"),
        ("tags", "[]"),
        ("tags_fts", ""),
        ("session_refs", "[]"),
        ("commits", "[]"),
        ("files", "[]"),
        ("created", "2026-05-04T00:00:00Z"),
        ("updated", "2026-05-04T00:00:00Z"),
        ("content_hash", "h"),
        ("index_hash", "h"),
        ("indexed_at", "2026-05-04T00:00:00Z"),
    ];
    for c in &mut cols {
        if c.0 == column {
            c.1 = bad_value;
        }
    }
    let names: Vec<&str> = cols.iter().map(|c| c.0).collect();
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "INSERT INTO records ({}) VALUES ({})",
        names.join(", "),
        placeholders.join(", "),
    );
    let values: Vec<&dyn rusqlite::ToSql> =
        cols.iter().map(|c| &c.1 as &dyn rusqlite::ToSql).collect();
    conn.execute(&sql, rusqlite::params_from_iter(values.iter()))
}

#[test]
fn check_constraint_rejects_bad_record_type() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "record_type", "garbage").is_err(),
        "bad record_type must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_source() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "source", "fake-source").is_err(),
        "bad source must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_agent() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "agent", "imaginary-agent").is_err(),
        "bad agent must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_confidence() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "confidence", "yolo").is_err(),
        "bad confidence must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_outcome() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "outcome", "abandoned").is_err(),
        "bad outcome must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_signature_status() {
    let (_dir, conn) = open();
    assert!(
        insert_with_field(&conn, "signature_status", "questionable").is_err(),
        "bad signature_status must violate CHECK"
    );
}

#[test]
fn check_constraint_rejects_bad_trust_basis() {
    let (_dir, conn) = open();
    let r = conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id, agent,
            confidence, outcome, signature_status, tags, tags_fts,
            session_refs, commits, files, created, updated, content_hash,
            index_hash, indexed_at, trust_basis
         ) VALUES (
            'y', 'decision', 't', 'b', 'local', 'git:test', 'codex',
            'medium', 'working', 'unsigned', '[]', '',
            '[]', '[]', '[]', '2026-05-04T00:00:00Z',
            '2026-05-04T00:00:00Z', 'h', 'h', '2026-05-04T00:00:00Z',
            'made-up'
         )",
        [],
    );
    assert!(r.is_err(), "bad trust_basis must violate CHECK");
}

#[test]
fn check_constraint_allows_null_trust_basis() {
    let (_dir, conn) = open();
    let r = conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id, agent,
            confidence, outcome, signature_status, tags, tags_fts,
            session_refs, commits, files, created, updated, content_hash,
            index_hash, indexed_at
         ) VALUES (
            'z', 'decision', 't', 'b', 'local', 'git:test', 'codex',
            'medium', 'working', 'unsigned', '[]', '',
            '[]', '[]', '[]', '2026-05-04T00:00:00Z',
            '2026-05-04T00:00:00Z', 'h', 'h', '2026-05-04T00:00:00Z'
         )",
        [],
    );
    assert!(r.is_ok(), "NULL trust_basis must be permitted; got: {r:?}");
}
