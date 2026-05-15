//! Cross-source / cross-project record-id collisions must coexist; the
//! composite UNIQUE constraint replaces the old standalone UNIQUE(id).

use nexum_core::{
    api,
    config::types::Config,
    indexer::db::open_or_create,
    query::{self, GetOpts},
    records::{GetOutcome, Source, TrustPolicy, types::RecordKey},
};
use rusqlite::Connection;
use tempfile::TempDir;

fn open() -> (TempDir, Connection) {
    let dir = TempDir::new().unwrap();
    let conn = open_or_create(&dir.path().join("index.db")).unwrap();
    (dir, conn)
}

fn insert_minimal(conn: &Connection, id: &str, source: Source, project_id: &str) {
    conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id,
            agent, confidence, outcome, crypto_result, tags, tags_fts,
            session_refs, commits, files, created, updated, content_hash, index_hash, indexed_at
         ) VALUES (?1, 'decision', ?2, 'b', ?3, ?4,
            'claude-code', 'medium', 'working', 'good', '[]', '',
            '[]', '[]', '[]', '2026-05-04T00:00:00Z',
            '2026-05-04T00:00:00Z', 'h', 'ih', '2026-05-04T00:00:00Z')",
        rusqlite::params![id, format!("t-{id}"), source.as_db_str(), project_id],
    )
    .unwrap();
}

#[test]
fn cross_source_same_id_coexists() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "shared-id", Source::Local, "git:proj-a");
    insert_minimal(&conn, "shared-id", Source::CcNative, "git:proj-a");
    insert_minimal(&conn, "shared-id", Source::CodexNative, "git:proj-a");
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM records WHERE id = 'shared-id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn cross_project_same_id_coexists() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "shared-id", Source::CcNative, "git:proj-a");
    insert_minimal(&conn, "shared-id", Source::CcNative, "git:proj-b");
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM records WHERE id = 'shared-id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn same_source_project_id_triple_is_unique() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "x", Source::CcNative, "git:p");
    let result = conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id,
            agent, confidence, outcome, crypto_result, tags, tags_fts,
            session_refs, commits, files, created, updated, content_hash, index_hash, indexed_at
         ) VALUES ('x', 'decision', 't', 'b', 'cc-native', 'git:p',
            'claude-code', 'medium', 'working', 'good', '[]', '',
            '[]', '[]', '[]', '2026-05-04T00:00:00Z',
            '2026-05-04T00:00:00Z', 'h', 'ih', '2026-05-04T00:00:00Z')",
        [],
    );
    assert!(result.is_err(), "duplicate composite key must error");
}

#[test]
fn get_by_bare_id_returns_ambiguous_when_multiple_match() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "shared-id", Source::CcNative, "git:proj-a");
    insert_minimal(&conn, "shared-id", Source::CodexNative, "git:proj-a");
    let opts = GetOpts {
        trust_policy: TrustPolicy::WarnButShow,
        include_unsigned: false,
        strict_revocation: false,
    };
    let result = query::get(&conn, &RecordKey::bare("shared-id"), &opts);
    match result {
        Err(query::QueryError::Ambiguous { matches }) => {
            assert_eq!(matches.len(), 2);
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }
}

#[test]
fn get_by_exact_key_returns_found() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "shared-id", Source::CcNative, "git:proj-a");
    insert_minimal(&conn, "shared-id", Source::CodexNative, "git:proj-a");
    let opts = GetOpts {
        trust_policy: TrustPolicy::WarnButShow,
        include_unsigned: false,
        strict_revocation: false,
    };
    let key = RecordKey::exact(Source::CodexNative, "git:proj-a", "shared-id");
    let result = query::get(&conn, &key, &opts).unwrap();
    assert!(matches!(result, GetOutcome::Found { .. }));
}

#[test]
fn get_by_bare_id_returns_found_when_unique() {
    let (_dir, conn) = open();
    insert_minimal(&conn, "uniq", Source::CcNative, "git:proj-a");
    let opts = GetOpts {
        trust_policy: TrustPolicy::WarnButShow,
        include_unsigned: false,
        strict_revocation: false,
    };
    let result = query::get(&conn, &RecordKey::bare("uniq"), &opts).unwrap();
    assert!(matches!(result, GetOutcome::Found { .. }));
}

// `api::get` accepts &RecordKey end-to-end (CLI's qualified parsing exercised
// at the CLI integration layer; this just confirms the api forwards correctly).
#[test]
fn api_get_round_trip_via_record_key() {
    let home = TempDir::new().unwrap();
    let paths = nexum_core::paths::Paths::with_home(home.path().to_owned());
    let conn = open_or_create(&paths.index_db).unwrap();
    insert_minimal(&conn, "tau", Source::Local, "git:proj-a");
    drop(conn);
    let opts = GetOpts {
        include_unsigned: false,
        trust_policy: TrustPolicy::WarnButShow,
        strict_revocation: false,
    };
    let cfg = Config::seed();
    let result = api::get(&paths, &cfg, &RecordKey::bare("tau"), &opts).unwrap();
    assert!(matches!(result, GetOutcome::Found { .. }));
}
