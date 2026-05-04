//! Integration test: real on-disk DB, populated v1 schema, full
//! `migrate_to_latest` flow.

use nexum_core::migrate::MigrationOutcome;
use nexum_core::migrate::index_db::{INDEX_DB_LATEST_VERSION, migrate_to_latest};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn migrate_to_latest_with_lock_succeeds_and_creates_backup() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE records (
                rowid INTEGER PRIMARY KEY, id TEXT, source TEXT, project_id TEXT,
                signature_status TEXT DEFAULT 'unsigned', trust_basis TEXT, warning_code TEXT,
                content_hash TEXT DEFAULT '', index_hash TEXT DEFAULT '',
                indexed_at TEXT DEFAULT '', title TEXT DEFAULT '', body TEXT DEFAULT '',
                tags JSON DEFAULT '[]', tags_fts TEXT DEFAULT '',
                confidence TEXT DEFAULT 'medium', outcome TEXT DEFAULT 'n-a',
                agent TEXT DEFAULT 'manual', created TEXT DEFAULT '', updated TEXT DEFAULT '',
                record_type TEXT DEFAULT 'untyped', summary TEXT, body_origin_path TEXT,
                session_refs JSON, files JSON, commits JSON,
                record_commit_sha TEXT, signer_fingerprint TEXT, extras JSON
            );
            PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    let mut conn = Connection::open(&db_path).unwrap();
    let outcome = migrate_to_latest(&mut conn, &db_path, true).unwrap();
    match outcome {
        MigrationOutcome::Migrated {
            from,
            to,
            backup_path,
        } => {
            assert_eq!(from, 1);
            assert_eq!(to, INDEX_DB_LATEST_VERSION);
            assert!(backup_path.exists(), "backup file should exist");
        }
        MigrationOutcome::NoOp => panic!("expected Migrated, got NoOp"),
    }

    let v: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, INDEX_DB_LATEST_VERSION);
}

#[test]
fn migrate_to_latest_without_lock_returns_migration_required() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
    }
    let mut conn = Connection::open(&db_path).unwrap();
    let err = migrate_to_latest(&mut conn, &db_path, false).unwrap_err();
    assert!(matches!(
        err,
        nexum_core::migrate::MigrationError::MigrationRequired {
            v_disk: 1,
            v_code: 2
        }
    ));
}

#[test]
fn migrate_to_latest_rejects_future_version() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
    }
    let mut conn = Connection::open(&db_path).unwrap();
    let err = migrate_to_latest(&mut conn, &db_path, true).unwrap_err();
    assert!(matches!(
        err,
        nexum_core::migrate::MigrationError::IncompatibleStore { v_disk: 99, .. }
    ));
}

#[test]
fn migrate_to_latest_on_current_version_is_noop() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA user_version = 2;").unwrap();
    }
    let mut conn = Connection::open(&db_path).unwrap();
    let outcome = migrate_to_latest(&mut conn, &db_path, true).unwrap();
    assert_eq!(outcome, MigrationOutcome::NoOp);
}
