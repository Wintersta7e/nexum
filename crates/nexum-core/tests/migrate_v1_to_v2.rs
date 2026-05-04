//! Integration test: real on-disk DB, populated v1 schema, full
//! `migrate_to_latest` flow.

use std::sync::Once;

use nexum_core::migrate::MigrationOutcome;
use nexum_core::migrate::index_db::{INDEX_DB_LATEST_VERSION, migrate_to_latest};
use rusqlite::Connection;
use tempfile::tempdir;

/// Register the `sqlite-vec` auto-extension hook once per process. Needed so
/// the v1 fixture can stand up a `record_embeddings USING vec0(...)` virtual
/// table; `verify_post_apply` after migration checks for its presence.
fn register_sqlite_vec() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: `sqlite3_auto_extension` registers an init function that
        // SQLite invokes when each new connection is opened.
        // `sqlite_vec::sqlite3_vec_init` is the standard sqlite-vec entry
        // point; the transmute reconciles the bindgen-generated `sqlite3`
        // alias against rusqlite's. This is the documented sqlite-vec pattern
        // for static linking with rusqlite.
        unsafe {
            let init_fn: unsafe extern "C" fn(
                *mut rusqlite::ffi::sqlite3,
                *mut *mut std::os::raw::c_char,
                *const rusqlite::ffi::sqlite3_api_routines,
            ) -> std::os::raw::c_int =
                std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
            rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
        }
    });
}

/// SQL for a minimal-but-faithful v1 index DB shape. Mirrors what a real v1
/// install would have written to disk: `records` + `record_embeddings` +
/// `records_fts` + the three FTS triggers. The v1 -> v2 step preserves these
/// and adds the trust/meta auxiliary tables.
const V1_FIXTURE_DDL: &str = "
CREATE TABLE records (
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
CREATE VIRTUAL TABLE record_embeddings USING vec0(
    record_rowid INTEGER PRIMARY KEY,
    embedding FLOAT[1024]
);
CREATE VIRTUAL TABLE records_fts USING fts5(
    title, body, tags_fts, content='records', content_rowid='rowid', tokenize='unicode61'
);
CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
    INSERT INTO records_fts(rowid, title, body, tags_fts) VALUES (new.rowid, new.title, new.body, new.tags_fts);
END;
CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, body, tags_fts) VALUES ('delete', old.rowid, old.title, old.body, old.tags_fts);
END;
CREATE TRIGGER records_au AFTER UPDATE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, body, tags_fts) VALUES ('delete', old.rowid, old.title, old.body, old.tags_fts);
    INSERT INTO records_fts(rowid, title, body, tags_fts) VALUES (new.rowid, new.title, new.body, new.tags_fts);
END;
PRAGMA user_version = 1;
";

#[test]
fn migrate_to_latest_with_lock_succeeds_and_creates_backup() {
    register_sqlite_vec();
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("index.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(V1_FIXTURE_DDL).unwrap();
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
