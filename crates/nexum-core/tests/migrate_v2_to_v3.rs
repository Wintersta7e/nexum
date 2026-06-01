//! Integration test: real on-disk DB, v2 fixture, full `migrate_to_latest`
//! flow exercising the genuine v2 -> v3 migration path.

use std::collections::HashSet;
use std::sync::Once;

use nexum_core::migrate::index_db::{migrate_to_latest, INDEX_DB_LATEST_VERSION};
use nexum_core::migrate::MigrationOutcome;
use rusqlite::Connection;
use tempfile::tempdir;

/// Register the `sqlite-vec` auto-extension hook once per process so the
/// fixture can stand up a `record_embeddings USING vec0(...)` virtual table
/// and `verify_post_apply` after migration passes its table presence check.
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

/// SQL for a faithful v2 DB shape: the full v2 schema INCLUDING the
/// trust/meta auxiliary tables added by the v1→v2 migration, but WITHOUT
/// the three lifecycle columns added by v2→v3. Mirrors what a real v2
/// install has on disk.
const V2_FIXTURE_DDL: &str = "
CREATE TABLE records (
    rowid INTEGER PRIMARY KEY,
    id TEXT NOT NULL,
    source TEXT NOT NULL,
    project_id TEXT NOT NULL,
    record_type TEXT NOT NULL DEFAULT 'untyped',
    title TEXT NOT NULL DEFAULT '',
    summary TEXT,
    body TEXT NOT NULL DEFAULT '',
    body_origin_path TEXT,
    tags JSON NOT NULL DEFAULT '[]',
    tags_fts TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    outcome TEXT NOT NULL DEFAULT 'n-a',
    agent TEXT NOT NULL DEFAULT 'manual',
    session_refs JSON,
    files JSON,
    commits JSON,
    created TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    index_hash TEXT NOT NULL DEFAULT '',
    record_commit_sha TEXT,
    signer_fingerprint TEXT,
    crypto_result TEXT NOT NULL DEFAULT 'no-signature',
    relevant_trust_events_commit TEXT,
    extras JSON,
    indexed_at TEXT NOT NULL DEFAULT '',
    UNIQUE (source, project_id, id)
);
CREATE VIRTUAL TABLE record_embeddings USING vec0(
    record_rowid INTEGER PRIMARY KEY,
    embedding FLOAT[1024]
);
CREATE VIRTUAL TABLE records_fts USING fts5(
    title, summary, body, tags_fts,
    content='records', content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
    INSERT INTO records_fts(rowid, title, summary, body, tags_fts)
    VALUES (new.rowid, new.title, new.summary, new.body, new.tags_fts);
END;
CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags_fts)
    VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags_fts);
END;
CREATE TRIGGER records_au AFTER UPDATE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags_fts)
    VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags_fts);
    INSERT INTO records_fts(rowid, title, summary, body, tags_fts)
    VALUES (new.rowid, new.title, new.summary, new.body, new.tags_fts);
END;
CREATE TABLE trust_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    fingerprint TEXT,
    old_fingerprint TEXT,
    new_fingerprint TEXT,
    public_key TEXT,
    effective_commit TEXT NOT NULL,
    effective_commit_topo_pos INTEGER NOT NULL,
    introduced_by_signer TEXT NOT NULL,
    chain_validated_by TEXT,
    reason TEXT,
    chain_anchor_lost INTEGER,
    materialized_at TEXT NOT NULL
);
CREATE INDEX idx_trust_events_topo ON trust_events(effective_commit_topo_pos);
CREATE INDEX idx_trust_events_fp ON trust_events(fingerprint);
CREATE INDEX idx_trust_events_introducer ON trust_events(introduced_by_signer);
CREATE TABLE trust_chain_tampering (
    at_commit TEXT NOT NULL,
    at_topo_pos INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    PRIMARY KEY (at_commit, event_id, kind)
);
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
PRAGMA user_version = 2;
";

#[test]
fn migrate_v2_to_v3_adds_lifecycle_columns() {
    register_sqlite_vec();
    let dir = tempdir().unwrap();
    let db = dir.path().join("index.db");

    // Build a genuine v2 fixture on disk.
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(V2_FIXTURE_DDL).unwrap();
    }

    let mut conn = Connection::open(&db).unwrap();
    let v_before: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v_before, 2, "fixture must start at user_version 2");

    let outcome = migrate_to_latest(&mut conn, &db, true).unwrap();
    assert!(
        matches!(outcome, MigrationOutcome::Migrated { to: 3, .. }),
        "expected Migrated {{ to: 3, .. }}, got {outcome:?}"
    );
    let v_after: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v_after, 3);
    assert_eq!(INDEX_DB_LATEST_VERSION, 3);

    let cols: HashSet<String> = conn
        .prepare("PRAGMA table_info(records)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for c in ["commit_evidence", "promoted_from", "inherited_warnings"] {
        assert!(cols.contains(c), "records.{c} missing after migrate");
    }

    // Backup must have been written.
    let bak_dir = dir.path().join(".bak");
    assert!(bak_dir.exists(), "backup dir should exist");
}
