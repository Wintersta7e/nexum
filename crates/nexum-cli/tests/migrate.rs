//! End-to-end: a too-old index.db gets bumped to the binary's latest via
//! the CLI command.

mod common;

use common::TestHome;
use std::path::Path;
use std::sync::Once;

// ─── sqlite-vec registration ─────────────────────────────────────────────────

/// Register the sqlite-vec auto-extension once in the test process so that
/// `Connection::open` on a DB containing `vec0` virtual tables succeeds.
/// Mirrors the pattern in `nexum-core`'s integration tests.
fn register_sqlite_vec() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: `sqlite3_auto_extension` registers an init function that
        // SQLite invokes when each new connection is opened.
        // `sqlite_vec::sqlite3_vec_init` is ABI-compatible with the SQLite
        // extension init signature; the transmute bridges the bindgen-
        // generated type alias. Same pattern used in nexum-core's tests.
        #[allow(unsafe_code)]
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

// ─── v1 fixture ──────────────────────────────────────────────────────────────

/// Minimal faithful v1 index.db DDL. Mirrors what a real v1 install wrote:
/// `records` (with the pre-v2 columns `signature_status`, `trust_basis`,
/// `warning_code`), the `record_embeddings` vec0 virtual table, FTS, and the
/// three FTS triggers. The v1 → v2 step preserves all of these and adds the
/// trust/meta auxiliary tables.
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

/// Plant a genuine v1-shaped index.db at `db_path`. Requires sqlite-vec
/// registered first (call `register_sqlite_vec()` before this).
fn plant_v1_db(db_path: &Path) {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute_batch(V1_FIXTURE_DDL).unwrap();
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[test]
fn migrate_bumps_an_old_index_db_to_latest() {
    // Register sqlite-vec in the test process so we can create the v1 fixture
    // (which includes a vec0 virtual table).
    register_sqlite_vec();

    // Init a nexum home (notebook.git + config.toml + signed bootstrap) but
    // skip `nexum index` — we will plant our own v1-shaped index.db.
    let home = TestHome::initialized_no_index();
    plant_v1_db(&home.path().join("index.db"));

    let out = home.run(&["migrate", "--json"]);

    assert!(
        out.status.success(),
        "migrate exited non-zero (exit={:?});\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must parse as JSON");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "migration.completed");
    assert!(
        payload["from"].as_u64().unwrap() < payload["to"].as_u64().unwrap(),
        "from must be less than to; got from={} to={}",
        payload["from"],
        payload["to"]
    );
}

#[test]
fn migrate_noop_when_already_current() {
    let home = TestHome::initialized_no_index();

    // Run nexum index to create a fresh v2 index.db.
    let idx_out = home.run(&["index"]);
    assert!(
        idx_out.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&idx_out.stderr)
    );

    // index.db is already at the latest version; migrate should be a no-op.
    let out = home.run(&["migrate", "--json"]);

    assert!(
        out.status.success(),
        "migrate exited non-zero (exit={:?});\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must parse as JSON");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "migration.noop");
}

// Suppress dead-code lint for common helpers pulled in transitively.
#[allow(unused_imports)]
use common::{nexum_bin, write_local_yaml};
