//! Integration tests for the §7 index DDL applied to a real `SQLite` connection.
//! Uses `NexumTestHome` to create an isolated temp dir for the database file,
//! and the sqlite-vec extension is loaded via `auto_extension` before the connection
//! opens (vec0 is required by the DDL).

mod common;

use common::NexumTestHome;
use nexum_core::index::schema;
use rusqlite::Connection;
use std::os::raw::{c_char, c_int};

fn register_sqlite_vec() {
    type RusqliteExtInit = unsafe extern "C" fn(
        *mut rusqlite::ffi::sqlite3,
        *mut *mut c_char,
        *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int;
    // SAFETY: sqlite3_auto_extension registers an init function that SQLite invokes
    // when each new connection is opened. sqlite_vec::sqlite3_vec_init is the standard
    // sqlite-vec entry point and is ABI-compatible with the SQLite-extension init
    // signature — but its rustc-visible type uses sqlite-vec's bindgen-generated
    // `sqlite3` opaque alias rather than rusqlite's, so the transmute bridges the two
    // ABI-equivalent function-pointer types. This is the pattern documented by
    // sqlite-vec for static linking with rusqlite.
    unsafe {
        let init_fn: RusqliteExtInit =
            std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
        rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
    }
}

#[test]
fn apply_succeeds_on_fresh_connection() {
    register_sqlite_vec();
    let home = NexumTestHome::new().expect("create test home");
    let conn = Connection::open(home.paths().index_db).expect("open temp db");
    schema::apply(&conn).expect("apply DDL");
}

#[test]
fn apply_creates_all_expected_tables_and_triggers() {
    register_sqlite_vec();
    let home = NexumTestHome::new().expect("create test home");
    let conn = Connection::open(home.paths().index_db).expect("open temp db");
    schema::apply(&conn).expect("apply DDL");

    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    // sqlite-vec creates internal companion tables for vec0 (e.g.,
    // record_embeddings_chunks, _info, _rowids); just check our 3 are there.
    for required in ["records", "record_embeddings", "records_fts"] {
        assert!(
            tables.iter().any(|t| t == required),
            "missing table {required} in {tables:?}"
        );
    }

    let triggers: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        triggers,
        vec!["records_ad", "records_ai", "records_au"],
        "expected exactly the 3 records_ai / ad / au triggers"
    );
}

#[test]
fn insert_record_propagates_to_records_fts_via_trigger() {
    register_sqlite_vec();
    let home = NexumTestHome::new().expect("create test home");
    let conn = Connection::open(home.paths().index_db).expect("open temp db");
    schema::apply(&conn).expect("apply DDL");

    // Minimal record insert covering the NOT NULL columns.
    conn.execute(
        "INSERT INTO records (
            id, source, project_id, record_type, title, body, tags, tags_fts,
            created, updated, content_hash, index_hash, signature_status, indexed_at
        ) VALUES (?1, 'local', 'p', 'decision', ?2, '', ?3, ?4,
                  '2026-04-30T00:00:00Z', '2026-04-30T00:00:00Z',
                  'h', 'ih', 'unsigned', '2026-04-30T00:00:00Z')",
        rusqlite::params![
            "rec-A",
            "alpha title",
            r#"["concurrency","database"]"#,
            "concurrency database",
        ],
    )
    .expect("insert record");

    // FTS over the title — should hit via the records_ai trigger.
    let mut stmt = conn
        .prepare("SELECT rowid FROM records_fts WHERE records_fts MATCH ?1")
        .unwrap();
    let fts_hits: Vec<i64> = stmt
        .query_map(rusqlite::params!["alpha"], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        fts_hits.len(),
        1,
        "title 'alpha' should match exactly one row"
    );

    // FTS over the tags_fts column — multi-token implicit AND.
    let tag_hits: Vec<i64> = stmt
        .query_map(
            rusqlite::params!["tags_fts:concurrency tags_fts:database"],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        tag_hits.len(),
        1,
        "tags_fts:concurrency tags_fts:database should match the row"
    );
}

#[test]
fn delete_in_correct_order_leaves_no_orphans() {
    register_sqlite_vec();
    let home = NexumTestHome::new().expect("create test home");
    let conn = Connection::open(home.paths().index_db).expect("open temp db");
    schema::apply(&conn).expect("apply DDL");

    // Insert one record (FTS row populated by records_ai trigger).
    conn.execute(
        "INSERT INTO records (
            id, source, project_id, record_type, title, body, tags, tags_fts,
            created, updated, content_hash, index_hash, signature_status, indexed_at
        ) VALUES (?1, 'local', 'p', 'decision', ?2, '', ?3, ?4,
                  '2026-04-30T00:00:00Z', '2026-04-30T00:00:00Z',
                  'h', 'ih', 'unsigned', '2026-04-30T00:00:00Z')",
        rusqlite::params!["rec-B", "beta", r#"["t1"]"#, "t1"],
    )
    .expect("insert");
    let rowid = conn.last_insert_rowid();

    // Application-managed: insert into record_embeddings AFTER records (per §7
    // ordering rule). Use a placeholder embedding; vec0 needs a 1024-dim FLOAT[].
    let embedding: Vec<u8> = (0..1024).flat_map(|_| 0.0_f32.to_le_bytes()).collect();
    conn.execute(
        "INSERT INTO record_embeddings(record_rowid, embedding) VALUES (?1, ?2)",
        rusqlite::params![rowid, embedding],
    )
    .expect("insert embedding");

    // Now delete in the §7-mandated order: vec0 first, then records.
    conn.execute(
        "DELETE FROM record_embeddings WHERE record_rowid = ?1",
        rusqlite::params![rowid],
    )
    .expect("delete embedding");
    conn.execute(
        "DELETE FROM records WHERE rowid = ?1",
        rusqlite::params![rowid],
    )
    .expect("delete record");

    // Assert all three tables empty.
    let r_count: i64 = conn
        .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
        .unwrap();
    let e_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |row| {
            row.get(0)
        })
        .unwrap();
    let f_count: i64 = conn
        .query_row("SELECT count(*) FROM records_fts", [], |row| row.get(0))
        .unwrap();
    assert_eq!((r_count, e_count, f_count), (0, 0, 0));
}
