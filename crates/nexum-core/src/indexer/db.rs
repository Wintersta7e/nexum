//! Open / create `index.db` — applies the index DDL on first call (lazy).

use rusqlite::Connection;
use std::{
    path::{Path, PathBuf},
    sync::Once,
};

#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    #[error("sqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    #[error("schema apply error: {0}")]
    Schema(#[from] crate::index::schema::SchemaError),
    #[error("io error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("adapter error: {0}")]
    Adapter(#[from] crate::adapter::AdapterError),
    #[error("config error: {0}")]
    Config(String),
    #[error("trust error: {0}")]
    Trust(#[from] crate::trust::events::TrustError),
}

/// Open an existing `index.db` for read-only access. Returns
/// [`crate::query::QueryError::IndexMissing`] if the file does not exist,
/// rather than silently creating an empty database — that would mask a
/// "you forgot to run `nexum index`" error as "no results".
///
/// Opens with `SQLITE_OPEN_READ_ONLY` at the OS level, which is a stronger
/// invariant than `READ_WRITE + PRAGMA query_only`: the connection is
/// non-writable from the moment it is created, not just after the pragma fires.
/// Sets `busy_timeout = 5000` so a concurrent indexer writer doesn't
/// immediately error out reads. Does not run DDL.
///
/// Uses `OpenFlags` without `SQLITE_OPEN_CREATE` so `SQLite` itself
/// enforces the no-create invariant even if the `path.exists()` pre-check
/// loses a race with a concurrent delete.
///
/// # Errors
/// Returns `QueryError::IndexMissing { path }` when the database file
/// is absent. Returns `QueryError::Rusqlite` on any rusqlite error
/// after the file has been opened.
pub fn open_existing(path: &Path) -> Result<Connection, crate::query::QueryError> {
    if !path.exists() {
        return Err(crate::query::QueryError::IndexMissing {
            path: path.to_owned(),
        });
    }
    register_sqlite_vec_once();
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    Ok(conn)
}

/// Open `index.db` at `path`, creating + applying the index DDL if the records
/// table is absent. Registers the sqlite-vec extension globally on first
/// invocation so subsequent connections see vec0 too.
///
/// This is the writer entry point — read verbs should call
/// [`open_existing`] instead so they surface a clear error when the
/// index has not been populated yet.
///
/// # Errors
/// Returns `IndexerError::Rusqlite` if the database can't be opened, or
/// `IndexerError::Schema` if the DDL apply fails. Returns `IndexerError::Io`
/// if parent-directory creation fails.
pub fn open_or_create(path: &Path) -> Result<Connection, IndexerError> {
    register_sqlite_vec_once();
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| IndexerError::Io {
            path: parent.to_owned(),
            source: e,
        })?;
    }
    let mut conn = Connection::open(path)?;
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='records'",
        [],
        |row| row.get(0),
    )?;
    if exists == 0 {
        crate::index::schema::apply(&mut conn)?;
    } else {
        // Set pragmas on the open connection regardless (WAL is per-DB but
        // busy_timeout / foreign_keys are per-connection).
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; \
             PRAGMA busy_timeout = 5000; \
             PRAGMA foreign_keys = ON;",
        )?;
    }
    Ok(conn)
}

static SQLITE_VEC_REGISTERED: Once = Once::new();

/// Register the `sqlite-vec` auto-extension hook. Idempotent — `Once::call_once`
/// guards repeat invocations. After the first call, every new `rusqlite::Connection`
/// auto-loads vec0 / `vec_each` / etc. without per-connection setup.
///
/// The unsafe block bridges sqlite-vec's bindgen-generated `sqlite3` opaque alias
/// onto rusqlite's via `mem::transmute` — both function-pointer types are ABI-
/// equivalent. This is the documented sqlite-vec pattern for static linking with
/// rusqlite (see `tests/index_schema.rs::register_sqlite_vec` for the same pattern).
#[allow(unsafe_code)]
fn register_sqlite_vec_once() {
    use std::os::raw::{c_char, c_int};
    type RusqliteExtInit = unsafe extern "C" fn(
        *mut rusqlite::ffi::sqlite3,
        *mut *mut c_char,
        *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int;
    SQLITE_VEC_REGISTERED.call_once(|| {
        // SAFETY: sqlite3_auto_extension registers an init function that SQLite
        // invokes when each new connection is opened. sqlite_vec::sqlite3_vec_init
        // is the standard sqlite-vec entry point and is ABI-compatible with the
        // SQLite-extension init signature — but its rustc-visible type uses
        // sqlite-vec's bindgen-generated `sqlite3` opaque alias rather than
        // rusqlite's, so the transmute bridges the two ABI-equivalent function-
        // pointer types. This is the pattern documented by sqlite-vec for
        // static linking with rusqlite.
        unsafe {
            let init_fn: RusqliteExtInit =
                std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
            rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
        }
    });
}

/// Open a fresh in-memory database with the full index schema applied.
/// Intended only for unit tests in the query layer; gated by `#[cfg(test)]`.
///
/// # Panics
/// Panics on any DB / schema error — acceptable in test code.
#[cfg(test)]
pub(crate) fn open_or_create_in_memory_for_tests() -> rusqlite::Connection {
    register_sqlite_vec_once();
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    crate::index::schema::apply(&mut conn).unwrap();
    conn
}

#[cfg(test)]
mod tests {
    use super::open_or_create;
    use tempfile::TempDir;

    #[test]
    fn open_or_create_on_fresh_path_lays_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.db");
        let conn = open_or_create(&path).unwrap();
        // records table exists.
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='records'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        // records_fts virtual table exists.
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='records_fts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        // record_embeddings vec0 virtual table exists (sqlite-vec registered).
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='record_embeddings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn open_or_create_on_existing_db_does_not_reapply() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.db");
        {
            let conn = open_or_create(&path).unwrap();
            conn.execute(
                "INSERT INTO records (id, source, project_id, record_type, title, body, \
                 tags, tags_fts, agent, confidence, outcome, created, updated, content_hash, \
                 index_hash, crypto_result, indexed_at) VALUES \
                 ('rec1', 'local', 'p', 'decision', 'titlec', '', '[]', '', \
                  'manual', 'medium', 'working', \
                  '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'hashc', 'ih', 'no-signature', \
                  '2026-04-29T00:01:00Z')",
                [],
            )
            .unwrap();
        }
        // Reopen and confirm row survives (i.e. DDL was not reapplied).
        let conn = open_or_create(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM records WHERE id = 'rec1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn open_or_create_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deeper").join("index.db");
        let _ = open_or_create(&path).unwrap();
        assert!(path.exists());
    }
}
