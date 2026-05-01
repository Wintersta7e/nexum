//! §7 index DDL constant + `apply()` helper that lands it onto a connection
//! and verifies the expected tables / triggers exist post-apply.

use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("sqlite error during DDL apply: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("expected {what} missing after DDL apply")]
    Missing { what: String },
}

/// Verbatim §7 DDL. Loaded from a sibling .sql file so SQL tooling works.
pub const DDL: &str = include_str!("schema.sql");

/// Apply the §7 DDL to a fresh connection.
///
/// Sets the §7 pragmas first (WAL mode, `busy_timeout`, `foreign_keys`), then runs
/// the DDL batch, then verifies the expected tables and triggers exist. Any
/// missing piece returns `SchemaError::Missing` rather than silently producing
/// a half-built schema.
///
/// **Caller contract:** the connection must already have the sqlite-vec extension
/// registered (e.g., via `rusqlite::ffi::sqlite3_auto_extension` before the
/// connection opens) — otherwise the `record_embeddings USING vec0(...)` table
/// creation will fail.
///
/// # Errors
///
/// Returns `SchemaError::Sqlite` if any pragma or DDL statement fails (including
/// vec0 table creation when the sqlite-vec extension is not registered). Returns
/// `SchemaError::Missing` if the post-apply verification finds any expected table
/// or trigger absent from `sqlite_master`.
pub fn apply(conn: &Connection) -> Result<(), SchemaError> {
    // Pragmas first. journal_mode = WAL is per-connection but persists in the file.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; \
         PRAGMA busy_timeout = 5000; \
         PRAGMA foreign_keys = ON;",
    )?;
    conn.execute_batch(DDL)?;
    // Verify expected tables exist.
    for name in ["records", "record_embeddings", "records_fts"] {
        let exists: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )?;
        if exists != 1 {
            return Err(SchemaError::Missing {
                what: format!("table:{name}"),
            });
        }
    }
    // Verify expected triggers exist.
    for name in ["records_ai", "records_ad", "records_au"] {
        let exists: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )?;
        if exists != 1 {
            return Err(SchemaError::Missing {
                what: format!("trigger:{name}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_constant_is_non_empty_and_mentions_records() {
        assert!(!DDL.is_empty(), "DDL constant must not be empty");
        assert!(
            DDL.contains("CREATE TABLE records"),
            "DDL must define records table"
        );
        assert!(
            DDL.contains("tags_fts TEXT NOT NULL"),
            "DDL must define tags_fts column"
        );
        assert!(
            DDL.contains("CREATE VIRTUAL TABLE records_fts USING fts5"),
            "DDL must define records_fts virtual table"
        );
    }
}
