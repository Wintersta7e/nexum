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

/// Apply the index DDL to a connection.
///
/// Sets the index pragmas first (WAL mode, `busy_timeout`, `foreign_keys`),
/// then either runs the full DDL batch on a fresh DB, or runs forward
/// migrations on an existing DB so rows persist across schema additions.
/// Verifies the expected tables / triggers / columns exist post-apply; any
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
/// Returns `SchemaError::Sqlite` if any pragma, DDL, or migration statement fails
/// (including vec0 table creation when the sqlite-vec extension is not
/// registered). Returns `SchemaError::Missing` if the post-apply verification
/// finds any expected table, trigger, or column absent from `sqlite_master`.
pub fn apply(conn: &Connection) -> Result<(), SchemaError> {
    // Pragmas first. journal_mode = WAL is per-connection but persists in the file.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; \
         PRAGMA busy_timeout = 5000; \
         PRAGMA foreign_keys = ON;",
    )?;
    if records_table_exists(conn)? {
        // Existing DB — apply additive migrations only. Bringing the DDL
        // again would `CREATE TABLE records` and fail on the existing table.
        migrate_existing(conn)?;
    } else {
        conn.execute_batch(DDL)?;
    }
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
    // Verify the verifier-provenance columns are present (added by
    // migrate_existing on older DBs, by the fresh DDL otherwise).
    for col in [
        "record_commit_sha",
        "signer_fingerprint",
        "trust_basis",
        "warning_code",
    ] {
        if !records_has_column(conn, col)? {
            return Err(SchemaError::Missing {
                what: format!("column:records.{col}"),
            });
        }
    }
    Ok(())
}

/// True iff the `records` table is already present in `sqlite_master`. Used
/// to choose between the fresh-DB DDL path and the additive-migration path.
fn records_table_exists(conn: &Connection) -> Result<bool, SchemaError> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='records'",
        [],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

/// True iff `records` already has a column named `col`. Read via
/// `PRAGMA table_info` so the lookup is structured rather than parsing
/// the stored CREATE statement.
fn records_has_column(conn: &Connection, col: &str) -> Result<bool, SchemaError> {
    let mut stmt = conn.prepare("PRAGMA table_info(records)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == col {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply additive migrations to an existing DB. Each step is idempotent
/// (skips when the target column / trigger / index already exists) so
/// re-running on an already-migrated DB is a no-op.
fn migrate_existing(conn: &Connection) -> Result<(), SchemaError> {
    // Verifier-provenance columns. All NULL-able TEXT — readers tolerate
    // missing values, so the migration is safe to apply mid-flight even
    // without a re-index pass.
    for col in [
        "record_commit_sha",
        "signer_fingerprint",
        "trust_basis",
        "warning_code",
    ] {
        if !records_has_column(conn, col)? {
            // SQLite parameter binding is not allowed for column names in
            // DDL, but the values come from a hardcoded slice (no untrusted
            // input) so the format-string concatenation is safe here.
            let stmt = format!("ALTER TABLE records ADD COLUMN {col} TEXT");
            conn.execute(&stmt, [])?;
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

    #[test]
    fn ddl_constant_includes_verifier_provenance_columns() {
        for col in [
            "record_commit_sha",
            "signer_fingerprint",
            "trust_basis",
            "warning_code",
        ] {
            assert!(
                DDL.contains(col),
                "DDL must include verifier-provenance column `{col}`"
            );
        }
    }

    #[test]
    fn migrate_existing_adds_missing_provenance_columns_and_is_idempotent() {
        // Recreate a pre-migration `records` shape (no verifier-provenance
        // columns) and confirm `apply` — which routes through the
        // migration branch — adds the four expected columns. A second
        // `apply` call must be a no-op.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE records (
                rowid INTEGER PRIMARY KEY,
                id TEXT NOT NULL,
                source TEXT NOT NULL,
                project_id TEXT NOT NULL
             );",
        )
        .unwrap();
        // A bare existing DB lacks the FTS / vec0 tables — but `apply`
        // requires them to be present for the post-apply verification, so
        // we bring up matching shells before invoking it.
        conn.execute_batch(
            "CREATE TABLE record_embeddings (rowid INTEGER PRIMARY KEY); \
             CREATE VIRTUAL TABLE records_fts USING fts5(title); \
             CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN SELECT 1; END; \
             CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN SELECT 1; END; \
             CREATE TRIGGER records_au AFTER UPDATE ON records BEGIN SELECT 1; END;",
        )
        .unwrap();

        // Sanity-check pre-state.
        for col in [
            "record_commit_sha",
            "signer_fingerprint",
            "trust_basis",
            "warning_code",
        ] {
            assert!(
                !records_has_column(&conn, col).unwrap(),
                "expected `{col}` to be missing pre-migration"
            );
        }

        apply(&conn).expect("first apply must succeed");
        for col in [
            "record_commit_sha",
            "signer_fingerprint",
            "trust_basis",
            "warning_code",
        ] {
            assert!(
                records_has_column(&conn, col).unwrap(),
                "expected `{col}` after migration"
            );
        }

        // Idempotent: a second apply must not error or duplicate columns.
        apply(&conn).expect("second apply must be a no-op");
    }
}
