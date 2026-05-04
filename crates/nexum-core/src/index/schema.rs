//! Index DDL constant + `apply()` helper that lands it onto a connection
//! and verifies the expected tables / triggers exist post-apply.

use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("sqlite error during DDL apply: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("expected {what} missing after DDL apply")]
    Missing { what: String },
    #[error(
        "migration required: on-disk schema is v{v_disk}; binary supports v{INDEX_DB_LATEST_VERSION}"
    )]
    MigrationRequired { v_disk: u32 },
}

/// Verbatim index DDL. Loaded from a sibling .sql file so SQL tooling works.
pub const DDL: &str = include_str!("schema.sql");

/// Latest index DB schema version known to this binary. Mirrors the
/// `PRAGMA user_version` value set inside `schema.sql`.
pub const INDEX_DB_LATEST_VERSION: u32 = 2;

/// Apply the index DDL to a connection.
///
/// Sets the index pragmas first (WAL mode, `busy_timeout`, `foreign_keys`),
/// then either runs the full DDL batch on a fresh DB, or returns
/// `SchemaError::MigrationRequired` for an older DB so the caller can dispatch
/// to `crate::migrate::index_db::migrate_to_latest`. Verifies the expected
/// tables / triggers / columns exist post-apply on the fresh path; any
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
/// Returns `SchemaError::Sqlite` if any pragma or DDL statement fails
/// (including vec0 table creation when the sqlite-vec extension is not
/// registered). Returns `SchemaError::Missing` if the post-apply verification
/// finds any expected table, trigger, or column absent from `sqlite_master`.
/// Returns `SchemaError::MigrationRequired` when the on-disk
/// `PRAGMA user_version` is older than `INDEX_DB_LATEST_VERSION`; the caller
/// must invoke the migration framework.
pub fn apply(conn: &mut Connection) -> Result<(), SchemaError> {
    // Pragmas first. journal_mode = WAL is per-connection but persists in the file.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; \
         PRAGMA busy_timeout = 5000; \
         PRAGMA foreign_keys = ON;",
    )?;

    let v_disk = read_user_version(conn)?;
    let records_exists = records_table_exists(conn)?;

    if v_disk == 0 && !records_exists {
        // Fresh DB: apply the full DDL. The `PRAGMA user_version = 2` inside
        // the DDL bumps the version sentinel as part of the same batch.
        conn.execute_batch(DDL)?;
    } else if v_disk == 0 && records_exists {
        // Pre-version-tracking DB written before the schema-migration
        // framework existed (no `PRAGMA user_version` was set). Bump the
        // version sentinel to 1 in-place so the v1->v2 migrator handles it
        // cleanly. This only synthesizes the version sentinel; no actual
        // schema mutation runs here.
        conn.execute_batch("PRAGMA user_version = 1;")?;
        return Err(SchemaError::MigrationRequired { v_disk: 1 });
    } else if v_disk == INDEX_DB_LATEST_VERSION {
        // Already current. Pragmas are set above; nothing else to do.
    } else {
        // Older versioned DB: caller must use
        // `crate::migrate::index_db::migrate_to_latest`.
        return Err(SchemaError::MigrationRequired { v_disk });
    }

    verify_post_apply(conn)?;
    Ok(())
}

/// Read the on-disk `PRAGMA user_version` sentinel.
fn read_user_version(conn: &Connection) -> Result<u32, SchemaError> {
    let v: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(v)
}

/// Verify the v2 schema shape is in place after `apply` returns Ok. Catches
/// scenarios where the DDL ran partially or a migration left tables missing.
fn verify_post_apply(conn: &Connection) -> Result<(), SchemaError> {
    for name in [
        "records",
        "record_embeddings",
        "records_fts",
        "trust_events",
        "trust_chain_tampering",
        "meta",
    ] {
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
    let cols = records_columns(conn)?;
    for col in [
        "record_commit_sha",
        "signer_fingerprint",
        "crypto_result",
        "relevant_trust_events_commit",
    ] {
        if !cols.contains(col) {
            return Err(SchemaError::Missing {
                what: format!("column:records.{col}"),
            });
        }
    }
    Ok(())
}

/// True iff the `records` table is already present in `sqlite_master`. Used
/// to choose between the fresh-DB DDL path and the migration-required branch.
pub(crate) fn records_table_exists(conn: &Connection) -> Result<bool, SchemaError> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='records'",
        [],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

/// Read the full set of column names for the `records` table in one
/// `PRAGMA table_info` call. Callers check membership against the returned
/// set instead of issuing a separate PRAGMA per column.
fn records_columns(conn: &Connection) -> Result<std::collections::HashSet<String>, SchemaError> {
    let mut stmt = conn.prepare("PRAGMA table_info(records)")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    rows.collect::<Result<std::collections::HashSet<_>, _>>()
        .map_err(SchemaError::from)
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
    fn ddl_constant_includes_v2_columns_and_tables() {
        for col in [
            "record_commit_sha",
            "signer_fingerprint",
            "crypto_result",
            "relevant_trust_events_commit",
        ] {
            assert!(DDL.contains(col), "DDL must include records column `{col}`");
        }
        for table in ["trust_events", "trust_chain_tampering", "meta"] {
            assert!(
                DDL.contains(&format!("CREATE TABLE {table}")),
                "DDL must define table `{table}`"
            );
        }
        assert!(
            DDL.contains("PRAGMA user_version = 2"),
            "DDL must bump user_version to 2"
        );
    }
}
