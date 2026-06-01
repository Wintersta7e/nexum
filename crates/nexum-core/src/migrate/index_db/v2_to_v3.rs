//! v2 -> v3: add the M3 lifecycle columns (`commit_evidence`, `promoted_from`,
//! `inherited_warnings`) to the records table. All nullable; populated only
//! for promoted decisions.

use rusqlite::Transaction;

use crate::migrate::MigrationError;

/// Apply the v2 -> v3 column additions inside an open transaction.
///
/// # Errors
/// Returns `MigrationError::Sqlite` on any DDL failure.
pub fn apply(tx: &Transaction, _from: u32) -> Result<(), MigrationError> {
    tx.execute_batch(
        "ALTER TABLE records ADD COLUMN commit_evidence JSON;
         ALTER TABLE records ADD COLUMN promoted_from JSON;
         ALTER TABLE records ADD COLUMN inherited_warnings JSON;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Minimal v2 records shape: includes all columns present after v1→v2 but
    /// without the three lifecycle columns added by this step.
    fn create_v2_records_shape(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE records (
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
            PRAGMA user_version = 2;",
        )
        .unwrap();
    }

    #[test]
    fn v2_to_v3_adds_lifecycle_columns() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_v2_records_shape(&conn);
        conn.execute(
            "INSERT INTO records (id, source, project_id) VALUES ('r1', 'local', 'p')",
            [],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        apply(&tx, 2).unwrap();
        tx.execute("PRAGMA user_version = 3", []).unwrap();
        tx.commit().unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(records)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for col in ["commit_evidence", "promoted_from", "inherited_warnings"] {
            assert!(cols.contains(&col.to_string()), "records.{col} missing");
        }

        // Existing row survives with NULLs in the new columns.
        let ce: Option<String> = conn
            .query_row(
                "SELECT commit_evidence FROM records WHERE id = 'r1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(ce.is_none());
    }
}
