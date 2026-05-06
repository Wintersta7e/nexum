//! v1 -> v2 migration: schema reshape for verifier work.
//!
//! - DROP `idx_records_signature`.
//! - DROP `signature_status` / `trust_basis` / `warning_code` columns from
//!   `records`.
//! - ADD `crypto_result` column (NOT NULL DEFAULT 'no-signature').
//! - ADD `relevant_trust_events_commit` column.
//! - CREATE `idx_records_crypto`.
//! - CREATE `idx_records_trust_events_commit`.
//! - CREATE `trust_events`, `trust_chain_tampering`, `meta` tables.
//!
//! Existing records survive the migration with `crypto_result='no-signature'`;
//! a re-run of `nexum index` repopulates the cache correctly.

use rusqlite::Transaction;

use crate::migrate::MigrationError;

/// Apply the v1 -> v2 reshape inside an open transaction. The framework
/// commits the transaction and bumps `PRAGMA user_version` on success.
///
/// # Errors
///
/// Returns `MigrationError::Sqlite` on any DDL failure. The caller (the
/// migration framework) wraps it into `MigrationError::StepFailed` with
/// from/to context.
pub fn apply(tx: &Transaction, _from: u32) -> Result<(), MigrationError> {
    tx.execute_batch("DROP INDEX IF EXISTS idx_records_signature;")?;

    tx.execute_batch(
        "ALTER TABLE records DROP COLUMN signature_status;
         ALTER TABLE records DROP COLUMN trust_basis;
         ALTER TABLE records DROP COLUMN warning_code;",
    )?;

    tx.execute_batch(
        "ALTER TABLE records ADD COLUMN crypto_result TEXT NOT NULL DEFAULT 'no-signature' \
         CHECK (crypto_result IN ('good', 'bad-signature', 'unknown-signer', 'no-signature'));
         CREATE INDEX idx_records_crypto ON records(crypto_result);
         ALTER TABLE records ADD COLUMN relevant_trust_events_commit TEXT;
         CREATE INDEX idx_records_trust_events_commit ON records(relevant_trust_events_commit);",
    )?;

    tx.execute_batch(
        "CREATE TABLE trust_events (
            event_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind IN ('BootstrapKey', 'KeyAdded', 'KeyRotatedOut', 'KeyCompromised', 'BootstrapReanchor')),
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
            kind TEXT NOT NULL CHECK (kind IN ('ReorderedDeleted', 'MutatedPayload', 'DuplicateId')),
            detected_at TEXT NOT NULL,
            PRIMARY KEY (at_commit, event_id, kind)
        );

        CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn create_v1_records_shape(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE records (
                rowid INTEGER PRIMARY KEY,
                id TEXT NOT NULL,
                source TEXT NOT NULL,
                project_id TEXT NOT NULL,
                signature_status TEXT NOT NULL DEFAULT 'unsigned',
                trust_basis TEXT,
                warning_code TEXT,
                content_hash TEXT NOT NULL DEFAULT '',
                index_hash TEXT NOT NULL DEFAULT '',
                indexed_at TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                tags JSON NOT NULL DEFAULT '[]',
                tags_fts TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'medium',
                outcome TEXT NOT NULL DEFAULT 'n-a',
                agent TEXT NOT NULL DEFAULT 'manual',
                created TEXT NOT NULL DEFAULT '',
                updated TEXT NOT NULL DEFAULT '',
                record_type TEXT NOT NULL DEFAULT 'untyped',
                summary TEXT,
                body_origin_path TEXT,
                session_refs JSON,
                files JSON,
                commits JSON,
                record_commit_sha TEXT,
                signer_fingerprint TEXT,
                extras JSON,
                UNIQUE (source, project_id, id)
            );
            CREATE INDEX idx_records_signature ON records(signature_status);
            PRAGMA user_version = 1;",
        )
        .unwrap();
    }

    #[test]
    fn v1_to_v2_drops_old_columns_and_adds_crypto_result() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_v1_records_shape(&conn);
        conn.execute(
            "INSERT INTO records (id, source, project_id, signature_status) \
             VALUES ('r1', 'local', 'p', 'verified')",
            [],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        apply(&tx, 1).unwrap();
        tx.execute("PRAGMA user_version = 2", []).unwrap();
        tx.commit().unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(records)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(cols.contains(&"crypto_result".to_string()));
        assert!(cols.contains(&"relevant_trust_events_commit".to_string()));
        assert!(!cols.contains(&"signature_status".to_string()));
        assert!(!cols.contains(&"trust_basis".to_string()));
        assert!(!cols.contains(&"warning_code".to_string()));

        let cr: String = conn
            .query_row(
                "SELECT crypto_result FROM records WHERE id = 'r1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cr, "no-signature");

        for table in ["trust_events", "trust_chain_tampering", "meta"] {
            let exists: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "expected table {table}");
        }
    }
}
