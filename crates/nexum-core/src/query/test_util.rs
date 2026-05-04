//! Shared test fixtures for the query module's unit tests. Compiled
//! only under `#[cfg(test)]`.

#![cfg(test)]

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

/// Open an in-memory DB pre-populated with 3 verified, 2 unsigned, and 1
/// invalid record. Used by `list`, `recent`, and `by_session` trust-policy
/// tests that need a mixed-status fixture. The `crypto_result` SQL column
/// uses the four `git verify-commit` exit-code states; this helper translates
/// the convenient (verified/unsigned/invalid) shorthand into the column form
/// (`good` / `no-signature` / `bad-signature`).
pub(crate) fn setup_test_db_with_mixed_signature_status() -> rusqlite::Connection {
    let conn = crate::indexer::db::open_or_create_in_memory_for_tests();
    let now = chrono::Utc::now();
    for (id, status) in [
        ("v1", "verified"),
        ("v2", "verified"),
        ("v3", "verified"),
        ("u1", "unsigned"),
        ("u2", "unsigned"),
        ("i1", "invalid"),
    ] {
        insert_minimal_record(&conn, id, status, now);
    }
    conn
}

/// Insert the bare minimum record needed for trust-policy and hide-filter
/// tests. Omits optional fields; populates every NOT NULL column with a
/// stable placeholder value.
///
/// `signature_status` is the in-memory shorthand (`verified` / `unsigned` /
/// `invalid` / `unknown`); the helper maps it onto the `crypto_result` SQL
/// column form (`good` / `no-signature` / `bad-signature` / `unknown-signer`).
pub(crate) fn insert_minimal_record(
    conn: &Connection,
    id: &str,
    signature_status: &str,
    updated: DateTime<Utc>,
) {
    let crypto_result = match signature_status {
        "verified" => "good",
        "invalid" => "bad-signature",
        "unknown" => "unknown-signer",
        _ => "no-signature",
    };
    conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id,
            agent, confidence, outcome,
            crypto_result, tags, tags_fts,
            created, updated, content_hash, index_hash, indexed_at
         ) VALUES (?1, 'decision', ?2, 'b', 'local', 'git:test',
            'manual', 'medium', 'working',
            ?3, '[]', '',
            ?4, ?4, 'h', 'ih', ?4)",
        params![
            id,
            format!("title-{id}"),
            crypto_result,
            updated.to_rfc3339()
        ],
    )
    .unwrap();
}
