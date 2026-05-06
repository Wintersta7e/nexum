//! Shared test fixtures for the query module's unit tests. Compiled
//! only under `#[cfg(test)]`.

#![cfg(test)]

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

/// Stable fingerprint for the bootstrap key seeded by
/// [`seed_bootstrap_chain`]. Verified rows in fixture data carry this
/// value in `records.signer_fingerprint` so the read-time projection
/// resolves them via the state machine to `Verified` + `Current`.
pub(crate) const TEST_BOOTSTRAP_FP: &str = "SHA256:test-bootstrap-fingerprint";

/// Stable trust-events commit SHA seeded by [`seed_bootstrap_chain`].
/// Verified rows in fixture data carry this value in
/// `records.relevant_trust_events_commit` so `topo_pos_of` resolves to
/// the seeded `BootstrapKey` event's topo position (0).
pub(crate) const TEST_TRUST_COMMIT: &str = "test-trust-commit-0";

/// Insert a single `BootstrapKey` row into `trust_events` at topo
/// position 0 keyed on [`TEST_BOOTSTRAP_FP`] / [`TEST_TRUST_COMMIT`].
/// Lets in-memory unit-test fixtures hydrate a non-empty `ChainState`
/// without invoking the full materializer against a notebook git repo.
pub(crate) fn seed_bootstrap_chain(conn: &Connection) {
    conn.execute(
        "INSERT INTO trust_events (
            event_id, kind, fingerprint, public_key,
            effective_commit, effective_commit_topo_pos,
            introduced_by_signer, materialized_at
         ) VALUES (
            'test-bootstrap-event', 'BootstrapKey', ?1, 'ssh-ed25519 AAAA test',
            ?2, 0,
            ?1, '2026-04-29T00:00:00Z'
         )",
        params![TEST_BOOTSTRAP_FP, TEST_TRUST_COMMIT],
    )
    .unwrap();
}

/// Open an in-memory DB pre-populated with 3 verified, 2 unsigned, and 1
/// invalid record. Used by `list`, `recent`, and `by_session` trust-policy
/// tests that need a mixed-status fixture. The `crypto_result` SQL column
/// uses the four `git verify-commit` exit-code states; this helper translates
/// the convenient (verified/unsigned/invalid) shorthand into the column form
/// (`good` / `no-signature` / `bad-signature`). Verified rows are tagged
/// with [`TEST_BOOTSTRAP_FP`] and [`TEST_TRUST_COMMIT`] so the read-time
/// projection can resolve them via the seeded chain.
pub(crate) fn setup_test_db_with_mixed_signature_status() -> rusqlite::Connection {
    let conn = crate::indexer::db::open_or_create_in_memory_for_tests();
    seed_bootstrap_chain(&conn);
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
/// Rows tagged `verified` carry [`TEST_BOOTSTRAP_FP`] +
/// [`TEST_TRUST_COMMIT`] so the projection resolves through the seeded
/// chain. Other states leave both columns NULL.
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
    let (signer_fp, trust_commit) = if signature_status == "verified" {
        (Some(TEST_BOOTSTRAP_FP), Some(TEST_TRUST_COMMIT))
    } else {
        (None, None)
    };
    conn.execute(
        "INSERT INTO records (
            id, record_type, title, body, source, project_id,
            agent, confidence, outcome,
            crypto_result, signer_fingerprint, relevant_trust_events_commit,
            tags, tags_fts,
            created, updated, content_hash, index_hash, indexed_at
         ) VALUES (?1, 'decision', ?2, 'b', 'local', 'git:test',
            'manual', 'medium', 'working',
            ?3, ?4, ?5,
            '[]', '',
            ?6, ?6, 'h', 'ih', ?6)",
        params![
            id,
            format!("title-{id}"),
            crypto_result,
            signer_fp,
            trust_commit,
            updated.to_rfc3339()
        ],
    )
    .unwrap();
}
