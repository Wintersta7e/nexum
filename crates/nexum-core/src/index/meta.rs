//! Typed read/write helpers for the `meta` key/value table.
//!
//! The `meta` table stores cache sentinels and persisted state that survives
//! materializer rebuilds without needing dedicated columns. Keys here are the
//! canonical names; readers use `read_str` / `read_topo` and writers use
//! `write_str` / `write_meta_min_topo`.

use chrono::Utc;
use rusqlite::Connection;

/// Cache sentinel: HEAD commit SHA on the branch carrying `.trust/events.yml`
/// at the time the trust-events materializer last ran. Used to short-circuit
/// rebuilds when nothing has changed.
pub const KEY_TRUST_EVENTS_HEAD_SHA: &str = "trust_events_source_head_sha";

/// Cache sentinel: blob SHA of the `.trust/events.yml` file at the time the
/// materializer last ran. Detects in-place edits even when HEAD hasn't moved.
pub const KEY_TRUST_EVENTS_BLOB_SHA: &str = "trust_events_source_blob_sha";

/// Cache sentinel: RFC3339 timestamp of the last successful materialization
/// pass. Surfaced in diagnostics; not load-bearing for correctness.
pub const KEY_TRUST_EVENTS_MATERIALIZED_AT: &str = "trust_events_materialized_at";

/// Topological position at which the chain became frozen (e.g., due to an
/// unauthorized `BootstrapReanchor` that failed authorization conditions).
/// NULL/missing means chain not frozen. An unauthorized reanchor surfaces as
/// "broken-trust-chain" warning -- this meta key is the persistence mechanism
/// that ensures this state survives a materializer rebuild without needing a
/// new `trust_chain_tampering` kind.
pub const KEY_CHAIN_FROZEN_AT_TOPO: &str = "chain_frozen_at_topo";

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Read a string value out of the `meta` table by key. Returns `Ok(None)` when
/// the key is absent (the canonical "no value yet" signal).
///
/// # Errors
///
/// Returns `MetaError::Sqlite` if the underlying query fails for reasons
/// other than "no row" (e.g., a busy lock or a schema-missing error).
pub fn read_str(conn: &Connection, key: &str) -> Result<Option<String>, MetaError> {
    let mut stmt = conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
    let v = stmt.query_row([key], |r| r.get::<_, String>(0)).ok();
    Ok(v)
}

/// Insert or replace the value for `key`, stamping `updated_at` with the
/// current UTC time.
///
/// # Errors
///
/// Returns `MetaError::Sqlite` if the upsert fails.
pub fn write_str(conn: &Connection, key: &str, value: &str) -> Result<(), MetaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        rusqlite::params![key, value, now],
    )?;
    Ok(())
}

/// Write `topo_pos` to `key` if absent, OR if the existing value is greater
/// than `topo_pos` (we keep the earliest freeze point -- once the chain is
/// frozen at topo N, any later freeze at M > N is redundant).
///
/// Note: lower `topo_pos` = earlier commit on the chain.
///
/// # Errors
///
/// Returns `MetaError::Sqlite` if the upsert fails.
pub fn write_meta_min_topo(conn: &Connection, key: &str, topo_pos: i64) -> Result<(), MetaError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at \
         WHERE CAST(excluded.value AS INTEGER) < CAST(meta.value AS INTEGER)",
        rusqlite::params![key, topo_pos.to_string(), now],
    )?;
    Ok(())
}

/// Read a topological-position value out of the `meta` table by key. Returns
/// `Ok(None)` when the key is absent or the stored value can't be parsed as
/// an unsigned 64-bit integer (callers treat both as "no value").
///
/// # Errors
///
/// Returns `MetaError::Sqlite` if the underlying query fails for reasons
/// other than "no row".
pub fn read_topo(conn: &Connection, key: &str) -> Result<Option<u64>, MetaError> {
    Ok(read_str(conn, key)?.and_then(|s| s.parse::<u64>().ok()))
}
