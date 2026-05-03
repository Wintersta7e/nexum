//! `index_state` — the stale-row sweep counter table.
//!
//! The reindex algorithm only computes deletes on `Authoritative` passes;
//! on `Partial` passes, "gone" candidates are deferred. The counter
//! `consecutive_authoritative_misses` per (source, id) records how many
//! Authoritative passes in a row have observed the record as missing. After
//! 3 such consecutive misses, the row is actually deleted. Any Partial pass
//! resets the counter for its source — we don't know which records were
//! actually missing vs. just-not-read-this-pass.

use rusqlite::{Connection, params};

use crate::records::{RecordId, Source};

#[derive(Debug, thiserror::Error)]
pub enum IndexStateError {
    #[error(transparent)]
    Rusqlite(#[from] rusqlite::Error),
}

/// Apply the `index_state` DDL on the supplied connection (idempotent).
///
/// # Errors
/// Returns `IndexStateError::Rusqlite` on DDL failure.
pub fn apply_index_state_ddl(conn: &Connection) -> Result<(), IndexStateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS index_state ( \
            source TEXT NOT NULL, \
            id TEXT NOT NULL, \
            consecutive_authoritative_misses INTEGER NOT NULL DEFAULT 0, \
            PRIMARY KEY (source, id) \
         ); \
         CREATE INDEX IF NOT EXISTS idx_index_state_source ON index_state(source);",
    )?;
    Ok(())
}

/// Increment the miss counter for one (source, id) tuple. Inserts the row at
/// counter=1 if it doesn't yet exist.
///
/// # Errors
/// Returns `IndexStateError::Rusqlite` on SQL failure.
pub fn bump_miss(conn: &Connection, source: Source, id: &RecordId) -> Result<u32, IndexStateError> {
    let src = serialize_source(source);
    conn.execute(
        "INSERT INTO index_state (source, id, consecutive_authoritative_misses) \
         VALUES (?1, ?2, 1) \
         ON CONFLICT(source, id) DO UPDATE SET \
            consecutive_authoritative_misses = consecutive_authoritative_misses + 1",
        params![src, id],
    )?;
    let n: i64 = conn.query_row(
        "SELECT consecutive_authoritative_misses FROM index_state WHERE source = ?1 AND id = ?2",
        params![src, id],
        |r| r.get(0),
    )?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Reset the miss counter for ALL records of a source. Used when a Partial
/// pass arrives — we don't know which records were actually missing.
///
/// # Errors
/// Returns `IndexStateError::Rusqlite` on SQL failure.
pub fn reset_misses_for_source(conn: &Connection, source: Source) -> Result<(), IndexStateError> {
    let src = serialize_source(source);
    conn.execute(
        "UPDATE index_state SET consecutive_authoritative_misses = 0 WHERE source = ?1",
        params![src],
    )?;
    Ok(())
}

/// Reset the miss counter for one (source, id) tuple. Used when an
/// Authoritative pass observes the record present again — its counter
/// goes back to zero.
///
/// # Errors
/// Returns `IndexStateError::Rusqlite` on SQL failure.
pub fn reset_miss_for_id(
    conn: &Connection,
    source: Source,
    id: &RecordId,
) -> Result<(), IndexStateError> {
    let src = serialize_source(source);
    conn.execute(
        "UPDATE index_state SET consecutive_authoritative_misses = 0 \
         WHERE source = ?1 AND id = ?2",
        params![src, id],
    )?;
    Ok(())
}

/// Drop the `index_state` row for one (source, id) tuple. Used after deleting
/// the record itself (so the next index pass starts fresh).
///
/// # Errors
/// Returns `IndexStateError::Rusqlite` on SQL failure.
pub fn drop_state(conn: &Connection, source: Source, id: &RecordId) -> Result<(), IndexStateError> {
    let src = serialize_source(source);
    conn.execute(
        "DELETE FROM index_state WHERE source = ?1 AND id = ?2",
        params![src, id],
    )?;
    Ok(())
}

/// `consecutive_authoritative_misses` threshold ("3 consecutive clean passes
/// confirm true deletion"). Exposed as a constant so tests can verify the
/// threshold is honored without re-deriving from the spec.
pub const STALE_THRESHOLD: u32 = 3;

fn serialize_source(s: Source) -> &'static str {
    match s {
        Source::CcNative => "cc-native",
        Source::CodexNative => "codex-native",
        Source::Local => "local",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        STALE_THRESHOLD, apply_index_state_ddl, bump_miss, drop_state, reset_misses_for_source,
    };
    use crate::records::Source;
    use rusqlite::Connection;

    fn open_with_state() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        apply_index_state_ddl(&conn).unwrap();
        conn
    }

    #[test]
    fn apply_is_idempotent() {
        let conn = open_with_state();
        apply_index_state_ddl(&conn).unwrap();
    }

    #[test]
    fn bump_miss_inserts_at_1() {
        let conn = open_with_state();
        let n = bump_miss(&conn, Source::Local, &"id1".to_owned()).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn bump_miss_increments() {
        let conn = open_with_state();
        bump_miss(&conn, Source::Local, &"id1".to_owned()).unwrap();
        let n = bump_miss(&conn, Source::Local, &"id1".to_owned()).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn reset_misses_for_source_zeroes_all_of_source() {
        let conn = open_with_state();
        bump_miss(&conn, Source::Local, &"id1".to_owned()).unwrap();
        bump_miss(&conn, Source::Local, &"id2".to_owned()).unwrap();
        bump_miss(&conn, Source::CcNative, &"cc1".to_owned()).unwrap();
        reset_misses_for_source(&conn, Source::Local).unwrap();
        let local_a: i64 = conn
            .query_row(
                "SELECT consecutive_authoritative_misses FROM index_state \
                 WHERE source='local' AND id='id1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let local_b: i64 = conn
            .query_row(
                "SELECT consecutive_authoritative_misses FROM index_state \
                 WHERE source='local' AND id='id2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let cc_a: i64 = conn
            .query_row(
                "SELECT consecutive_authoritative_misses FROM index_state \
                 WHERE source='cc-native' AND id='cc1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(local_a, 0);
        assert_eq!(local_b, 0);
        assert_eq!(cc_a, 1, "other-source counters must be untouched");
    }

    #[test]
    fn drop_state_removes_row() {
        let conn = open_with_state();
        bump_miss(&conn, Source::Local, &"id1".to_owned()).unwrap();
        drop_state(&conn, Source::Local, &"id1".to_owned()).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM index_state WHERE id = 'id1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn stale_threshold_is_three() {
        assert_eq!(STALE_THRESHOLD, 3);
    }
}
