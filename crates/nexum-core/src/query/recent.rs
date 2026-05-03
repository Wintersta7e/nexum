//! `recent(conn, limit, source)` — wrapper that specializes `list` to
//! `ORDER BY updated DESC` with an optional source filter.

use rusqlite::Connection;

use super::{
    list::list,
    types::{Filters, QueryError, ResultSet},
};
use crate::records::{Source, TrustPolicy};

/// Recently-updated records.
///
/// `trust_policy` is forwarded into [`list`] so the response envelope's
/// `_meta.trust_policy` reflects the runtime configuration.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::InvalidFilter` if `source` is unrecognized.
pub fn recent(
    conn: &Connection,
    trust_policy: TrustPolicy,
    limit: u32,
    source: Option<&str>,
) -> Result<ResultSet, QueryError> {
    // `Source::try_from_user_str` is the parse-from-untrusted-input boundary
    // that returns `None` on unknown values; here we lift that to an explicit
    // `QueryError::InvalidFilter`. The trusted-DB-column counterpart
    // (`Source::from_db_str`) silently defaults and is the wrong tool here.
    let source_filter = source
        .map(|s| {
            Source::try_from_user_str(s).ok_or_else(|| QueryError::InvalidFilter {
                detail: format!("unknown source: {s}"),
            })
        })
        .transpose()?;
    let filters = Filters {
        source: source_filter,
        ..Filters::default()
    };
    list(conn, &filters, trust_policy, limit, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::db::open_or_create;
    use tempfile::TempDir;

    fn open() -> (TempDir, rusqlite::Connection) {
        let dir = TempDir::new().unwrap();
        let conn = open_or_create(&dir.path().join("index.db")).unwrap();
        (dir, conn)
    }

    #[test]
    fn unknown_source_yields_invalid_filter() {
        let (_dir, conn) = open();
        let err = recent(&conn, TrustPolicy::WarnButShow, 10, Some("not-a-source")).unwrap_err();
        assert!(matches!(err, QueryError::InvalidFilter { .. }));
    }

    #[test]
    fn trust_policy_round_trips_into_meta() {
        let (_dir, conn) = open();
        let rs = recent(&conn, TrustPolicy::WarnButShow, 10, None).unwrap();
        assert_eq!(rs.meta.trust_policy, TrustPolicy::WarnButShow);
        let rs = recent(&conn, TrustPolicy::Hide, 10, None).unwrap();
        assert_eq!(rs.meta.trust_policy, TrustPolicy::Hide);
    }

    #[test]
    fn recent_with_no_source_returns_all() {
        let (_dir, conn) = open();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, signature_status, indexed_at) VALUES \
             ('a','local','p','decision','x','','[]','','manual','[]','[]','[]','medium', \
              '2026-04-01T00:00:00Z','2026-04-01T00:00:00Z','h','unsigned','2026-04-29T00:00:00Z'), \
             ('b','cc-native','p','decision','y','','[]','','claude-code','[]','[]','[]','medium', \
              '2026-04-02T00:00:00Z','2026-04-02T00:00:00Z','h','unsigned','2026-04-29T00:00:00Z')",
            [],
        )
        .unwrap();
        let rs = recent(&conn, TrustPolicy::WarnButShow, 10, None).unwrap();
        assert_eq!(rs.results.len(), 2);
    }
}
