//! `recent(conn, limit, source)` — wrapper that specializes `list` to
//! `ORDER BY updated DESC` with an optional source filter.

use rusqlite::Connection;

use super::{
    list::list,
    types::{Filters, QueryError, ResultSet},
};
use crate::records::Source;

/// Recently-updated records.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::InvalidFilter` if `source` is unrecognized.
pub fn recent(
    conn: &Connection,
    limit: u32,
    source: Option<&str>,
) -> Result<ResultSet, QueryError> {
    let source_filter = match source {
        Some("local") => Some(Source::Local),
        Some("cc-native") => Some(Source::CcNative),
        Some("codex-native") => Some(Source::CodexNative),
        Some(other) => {
            return Err(QueryError::InvalidFilter {
                detail: format!("unknown source: {other}"),
            });
        }
        None => None,
    };
    let filters = Filters {
        source: source_filter,
        ..Filters::default()
    };
    list(conn, &filters, limit, None)
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
        let err = recent(&conn, 10, Some("not-a-source")).unwrap_err();
        assert!(matches!(err, QueryError::InvalidFilter { .. }));
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
        let rs = recent(&conn, 10, None).unwrap();
        assert_eq!(rs.results.len(), 2);
    }
}
