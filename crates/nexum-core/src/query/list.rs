//! `list(conn, filters, limit, cursor)` — paginated list with filter pushdown.
//! Sort order: `updated DESC, rowid DESC` for stable pagination.

use rusqlite::Connection;

use super::{
    search::build_filter_sql,
    types::{Filters, QueryError, ResultSet, SearchResult},
};
use crate::records::{RecordType, SignatureStatus, Source, TrustBasis, TrustPolicy};

/// Sentinel used in the keyset compare when no cursor is supplied. Any
/// `updated` string (RFC3339 timestamp) compares strictly less than this
/// sentinel under `SQLite`'s lexicographic text ordering, making the
/// `(updated, rowid) < (?1, ?2)` predicate non-restrictive on the first
/// page.
const CURSOR_SENTINEL_UPDATED: &str = "9999-12-31T23:59:59Z";

/// Paginated list with `(updated DESC, rowid DESC)` ordering.
///
/// The cursor encodes the full sort key — both `updated` and `rowid` — so
/// pagination remains correct when insertion order does not match
/// `updated DESC` order. The wire format is opaque
/// (`"<updated>|<rowid>"`); the `|` separator is collision-safe because
/// RFC3339 timestamps never contain it.
///
/// `trust_policy` is passed through verbatim into the response envelope so
/// the `_meta.trust_policy` field accurately reflects the runtime
/// `[trust] unsigned_default` setting.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::InvalidFilter` if the cursor is malformed.
pub fn list(
    conn: &Connection,
    filters: &Filters,
    trust_policy: TrustPolicy,
    limit: u32,
    cursor: Option<&str>,
) -> Result<ResultSet, QueryError> {
    let (filter_sql, filter_params) = build_filter_sql(filters);

    // Decode cursor → (updated, rowid). On the first page, use a sentinel
    // pair that compares strictly greater than any plausible row so the
    // keyset predicate is non-restrictive.
    let (cursor_updated, cursor_rowid): (String, i64) = match cursor {
        Some(c) => decode_cursor(c)?,
        None => (CURSOR_SENTINEL_UPDATED.to_owned(), i64::MAX),
    };

    // Param layout: `?1` = cursor_updated, `?2` = cursor_rowid; filters
    // bind at `?3..?N` (matching `build_filter_sql`'s `next_idx` start);
    // LIMIT binds last at the placeholder index computed below.
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    params.push(rusqlite::types::Value::Text(cursor_updated));
    params.push(rusqlite::types::Value::Integer(cursor_rowid));
    let filter_param_count = filter_params.len();
    for p in filter_params {
        params.push(p);
    }
    // After cursor (2) + filters, LIMIT lives at `?{filter_param_count + 3}`.
    let limit_idx = filter_param_count + 3;
    params.push(rusqlite::types::Value::Integer(i64::from(limit + 1)));

    let sql = format!(
        "SELECT records.rowid, records.id, records.record_type, records.title, records.summary, \
                records.source, records.project_id, records.signature_status, records.updated \
         FROM records \
         WHERE (records.updated, records.rowid) < (?1, ?2) {filter_sql} \
         ORDER BY records.updated DESC, records.rowid DESC \
         LIMIT ?{limit_idx}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .flatten();

    let mut accumulated: Vec<(i64, SearchResult)> = Vec::new();
    for (rowid, id, rt, title, summary, source, project_id, sig, updated) in rows {
        let signature_status = SignatureStatus::from_db_str(&sig);
        let trust_basis = if signature_status == SignatureStatus::Verified {
            Some(TrustBasis::Current)
        } else {
            None
        };
        let mut warnings: Vec<String> = Vec::new();
        if signature_status != SignatureStatus::Verified {
            warnings.push("unsigned".into());
        }
        accumulated.push((
            rowid,
            SearchResult {
                id,
                record_type: RecordType::from_db_str(&rt),
                title,
                summary,
                score: 0.0,
                source: Source::from_db_str(&source),
                project_id,
                signature_status,
                trust_basis,
                warnings,
                body: None,
                updated,
            },
        ));
    }

    // Drop the over-limit sentinel row so it does not leak into the
    // results, then encode the cursor from the LAST RETURNED row's
    // sort key. The next page asks for rows STRICTLY beyond that key
    // (`(updated, rowid) < (cursor)`), which is the canonical keyset
    // pagination invariant.
    let over_limit = accumulated.len() > usize::try_from(limit).unwrap_or(0);
    if over_limit {
        accumulated.pop();
    }
    let next_cursor: Option<String> = if over_limit {
        accumulated
            .last()
            .map(|(rowid, r)| encode_cursor(&r.updated, *rowid))
    } else {
        None
    };
    let results: Vec<SearchResult> = accumulated.into_iter().map(|(_, r)| r).collect();
    let total = u32::try_from(results.len()).unwrap_or(u32::MAX);

    let meta = super::meta::build_meta(conn, &results, trust_policy, false, 0)?;
    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor,
        meta,
    })
}

/// Encode the keyset pivot as an opaque cursor string.
fn encode_cursor(updated: &str, rowid: i64) -> String {
    format!("{updated}|{rowid}")
}

/// Decode an opaque cursor back into its `(updated, rowid)` keyset pair.
fn decode_cursor(c: &str) -> Result<(String, i64), QueryError> {
    let (u, r) = c.split_once('|').ok_or_else(|| QueryError::InvalidFilter {
        detail: format!("invalid cursor: {c}"),
    })?;
    let rowid: i64 = r.parse().map_err(|_| QueryError::InvalidFilter {
        detail: format!("invalid cursor rowid: {r}"),
    })?;
    Ok((u.to_owned(), rowid))
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

    fn insert(conn: &rusqlite::Connection, id: &str, updated: &str) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, \
             created, updated, content_hash, signature_status, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', \
                     '2026-01-01T00:00:00Z', ?2, 'h', 'verified', '2026-04-29T00:01:00Z')",
            rusqlite::params![id, updated],
        )
        .unwrap();
    }

    #[test]
    fn list_returns_results_in_updated_desc_order() {
        let (_dir, conn) = open();
        insert(&conn, "older", "2026-01-01T00:00:00Z");
        insert(&conn, "newer", "2026-04-01T00:00:00Z");
        let rs = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            10,
            None,
        )
        .unwrap();
        assert_eq!(rs.results[0].id, "newer");
        assert_eq!(rs.results[1].id, "older");
    }

    #[test]
    fn list_pagination_yields_next_cursor_when_over_limit() {
        let (_dir, conn) = open();
        for i in 0..5 {
            insert(
                &conn,
                &format!("r{i}"),
                &format!("2026-04-{:02}T00:00:00Z", i + 1),
            );
        }
        let rs = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            3,
            None,
        )
        .unwrap();
        assert_eq!(rs.results.len(), 3);
        assert!(rs.next_cursor.is_some());
    }

    #[test]
    fn list_filter_by_record_type_pushes_into_sql() {
        let (_dir, conn) = open();
        insert(&conn, "d1", "2026-04-01T00:00:00Z");
        // Insert a recommendation manually so the filter has a target.
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, signature_status, indexed_at) VALUES \
             ('r1', 'local', 'p', 'recommendation', 't', '', '[]', '', 'manual', '[]', '[]', '[]', \
              'medium', '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z', 'h', 'verified', '2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        let filters = Filters {
            record_type: Some(crate::records::RecordType::Recommendation),
            ..Filters::default()
        };
        let rs = list(&conn, &filters, TrustPolicy::WarnButShow, 10, None).unwrap();
        assert_eq!(rs.results.len(), 1);
        assert_eq!(rs.results[0].id, "r1");
    }

    /// Regression: pagination must remain correct when insertion order
    /// does not match `updated DESC` ordering. Prior to the keyset fix
    /// the cursor only encoded `rowid`, so `WHERE rowid < ?1` skipped
    /// rows whose `updated` placed them before the pivot but whose
    /// `rowid` was larger than the pivot's rowid — yielding duplicates
    /// across pages.
    #[test]
    fn list_pagination_correct_when_rowid_order_differs_from_updated_desc() {
        let (_dir, conn) = open();
        // Insert in id order (rowids 1..=5) but with shuffled `updated`
        // timestamps so `(updated DESC, rowid DESC)` ranks them
        // [r2, r5, r3, r1, r4] (updated desc ordering of the values
        // below).
        insert(&conn, "r1", "2026-04-01T00:00:00Z"); // rowid=1
        insert(&conn, "r2", "2026-04-15T00:00:00Z"); // rowid=2
        insert(&conn, "r3", "2026-04-10T00:00:00Z"); // rowid=3
        insert(&conn, "r4", "2026-03-20T00:00:00Z"); // rowid=4
        insert(&conn, "r5", "2026-04-12T00:00:00Z"); // rowid=5

        let mut all_ids: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        // Hard cap to avoid an accidental infinite loop if pagination is
        // broken in a way that always re-emits the same pivot.
        for _ in 0..10 {
            let page = list(
                &conn,
                &Filters::default(),
                TrustPolicy::WarnButShow,
                1,
                cursor.as_deref(),
            )
            .unwrap();
            for r in &page.results {
                all_ids.push(r.id.clone());
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        // Union must contain every record exactly once.
        let mut sorted = all_ids.clone();
        sorted.sort();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted, deduped, "duplicate ids across pages: {all_ids:?}");
        assert_eq!(
            sorted,
            vec![
                "r1".to_owned(),
                "r2".to_owned(),
                "r3".to_owned(),
                "r4".to_owned(),
                "r5".to_owned(),
            ],
            "pagination missed records"
        );

        // Order across pages must match `updated DESC`.
        assert_eq!(
            all_ids,
            vec![
                "r2".to_owned(), // 2026-04-15
                "r5".to_owned(), // 2026-04-12
                "r3".to_owned(), // 2026-04-10
                "r1".to_owned(), // 2026-04-01
                "r4".to_owned(), // 2026-03-20
            ],
        );
    }

    #[test]
    fn trust_policy_round_trips_into_meta() {
        let (_dir, conn) = open();
        insert(&conn, "x", "2026-04-01T00:00:00Z");
        let rs = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            10,
            None,
        )
        .unwrap();
        assert_eq!(rs.meta.trust_policy, TrustPolicy::WarnButShow);
        let rs = list(&conn, &Filters::default(), TrustPolicy::Hide, 10, None).unwrap();
        assert_eq!(rs.meta.trust_policy, TrustPolicy::Hide);
    }

    #[test]
    fn list_rejects_malformed_cursor() {
        let (_dir, conn) = open();
        let err = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            1,
            Some("not-a-cursor"),
        )
        .unwrap_err();
        assert!(matches!(err, QueryError::InvalidFilter { .. }));
        let err = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            1,
            Some("2026-04-01T00:00:00Z|notanint"),
        )
        .unwrap_err();
        assert!(matches!(err, QueryError::InvalidFilter { .. }));
    }
}
