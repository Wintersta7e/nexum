//! `list(conn, filters, limit, cursor)` — paginated list with filter pushdown.
//! Sort order: `updated DESC, rowid DESC` for stable pagination.

use rusqlite::Connection;

use super::{
    policy::{PolicyOpts, apply as apply_policy},
    search::build_filter_sql,
    types::{Filters, QueryError, ResultSet, SearchResult},
    verify::{CachedCrypto, ProjectedTrust, ProjectionContext},
};
use crate::records::{CryptoResult, RecordType, Source, TrustPolicy};

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
/// `[trust] unsigned_default` setting. The strict-revocation overlay
/// rides on [`Filters::strict_revocation`]; the api facade fills it from
/// `cfg.trust.strict_revocation`.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::InvalidFilter` if the cursor is malformed;
/// `QueryError::Trust` if the chain-state hydration fails.
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
                records.source, records.project_id, records.crypto_result, records.updated, \
                records.record_commit_sha, records.signer_fingerprint, \
                records.relevant_trust_events_commit \
         FROM records \
         WHERE (records.updated, records.rowid) < (?1, ?2) {filter_sql} \
         ORDER BY records.updated DESC, records.rowid DESC \
         LIMIT ?{limit_idx}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), row_to_raw)?
        .collect::<Result<Vec<_>, _>>()?;

    // Hydrate the chain once per verb invocation. Reused for every row's
    // projection.
    let ctx = ProjectionContext::new(conn)?;

    // Project every row up-front so the projected trust shape is
    // available both for the policy filter and for materializing
    // `SearchResult` items.
    let mut projected_rows: Vec<(ListRow, ProjectedTrust)> =
        ctx.project_rows(rows, filters.strict_revocation, |raw| CachedCrypto {
            crypto_result: CryptoResult::from_db_str(&raw.crypto_result),
            signer_fingerprint: raw.signer_fingerprint.as_deref(),
            commit_sha: raw.record_commit_sha.as_deref(),
            relevant_trust_events_commit: raw.relevant_trust_events_commit.as_deref(),
        })?;

    // Drop the over-limit sentinel row before policy filtering so the
    // cursor is encoded from the last RETURNED row's sort key, regardless
    // of whether that row would have been hidden by policy. The next page
    // walks through the same projection + policy steps.
    let over_limit = projected_rows.len() > usize::try_from(limit).unwrap_or(0);
    if over_limit {
        projected_rows.pop();
    }
    let next_cursor: Option<String> = if over_limit {
        projected_rows
            .last()
            .map(|(raw, _)| encode_cursor(&raw.updated, raw.rowid))
    } else {
        None
    };

    // Centralized warn/hide/strict policy filter.
    let policy_opts = PolicyOpts {
        policy: trust_policy,
        require_signed: filters.require_signed,
    };
    let mut outcome = apply_policy(projected_rows, policy_opts, |row| &row.1);

    // Pluck the visible rows out so the policy bucket counters survive
    // the rest of the `outcome` value being consumed via `meta.apply_*`.
    let visible = std::mem::take(&mut outcome.visible);
    let results: Vec<SearchResult> = visible
        .into_iter()
        .map(|(raw, projected)| row_to_search_result(raw, projected))
        .collect();
    let total = u32::try_from(results.len()).unwrap_or(u32::MAX);

    let mut meta = super::meta::build_meta_listing(conn, trust_policy)?;
    meta.apply_policy_outcome(&outcome);
    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor,
        meta,
    })
}

/// Raw column tuple read out of a `records` row in the list / recent SELECT.
/// Mirrors the SELECT column order so `row_to_raw` stays a straight read.
struct ListRow {
    rowid: i64,
    id: String,
    record_type: String,
    title: String,
    summary: Option<String>,
    source: String,
    project_id: String,
    /// `records.crypto_result` SQL column (one of `good` / `bad-signature` /
    /// `unknown-signer` / `no-signature`).
    crypto_result: String,
    updated: String,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    /// SHA of the events.yml commit effective at the record's commit time.
    /// Forwarded into [`CachedCrypto`] for the read-time projection.
    relevant_trust_events_commit: Option<String>,
}

fn row_to_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<ListRow> {
    Ok(ListRow {
        rowid: r.get(0)?,
        id: r.get(1)?,
        record_type: r.get(2)?,
        title: r.get(3)?,
        summary: r.get(4)?,
        source: r.get(5)?,
        project_id: r.get(6)?,
        crypto_result: r.get(7)?,
        updated: r.get(8)?,
        record_commit_sha: r.get(9)?,
        signer_fingerprint: r.get(10)?,
        relevant_trust_events_commit: r.get(11)?,
    })
}

/// Materialize one (raw row, projected trust) pair into a `SearchResult`.
/// Splits out of `list` so the verb stays under the strict-clippy
/// `too-many-lines` threshold.
fn row_to_search_result(raw: ListRow, projected: ProjectedTrust) -> SearchResult {
    SearchResult {
        id: raw.id,
        record_type: RecordType::from_db_str(&raw.record_type),
        title: raw.title,
        summary: raw.summary,
        score: 0.0,
        source: Source::from_db_str(&raw.source),
        project_id: raw.project_id,
        signature_status: projected.signature_status,
        trust_basis: projected.trust_basis,
        record_commit_sha: raw.record_commit_sha,
        signer_fingerprint: raw.signer_fingerprint,
        warnings: projected.warnings,
        body: None,
        updated: raw.updated,
    }
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
    use crate::query::test_util::open_test_db_with_seeded_chain;

    fn open() -> (tempfile::TempDir, rusqlite::Connection) {
        open_test_db_with_seeded_chain()
    }

    fn insert(conn: &rusqlite::Connection, id: &str, updated: &str) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, \
             created, updated, content_hash, index_hash, crypto_result, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', 'working', \
                     '2026-01-01T00:00:00Z', ?2, 'h', 'ih', 'good', '2026-04-29T00:01:00Z')",
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
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('r1', 'local', 'p', 'recommendation', 't', '', '[]', '', 'manual', '[]', '[]', '[]', \
              'medium', 'proposed', '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z', 'h', 'ih', 'good', '2026-04-29T00:01:00Z')",
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

    #[test]
    fn list_with_hide_policy_filters_unsigned_and_counts_hidden() {
        let conn = crate::query::test_util::setup_test_db_with_mixed_signature_status();
        // 3 verified, 2 unsigned, 1 invalid in fixtures.
        let rs = list(&conn, &Filters::default(), TrustPolicy::Hide, 100, None).unwrap();
        assert_eq!(
            rs.results.len(),
            3,
            "only verified records visible under hide"
        );
        assert_eq!(rs.meta.hidden_unsigned, 2);
        assert_eq!(rs.meta.hidden_invalid, 1);
        assert_eq!(rs.meta.trust_policy, TrustPolicy::Hide);
    }

    #[test]
    fn list_with_warn_but_show_returns_all_zero_hidden() {
        let conn = crate::query::test_util::setup_test_db_with_mixed_signature_status();
        let rs = list(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            100,
            None,
        )
        .unwrap();
        assert_eq!(rs.results.len(), 6);
        assert_eq!(rs.meta.hidden_unsigned, 0);
        assert_eq!(rs.meta.hidden_invalid, 0);
    }
}
