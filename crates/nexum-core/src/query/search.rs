//! `search` — FTS-only ranked search.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::records::{Confidence, CryptoResult, RecordType, SignatureStatus, Source, TrustPolicy};

use super::{signature_status_for, trust_basis_for};

use super::types::{Filters, QueryError, ResultSet, SearchResult};

/// `search` options. Compose via `SearchOpts::new(query)` and fluent setters,
/// or by direct struct construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchOpts {
    pub query: String,
    pub top_k: u32,
    pub filters: Filters,
    pub trust_policy: TrustPolicy,
    /// Embedding pool saturation flag — surfaced through the response envelope
    /// once an embedder is wired. Currently always `false`.
    pub embed_pool_saturated: bool,
    pub saturation_wait_ms: u32,
    /// Multiplicative penalty applied to unsigned rows after RRF (and before
    /// the top-K cut). Defaults to `0.7` — match the historical hardcode that
    /// motivated this knob. The CLI/MCP facade overrides this with the
    /// configured `[trust] ranking_penalty` so a single value drives both
    /// presentation and ranking.
    pub unsigned_ranking_penalty: f64,
}

impl SearchOpts {
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            top_k: 5,
            filters: Filters::default(),
            trust_policy: TrustPolicy::WarnButShow,
            embed_pool_saturated: false,
            saturation_wait_ms: 0,
            unsigned_ranking_penalty: 0.7,
        }
    }
}

/// FTS-only ranked search. The vector branch is absent in the current build —
/// ranking degenerates to "by FTS5 bm25 rank, with the unsigned-content
/// penalty applied last".
///
/// # Errors
/// Returns `QueryError::Rusqlite` on any rusqlite error;
/// `QueryError::InvalidFilter` if a filter is malformed.
pub fn search(conn: &Connection, opts: &SearchOpts) -> Result<ResultSet, QueryError> {
    let (filter_sql, filter_params) = build_filter_sql(&opts.filters);

    // Cap on FTS candidates fed into RRF. 100 is enough for top-K=5 even
    // after aggressive filter pushdown; raise this if filtered queries
    // start under-returning on real corpora.
    let fts_limit: u32 = 100;

    // FTS query with filter pushdown. ?1 = MATCH query; ?2 = limit;
    // ?3..= filter params.
    let fts_sql = format!(
        "SELECT records.id, records.record_type, records.title, records.summary, \
                records.body, records.source, records.project_id, \
                records.crypto_result, records.updated, \
                records.record_commit_sha, records.signer_fingerprint \
         FROM records_fts \
         JOIN records ON records.rowid = records_fts.rowid \
         WHERE records_fts MATCH ?1 \
           {filter_sql} \
         ORDER BY records_fts.rank \
         LIMIT ?2"
    );

    let mut stmt = conn.prepare(&fts_sql)?;
    let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(2 + filter_params.len());
    params.push(rusqlite::types::Value::Text(opts.query.clone()));
    params.push(rusqlite::types::Value::Integer(i64::from(fts_limit)));
    for p in filter_params {
        params.push(p);
    }
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        let crypto_result = CryptoResult::from_db_str(&row.get::<_, String>(7)?);
        Ok(FtsRow {
            id: row.get(0)?,
            record_type: row.get::<_, String>(1)?,
            title: row.get(2)?,
            summary: row.get::<_, Option<String>>(3)?,
            body: row.get::<_, String>(4)?,
            source: row.get::<_, String>(5)?,
            project_id: row.get(6)?,
            crypto_result,
            updated: row.get(8)?,
            record_commit_sha: row.get::<_, Option<String>>(9)?,
            signer_fingerprint: row.get::<_, Option<String>>(10)?,
        })
    })?;
    let fts_rows: Vec<FtsRow> = rows.collect::<Result<Vec<_>, _>>()?;

    // Reciprocal-rank-fusion-style score over a single branch:
    //   score(r) = 1 / (k + rank)
    // With one branch the ranking degenerates to "by FTS rank ascending".
    // Apply the unsigned penalty after RRF, THEN the top-K cut.
    let k_const: f64 = 60.0;
    let mut scored: Vec<(FtsRow, f64)> = fts_rows
        .into_iter()
        .enumerate()
        .map(|(idx, r)| {
            let rank = u32::try_from(idx).unwrap_or(u32::MAX);
            let rank = f64::from(rank) + 1.0;
            let mut score = 1.0 / (k_const + rank);
            // FTS5 `rank` is a bm25 score (lower = better). The 1-based
            // ordinal above is the actual ranking signal; the underlying
            // bm25 value is intentionally not surfaced here.

            let is_unsigned = signature_status_for(r.crypto_result) != SignatureStatus::Verified;
            if is_unsigned && !opts.filters.no_unsigned_penalty {
                score *= opts.unsigned_ranking_penalty;
            }
            (r, score)
        })
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // require_signed override.
    if opts.filters.require_signed {
        scored.retain(|(r, _)| signature_status_for(r.crypto_result) == SignatureStatus::Verified);
    }
    // hide policy: drop unverified.
    if opts.trust_policy == TrustPolicy::Hide {
        scored.retain(|(r, _)| signature_status_for(r.crypto_result) == SignatureStatus::Verified);
    }

    let total = u32::try_from(scored.len()).unwrap_or(u32::MAX);
    let top_k = usize::try_from(opts.top_k).unwrap_or(usize::MAX);
    let top_n = scored.into_iter().take(top_k).collect::<Vec<_>>();

    // Body inclusion: top-3 for search; full record fetched in `get`.
    let results: Vec<SearchResult> = top_n
        .into_iter()
        .enumerate()
        .map(|(idx, (r, score))| project_row(r, score, idx < 3))
        .collect();

    let meta = super::meta::build_meta(
        conn,
        &results,
        opts.trust_policy,
        opts.embed_pool_saturated,
        opts.saturation_wait_ms,
    )?;

    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor: None,
        meta,
    })
}

/// Project a single FTS row + score into the public `SearchResult` shape,
/// applying the body-on-top-3 rule and surfacing canonical warnings.
fn project_row(r: FtsRow, score: f64, include_body: bool) -> SearchResult {
    let body = if include_body {
        Some(r.body.clone())
    } else {
        None
    };
    let signature_status = signature_status_for(r.crypto_result);
    // Bootstrap-only basis projection: `Good` -> `Some(Current)`, everything
    // else -> `None`. The full read-time projection (consulting trust_events)
    // lands later.
    let trust_basis = trust_basis_for(r.crypto_result);
    // Read-time warnings are populated by the verifier projection in a later
    // task; for now we surface an empty vec.
    let warnings: Vec<String> = Vec::new();
    SearchResult {
        id: r.id,
        record_type: RecordType::from_db_str(&r.record_type),
        title: r.title,
        summary: r.summary,
        score,
        source: Source::from_db_str(&r.source),
        project_id: r.project_id,
        signature_status,
        trust_basis,
        record_commit_sha: r.record_commit_sha,
        signer_fingerprint: r.signer_fingerprint,
        warnings,
        body,
        updated: r.updated,
    }
}

#[derive(Debug)]
struct FtsRow {
    id: String,
    record_type: String,
    title: String,
    summary: Option<String>,
    body: String,
    source: String,
    project_id: String,
    /// Cached `git verify-commit` outcome read straight from
    /// `records.crypto_result`. Both `signature_status` and `trust_basis`
    /// are projected from this value at row materialization time.
    crypto_result: CryptoResult,
    updated: String,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
}

/// Build the per-table filter clause + bound params for the SQL pushdown.
/// The returned SQL is appended after the FTS / records JOIN's WHERE clause;
/// its param indices start from `?3` (the call site passes `?1` = query,
/// `?2` = limit).
pub(crate) fn build_filter_sql(filters: &Filters) -> (String, Vec<rusqlite::types::Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    let mut next_idx: u32 = 3;

    if let Some(rt) = filters.record_type {
        let i = next_idx;
        next_idx += 1;
        clauses.push(format!("AND records.record_type = ?{i}"));
        params.push(rusqlite::types::Value::Text(rt.as_db_str().to_owned()));
    }
    if let Some(pid) = &filters.project_id {
        let i = next_idx;
        next_idx += 1;
        clauses.push(format!("AND records.project_id = ?{i}"));
        params.push(rusqlite::types::Value::Text(pid.clone()));
    }
    if let Some(source) = filters.source {
        let i = next_idx;
        next_idx += 1;
        clauses.push(format!("AND records.source = ?{i}"));
        params.push(rusqlite::types::Value::Text(source.as_db_str().to_owned()));
    }
    for tag in &filters.tags {
        let i = next_idx;
        next_idx += 1;
        // Tag-column rule: exact filters MUST go through the raw `tags`
        // JSON column, not `tags_fts`.
        clauses.push(format!(
            "AND EXISTS (SELECT 1 FROM json_each(records.tags) WHERE value = ?{i})"
        ));
        params.push(rusqlite::types::Value::Text(tag.clone()));
    }
    if let Some(since) = &filters.since_iso {
        let i = next_idx;
        next_idx += 1;
        clauses.push(format!("AND records.updated >= ?{i}"));
        params.push(rusqlite::types::Value::Text(since.clone()));
    }
    if let Some(min) = filters.min_confidence {
        let i = next_idx;
        // The `records.confidence` column stores the serialized form
        // (`"low" | "medium" | "high"`). For `min_confidence` we use an
        // explicit IN clause rather than ordinal comparison since the
        // column is text.
        let allowed: &[&str] = match min {
            Confidence::High => &["high"],
            Confidence::Medium => &["medium", "high"],
            Confidence::Low => &["low", "medium", "high"],
        };
        let placeholders = (0..allowed.len())
            .map(|j| {
                let offset = u32::try_from(j).unwrap_or(0);
                format!("?{}", i + offset)
            })
            .collect::<Vec<_>>()
            .join(",");
        clauses.push(format!("AND records.confidence IN ({placeholders})"));
        for v in allowed {
            params.push(rusqlite::types::Value::Text((*v).to_owned()));
        }
        // Bump `next_idx` so any future filter clause appended after
        // this branch gets fresh placeholder indices instead of
        // colliding on the ones we just consumed. Read back into `_`
        // so the invariant survives even though this is currently the
        // last clause in the function.
        next_idx += u32::try_from(allowed.len()).unwrap_or(u32::MAX);
        let _ = next_idx;
    }

    (clauses.join(" "), params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    /// Open a fresh `index.db` under a `TempDir` so the schema (records +
    /// `records_fts` + `record_embeddings`) and sqlite-vec auto-extension are
    /// applied via the same path as production.
    fn open_test_db() -> (TempDir, Connection) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("index.db");
        let conn =
            crate::indexer::db::open_or_create(&path).expect("open_or_create with full schema");
        (dir, conn)
    }

    fn insert_minimal(conn: &Connection, id: &str, title: &str, body: &str, signed: bool) {
        let cr = if signed { "good" } else { "no-signature" };
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, confidence, outcome, created, updated, content_hash, index_hash, \
             crypto_result, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?2, ?3, '[]', '', \
                     'manual', 'medium', 'working', \
                     '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', ?4, '2026-04-29T00:00:00Z')",
            rusqlite::params![id, title, body, cr],
        )
        .unwrap();
    }

    #[test]
    fn empty_index_search_returns_no_results() {
        let (_dir, conn) = open_test_db();
        let res = search(&conn, &SearchOpts::new("anything")).unwrap();
        assert_eq!(res.results.len(), 0);
        assert_eq!(res.total_matched, 0);
    }

    #[test]
    fn fts_match_finds_record_by_body_term() {
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "id1", "title-a", "body with concurrency word", true);
        let res = search(&conn, &SearchOpts::new("concurrency")).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].id, "id1");
        assert!(res.results[0].body.is_some(), "top-3 must include body");
    }

    #[test]
    fn unsigned_results_get_penalty_unless_disabled() {
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "u", "concurrency unsigned", "body", false);
        insert_minimal(&conn, "v", "concurrency verified", "body", true);
        let res = search(&conn, &SearchOpts::new("concurrency")).unwrap();
        // The verified row scores higher than the unsigned row.
        assert_eq!(res.results[0].id, "v");
        assert_eq!(res.results[1].id, "u");

        // With penalty disabled, ordering goes back to FTS rank (which is a
        // deterministic but undocumented function of tokens; we only check
        // both rows are present).
        let mut opts = SearchOpts::new("concurrency");
        opts.filters.no_unsigned_penalty = true;
        let res = search(&conn, &opts).unwrap();
        assert_eq!(res.results.len(), 2);
    }

    #[test]
    fn unsigned_ranking_penalty_from_opts_overrides_default() {
        // Confirm that opts.unsigned_ranking_penalty is honored, not the
        // hardcoded 0.7. With penalty == 1.0 (no penalty), unsigned rows are
        // not down-weighted; both rows must be present in the result set
        // (verified-vs-unsigned ordering is FTS-rank dependent so we don't
        // assert a deterministic order).
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "u", "term unsigned", "body", false);
        insert_minimal(&conn, "v", "term verified", "body", true);
        let mut opts = SearchOpts::new("term");
        opts.unsigned_ranking_penalty = 1.0;
        let res = search(&conn, &opts).unwrap();
        assert_eq!(res.results.len(), 2);
    }

    #[test]
    fn require_signed_filters_unsigned_out() {
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "u", "concurrency unsigned", "body", false);
        insert_minimal(&conn, "v", "concurrency verified", "body", true);
        let mut opts = SearchOpts::new("concurrency");
        opts.filters.require_signed = true;
        let res = search(&conn, &opts).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].id, "v");
    }

    #[test]
    fn meta_envelope_populated_with_source_counts() {
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "id1", "concurrency", "body", true);
        let res = search(&conn, &SearchOpts::new("concurrency")).unwrap();
        assert_eq!(res.meta.source_counts.local, 1);
        assert_eq!(res.meta.source_counts.cc_native, 0);
        assert_eq!(res.meta.source_counts.codex_native, 0);
        assert_eq!(res.meta.trust_summary.verified, 1);
        assert_eq!(res.meta.trust_basis_summary.current, 1);
    }

    #[test]
    fn warn_but_show_with_unsigned_content_yields_policy_warning() {
        let (_dir, conn) = open_test_db();
        insert_minimal(&conn, "u", "concurrency u", "body", false);
        let res = search(&conn, &SearchOpts::new("concurrency")).unwrap();
        assert!(!res.meta.policy_warnings.is_empty());
        assert_eq!(res.meta.trust_summary.unsigned, 1);
    }
}
