//! `search` — FTS-only ranked search.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::records::{Confidence, CryptoResult, RecordType, SignatureStatus, Source, TrustPolicy};

use super::policy::{apply as apply_policy, PolicyOpts};
use super::types::{Filters, QueryError, ResultSet, SearchResult};
use super::verify::{CachedCrypto, ProjectedTrust, ProjectionContext};

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
    /// Candidate-pool size for the semantic (vector) branch. The facade
    /// populates this from `cfg.embed.top_k_semantic`; the default mirrors the
    /// config default so unit-level callers get the same shape without wiring
    /// a `Config`.
    pub top_k_semantic: u32,
    /// Candidate-pool size for the FTS branch. The facade populates this from
    /// `cfg.embed.top_k_fts`; the default mirrors the config default so the
    /// branches stay in lockstep.
    pub top_k_fts: u32,
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
            top_k_semantic: 100,
            top_k_fts: 100,
        }
    }
}

/// FTS-only ranked search. The vector branch is absent in the current build —
/// ranking degenerates to "by FTS5 bm25 rank, with the unsigned-content
/// penalty applied last".
///
/// # Errors
/// Returns `QueryError::Rusqlite` on any rusqlite error;
/// `QueryError::InvalidFilter` if a filter is malformed;
/// `QueryError::Trust` if the chain-state hydration fails.
pub fn search(conn: &Connection, opts: &SearchOpts) -> Result<ResultSet, QueryError> {
    let projected_rows = fetch_and_project(conn, opts)?;

    // Reciprocal-rank-fusion-style score over a single branch:
    //   score(r) = 1 / (k + rank)
    // With one branch the ranking degenerates to "by FTS rank ascending".
    // Apply the unsigned penalty after RRF; the policy filter runs after
    // sorting so the top-K cut is taken from the visible set.
    let k_const: f64 = 60.0;
    let mut scored: Vec<(FtsRow, ProjectedTrust, f64)> = projected_rows
        .into_iter()
        .enumerate()
        .map(|(idx, (r, p))| {
            let rank = u32::try_from(idx).unwrap_or(u32::MAX);
            let rank = f64::from(rank) + 1.0;
            let mut score = 1.0 / (k_const + rank);
            // FTS5 `rank` is a bm25 score (lower = better). The 1-based
            // ordinal above is the actual ranking signal; the underlying
            // bm25 value is intentionally not surfaced here.

            let is_unsigned = p.signature_status != SignatureStatus::Verified;
            if is_unsigned && !opts.filters.no_unsigned_penalty {
                score *= opts.unsigned_ranking_penalty;
            }
            (r, p, score)
        })
        .collect();
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

    // Centralized warn/hide/strict policy filter. The closure plucks the
    // projected trust shape out of the (row, projected, score) tuple so
    // `apply` can route every row through the same decision tree as the
    // other read verbs.
    let policy_opts = PolicyOpts {
        policy: opts.trust_policy,
        require_signed: opts.filters.require_signed,
    };
    let mut outcome = apply_policy(scored, policy_opts, |row| &row.1);

    let total = u32::try_from(outcome.visible.len()).unwrap_or(u32::MAX);
    let top_k = usize::try_from(opts.top_k).unwrap_or(usize::MAX);
    // Pluck the visible rows so the policy bucket counters and warnings on
    // `outcome` survive the rest of the `outcome` value being consumed.
    let visible = std::mem::take(&mut outcome.visible);
    let top_n = visible.into_iter().take(top_k).collect::<Vec<_>>();

    // Body inclusion: top-3 for search; full record fetched in `get`.
    let results: Vec<SearchResult> = top_n
        .into_iter()
        .enumerate()
        .map(|(idx, (r, p, score))| project_row(r, p, score, idx < 3))
        .collect();

    let mut meta = super::meta::build_meta_search(
        conn,
        opts.trust_policy,
        opts.embed_pool_saturated,
        opts.saturation_wait_ms,
    )?;
    meta.apply_policy_outcome(&outcome);

    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor: None,
        meta,
    })
}

/// Fetch the FTS-matched rows and project per-row trust. Splits out of
/// `search` so the verb stays under the strict-clippy `too-many-lines`
/// threshold.
fn fetch_and_project(
    conn: &Connection,
    opts: &SearchOpts,
) -> Result<Vec<(FtsRow, ProjectedTrust)>, QueryError> {
    let (filter_sql, filter_params) = build_filter_sql(&opts.filters);

    // Cap on FTS candidates fed into RRF. The facade populates
    // `opts.top_k_fts` from `cfg.embed.top_k_fts`; the field default keeps
    // unit callers at the historical 100. Raise via config if filtered
    // queries start under-returning on real corpora.
    let fts_limit: u32 = opts.top_k_fts;

    // FTS query with filter pushdown. ?1 = MATCH query; ?2 = limit;
    // ?3..= filter params. The SELECT also pulls the per-record
    // `relevant_trust_events_commit` so the read-time projection can look
    // up trust state at the events.yml commit effective when the record
    // was signed.
    let fts_sql = format!(
        "SELECT records.id, records.record_type, records.title, records.summary, \
                records.body, records.source, records.project_id, \
                records.crypto_result, records.updated, \
                records.record_commit_sha, records.signer_fingerprint, \
                records.relevant_trust_events_commit \
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
            relevant_trust_events_commit: row.get::<_, Option<String>>(11)?,
        })
    })?;
    let fts_rows: Vec<FtsRow> = rows.collect::<Result<Vec<_>, _>>()?;

    // Hydrate the chain once per verb invocation. Reused for every row's
    // projection. Empty trust_events / no notebook history degrades into a
    // pre-bootstrap chain that trusts cached `Good` crypto on its face.
    let ctx = ProjectionContext::new(conn)?;
    ctx.project_rows(fts_rows, opts.filters.strict_revocation, |row| {
        CachedCrypto {
            crypto_result: row.crypto_result,
            signer_fingerprint: row.signer_fingerprint.as_deref(),
            commit_sha: row.record_commit_sha.as_deref(),
            relevant_trust_events_commit: row.relevant_trust_events_commit.as_deref(),
        }
    })
}

/// Project a single FTS row + projected trust + score into the public
/// `SearchResult` shape, applying the body-on-top-3 rule.
fn project_row(r: FtsRow, p: ProjectedTrust, score: f64, include_body: bool) -> SearchResult {
    let body = if include_body {
        Some(r.body.clone())
    } else {
        None
    };
    SearchResult {
        id: r.id,
        record_type: RecordType::from_db_str(&r.record_type),
        title: r.title,
        summary: r.summary,
        score,
        source: Source::from_db_str(&r.source),
        project_id: r.project_id,
        signature_status: p.signature_status,
        trust_basis: p.trust_basis,
        record_commit_sha: r.record_commit_sha,
        signer_fingerprint: r.signer_fingerprint,
        warnings: p.warnings,
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
    /// `records.crypto_result`. Forwarded into [`CachedCrypto`] for the
    /// read-time projection.
    crypto_result: CryptoResult,
    updated: String,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    /// SHA of the events.yml commit effective at the record's commit time.
    /// `None` for adapters with no events.yml correlation (cc-native /
    /// codex-native) or for records indexed before the column was wired.
    relevant_trust_events_commit: Option<String>,
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

/// Run the sqlite-vec k-NN query against `record_embeddings`, narrowed by the
/// same metadata filter the FTS branch already pushes down. Returns
/// `(record_rowid, l2_distance)` ordered nearest-first, up to `top_k`
/// candidates.
///
/// The query vector binds as raw little-endian f32 bytes wrapped by the
/// `vec_f32(?)` SQL function — the canonical sqlite-vec 0.1 shape. The filter
/// IN-subquery scopes to `records`, so the qualified `records.<col>` clauses
/// emitted by `build_filter_sql` resolve directly inside it.
///
/// # Errors
/// `QueryError::Rusqlite` on any rusqlite error;
/// `QueryError::InvalidFilter` if the query vector has the wrong dimension.
// Transitional: the RRF-fusion site that consumes this helper lands in the
// next task; tests exercise it directly so the dead-code lint fires until
// then. Remove this allow when the hybrid scoring wire-up arrives.
#[allow(dead_code)]
pub(crate) fn fetch_semantic_candidates(
    conn: &Connection,
    filters: &Filters,
    query_vector: &[f32],
    top_k: u32,
) -> Result<Vec<(i64, f32)>, QueryError> {
    if query_vector.len() != crate::embed::EMBED_DIM {
        return Err(QueryError::InvalidFilter {
            detail: format!(
                "query_vector has {} dims; expected {}",
                query_vector.len(),
                crate::embed::EMBED_DIM
            ),
        });
    }

    let (filter_sql, filter_params) = build_filter_sql(filters);

    let sql = if filter_sql.is_empty() {
        "SELECT record_rowid, distance \
           FROM record_embeddings \
          WHERE embedding MATCH vec_f32(?1) AND k = ?2"
            .to_string()
    } else {
        format!(
            "SELECT record_rowid, distance \
               FROM record_embeddings \
              WHERE record_rowid IN (SELECT rowid FROM records WHERE 1=1 {filter_sql}) \
                AND embedding MATCH vec_f32(?1) \
                AND k = ?2"
        )
    };

    let blob = crate::embed::f32_slice_to_le_bytes(query_vector);
    let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(2 + filter_params.len());
    params.push(rusqlite::types::Value::Blob(blob));
    params.push(rusqlite::types::Value::Integer(i64::from(top_k)));
    for p in filter_params {
        params.push(p);
    }

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, f32>(1)?))
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(QueryError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    /// Open a fresh `index.db` under a `TempDir` with the bootstrap chain
    /// seeded so verified rows resolve through the read-time projection.
    /// Delegates to the shared helper used by all read-verb unit tests.
    fn open_test_db() -> (TempDir, Connection) {
        crate::query::test_util::open_test_db_with_seeded_chain()
    }

    fn insert_minimal(conn: &Connection, id: &str, title: &str, body: &str, signed: bool) {
        let cr = if signed { "good" } else { "no-signature" };
        let (signer_fp, trust_commit) = if signed {
            (
                Some(crate::query::test_util::TEST_BOOTSTRAP_FP),
                Some(crate::query::test_util::TEST_TRUST_COMMIT),
            )
        } else {
            (None, None)
        };
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, confidence, outcome, created, updated, content_hash, index_hash, \
             crypto_result, signer_fingerprint, relevant_trust_events_commit, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?2, ?3, '[]', '', \
                     'manual', 'medium', 'working', \
                     '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', ?4, ?5, ?6, '2026-04-29T00:00:00Z')",
            rusqlite::params![id, title, body, cr, signer_fp, trust_commit],
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

    fn mostly_ones() -> Vec<f32> {
        let mut v = vec![0.0_f32; crate::embed::EMBED_DIM];
        for slot in v.iter_mut().take(64) {
            *slot = 1.0;
        }
        v
    }

    fn mostly_zeros() -> Vec<f32> {
        let mut v = vec![0.0_f32; crate::embed::EMBED_DIM];
        v[0] = 0.001;
        v
    }

    fn insert_record_with_vector(
        conn: &Connection,
        id: &str,
        title: &str,
        vec: &[f32],
        project_id: &str,
    ) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, confidence, outcome, created, updated, content_hash, index_hash, \
             crypto_result, indexed_at) VALUES \
             (?1, 'local', ?2, 'decision', ?3, '', '[]', '', 'manual', 'medium', 'working', \
              '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', 'no-signature', \
              '2026-04-29T00:00:00Z')",
            rusqlite::params![id, project_id, title],
        )
        .unwrap();
        let rowid: i64 = conn
            .query_row(
                "SELECT rowid FROM records WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .unwrap();
        let blob = crate::embed::f32_slice_to_le_bytes(vec);
        conn.execute(
            "INSERT INTO record_embeddings (record_rowid, embedding) VALUES (?1, vec_f32(?2))",
            rusqlite::params![rowid, blob.as_slice()],
        )
        .unwrap();
    }

    #[test]
    fn semantic_branch_orders_by_distance() {
        let (_dir, conn) = open_test_db();
        insert_record_with_vector(&conn, "a", "title-a", &mostly_ones(), "p");
        insert_record_with_vector(&conn, "b", "title-b", &mostly_zeros(), "p");

        let query_vec = mostly_ones();
        let filters = Filters::default();
        let candidates =
            fetch_semantic_candidates(&conn, &filters, &query_vec, 10).expect("semantic query");
        assert_eq!(candidates.len(), 2);

        let ids: Vec<String> = candidates
            .iter()
            .map(|(rowid, _)| {
                conn.query_row(
                    "SELECT id FROM records WHERE rowid = ?1",
                    rusqlite::params![rowid],
                    |r| r.get::<_, String>(0),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(ids[0], "a");
        assert_eq!(ids[1], "b");
    }

    #[test]
    fn semantic_branch_honors_filter_pushdown() {
        let (_dir, conn) = open_test_db();
        insert_record_with_vector(&conn, "p1-a", "title-a", &mostly_ones(), "p");
        insert_record_with_vector(&conn, "p2-a", "title-a", &mostly_ones(), "p2");

        let query_vec = mostly_ones();
        let filters = Filters {
            project_id: Some("p2".into()),
            ..Default::default()
        };
        let candidates =
            fetch_semantic_candidates(&conn, &filters, &query_vec, 10).expect("semantic query");
        assert_eq!(candidates.len(), 1);
        let rowid = candidates[0].0;
        let pid: String = conn
            .query_row(
                "SELECT project_id FROM records WHERE rowid = ?1",
                rusqlite::params![rowid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pid, "p2");
    }
}
