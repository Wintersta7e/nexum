//! `search` — hybrid (FTS + optional vector) ranked search.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::records::{Confidence, CryptoResult, RecordType, SignatureStatus, Source, TrustPolicy};

use super::policy::{PolicyOpts, apply as apply_policy};
use super::types::{EmbedStatus, Filters, QueryError, ResultSet, SearchResult};
use super::verify::{CachedCrypto, ProjectedTrust, ProjectionContext};

/// `search` options. Compose via `SearchOpts::new(query)` and fluent setters,
/// or by direct struct construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchOpts {
    pub query: String,
    pub top_k: u32,
    pub filters: Filters,
    pub trust_policy: TrustPolicy,
    /// Set to true by the api facade when `embed.enabled` was requested but
    /// the vector branch did not contribute to this query (model not
    /// installed, embedder load failed, query embedding failed, or the
    /// embed pool was saturated). Preserved for back-compat — see
    /// `meta.embed_status` for the structured signal.
    pub embed_pool_saturated: bool,
    pub saturation_wait_ms: u32,
    /// Per-query disposition of the semantic ranking branch. Filled by the
    /// api facade (`build_query_vector`); the search verb passes it through
    /// to `_meta.embed_status` unchanged. Defaults to `Disabled` so unit
    /// callers that don't go through the facade get the FTS-only shape.
    pub embed_status: EmbedStatus,
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
    /// Query embedding for the vector branch. The api facade builds this
    /// from the configured embedder when `embed.enabled` and `embed_status`
    /// would otherwise be `Ok`. Unit-test callers that drive
    /// `query::search::search` directly can construct a fixture vector and
    /// set this field manually; the FTS-only fallback runs when `None`.
    /// Skipped during (de)serialization — vectors don't round-trip through
    /// JSON / MCP DTOs.
    #[serde(skip)]
    pub query_vector: Option<Vec<f32>>,
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
            query_vector: None,
            embed_status: EmbedStatus::Disabled,
        }
    }
}

/// `k` constant for the RRF score `1 / (k + rank)`. The TREC literature uses
/// 60; the value is intentionally not exposed as a knob — it makes the two
/// branch contributions comparable without giving either a runaway tail.
const K_RRF: f64 = 60.0;

/// Scored fts-projected row triple used inside the scoring pipeline. The
/// triple shape is unavoidable (the row, the projected trust state, and
/// the fused score travel together through the post-policy step); the
/// alias keeps the per-function return types under the strict-clippy
/// `type-complexity` threshold.
type ScoredRow = (FtsRow, ProjectedTrust, f64);

/// Hybrid ranked search.
///
/// When `opts.query_vector` is `Some`, both the FTS and vector branches run;
/// their ranked rowid lists are fused via reciprocal-rank-fusion (`k = 60`)
/// before the unsigned-content penalty, the warn/hide/strict policy filter,
/// and the top-K cut. When `query_vector` is `None`, only the FTS branch
/// runs and the score collapses to `1 / (60 + fts_rank)`.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on any rusqlite error;
/// `QueryError::InvalidFilter` if a filter is malformed;
/// `QueryError::Trust` if the chain-state hydration fails.
pub fn search(conn: &Connection, opts: &SearchOpts) -> Result<ResultSet, QueryError> {
    // FTS branch: always runs. Carries the projected trust shape so the
    // fusion path can re-use the projection (cheap) for any rowid that
    // came back from FTS instead of re-hydrating it row-by-row.
    let fts_projected = fetch_and_project(conn, opts)?;

    let (scored, vector_candidates): (Vec<ScoredRow>, u32) =
        if let Some(query_vector) = opts.query_vector.as_deref() {
            score_hybrid(conn, opts, fts_projected, query_vector)?
        } else {
            (score_fts_only(opts, fts_projected), 0)
        };

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
        opts.embed_status,
        vector_candidates,
    )?;
    meta.apply_policy_outcome(&outcome);

    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor: None,
        meta,
    })
}

/// FTS-only scoring path. Ranks degenerate to FTS rank ascending; the score
/// is `1 / (k + rank)` with the unsigned-content penalty applied afterwards.
/// Sorting is deferred to the post-policy stage.
fn score_fts_only(
    opts: &SearchOpts,
    projected_rows: Vec<(FtsRow, ProjectedTrust)>,
) -> Vec<ScoredRow> {
    let mut scored: Vec<ScoredRow> = projected_rows
        .into_iter()
        .enumerate()
        .map(|(idx, (r, p))| {
            let rank = u32::try_from(idx).unwrap_or(u32::MAX);
            let rank = f64::from(rank) + 1.0;
            let mut score = 1.0 / (K_RRF + rank);
            // FTS5 `rank` is a bm25 score (lower = better). The 1-based
            // ordinal above is the actual ranking signal; the underlying
            // bm25 value is intentionally not surfaced here.
            if !is_verified(&p) && !opts.filters.no_unsigned_penalty {
                score *= opts.unsigned_ranking_penalty;
            }
            (r, p, score)
        })
        .collect();
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

/// Hybrid scoring path. Runs the vector branch, fuses with the FTS rowid
/// list via RRF, and rehydrates any rowid that came from the vector branch
/// but did not appear in the FTS candidates. The unsigned-content penalty
/// applies to the fused score, not per-branch.
fn score_hybrid(
    conn: &Connection,
    opts: &SearchOpts,
    fts_projected: Vec<(FtsRow, ProjectedTrust)>,
    query_vector: &[f32],
) -> Result<(Vec<ScoredRow>, u32), QueryError> {
    let fts_ranked: Vec<(i64, f64)> = fts_projected
        .iter()
        .map(|(row, _)| (row.rowid, 0.0))
        .collect();
    let vec_ranked: Vec<(i64, f64)> =
        fetch_semantic_candidates(conn, &opts.filters, query_vector, opts.top_k_semantic)?
            .into_iter()
            .map(|(rowid, distance)| (rowid, f64::from(distance)))
            .collect();
    let vector_candidates = u32::try_from(vec_ranked.len()).unwrap_or(u32::MAX);

    let fused = rrf_fuse(&vec_ranked, &fts_ranked, K_RRF);

    // Index the FTS-projected rows by rowid so the hydration step pulls
    // straight from memory rather than re-querying the records table for
    // rows we already have.
    let mut fts_by_rowid: std::collections::HashMap<i64, (FtsRow, ProjectedTrust)> = fts_projected
        .into_iter()
        .map(|(r, p)| (r.rowid, (r, p)))
        .collect();

    // Any rowid that surfaced only from the vector branch needs hydration.
    let vec_only: Vec<i64> = fused
        .iter()
        .filter_map(|(rowid, _)| {
            if fts_by_rowid.contains_key(rowid) {
                None
            } else {
                Some(*rowid)
            }
        })
        .collect();
    let mut hydrated: std::collections::HashMap<i64, (FtsRow, ProjectedTrust)> =
        hydrate_rows_by_rowid(conn, opts, &vec_only)?
            .into_iter()
            .map(|(r, p)| (r.rowid, (r, p)))
            .collect();

    let mut scored: Vec<ScoredRow> = Vec::with_capacity(fused.len());
    for (rowid, fused_score) in fused {
        let (row, projected) = if let Some(pair) = fts_by_rowid.remove(&rowid) {
            pair
        } else if let Some(pair) = hydrated.remove(&rowid) {
            pair
        } else {
            // The rowid surfaced from the vector branch but was filtered
            // out by the metadata pushdown during hydration (the two
            // branches share the same filter SQL, so this is unreachable
            // in practice). Skip rather than fabricate a row.
            continue;
        };
        let mut score = fused_score;
        if !is_verified(&projected) && !opts.filters.no_unsigned_penalty {
            score *= opts.unsigned_ranking_penalty;
        }
        scored.push((row, projected, score));
    }
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    Ok((scored, vector_candidates))
}

/// Convenience: a row is "verified" when its projected signature status is
/// `Verified`. Drives the unsigned-content penalty branch in both scoring
/// paths.
fn is_verified(p: &ProjectedTrust) -> bool {
    p.signature_status == SignatureStatus::Verified
}

/// Reciprocal-rank-fusion over two ranked candidate lists. Both inputs are
/// sorted best-first; the position (1-indexed) is the rank used in
/// `1 / (k + rank)`. Rows present in both branches see their scores
/// summed.
///
/// Returns `(rowid, score)` sorted by descending score. Ties are
/// broken by `sort_by`'s stability against the accumulation order, so
/// callers MUST NOT depend on the relative order of equal-scored rows
/// — a future change (e.g., breaking ties by trust signal) is in
/// scope and won't be a contract break. The score-equal sort step
/// uses `partial_cmp` and falls back to `Ordering::Equal` so NaN
/// scores (impossible here, defended for sanity) do not panic.
pub(crate) fn rrf_fuse(
    vec_ranked: &[(i64, f64)],
    fts_ranked: &[(i64, f64)],
    k: f64,
) -> Vec<(i64, f64)> {
    use std::collections::HashMap;
    let mut acc: HashMap<i64, f64> = HashMap::new();
    let mut order: Vec<i64> = Vec::with_capacity(vec_ranked.len() + fts_ranked.len());

    let mut accumulate = |branch: &[(i64, f64)]| {
        for (idx, (rowid, _)) in branch.iter().enumerate() {
            let rank = u32::try_from(idx).unwrap_or(u32::MAX);
            let rank = f64::from(rank) + 1.0;
            let contribution = 1.0 / (k + rank);
            acc.entry(*rowid)
                .and_modify(|s| *s += contribution)
                .or_insert_with(|| {
                    order.push(*rowid);
                    contribution
                });
        }
    };
    accumulate(vec_ranked);
    accumulate(fts_ranked);

    let mut out: Vec<(i64, f64)> = order.into_iter().map(|id| (id, acc[&id])).collect();
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Re-fetch records by rowid and project per-row trust. Used by the hybrid
/// path for rowids that came from the vector branch but were absent from
/// the FTS candidates. Empty `rowids` short-circuits.
fn hydrate_rows_by_rowid(
    conn: &Connection,
    opts: &SearchOpts,
    rowids: &[i64],
) -> Result<Vec<(FtsRow, ProjectedTrust)>, QueryError> {
    if rowids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = (1..=rowids.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT records.rowid, records.id, records.record_type, records.title, records.summary, \
                records.body, records.source, records.project_id, \
                records.crypto_result, records.updated, \
                records.record_commit_sha, records.signer_fingerprint, \
                records.relevant_trust_events_commit, \
                json_extract(records.extras, '$.cc_type') \
         FROM records WHERE records.rowid IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let params: Vec<rusqlite::types::Value> = rowids
        .iter()
        .map(|id| rusqlite::types::Value::Integer(*id))
        .collect();
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        let crypto_result = CryptoResult::from_db_str(&row.get::<_, String>(8)?);
        Ok(FtsRow {
            rowid: row.get(0)?,
            id: row.get(1)?,
            record_type: row.get::<_, String>(2)?,
            title: row.get(3)?,
            summary: row.get::<_, Option<String>>(4)?,
            body: row.get::<_, String>(5)?,
            source: row.get::<_, String>(6)?,
            project_id: row.get(7)?,
            crypto_result,
            updated: row.get(9)?,
            record_commit_sha: row.get::<_, Option<String>>(10)?,
            signer_fingerprint: row.get::<_, Option<String>>(11)?,
            relevant_trust_events_commit: row.get::<_, Option<String>>(12)?,
            metadata_type: row.get::<_, Option<String>>(13)?,
        })
    })?;
    let raw_rows: Vec<FtsRow> = rows.collect::<Result<Vec<_>, _>>()?;

    let ctx = ProjectionContext::new(conn)?;
    ctx.project_rows(raw_rows, opts.filters.strict_revocation, |row| {
        CachedCrypto {
            crypto_result: row.crypto_result,
            signer_fingerprint: row.signer_fingerprint.as_deref(),
            commit_sha: row.record_commit_sha.as_deref(),
            relevant_trust_events_commit: row.relevant_trust_events_commit.as_deref(),
        }
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
        "SELECT records.rowid, records.id, records.record_type, records.title, records.summary, \
                records.body, records.source, records.project_id, \
                records.crypto_result, records.updated, \
                records.record_commit_sha, records.signer_fingerprint, \
                records.relevant_trust_events_commit, \
                json_extract(records.extras, '$.cc_type') \
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
        let crypto_result = CryptoResult::from_db_str(&row.get::<_, String>(8)?);
        Ok(FtsRow {
            rowid: row.get(0)?,
            id: row.get(1)?,
            record_type: row.get::<_, String>(2)?,
            title: row.get(3)?,
            summary: row.get::<_, Option<String>>(4)?,
            body: row.get::<_, String>(5)?,
            source: row.get::<_, String>(6)?,
            project_id: row.get(7)?,
            crypto_result,
            updated: row.get(9)?,
            record_commit_sha: row.get::<_, Option<String>>(10)?,
            signer_fingerprint: row.get::<_, Option<String>>(11)?,
            relevant_trust_events_commit: row.get::<_, Option<String>>(12)?,
            metadata_type: row.get::<_, Option<String>>(13)?,
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
        metadata_type: r.metadata_type,
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
    /// `records.rowid` — kept so the hybrid branch can fuse the FTS and vector
    /// candidate lists by rowid before re-hydrating projected rows.
    rowid: i64,
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
    /// `json_extract(records.extras, '$.cc_type')` — adapter-specific
    /// metadata type. `None` for sources that don't store it.
    metadata_type: Option<String>,
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
    if let Some(mt) = &filters.metadata_type {
        let i = next_idx;
        next_idx += 1;
        // `extras.cc_type` is the cc adapter's frontmatter type. Other
        // sources never store this key, so NULL = ? is false and they
        // drop out — which is the right behaviour for a filter that's
        // only meaningful on cc-native today.
        clauses.push(format!(
            "AND json_extract(records.extras, '$.cc_type') = ?{i}"
        ));
        params.push(rusqlite::types::Value::Text(mt.clone()));
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
    fn rrf_fuses_vec_and_fts_ranks() {
        // Both branches list rowid 10 at rank 1. Rowid 20 is rank-2 in the
        // vector branch only; rowid 30 is rank-2 in the FTS branch only.
        // Rowid 10 sums both contributions (1/61 + 1/61). Rowids 20 and 30
        // each score 1/62; the test asserts they both appear after rowid 10
        // without depending on their relative order — that's an internal
        // detail of the accumulator and may change when tie-breaking grows
        // a trust-signal pass.
        let vec_ranked = vec![(10_i64, 0.1), (20, 0.2)];
        let fts_ranked = vec![(10_i64, 0.5), (30, 0.6)];
        let fused = super::rrf_fuse(&vec_ranked, &fts_ranked, 60.0);

        let ids: Vec<i64> = fused.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids[0], 10);
        assert_eq!(ids.len(), 3);
        assert!(ids[1..].contains(&20));
        assert!(ids[1..].contains(&30));

        let expected_tied = 1.0 / 62.0;
        for (id, score) in &fused[1..] {
            assert!(
                (score - expected_tied).abs() < 1e-9,
                "tied rowid {id} got score {score}"
            );
        }
        let expected_both = 1.0 / 61.0 + 1.0 / 61.0;
        assert!((fused[0].1 - expected_both).abs() < 1e-9);
    }

    #[test]
    fn rrf_sums_distinct_rank_contributions() {
        // Rowid 7 is rank-1 in vector, rank-5 in FTS. Expected score:
        // 1/(60+1) + 1/(60+5) = 1/61 + 1/65. This distinguishes
        // `acc.insert` from `acc.and_modify` (the same-rank test cannot).
        let vec_ranked = vec![(7_i64, 0.1), (8, 0.2), (9, 0.3), (10, 0.4), (11, 0.5)];
        let fts_ranked = vec![(1_i64, 0.1), (2, 0.2), (3, 0.3), (4, 0.4), (7, 0.5)];
        let fused = super::rrf_fuse(&vec_ranked, &fts_ranked, 60.0);

        let (_, score) = fused
            .iter()
            .find(|(id, _)| *id == 7)
            .expect("rowid 7 present");
        let expected = 1.0 / 61.0 + 1.0 / 65.0;
        assert!(
            (score - expected).abs() < 1e-9,
            "got {score}, expected {expected}"
        );
    }

    #[test]
    fn rrf_vec_only_degenerates_cleanly() {
        let vec_ranked = vec![(10_i64, 0.1), (20, 0.2), (30, 0.3)];
        let fused = super::rrf_fuse(&vec_ranked, &[], 60.0);
        assert_eq!(
            fused.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn rrf_fts_only_degenerates_cleanly() {
        let fts_ranked = vec![(10_i64, 0.1), (20, 0.2), (30, 0.3)];
        let fused = super::rrf_fuse(&[], &fts_ranked, 60.0);
        assert_eq!(
            fused.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn hybrid_search_returns_rows_from_both_branches() {
        // Row "a-fts" has a title matching the FTS query but a vector that
        // is far from the query vector. Row "b-vec" has a title that does
        // not match the FTS query but a vector close to the query vector.
        // With both branches running, fusion must surface both rowids.
        let (_dir, conn) = open_test_db();
        insert_record_with_vector(&conn, "a-fts", "concurrency match", &mostly_zeros(), "p");
        insert_record_with_vector(&conn, "b-vec", "title-b", &mostly_ones(), "p");

        let mut opts = SearchOpts::new("concurrency");
        opts.query_vector = Some(mostly_ones());
        opts.top_k = 5;

        let res = search(&conn, &opts).expect("hybrid search");
        let ids: std::collections::HashSet<String> =
            res.results.iter().map(|r| r.id.clone()).collect();
        assert!(
            ids.contains("a-fts"),
            "FTS-only match should appear: {ids:?}"
        );
        assert!(
            ids.contains("b-vec"),
            "vector-only match should appear: {ids:?}"
        );
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

    /// Insert a record with both a vector embedding and a signed/unsigned
    /// crypto state, so hybrid-path tests can mix the two branches with the
    /// unsigned penalty. Shares the SQL shape with `insert_record_with_vector`
    /// but flips the trust columns based on `signed`.
    fn insert_record_with_vector_signed(
        conn: &Connection,
        id: &str,
        title: &str,
        body: &str,
        vec: &[f32],
        signed: bool,
    ) {
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
             VALUES (?1, 'local', 'p', 'decision', ?2, ?3, '[]', '', 'manual', 'medium', \
             'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', ?4, ?5, ?6, \
             '2026-04-29T00:00:00Z')",
            rusqlite::params![id, title, body, cr, signer_fp, trust_commit],
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
    fn hybrid_unsigned_penalty_applies_to_fused_score() {
        // Two rows with identical title / body so they tie on the FTS
        // branch, and identical vectors so they tie on the vector branch
        // before the penalty. With penalty enabled, the verified row must
        // rank above the unsigned row purely because of the penalty.
        let (_dir, conn) = open_test_db();
        insert_record_with_vector_signed(
            &conn,
            "v",
            "concurrency match",
            "shared body",
            &mostly_ones(),
            true,
        );
        insert_record_with_vector_signed(
            &conn,
            "u",
            "concurrency match",
            "shared body",
            &mostly_ones(),
            false,
        );

        let mut opts = SearchOpts::new("concurrency");
        opts.query_vector = Some(mostly_ones());
        opts.top_k = 5;

        let res = search(&conn, &opts).expect("hybrid search");
        let ids: Vec<String> = res.results.iter().map(|r| r.id.clone()).collect();
        let v_idx = ids.iter().position(|id| id == "v").expect("verified row");
        let u_idx = ids.iter().position(|id| id == "u").expect("unsigned row");
        assert!(
            v_idx < u_idx,
            "verified must rank above unsigned on the hybrid path: {ids:?}"
        );

        // With the penalty disabled both rows still surface; we don't
        // assert their relative order — the FTS-rank tie-break is a
        // deterministic but undocumented function of tokens / rowid.
        let mut opts_no_penalty = opts.clone();
        opts_no_penalty.filters.no_unsigned_penalty = true;
        let res_no_penalty = search(&conn, &opts_no_penalty).expect("hybrid search no penalty");
        let ids_np: std::collections::HashSet<String> = res_no_penalty
            .results
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert!(ids_np.contains("v"));
        assert!(ids_np.contains("u"));
    }
}
