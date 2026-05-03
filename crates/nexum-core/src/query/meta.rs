//! Shared `Meta` envelope construction for query verbs.
//!
//! Every query verb returns a `_meta` envelope with `source_counts` (across the
//! whole index), `trust_summary` / `trust_basis_summary` (counted over the
//! returned rows), and an optional `policy_warnings` entry. Centralizing it
//! here keeps the per-verb files focused on filter shape and pagination, and
//! collapses three `count(*)` round-trips into a single grouped query.

use rusqlite::Connection;

use super::types::{
    Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError, SearchResult,
};
use crate::records::SignatureStatus;

/// Build the `_meta` envelope for a query result set.
///
/// `source_counts` aggregates across the WHOLE index (one `GROUP BY` query).
/// `trust_summary` and `trust_basis_summary` count over the RETURNED results.
/// Under `trust_policy = "warn-but-show"` with non-verified rows present,
/// emits a `policy_warnings` entry naming the issue.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on DB failure.
pub(crate) fn build_meta(
    conn: &Connection,
    results: &[SearchResult],
    trust_policy: &str,
    embed_pool_saturated: bool,
    saturation_wait_ms: u32,
) -> Result<Meta, QueryError> {
    // source_counts: one grouped query instead of three separate count(*)
    // round-trips. The schema CHECK constraint already restricts source to
    // {local, cc-native, codex-native}, so unknown values are dropped silently.
    let mut source_counts = MetaSourceCounts::default();
    let mut stmt = conn.prepare("SELECT source, count(*) FROM records GROUP BY source")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows.flatten() {
        let (source, count) = row;
        let saturated = u32::try_from(count).unwrap_or(u32::MAX);
        match source.as_str() {
            "local" => source_counts.local = saturated,
            "cc-native" => source_counts.cc_native = saturated,
            "codex-native" => source_counts.codex_native = saturated,
            _ => {}
        }
    }

    let mut ts = MetaTrustSummary::default();
    let mut tbs = MetaTrustBasisSummary::default();
    let mut policy_warnings: Vec<String> = Vec::new();
    for r in results {
        match r.signature_status {
            SignatureStatus::Verified => {
                ts.verified += 1;
                tbs.current += 1;
            }
            SignatureStatus::Unsigned => ts.unsigned += 1,
            SignatureStatus::Invalid => ts.invalid += 1,
            SignatureStatus::Unknown => ts.unknown += 1,
        }
    }
    if trust_policy == "warn-but-show" && (ts.unsigned + ts.invalid + ts.unknown) > 0 {
        policy_warnings.push("response includes unsigned content".into());
    }

    Ok(Meta {
        source_counts,
        trust_policy: trust_policy.to_owned(),
        trust_summary: ts,
        trust_basis_summary: tbs,
        policy_warnings,
        embed_pool_saturated,
        saturation_wait_ms,
    })
}
