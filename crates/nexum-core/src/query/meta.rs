//! Shared `Meta` envelope construction for query verbs.
//!
//! Every query verb returns a `_meta` envelope with `source_counts` (across
//! the whole index) and `trust_summary` / `trust_basis_summary` (counted over
//! the returned rows). The hide-bucket counters (`hidden_unsigned`,
//! `hidden_invalid`, `hidden_compromised`) and the `policy_warnings` envelope
//! codes are populated by the verb from the [`crate::query::policy::apply`]
//! outcome, since the policy filter is the only place that knows how many
//! rows it dropped and why.

use rusqlite::Connection;

use super::types::{
    Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError, SearchResult,
};
use crate::records::{SignatureStatus, TrustBasis, TrustPolicy};

/// Build the `_meta` envelope for a query result set.
///
/// `source_counts` aggregates across the WHOLE index (one `GROUP BY` query).
/// `trust_summary` and `trust_basis_summary` count over the RETURNED results.
/// Hide-bucket counters and `policy_warnings` are left at their defaults; the
/// caller overwrites them from the [`crate::query::policy::PolicyOutcome`]
/// surfaced by the policy filter.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on DB failure.
pub(crate) fn build_meta(
    conn: &Connection,
    results: &[SearchResult],
    trust_policy: TrustPolicy,
    embed_pool_saturated: bool,
    saturation_wait_ms: u32,
) -> Result<Meta, QueryError> {
    // source_counts: one grouped query instead of three separate count(*)
    // round-trips. The schema CHECK constraint already restricts source to
    // {local, cc-native, codex-native}, so unknown values are dropped
    // silently.
    let mut source_counts = MetaSourceCounts::default();
    let mut stmt = conn.prepare("SELECT source, count(*) FROM records GROUP BY source")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows.collect::<Result<Vec<_>, _>>()? {
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
    for r in results {
        match r.signature_status {
            SignatureStatus::Verified => ts.verified += 1,
            SignatureStatus::Unsigned => ts.unsigned += 1,
            SignatureStatus::Invalid => ts.invalid += 1,
            SignatureStatus::Unknown => ts.unknown += 1,
        }
        // Trust-basis bucketing tallies the four spec-aligned values; rows
        // without a basis (unsigned, invalid, unknown-signer) carry `None`
        // and do not contribute to the basis summary. The
        // `signature_status_summary` already exposes the unsigned / invalid
        // / unknown counts separately.
        match r.trust_basis {
            Some(TrustBasis::Current) => tbs.current += 1,
            Some(TrustBasis::RotatedHistorical) => tbs.rotated_historical += 1,
            Some(TrustBasis::RotatedHistoricalCompromised) => {
                tbs.rotated_historical_compromised += 1;
            }
            Some(TrustBasis::PreReanchor) => tbs.pre_reanchor += 1,
            None => {}
        }
    }

    Ok(Meta {
        source_counts,
        trust_policy,
        trust_summary: ts,
        trust_basis_summary: tbs,
        policy_warnings: Vec::new(),
        embed_pool_saturated,
        saturation_wait_ms,
        hidden_unsigned: 0,
        hidden_invalid: 0,
        hidden_compromised: 0,
    })
}
