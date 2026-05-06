//! Shared `Meta` envelope construction for query verbs.
//!
//! Every query verb returns a `_meta` envelope with `source_counts` (across
//! the whole index) and `trust_summary` / `trust_basis_summary` (counted over
//! the returned rows). The hide-bucket counters (`hidden_unsigned`,
//! `hidden_invalid`, `hidden_compromised`) and the `policy_warnings` envelope
//! codes are populated by the verb via [`Meta::apply_policy_outcome`] from
//! the [`crate::query::policy::apply`] outcome, since the policy filter is
//! the only place that knows how many rows it dropped and why.

use rusqlite::Connection;

use super::policy::PolicyOutcome;
use super::types::SearchResult;
use super::types::{Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError};
use crate::records::{SignatureStatus, TrustBasis, TrustPolicy};

/// Build the `_meta` envelope for a listing-shaped query (`list` / `recent`
/// / `by_session`). The embedding-pool saturation fields don't apply to
/// these verbs; `search` uses [`build_meta_search`] for that channel.
///
/// `source_counts` aggregates across the WHOLE index (one `GROUP BY` query).
/// `trust_summary` and `trust_basis_summary` count over the RETURNED results.
/// Hide-bucket counters and `policy_warnings` are left at their defaults; the
/// caller overwrites them from the [`crate::query::policy::PolicyOutcome`]
/// surfaced by the policy filter via [`Meta::apply_policy_outcome`].
///
/// # Errors
/// Returns `QueryError::Rusqlite` on DB failure.
pub(crate) fn build_meta_listing(
    conn: &Connection,
    results: &[SearchResult],
    trust_policy: TrustPolicy,
) -> Result<Meta, QueryError> {
    build_meta_inner(conn, results, trust_policy, false, 0)
}

/// Build the `_meta` envelope for `search`. Carries the embedding-pool
/// saturation surface alongside the shared listing fields.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on DB failure.
pub(crate) fn build_meta_search(
    conn: &Connection,
    results: &[SearchResult],
    trust_policy: TrustPolicy,
    embed_pool_saturated: bool,
    saturation_wait_ms: u32,
) -> Result<Meta, QueryError> {
    build_meta_inner(
        conn,
        results,
        trust_policy,
        embed_pool_saturated,
        saturation_wait_ms,
    )
}

/// Shared body for the two facade variants. The embedding-pool channel is
/// always populated; the listing facade hardcodes `(false, 0)` so the
/// channel stays falsy in JSON.
fn build_meta_inner(
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
        embed_pool_saturated,
        saturation_wait_ms,
        ..Meta::default()
    })
}

impl Meta {
    /// Fold the policy filter's bucket counts and envelope warnings into
    /// the meta. Centralizes the four-line copy every read verb used to
    /// repeat after calling [`crate::query::policy::apply`].
    pub(crate) fn apply_policy_outcome<T>(&mut self, outcome: &PolicyOutcome<T>) {
        self.hidden_unsigned = outcome.hidden_unsigned;
        self.hidden_invalid = outcome.hidden_invalid;
        self.hidden_compromised = outcome.hidden_compromised;
        self.policy_warnings.clone_from(&outcome.policy_warnings);
    }
}
