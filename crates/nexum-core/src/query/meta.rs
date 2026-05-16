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
use super::types::{EmbedStatus, Meta, MetaSourceCounts, QueryError};
use crate::records::TrustPolicy;

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
    trust_policy: TrustPolicy,
) -> Result<Meta, QueryError> {
    build_meta_inner(conn, trust_policy, false, 0, EmbedStatus::Disabled, 0)
}

/// Build the `_meta` envelope for `search`. Carries the embedding-pool
/// saturation surface plus the richer `embed_status` + `vector_candidates`
/// pair alongside the shared listing fields.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on DB failure.
pub(crate) fn build_meta_search(
    conn: &Connection,
    trust_policy: TrustPolicy,
    embed_pool_saturated: bool,
    saturation_wait_ms: u32,
    embed_status: EmbedStatus,
    vector_candidates: u32,
) -> Result<Meta, QueryError> {
    build_meta_inner(
        conn,
        trust_policy,
        embed_pool_saturated,
        saturation_wait_ms,
        embed_status,
        vector_candidates,
    )
}

/// Shared body for the two facade variants. The embedding-pool channel is
/// always populated; the listing facade hardcodes `(false, 0, Disabled, 0)`
/// so the channel stays falsy in JSON.
fn build_meta_inner(
    conn: &Connection,
    trust_policy: TrustPolicy,
    embed_pool_saturated: bool,
    saturation_wait_ms: u32,
    embed_status: EmbedStatus,
    vector_candidates: u32,
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

    // trust_summary + trust_basis_summary are filled by the caller via
    // [`Meta::apply_policy_outcome`] from the pre-policy tally that
    // [`crate::query::policy::apply`] produces.
    Ok(Meta {
        source_counts,
        trust_policy,
        embed_pool_saturated,
        saturation_wait_ms,
        embed_status,
        vector_candidates,
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
        // Transparency channel: trust_summary / trust_basis_summary
        // count over the pre-policy projected rows so the response reflects
        // every row the projection produced, not only the visible subset.
        self.trust_summary = outcome.trust_summary;
        self.trust_basis_summary = outcome.trust_basis_summary;
    }
}
