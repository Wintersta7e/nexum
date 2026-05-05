//! Query-layer types — `Filters`, `SearchResult`, `ResultSet`, `Meta`,
//! `QueryError`. Mirrors the response-envelope spec.

use serde::{Deserialize, Serialize};

use crate::records::{
    Confidence, ProjectId, RecordId, RecordKey, RecordType, SignatureStatus, Source, TrustBasis,
    TrustPolicy,
};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid filter value: {detail}")]
    InvalidFilter { detail: String },
    #[error(
        "index database not found at `{}`; run `nexum index` first to populate it",
        path.display()
    )]
    IndexMissing { path: std::path::PathBuf },
    /// A bare-id or partial-key lookup matched more than one row. The
    /// caller should disambiguate by supplying a fully-qualified
    /// `RecordKey` (e.g. `local:git:abc:my-record`).
    #[error("ambiguous record id; {} candidates match", matches.len())]
    Ambiguous { matches: Vec<RecordKey> },
}

/// Filter set shared across `search` / `list` / `recent` / `by_session`.
/// Pushed into SQL before ranking.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<RecordType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// Exact tag list — applied as a JSON `EXISTS (... json_each ...)`
    /// filter on `records.tags`, NOT against the normalized `tags_fts`
    /// column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// `since` window (records with `updated >= since`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<Confidence>,
    /// When true, results without `signature_status = "verified"` are
    /// excluded regardless of policy.
    #[serde(default)]
    pub require_signed: bool,
    /// Future-compat pass-through — the trust state machine isn't wired
    /// up yet, so this currently has no effect.
    #[serde(default)]
    pub strict_revocation: bool,
    /// When true, suppress the unsigned-content ranking penalty (×0.7).
    /// CLI flag `--no-unsigned-penalty`; MCP `no_unsigned_penalty`.
    #[serde(default)]
    pub no_unsigned_penalty: bool,
}

/// Per-result row, the `search` / `list` shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: RecordId,
    pub record_type: RecordType,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub score: f64,
    pub source: Source,
    pub project_id: ProjectId,
    pub signature_status: SignatureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_basis: Option<TrustBasis>,
    /// Git commit SHA of the record's last-touching commit, as recorded by the
    /// verifier. `None` for adapters that don't track commit provenance or for
    /// rows written before the column was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_commit_sha: Option<String>,
    /// Signing key fingerprint used to verify the record's last-touching
    /// commit. `None` when the record is unsigned or the verifier has not yet
    /// populated the column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Body included only on top-3 in `search`; always in `get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub updated: String,
}

/// Paginated result set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultSet {
    pub results: Vec<SearchResult>,
    pub total_matched: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(rename = "_meta")]
    pub meta: Meta,
}

/// Response `_meta` envelope. Filled with `source_counts`, `trust_summary`,
/// `trust_basis_summary` (with mostly-zero rotation entries since the trust
/// state machine is stubbed), and `policy_warnings` when warranted.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub source_counts: MetaSourceCounts,
    pub trust_policy: TrustPolicy,
    #[serde(default)]
    pub trust_summary: MetaTrustSummary,
    #[serde(default)]
    pub trust_basis_summary: MetaTrustBasisSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_warnings: Vec<String>,
    #[serde(default)]
    pub embed_pool_saturated: bool,
    #[serde(default)]
    pub saturation_wait_ms: u32,
    /// Count of `unsigned` records anywhere in the index that the current
    /// `trust_policy` would withhold under `Hide`. Whole-table count, not
    /// filter-respecting; a future revision may narrow this to the
    /// requested filter scope if cost shows up.
    #[serde(default)]
    pub hidden_unsigned: u32,
    /// Count of `invalid` records anywhere in the index that the current
    /// `trust_policy` would withhold under `Hide`. Whole-table count, not
    /// filter-respecting; a future revision may narrow this to the
    /// requested filter scope if cost shows up.
    #[serde(default)]
    pub hidden_invalid: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetaSourceCounts {
    pub local: u32,
    #[serde(rename = "cc-native")]
    pub cc_native: u32,
    #[serde(rename = "codex-native")]
    pub codex_native: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetaTrustSummary {
    pub verified: u32,
    pub unsigned: u32,
    pub invalid: u32,
    pub unknown: u32,
}

/// Tally of returned rows by `trust_basis`. Rows without a basis (unsigned,
/// invalid, unknown-signer) carry `None` and are NOT counted here; the
/// `trust_summary` field exposes the per-`SignatureStatus` counts. Wire
/// shape uses kebab-case keys so the JSON form mirrors the spec value set.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetaTrustBasisSummary {
    pub current: u32,
    pub rotated_historical: u32,
    pub rotated_historical_compromised: u32,
    pub pre_reanchor: u32,
}

/// Cursor — opaque base64-encoded `last_rowid`. Currently uses a simple
/// "after rowid X" strategy; richer cursors land later.
pub type Cursor = String;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_trust_basis_summary_serializes_kebab_case() {
        let summary = MetaTrustBasisSummary {
            current: 1,
            rotated_historical: 2,
            rotated_historical_compromised: 3,
            pre_reanchor: 4,
        };
        let json = serde_json::to_string(&summary).unwrap();
        // Wire-format guard: all four keys must serialize as kebab-case so the
        // JSON shape matches the value set used elsewhere in the API.
        assert!(
            json.contains("\"current\":1"),
            "expected `current` key, got {json}"
        );
        assert!(
            json.contains("\"rotated-historical\":2"),
            "expected `rotated-historical` key, got {json}"
        );
        assert!(
            json.contains("\"rotated-historical-compromised\":3"),
            "expected `rotated-historical-compromised` key, got {json}"
        );
        assert!(
            json.contains("\"pre-reanchor\":4"),
            "expected `pre-reanchor` key, got {json}"
        );
    }
}
