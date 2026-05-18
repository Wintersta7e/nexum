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
    /// Trust-state error surfaced from `ChainState::from_view` or any
    /// `TrustEventsView` query the read-time projection issues. Wraps the
    /// underlying [`crate::trust::events::TrustError`].
    #[error(transparent)]
    Trust(#[from] crate::trust::events::TrustError),
    /// The on-disk schema is older than the binary supports. The caller
    /// should prompt the user to run `nexum migrate`.
    #[error("index schema v{v_disk} is older than this binary; run `nexum migrate`")]
    MigrationRequired { v_disk: u32 },
}

/// Per-query disposition of the semantic ranking branch. Agents read this
/// from `_meta.embed_status` and branch their retry/back-off logic on the
/// variant rather than the legacy `embed_pool_saturated` bool (which
/// conflates four distinct failure modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedStatus {
    /// `embed.enabled = false`. Hybrid not attempted; FTS-only path ran.
    #[default]
    Disabled,
    /// Vector branch ran and contributed candidates.
    Ok,
    /// Pool saturated; the vector branch was skipped for this query.
    Saturated,
    /// `embed.enabled = true` but the configured model is not installed.
    ModelMissing,
    /// Tokenizer or ORT inference failed for this query.
    EmbedFailed,
}

/// Filter set shared across `search` / `list` / `recent` / `by_session`.
/// Pushed into SQL before ranking.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<RecordType>,
    /// Adapter-specific metadata type (e.g. CC frontmatter `metadata.type`
    /// surfaced as `cc_type`). Matches `json_extract(extras, '$.cc_type')`
    /// at query time. Implicitly narrows to records that carry it (today
    /// only `cc-native`); other sources never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_type: Option<String>,
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
    /// When set, records signed by a key the chain now records as
    /// compromised project to `Invalid` (carrying both the
    /// `signed-by-compromised-key` and `strict-revocation-active`
    /// warnings) instead of the default `Verified` with a warning. Other
    /// branches of the read-time projection are unaffected.
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
    /// Adapter-specific metadata type surfaced from `records.extras`. For
    /// `cc-native` records this is the original frontmatter `metadata.type`
    /// (e.g. `"feedback"`, `"reference"`, `"user"`). `None` for sources
    /// without an analogous field (codex, local).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_type: Option<String>,
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
    /// Why the semantic ranking did or did not contribute to this result.
    /// Agents branch on this — `model_missing` means "run `nexum models
    /// install bge-m3` then retry"; `embed_failed` means "log + retry";
    /// `saturated` means "transient — back off and retry"; `ok` means "the
    /// vector branch contributed `vector_candidates` rows".
    #[serde(default)]
    pub embed_status: EmbedStatus,
    /// Number of candidates the vector branch contributed to the fused
    /// pool. Zero when `embed_status != Ok`, or when the index has no
    /// embeddings yet for the queried records.
    #[serde(default)]
    pub vector_candidates: u32,
    /// Count of rows withheld from the response because their projected
    /// `signature_status` is `Unsigned` and the active policy or
    /// `require_signed` override filters them out. Counted from the
    /// response rows after projection, not the whole index.
    #[serde(default)]
    pub hidden_unsigned: u32,
    /// Count of rows withheld from the response because their projected
    /// `signature_status` is `Invalid` (other than strict-revocation
    /// hits, which are tallied separately in `hidden_compromised`).
    /// Counted from the response rows after projection, not the whole
    /// index.
    #[serde(default)]
    pub hidden_invalid: u32,
    /// Count of rows withheld from the response because they were signed
    /// by a key the trust chain marks compromised and the
    /// `strict-revocation-active` overlay fired. Independent of policy
    /// and `require_signed`; revocation hits are always filtered.
    #[serde(default)]
    pub hidden_compromised: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetaSourceCounts {
    pub local: u32,
    #[serde(rename = "cc-native")]
    pub cc_native: u32,
    #[serde(rename = "codex-native")]
    pub codex_native: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
