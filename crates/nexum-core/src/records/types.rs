//! `UnifiedRecord` and supporting enums — the canonical in-memory record shape.
//!
//! Every adapter normalizes its on-disk shape to `UnifiedRecord` before the
//! indexer writes it. The indexer in turn serializes the record into the
//! `records` table's column projection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Record id, e.g. `"2026-04-29-jwt-over-sessions"` (filename minus `.yml`).
pub type RecordId = String;

/// Project id surfaced by `project::resolve`, e.g. `"git:abc123def456"` or
/// `"name:my-project"`. Opaque to the records layer.
pub type ProjectId = String;

/// `sha256` digest of the normalized `title|summary|body` triple. 64 hex chars.
pub type ContentHash = String;

/// Record-type enum. JSON form is lowercase (`"decision"`, `"recommendation"`,
/// `"failure"`, `"untyped"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordType {
    Decision,
    Recommendation,
    Failure,
    Untyped,
}

impl RecordType {
    /// Short string used in the `records.record_type` column.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            RecordType::Decision => "decision",
            RecordType::Recommendation => "recommendation",
            RecordType::Failure => "failure",
            RecordType::Untyped => "untyped",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `Untyped` for unrecognized values; the schema CHECK
    /// constraint already restricts inserted values to the known set, so the
    /// fallback exists for forward-compatibility only.
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "decision" => RecordType::Decision,
            "recommendation" => RecordType::Recommendation,
            "failure" => RecordType::Failure,
            _ => RecordType::Untyped,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Companion to [`from_db_str`], which silently defaults at the trusted-DB
    /// boundary.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "decision" => Some(RecordType::Decision),
            "recommendation" => Some(RecordType::Recommendation),
            "failure" => Some(RecordType::Failure),
            "untyped" => Some(RecordType::Untyped),
            _ => None,
        }
    }
}

/// Source-of-record enum. JSON form is kebab-case (`"cc-native"`,
/// `"codex-native"`, `"local"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    CcNative,
    CodexNative,
    Local,
}

impl Source {
    /// Short string used in the `records.source` and `index_state.source` columns.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Source::CcNative => "cc-native",
            Source::CodexNative => "codex-native",
            Source::Local => "local",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `CodexNative` for unrecognized values. This is the
    /// trusted-DB-column boundary; for parsing untrusted user input that must
    /// reject unknown sources, use [`try_from_user_str`].
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "local" => Source::Local,
            "cc-native" => Source::CcNative,
            _ => Source::CodexNative,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Companion to [`from_db_str`], which silently defaults at the trusted-DB
    /// boundary.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "local" => Some(Source::Local),
            "cc-native" => Some(Source::CcNative),
            "codex-native" => Some(Source::CodexNative),
            _ => None,
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_db_str())
    }
}

/// Confidence enum. JSON form is lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Short string used in the `records.confidence` column.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `Medium` for unrecognized values.
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "low" => Confidence::Low,
            "high" => Confidence::High,
            _ => Confidence::Medium,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Companion to [`from_db_str`], which silently defaults at the trusted-DB
    /// boundary.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Confidence::Low),
            "medium" => Some(Confidence::Medium),
            "high" => Some(Confidence::High),
            _ => None,
        }
    }
}

/// Outcome enum, unioning all per-record-type lifecycles. JSON form is
/// kebab-case. Validity is caller-enforced (e.g., `Working` is only valid
/// on `Decision`):
///
/// | `RecordType`     | Valid outcomes                              |
/// |------------------|---------------------------------------------|
/// | `Decision`       | `Working` \| `Reverted` \| `Superseded`     |
/// | `Recommendation` | `Proposed` \| `Promoted` \| `Rejected` \| `Stale` |
/// | `Failure`        | `Attempted` (immutable)                     |
/// | `Untyped`        | `NotApplicable`                             |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Working,
    Reverted,
    Superseded,
    Proposed,
    Promoted,
    Rejected,
    Stale,
    Attempted,
    NotApplicable,
}

impl Outcome {
    /// Short string used in the `records.outcome` column. `NotApplicable` maps
    /// to `"n-a"`, which differs from the JSON form (`"not-applicable"`).
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Outcome::Working => "working",
            Outcome::Reverted => "reverted",
            Outcome::Superseded => "superseded",
            Outcome::Proposed => "proposed",
            Outcome::Promoted => "promoted",
            Outcome::Rejected => "rejected",
            Outcome::Stale => "stale",
            Outcome::Attempted => "attempted",
            Outcome::NotApplicable => "n-a",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// The DB encoding for `NotApplicable` is `"n-a"`; an unrecognized value
    /// also collapses there for safety.
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "working" => Outcome::Working,
            "reverted" => Outcome::Reverted,
            "superseded" => Outcome::Superseded,
            "proposed" => Outcome::Proposed,
            "promoted" => Outcome::Promoted,
            "rejected" => Outcome::Rejected,
            "stale" => Outcome::Stale,
            "attempted" => Outcome::Attempted,
            _ => Outcome::NotApplicable,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Accepts the JSON / kebab-case form for `NotApplicable` (`"not-applicable"`)
    /// alongside the DB encoding (`"n-a"`) for symmetry with the other variants.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "working" => Some(Outcome::Working),
            "reverted" => Some(Outcome::Reverted),
            "superseded" => Some(Outcome::Superseded),
            "proposed" => Some(Outcome::Proposed),
            "promoted" => Some(Outcome::Promoted),
            "rejected" => Some(Outcome::Rejected),
            "stale" => Some(Outcome::Stale),
            "attempted" => Some(Outcome::Attempted),
            "not-applicable" | "n-a" => Some(Outcome::NotApplicable),
            _ => None,
        }
    }
}

/// Agent enum (who produced the record). JSON form is kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    Codex,
    ClaudeCode,
    Manual,
}

impl Agent {
    /// Short string used in the `records.agent` column.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Agent::Codex => "codex",
            Agent::ClaudeCode => "claude-code",
            Agent::Manual => "manual",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `Manual` for unrecognized values.
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "codex" => Agent::Codex,
            "claude-code" => Agent::ClaudeCode,
            _ => Agent::Manual,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Companion to [`from_db_str`], which silently defaults at the trusted-DB
    /// boundary.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "codex" => Some(Agent::Codex),
            "claude-code" => Some(Agent::ClaudeCode),
            "manual" => Some(Agent::Manual),
            _ => None,
        }
    }
}

/// Signature status. JSON form is lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureStatus {
    Verified,
    Unsigned,
    Invalid,
    Unknown,
}

impl SignatureStatus {
    /// Short string used in the `records.signature_status` column.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            SignatureStatus::Verified => "verified",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::Unknown => "unknown",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `Unsigned` for unrecognized values (the safest default —
    /// downstream policy treats unknown trust as untrusted).
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "verified" => SignatureStatus::Verified,
            "invalid" => SignatureStatus::Invalid,
            "unknown" => SignatureStatus::Unknown,
            _ => SignatureStatus::Unsigned,
        }
    }

    /// Reject unknown values — for parsing untrusted user input (CLI args, MCP).
    /// Companion to [`from_db_str`], which silently defaults at the trusted-DB
    /// boundary.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "verified" => Some(SignatureStatus::Verified),
            "unsigned" => Some(SignatureStatus::Unsigned),
            "invalid" => Some(SignatureStatus::Invalid),
            "unknown" => Some(SignatureStatus::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_db_str())
    }
}

/// Trust policy applied to unsigned records. JSON / TOML form is kebab-case.
///
/// Serializes as `"warn-but-show"` / `"hide"` so the wire shape and
/// `config.toml` representation are identical (no extra wrapping object).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum TrustPolicy {
    /// Surface unsigned records but add a warning to the meta envelope.
    #[default]
    WarnButShow,
    /// Drop unsigned records from results entirely.
    Hide,
}

impl TrustPolicy {
    /// Short string used in the DB `trust_policy` column and TOML config.
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            TrustPolicy::WarnButShow => "warn-but-show",
            TrustPolicy::Hide => "hide",
        }
    }

    /// Inverse of [`as_db_str`]: parse from a DB / config value.
    /// Unknown values default to `WarnButShow` (safe-open posture).
    // Forward-compat: called when trust_policy is persisted in the DB (a later milestone).
    #[allow(dead_code)]
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "hide" => TrustPolicy::Hide,
            _ => TrustPolicy::WarnButShow,
        }
    }

    /// Parse from untrusted user input (CLI arg, MCP param). Returns `None`
    /// for unrecognized values rather than silently defaulting.
    #[must_use]
    pub fn try_from_user_str(s: &str) -> Option<Self> {
        match s {
            "warn-but-show" => Some(TrustPolicy::WarnButShow),
            "hide" => Some(TrustPolicy::Hide),
            _ => None,
        }
    }
}

impl std::fmt::Display for TrustPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_db_str())
    }
}

/// Result of a `get`-by-id operation. Distinguishes "record not found" from
/// "record exists but hidden by trust policy" so the CLI can give targeted
/// guidance instead of a generic "not found" message.
#[derive(Debug, Clone, PartialEq)]
pub enum GetOutcome {
    /// Record present and visible under current trust policy.
    Found(Box<UnifiedRecord>),
    /// No record matches the requested id.
    NotFound,
    /// Record exists but is hidden by the current trust policy. The
    /// `signature_status` lets callers decide whether retrying with
    /// `--include-unsigned` would help.
    HiddenByPolicy { signature_status: SignatureStatus },
}

/// Composite record identity: `(source, project_id, id)`. The same `id`
/// can legitimately appear under different sources (e.g., a CC-native
/// memory and a local YAML record both named `2026-04-29-x`) or different
/// projects, so the natural key is the triple, not just the id.
///
/// Three modes:
/// - **Exact** (`source` and `project_id` both `Some`) — fully qualified
///   key, looked up via the `UNIQUE (source, project_id, id)` index.
/// - **Bare** (`source` and `project_id` both `None`) — id-only lookup;
///   the query layer disambiguates and may return `QueryError::Ambiguous`.
/// - **Partial** (one side `Some`) — narrows by either source or project
///   alone; same disambiguation contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RecordKey {
    pub source: Option<Source>,
    pub project_id: Option<String>,
    pub id: String,
}

impl RecordKey {
    /// Construct a fully-qualified key — `(source, project_id, id)` all known.
    pub fn exact(source: Source, project_id: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            source: Some(source),
            project_id: Some(project_id.into()),
            id: id.into(),
        }
    }

    /// Construct from a bare id; lookups will need to disambiguate.
    pub fn bare(id: impl Into<String>) -> Self {
        Self {
            source: None,
            project_id: None,
            id: id.into(),
        }
    }

    /// Parse the CLI form `<source>:<project_id>:<id>`. The `project_id` may
    /// itself contain colons (e.g., `git:abc123`); we split source off the
    /// front and id off the back.
    #[must_use]
    pub fn parse_qualified(s: &str) -> Option<Self> {
        let (source_str, rest) = s.split_once(':')?;
        let (project_id, id) = rest.rsplit_once(':')?;
        let source = Source::try_from_user_str(source_str)?;
        if project_id.is_empty() || id.is_empty() {
            return None;
        }
        Some(Self::exact(source, project_id, id))
    }

    /// `true` when both `source` and `project_id` are present, so the key
    /// addresses exactly one row via the composite UNIQUE index.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.source.is_some() && self.project_id.is_some()
    }
}

impl std::fmt::Display for RecordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.source, self.project_id.as_deref()) {
            (Some(s), Some(p)) => write!(f, "{}:{}:{}", s.as_db_str(), p, self.id),
            _ => write!(f, "{}", self.id),
        }
    }
}

/// Trust basis (recomputed per query). JSON form is kebab-case.
///
/// Currently only emits `Current` (for verified records) or `None` (for
/// unsigned). The richer rotation/compromise/reanchor states are populated
/// when the trust state machine is fully wired in a later milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustBasis {
    Current,
    RotatedHistorical,
    RotatedHistoricalCompromised,
    PreReanchor,
}

/// Tagged session-reference enum. The variant determines how a consumer
/// retrieves the underlying session content. Wire shape mirrors the canonical
/// YAML record form: `kind: <variant_snake_case>` plus per-variant fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionRef {
    /// CC session UUID (from frontmatter `originSessionId`).
    CcSession { uuid: uuid::Uuid },
    /// Codex rollout file (canonical path to `.jsonl`).
    CodexRollout { path: PathBuf },
    /// Codex thread row in `state_5.sqlite.threads`.
    CodexThread {
        thread_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rollout_path: Option<PathBuf>,
    },
    /// Manual entry; no session source.
    Manual,
}

/// File-evidence shape — distinguishes how a file came to be associated with a
/// record. `extracted` is weaker than `committed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvidence {
    pub path: PathBuf,
    #[serde(flatten)]
    pub kind: FileEvidenceKind,
}

/// File-evidence kind. JSON form uses an explicit `kind` discriminator
/// (`snake_case`) plus per-variant fields, matching the canonical YAML shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileEvidenceKind {
    /// Mentioned in tool calls during the source session.
    ExtractedFromSession { confidence: Confidence },
    /// Parsed out of the body of a native memory file (CC / Codex).
    ParsedFromMemoryBody,
    /// Touched by a commit referenced in the record's `commits` field.
    CommittedAt { sha: String },
}

/// Provenance struct. `extractor` and `digest_hash` are populated by the
/// extraction pipeline (a later milestone); the read path leaves them `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: Source,
    pub signature_status: SignatureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_basis: Option<TrustBasis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extractor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hash: Option<String>,
}

/// Unified in-memory record. Every adapter normalizes its on-disk shape to
/// this struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnifiedRecord {
    pub id: RecordId,
    pub record_type: RecordType,
    pub source: Source,
    pub project_id: ProjectId,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub body: String,
    /// Optional pointer to the on-disk file the record originated from
    /// (CC / Codex memories file path; local YAML path). Surfaced for the
    /// `body_origin_path` column in the index schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_origin_path: Option<PathBuf>,
    pub tags: Vec<String>,
    pub agent: Agent,
    pub session_refs: Vec<SessionRef>,
    pub files: Vec<FileEvidence>,
    pub commits: Vec<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub confidence: Confidence,
    pub outcome: Outcome,
    pub provenance: Provenance,
    /// Adapter-specific overflow only — never load-bearing for ranking or trust.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extras: HashMap<String, serde_json::Value>,
    pub content_hash: ContentHash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn trust_policy_round_trip_db_str() {
        for variant in [TrustPolicy::WarnButShow, TrustPolicy::Hide] {
            let s = variant.as_db_str();
            let back = TrustPolicy::from_db_str(s);
            assert_eq!(variant, back, "round-trip via {s}");
        }
    }

    #[test]
    fn trust_policy_user_str_accepts_canonical() {
        assert_eq!(
            TrustPolicy::try_from_user_str("warn-but-show"),
            Some(TrustPolicy::WarnButShow)
        );
        assert_eq!(
            TrustPolicy::try_from_user_str("hide"),
            Some(TrustPolicy::Hide)
        );
    }

    #[test]
    fn trust_policy_user_str_rejects_unknown() {
        assert_eq!(TrustPolicy::try_from_user_str("strict"), None);
        assert_eq!(TrustPolicy::try_from_user_str(""), None);
    }

    #[test]
    fn get_outcome_variants_match_intent() {
        let r = sample_record();
        let found = GetOutcome::Found(Box::new(r.clone()));
        let not_found = GetOutcome::NotFound;
        let hidden = GetOutcome::HiddenByPolicy {
            signature_status: SignatureStatus::Unsigned,
        };
        assert!(matches!(found, GetOutcome::Found(_)));
        assert!(matches!(not_found, GetOutcome::NotFound));
        assert!(matches!(
            hidden,
            GetOutcome::HiddenByPolicy {
                signature_status: SignatureStatus::Unsigned
            }
        ));
        // Distinct variants are unequal — exercises the derived PartialEq.
        assert_ne!(found, not_found);
        assert_ne!(not_found, hidden);
        assert_ne!(found, hidden);
        // ensure Clone works
        let _ = found.clone();
    }

    fn sample_record() -> UnifiedRecord {
        UnifiedRecord {
            id: "2026-04-29-jwt-over-sessions".into(),
            record_type: RecordType::Decision,
            source: Source::Local,
            project_id: "git:abc123".into(),
            title: "Use JWT (RS256) for stateless auth".into(),
            summary: Some("Adopt JWT with refresh tokens; reject Redis sessions.".into()),
            body: "Long-form rationale ...".into(),
            tags: vec!["auth".into(), "security".into()],
            agent: Agent::Manual,
            session_refs: vec![SessionRef::Manual],
            files: vec![FileEvidence {
                path: PathBuf::from("src/auth/TokenStore.java"),
                kind: FileEvidenceKind::CommittedAt {
                    sha: "a1b2c3d".into(),
                },
            }],
            commits: vec!["a1b2c3d".into()],
            created: Utc.with_ymd_and_hms(2026, 4, 29, 14, 32, 0).unwrap(),
            updated: Utc.with_ymd_and_hms(2026, 4, 29, 14, 32, 0).unwrap(),
            confidence: Confidence::High,
            outcome: Outcome::Working,
            provenance: Provenance {
                source: Source::Local,
                signature_status: SignatureStatus::Verified,
                trust_basis: Some(TrustBasis::Current),
                extractor: None,
                digest_hash: None,
            },
            extras: HashMap::new(),
            content_hash: "ec22deadbeef".into(),
            body_origin_path: None,
        }
    }

    #[test]
    fn round_trip_via_serde_json() {
        let r = sample_record();
        let json = serde_json::to_string(&r).expect("serialize");
        let back: UnifiedRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn record_type_serializes_lowercase_kebab() {
        assert_eq!(
            serde_json::to_string(&RecordType::Decision).unwrap(),
            "\"decision\""
        );
        assert_eq!(
            serde_json::to_string(&RecordType::Untyped).unwrap(),
            "\"untyped\""
        );
    }

    #[test]
    fn source_serializes_kebab() {
        assert_eq!(
            serde_json::to_string(&Source::CcNative).unwrap(),
            "\"cc-native\""
        );
        assert_eq!(
            serde_json::to_string(&Source::CodexNative).unwrap(),
            "\"codex-native\""
        );
        assert_eq!(serde_json::to_string(&Source::Local).unwrap(), "\"local\"");
    }

    #[test]
    fn signature_status_serializes_kebab() {
        assert_eq!(
            serde_json::to_string(&SignatureStatus::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&SignatureStatus::Unsigned).unwrap(),
            "\"unsigned\""
        );
    }

    #[test]
    fn session_ref_round_trips_each_variant() {
        let cases = vec![
            SessionRef::CcSession {
                uuid: uuid::Uuid::nil(),
            },
            SessionRef::CodexRollout {
                path: PathBuf::from("/tmp/rollout.jsonl"),
            },
            SessionRef::CodexThread {
                thread_id: "thread-aaa".into(),
                rollout_path: Some(PathBuf::from("/tmp/rollout.jsonl")),
            },
            SessionRef::CodexThread {
                thread_id: "thread-bbb".into(),
                rollout_path: None,
            },
            SessionRef::Manual,
        ];
        for r in cases {
            let s = serde_json::to_string(&r).unwrap();
            let back: SessionRef = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn session_ref_struct_variant_wire_shape_matches_yaml() {
        // The canonical YAML record uses `kind: codex_rollout` + `path: ...`
        // — verify the JSON form preserves that exact wire shape.
        let r = SessionRef::CodexRollout {
            path: PathBuf::from("/tmp/x.jsonl"),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"kind\":\"codex_rollout\""));
        assert!(s.contains("\"path\":\"/tmp/x.jsonl\""));
    }

    #[test]
    fn try_from_user_str_rejects_unknown_for_each_enum() {
        // RecordType
        assert_eq!(
            RecordType::try_from_user_str("decision"),
            Some(RecordType::Decision)
        );
        assert_eq!(
            RecordType::try_from_user_str("recommendation"),
            Some(RecordType::Recommendation)
        );
        assert_eq!(
            RecordType::try_from_user_str("failure"),
            Some(RecordType::Failure)
        );
        assert_eq!(
            RecordType::try_from_user_str("untyped"),
            Some(RecordType::Untyped)
        );
        assert_eq!(RecordType::try_from_user_str("not-a-type"), None);

        // Source
        assert_eq!(Source::try_from_user_str("local"), Some(Source::Local));
        assert_eq!(
            Source::try_from_user_str("cc-native"),
            Some(Source::CcNative)
        );
        assert_eq!(
            Source::try_from_user_str("codex-native"),
            Some(Source::CodexNative)
        );
        assert_eq!(Source::try_from_user_str("not-a-source"), None);

        // Confidence
        assert_eq!(Confidence::try_from_user_str("low"), Some(Confidence::Low));
        assert_eq!(
            Confidence::try_from_user_str("medium"),
            Some(Confidence::Medium)
        );
        assert_eq!(
            Confidence::try_from_user_str("high"),
            Some(Confidence::High)
        );
        assert_eq!(Confidence::try_from_user_str("very-high"), None);

        // Outcome (accepts both DB-form `"n-a"` and user-form `"not-applicable"`)
        assert_eq!(
            Outcome::try_from_user_str("working"),
            Some(Outcome::Working)
        );
        assert_eq!(
            Outcome::try_from_user_str("not-applicable"),
            Some(Outcome::NotApplicable)
        );
        assert_eq!(
            Outcome::try_from_user_str("n-a"),
            Some(Outcome::NotApplicable)
        );
        assert_eq!(Outcome::try_from_user_str("bogus"), None);

        // Agent
        assert_eq!(Agent::try_from_user_str("codex"), Some(Agent::Codex));
        assert_eq!(
            Agent::try_from_user_str("claude-code"),
            Some(Agent::ClaudeCode)
        );
        assert_eq!(Agent::try_from_user_str("manual"), Some(Agent::Manual));
        assert_eq!(Agent::try_from_user_str("rogue"), None);

        // SignatureStatus
        assert_eq!(
            SignatureStatus::try_from_user_str("verified"),
            Some(SignatureStatus::Verified)
        );
        assert_eq!(
            SignatureStatus::try_from_user_str("unsigned"),
            Some(SignatureStatus::Unsigned)
        );
        assert_eq!(
            SignatureStatus::try_from_user_str("invalid"),
            Some(SignatureStatus::Invalid)
        );
        assert_eq!(
            SignatureStatus::try_from_user_str("unknown"),
            Some(SignatureStatus::Unknown)
        );
        assert_eq!(SignatureStatus::try_from_user_str("rotated"), None);
    }

    #[test]
    fn file_evidence_kind_round_trips_each_variant() {
        let cases = vec![
            FileEvidence {
                path: PathBuf::from("a.txt"),
                kind: FileEvidenceKind::ExtractedFromSession {
                    confidence: Confidence::Medium,
                },
            },
            FileEvidence {
                path: PathBuf::from("b.txt"),
                kind: FileEvidenceKind::ParsedFromMemoryBody,
            },
            FileEvidence {
                path: PathBuf::from("c.txt"),
                kind: FileEvidenceKind::CommittedAt { sha: "abc".into() },
            },
        ];
        for r in cases {
            let s = serde_json::to_string(&r).unwrap();
            let back: FileEvidence = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn record_key_parses_qualified_form() {
        let k = RecordKey::parse_qualified("cc-native:git:abc123:my-record").unwrap();
        assert_eq!(k.source, Some(Source::CcNative));
        assert_eq!(k.project_id.as_deref(), Some("git:abc123"));
        assert_eq!(k.id, "my-record");
        assert!(k.is_exact());
    }

    #[test]
    fn record_key_rejects_unqualified() {
        assert!(RecordKey::parse_qualified("just-an-id").is_none());
        // Missing id segment.
        assert!(RecordKey::parse_qualified("local:proj").is_none());
        // Unknown source.
        assert!(RecordKey::parse_qualified("nope:git:abc:rec").is_none());
        // Empty id segment.
        assert!(RecordKey::parse_qualified("local:git:abc:").is_none());
        // Empty project_id segment between two colons.
        assert!(RecordKey::parse_qualified("local::my-record").is_none());
    }

    #[test]
    fn record_key_display_round_trip() {
        let k = RecordKey::exact(Source::Local, "git:abc", "my-record");
        let s = format!("{k}");
        assert_eq!(s, "local:git:abc:my-record");
        let parsed = RecordKey::parse_qualified(&s).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn record_key_bare_display_omits_qualifiers() {
        let k = RecordKey::bare("just-an-id");
        assert_eq!(format!("{k}"), "just-an-id");
        assert!(!k.is_exact());
    }
}
