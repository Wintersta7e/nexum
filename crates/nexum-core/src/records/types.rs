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
    pub(crate) fn as_db_str(self) -> &'static str {
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
}

/// Source-of-record enum. JSON form is kebab-case (`"cc-native"`,
/// `"codex-native"`, `"local"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    CcNative,
    CodexNative,
    Local,
}

impl Source {
    /// Short string used in the `records.source` and `index_state.source` columns.
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            Source::CcNative => "cc-native",
            Source::CodexNative => "codex-native",
            Source::Local => "local",
        }
    }

    /// Inverse of [`as_db_str`]: parse a value from the corresponding column.
    /// Falls through to `CodexNative` for unrecognized values. This is the
    /// trusted-DB-column boundary; for parsing untrusted user input that must
    /// reject unknown sources, use the explicit match in `query::recent`.
    pub(crate) fn from_db_str(s: &str) -> Self {
        match s {
            "local" => Source::Local,
            "cc-native" => Source::CcNative,
            _ => Source::CodexNative,
        }
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
    pub(crate) fn as_db_str(self) -> &'static str {
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
    pub(crate) fn as_db_str(self) -> &'static str {
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
    pub(crate) fn as_db_str(self) -> &'static str {
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
    pub(crate) fn as_db_str(self) -> &'static str {
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
}
