//! `Adapter` trait + `AdapterPass` types — the read-path contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::records::{RecordId, RecordSummary, Source, UnifiedRecord};

/// One reason a single file was skipped during an adapter list pass. The set
/// of reasons populates `PassCompleteness::Partial::skipped`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipReason {
    pub path: PathBuf,
    pub kind: SkipKind,
    pub at: DateTime<Utc>,
}

/// Why a single file was skipped. JSON form is kebab-case.
///
/// `FileTransient` covers stable-double-read failures and other "try again
/// next pass" cases; `FileMalformed` is content the parser couldn't handle
/// even after the file was fully read; `LockContention` is the SQLite-locked
/// case for the Codex adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipKind {
    FileTransient,
    FileMalformed,
    LockContention,
}

/// Adapter pass-completeness contract.
///
/// `Authoritative` — every file in scope was read + parsed cleanly. The
/// indexer is allowed to compute deletes against indexed state.
///
/// `Partial { skipped }` — some files were skipped due to transient errors
/// (stable-double-read failure, parser validation failure, mid-rewrite from
/// an upstream tool). Upserts proceed; deletes are suppressed.
///
/// `Failed { reason }` — the adapter could not enumerate at all. No upserts;
/// no deletes; the indexer treats this pass as a no-op for this source.
///
/// `MissingRoot { path }` — the configured root directory does not exist. The
/// indexer suppresses both upserts and deletes to avoid false-pruning records
/// from a temporarily absent mount or workspace. If no prior records exist for
/// this source the pass is a silent no-op; if prior records do exist a warning
/// is emitted.
///
/// `Unreadable { path, reason }` — the root exists but cannot be enumerated
/// (permissions failure, I/O error). The indexer always treats this as a hard
/// no-op with a warning regardless of prior record state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PassCompleteness {
    Authoritative,
    Partial { skipped: Vec<SkipReason> },
    Failed { reason: String },
    MissingRoot { path: PathBuf },
    Unreadable { path: PathBuf, reason: String },
}

/// One pass's worth of summaries from a single adapter. The indexer
/// consumes this directly; see `crate::indexer::run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterPass {
    pub source: Source,
    pub records: Vec<RecordSummary>,
    pub completeness: PassCompleteness,
}

/// Adapter-level error.
///
/// `Fatal` is reserved for genuine bugs (parser panics caught at the trait
/// boundary, schema-detection failures the adapter doesn't know how to fold
/// into a `Failed` pass). Ordinary "couldn't read this file right now" cases
/// are NOT errors — they ride along on `PassCompleteness::Partial`.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter fatal error: {detail}")]
    Fatal { detail: String },
    #[error("io error in adapter at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("rusqlite error in adapter: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    /// Record body / frontmatter / yaml could not be parsed. `detail` carries
    /// a short reason (the underlying parser's error message); `path` points
    /// at the file the parser choked on.
    #[error("malformed record at {path:?}: {detail}")]
    MalformedRecord { path: PathBuf, detail: String },
    #[error("config integration error: {0}")]
    Config(String),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectError),
}

/// Adapter trait. Two methods — `list` returns a pass shape, `read` fetches
/// the full record body for a single id (used by `query::get` for sources whose
/// indexed body is truncated; the read path stores full bodies and rarely needs
/// `read`, but the contract is preserved for future use).
pub trait Adapter {
    /// What source this adapter speaks for.
    fn source(&self) -> Source;

    /// Enumerate all records visible to this adapter (one pass).
    ///
    /// # Errors
    /// Returns `AdapterError::Fatal` on parser panics caught at the boundary
    /// or other genuine bugs. Ordinary contention is reported via
    /// `PassCompleteness::Partial` / `Failed` on the returned `AdapterPass`,
    /// not as an `Err`.
    fn list(&self) -> Result<AdapterPass, AdapterError>;

    /// Fetch the full `UnifiedRecord` for a given id.
    ///
    /// # Errors
    /// Returns `AdapterError::Io` if the underlying file is missing or
    /// unreadable; `AdapterError::MalformedRecord` if parsing fails; other
    /// variants for per-source-specific failures.
    fn read(&self, id: &RecordId) -> Result<UnifiedRecord, AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_completeness_authoritative_round_trips() {
        let p = PassCompleteness::Authoritative;
        let s = serde_json::to_string(&p).unwrap();
        let back: PassCompleteness = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn pass_completeness_partial_round_trips() {
        let p = PassCompleteness::Partial {
            skipped: vec![SkipReason {
                path: PathBuf::from("/tmp/codex/MEMORY.md"),
                kind: SkipKind::FileTransient,
                at: chrono::Utc::now(),
            }],
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PassCompleteness = serde_json::from_str(&s).unwrap();
        match back {
            PassCompleteness::Partial { skipped } => assert_eq!(skipped.len(), 1),
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn pass_completeness_failed_round_trips() {
        let p = PassCompleteness::Failed {
            reason: "state_5.sqlite missing".into(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PassCompleteness = serde_json::from_str(&s).unwrap();
        match back {
            PassCompleteness::Failed { reason } => assert_eq!(reason, "state_5.sqlite missing"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn skip_kind_serializes_kebab_case() {
        for (k, expected) in [
            (SkipKind::FileTransient, "\"file-transient\""),
            (SkipKind::FileMalformed, "\"file-malformed\""),
            (SkipKind::LockContention, "\"lock-contention\""),
        ] {
            assert_eq!(serde_json::to_string(&k).unwrap(), expected);
        }
    }

    #[test]
    fn adapter_pass_aggregates_records_and_completeness() {
        let pass = AdapterPass {
            source: Source::Local,
            records: vec![RecordSummary {
                id: "alpha".into(),
                content_hash: "deadbeef".into(),
            }],
            completeness: PassCompleteness::Authoritative,
        };
        let s = serde_json::to_string(&pass).unwrap();
        let back: AdapterPass = serde_json::from_str(&s).unwrap();
        assert_eq!(pass, back);
    }

    #[test]
    fn pass_completeness_missing_root_round_trips() {
        let p = PassCompleteness::MissingRoot {
            path: PathBuf::from("/tmp/missing"),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PassCompleteness = serde_json::from_str(&s).unwrap();
        match back {
            PassCompleteness::MissingRoot { path } => {
                assert_eq!(path, PathBuf::from("/tmp/missing"));
            }
            other => panic!("expected MissingRoot, got {other:?}"),
        }
    }

    #[test]
    fn pass_completeness_unreadable_round_trips() {
        let p = PassCompleteness::Unreadable {
            path: PathBuf::from("/tmp/unreadable"),
            reason: "permission denied".to_string(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PassCompleteness = serde_json::from_str(&s).unwrap();
        match back {
            PassCompleteness::Unreadable { path, reason } => {
                assert_eq!(path, PathBuf::from("/tmp/unreadable"));
                assert_eq!(reason, "permission denied");
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }
}
