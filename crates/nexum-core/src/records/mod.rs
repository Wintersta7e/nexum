//! In-memory record types — adapters normalize their inputs to `UnifiedRecord`
//! before the indexer writes them. Mirrors the canonical record schema.

pub mod hash;
pub mod types;

pub use hash::{RecordSummary, content_hash};
pub use types::{
    Agent, Confidence, ContentHash, FileEvidence, FileEvidenceKind, GetOutcome, Outcome, ProjectId,
    Provenance, RecordId, RecordKey, RecordType, SessionRef, SignatureStatus, Source, TrustBasis,
    TrustPolicy, UnifiedRecord,
};
