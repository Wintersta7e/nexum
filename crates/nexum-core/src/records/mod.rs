//! In-memory record types — adapters normalize their inputs to `UnifiedRecord`
//! before the indexer writes them. Mirrors the canonical record schema.

pub mod hash;
pub mod types;

pub use types::{
    Agent, Confidence, ContentHash, FileEvidence, FileEvidenceKind, Outcome, ProjectId, Provenance,
    RecordId, RecordType, SessionRef, SignatureStatus, Source, TrustBasis, UnifiedRecord,
};
// `pub use hash::{RecordSummary, content_hash};` lands in the next task.
