//! In-memory record types — adapters normalize their inputs to `UnifiedRecord`
//! before the indexer writes them. Mirrors §4 of the design spec.

pub mod hash;
pub mod types;

// Uncommented incrementally:
//   Task 2 (02-records.md) → uncomment `pub use types::{...};`
//   Task 3 (02-records.md) → uncomment `pub use hash::{RecordSummary, content_hash};`
// pub use hash::{RecordSummary, content_hash};
// pub use types::{
//     Agent, Confidence, ContentHash, FileEvidence, FileEvidenceKind, Outcome, Provenance,
//     ProjectId, RecordId, RecordType, SessionRef, SignatureStatus, Source, TrustBasis,
//     UnifiedRecord,
// };
