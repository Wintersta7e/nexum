//! Indexer — open / create `index.db`, run a reindex pass over all enabled
//! adapters, write results into `records` + `records_fts` per §7.
//!
//! The `record_embeddings` (vec0) virtual table is created by the §7 DDL but
//! is NOT populated in Phase 3 — semantic embeddings land in a later phase.

pub mod db;
pub mod run;
pub mod state;

// Uncommented incrementally:
//   Task 8 → uncomment `pub use db::{IndexerError, open_or_create};`
//   Task 10 → uncomment `pub use run::{IndexerOutcome, run};`
// pub use db::{IndexerError, open_or_create};
// pub use run::{IndexerOutcome, run};
