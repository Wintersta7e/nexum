//! Indexer — open / create `index.db`, run a reindex pass over all enabled
//! adapters, write results into `records` + `records_fts`.
//!
//! The `record_embeddings` (vec0) virtual table is created by the index DDL but
//! is NOT populated yet — semantic embeddings land in a later phase.

pub(crate) mod crypto_batch;
pub mod db;
pub mod run;
pub mod state;

pub use db::{IndexerError, open_or_create};
pub use run::{IndexerOpts, IndexerOutcome, run, run_with_opts};
