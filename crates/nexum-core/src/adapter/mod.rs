//! Adapter surface — one trait, three implementations.
//!
//! Each adapter (cc / codex / local) implements `Adapter` from
//! `crate::adapter::trait_def`. The `indexer` module composes all enabled
//! adapters into a single reindex pipeline against `index.db`.

pub mod cc;
pub mod codex;
pub mod local;
pub mod trait_def;

// Uncommented when Task 4 (03-adapter-trait.md) lands:
// pub use trait_def::{
//     Adapter, AdapterError, AdapterPass, AdapterRecordSummary, PassCompleteness,
//     SkipKind, SkipReason,
// };
