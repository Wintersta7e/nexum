//! `nexum init` orchestrator and supporting helpers.
//!
//! `run(opts)` is the public entry point. It acquires the writer lock,
//! performs the §8 10-step init flow, and rolls back on failure.

pub mod git_ops;
pub mod hooks;
pub mod options;
pub mod run;

pub use options::{InitError, InitOpts, InitOutcome};
pub use run::run;
