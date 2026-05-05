//! Session startup orchestration.
//!
//! Per-command pre-checks that run before any subcommand work; centralizes
//! refusal logic for global preconditions (reanchor pending, future:
//! read-only DB lock, schema migration required).

pub mod startup;

pub use startup::{StartupError, pre_check};
