//! Session startup orchestration.
//!
//! Per-command pre-checks that run before any subcommand work; centralizes
//! refusal logic for global preconditions (reanchor pending, future:
//! read-only DB lock, schema migration required). `runtime` sequences the
//! full `Paths` + pre-check + `Config` resolution every entry point shares.

pub mod runtime;
pub mod startup;

pub use runtime::{resolve_runtime, resolve_runtime_for};
pub use startup::{StartupError, pre_check};
