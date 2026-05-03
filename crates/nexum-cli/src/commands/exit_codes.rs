//! CLI exit-code taxonomy.
//!
//! - `0` (`ExitCode::SUCCESS`): success. The verb completed.
//! - `1` (`ExitCode::FAILURE`): generic failure (serialization, internal panic).
//! - `2` ([`USAGE`]): invalid argument combination.
//! - `3` ([`NOT_INITIALIZED`]): nexum home / config missing or unreadable
//!   (suggests `nexum init`).
//! - `4` ([`RUNTIME`]): store / api error during the verb's main work
//!   (rusqlite, indexer, query).
//!
//! Codes 5+ are reserved for structured error variants that don't yet exist
//! in `nexum-core` (e.g., busy / migration-required / concurrent-access).

pub(crate) const USAGE: u8 = 2;
pub(crate) const NOT_INITIALIZED: u8 = 3;
pub(crate) const RUNTIME: u8 = 4;
