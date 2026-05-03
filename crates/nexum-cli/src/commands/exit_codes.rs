//! CLI exit-code taxonomy.
//!
//! - `0` (`ExitCode::SUCCESS`): success. The verb completed.
//! - `1` (`ExitCode::FAILURE`): generic failure (serialization, internal panic).
//! - `2` ([`USAGE`]): invalid argument combination.
//! - `3` ([`NOT_INITIALIZED`]): nexum home / config missing or unreadable
//!   (suggests `nexum init`).
//! - `4` ([`RUNTIME`]): store / api error during the verb's main work
//!   (rusqlite, indexer, query).
//! - `5`: reserved (migration-required / concurrent-access).
//! - `6` ([`NOT_FOUND`]): no record matches the requested id.
//! - `7` ([`HIDDEN_BY_POLICY`]): record exists but suppressed by trust policy
//!   (suggests retrying with `--include-unsigned`).

pub(crate) const USAGE: u8 = 2;
pub(crate) const NOT_INITIALIZED: u8 = 3;
pub(crate) const RUNTIME: u8 = 4;
pub(crate) const NOT_FOUND: u8 = 6;
pub(crate) const HIDDEN_BY_POLICY: u8 = 7;
