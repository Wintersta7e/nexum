//! CLI exit-code taxonomy.
//!
//! - `0` (`ExitCode::SUCCESS`): success.
//! - `1` (`ExitCode::FAILURE`): generic failure.
//! - `2` ([`USAGE`]): invalid argument combination.
//! - `3` ([`NOT_INITIALIZED`]): nexum home / config missing or unreadable.
//! - `4` ([`STORE_INTEGRITY`]): store / api error during verb's main work
//!   (rusqlite, indexer, query); suggests `index --force`.
//! - `5` ([`BUSY`]): embed pool saturated (reserved for embedder work).
//! - `6` ([`MIGRATION_REQUIRED`]): index.db schema older than binary; run
//!   `nexum migrate`.
//! - `7` ([`CONCURRENT`]): another nexum process holds the global mutation
//!   lock at `~/.nexum/.lock`.
//! - `8` ([`REANCHOR_PENDING`]): `~/.nexum/.reanchor_pending` exists; trust
//!   state indeterminate. `nexum doctor --resolve-pending-reanchor` resolves.
//! - `9` ([`TRUST_SCHEMA_UNSUPPORTED`]): `events.yml.schema_version` newer
//!   than this binary supports.
//! - `10` ([`NOT_INDEXED`]): no index database yet (suggest `nexum index`).
//! - `11` ([`NOT_FOUND`]): no record matches the requested id.
//! - `12` ([`HIDDEN_BY_POLICY`]): record exists but suppressed by trust
//!   policy (suggest retrying with `--include-unsigned`).
//! - `13` ([`AMBIGUOUS`]): bare id matched multiple records.

pub(crate) const USAGE: u8 = 2;
pub(crate) const NOT_INITIALIZED: u8 = 3;
pub(crate) const STORE_INTEGRITY: u8 = 4;
// Reserved slot wired up by future embedder work; see module docs.
#[allow(dead_code)]
pub(crate) const BUSY: u8 = 5;
pub(crate) const MIGRATION_REQUIRED: u8 = 6;
// Reserved slot wired up by future lock-holder work; see module docs.
#[allow(dead_code)]
pub(crate) const CONCURRENT: u8 = 7;
pub(crate) const REANCHOR_PENDING: u8 = 8;
// Reserved slot wired up by future trust-schema gate; see module docs.
#[allow(dead_code)]
pub(crate) const TRUST_SCHEMA_UNSUPPORTED: u8 = 9;
pub(crate) const NOT_INDEXED: u8 = 10;
pub(crate) const NOT_FOUND: u8 = 11;
pub(crate) const HIDDEN_BY_POLICY: u8 = 12;
pub(crate) const AMBIGUOUS: u8 = 13;
