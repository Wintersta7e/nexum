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
//! - `20` ([`EXTRACT_NOT_ACKNOWLEDGED`]): consent missing; run
//!   `nexum extract --session <id>` interactively once.
//! - `21` ([`EXTRACT_DRY_RUN_REQUIRED`]): `--backfill` invoked without a
//!   prior `--dry-run` manifest.
//! - `22` ([`EXTRACT_DRY_RUN_MISMATCH`]): the manifest id no longer matches
//!   the recomputed basis; re-run `--dry-run`.
//! - `23` ([`EXTRACT_NO_API_KEY`]): provider API-key env var unset.
//! - `24` ([`EXTRACT_PROVIDER_UNSUPPORTED`]): configured provider has no
//!   working client in this build.
//! - `25` ([`EXTRACT_MODEL_ERROR`]): catch-all for transport / redaction
//!   / digest / I/O / JSON / YAML / git failures during extraction.
//! - `26` ([`EXTRACT_PARSE`]): model response was not valid YAML.
//! - `27` ([`EXTRACT_VALIDATION`]): parsed record failed schema validation.
//! - `28` ([`EXTRACT_NO_SESSIONS`]): selector matched no sessions.

/// Generic failure (mirrors `ExitCode::FAILURE`); surfaces from the
/// `for_envelope` wildcard arm and from `SERIALIZE_FAILED`.
pub(crate) const FAILURE: u8 = 1;
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
pub(crate) const TRUST_SCHEMA_UNSUPPORTED: u8 = 9;
pub(crate) const NOT_INDEXED: u8 = 10;
pub(crate) const NOT_FOUND: u8 = 11;
pub(crate) const HIDDEN_BY_POLICY: u8 = 12;
pub(crate) const AMBIGUOUS: u8 = 13;
pub(crate) const EXTRACT_NOT_ACKNOWLEDGED: u8 = 20;
pub(crate) const EXTRACT_DRY_RUN_REQUIRED: u8 = 21;
pub(crate) const EXTRACT_DRY_RUN_MISMATCH: u8 = 22;
pub(crate) const EXTRACT_NO_API_KEY: u8 = 23;
pub(crate) const EXTRACT_PROVIDER_UNSUPPORTED: u8 = 24;
pub(crate) const EXTRACT_MODEL_ERROR: u8 = 25;
pub(crate) const EXTRACT_PARSE: u8 = 26;
pub(crate) const EXTRACT_VALIDATION: u8 = 27;
pub(crate) const EXTRACT_NO_SESSIONS: u8 = 28;

/// Map an `ErrorEnvelope`'s `error_code` to the matching CLI exit code.
///
/// The mapping is the single source of truth for code-to-exit translation;
/// every `--json`-bearing verb routes through `json_emit::emit_error(env,
/// for_envelope(env))` so the two channels stay in sync.
pub(crate) fn for_envelope(env: &nexum_core::api::error::ErrorEnvelope) -> u8 {
    use nexum_core::api::error::error_codes as ec;
    match env.error_code {
        ec::USAGE => USAGE,
        ec::NOT_INITIALIZED => NOT_INITIALIZED,
        ec::STORE_INTEGRITY | ec::INVALID_FILTER | ec::TAMPERING_DETECTED => STORE_INTEGRITY,
        ec::MIGRATION_REQUIRED => MIGRATION_REQUIRED,
        ec::REANCHOR_PENDING => REANCHOR_PENDING,
        ec::TRUST_SCHEMA_UNSUPPORTED => TRUST_SCHEMA_UNSUPPORTED,
        ec::NOT_INDEXED => NOT_INDEXED,
        ec::NOT_FOUND => NOT_FOUND,
        ec::HIDDEN_BY_POLICY => HIDDEN_BY_POLICY,
        ec::AMBIGUOUS_KEY => AMBIGUOUS,
        ec::EXTRACT_NOT_ACKNOWLEDGED => EXTRACT_NOT_ACKNOWLEDGED,
        ec::EXTRACT_DRY_RUN_REQUIRED => EXTRACT_DRY_RUN_REQUIRED,
        ec::EXTRACT_DRY_RUN_MISMATCH => EXTRACT_DRY_RUN_MISMATCH,
        ec::EXTRACT_NO_API_KEY => EXTRACT_NO_API_KEY,
        ec::EXTRACT_PROVIDER_UNSUPPORTED => EXTRACT_PROVIDER_UNSUPPORTED,
        ec::EXTRACT_MODEL_ERROR => EXTRACT_MODEL_ERROR,
        ec::EXTRACT_PARSE => EXTRACT_PARSE,
        ec::EXTRACT_VALIDATION => EXTRACT_VALIDATION,
        ec::EXTRACT_NO_SESSIONS => EXTRACT_NO_SESSIONS,
        // SERIALIZE_FAILED + any future unmapped code routes to generic
        // FAILURE; the stable envelope_code on the wire stays accurate.
        _ => FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexum_core::api::error::{ErrorEnvelope, error_codes};

    fn env(code: &'static str) -> ErrorEnvelope {
        ErrorEnvelope {
            error_code: code,
            message: "test".into(),
            remediation: None,
            context: serde_json::json!({}),
        }
    }

    #[test]
    fn migration_required_routes_to_six() {
        assert_eq!(for_envelope(&env(error_codes::MIGRATION_REQUIRED)), 6);
    }

    #[test]
    fn not_indexed_routes_to_ten() {
        assert_eq!(for_envelope(&env(error_codes::NOT_INDEXED)), 10);
    }

    #[test]
    fn ambiguous_key_routes_to_thirteen() {
        assert_eq!(for_envelope(&env(error_codes::AMBIGUOUS_KEY)), 13);
    }

    #[test]
    fn tampering_detected_routes_to_store_integrity() {
        assert_eq!(for_envelope(&env(error_codes::TAMPERING_DETECTED)), 4);
    }

    #[test]
    fn extract_not_acknowledged_routes_to_twenty() {
        assert_eq!(
            for_envelope(&env(error_codes::EXTRACT_NOT_ACKNOWLEDGED)),
            20
        );
    }

    #[test]
    fn extract_no_sessions_routes_to_twenty_eight() {
        assert_eq!(for_envelope(&env(error_codes::EXTRACT_NO_SESSIONS)), 28);
    }
}
