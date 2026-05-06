//! Shared CLI handler helpers — runtime resolution and common error responses.

use std::{path::Path, process::ExitCode};

use nexum_core::{
    api::ApiError,
    config::{io::load as load_config, types::Config},
    paths::Paths,
    query::QueryError,
    trust::events::TrustError,
};

use super::exit_codes;

/// Resolve `Paths`, run the global session pre-check, and load the config.
/// Returns the runtime context shared by every read-side CLI verb (`index`,
/// `search`, `get`, `list`, `recent`, `by_session`, `project`).
///
/// On `Paths::resolve` failure prints an init-suggestion hint and returns
/// `ExitCode::from(exit_codes::NOT_INITIALIZED)`. If `session::startup::pre_check`
/// detects a `.reanchor_pending` sentinel, returns
/// `ExitCode::from(exit_codes::REANCHOR_PENDING)` (8); other startup errors
/// map to `STORE_INTEGRITY`. On `load_config` failure prints the underlying
/// error and returns `NOT_INITIALIZED`.
pub(crate) fn resolve_runtime() -> Result<(Paths, Config), ExitCode> {
    let paths = Paths::resolve().map_err(|e| {
        eprintln!("error: {e}\nDid you run `nexum init`?");
        ExitCode::from(exit_codes::NOT_INITIALIZED)
    })?;
    nexum_core::session::startup::pre_check(&paths.home).map_err(|e| match e {
        nexum_core::session::startup::StartupError::Trust(
            nexum_core::trust::events::TrustError::ReanchorPending { message },
        ) => {
            eprintln!("error: {message}");
            ExitCode::from(exit_codes::REANCHOR_PENDING)
        }
        nexum_core::session::startup::StartupError::Trust(other) => {
            eprintln!("error: {other}");
            ExitCode::from(exit_codes::STORE_INTEGRITY)
        }
    })?;
    let cfg = load_config(&paths.config).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(exit_codes::NOT_INITIALIZED)
    })?;
    Ok((paths, cfg))
}

/// Print the "no index database" error and return the appropriate exit code.
/// Used by every read-side verb to handle `QueryError::IndexMissing`.
pub(crate) fn handle_index_missing(path: &Path) -> ExitCode {
    eprintln!(
        "error: no index database at `{}`; run `nexum index` to populate it",
        path.display()
    );
    ExitCode::from(exit_codes::NOT_INDEXED)
}

/// Translate an [`ApiError::MigrationRequired`] into the dedicated CLI exit
/// code. Other `ApiError` variants are caller-specific and stay with their
/// per-verb handlers; centralizing this one keeps the user-facing message
/// consistent.
pub(crate) fn handle_migration_required(err: &ApiError) -> Option<ExitCode> {
    if let ApiError::MigrationRequired { v_disk, v_code } = err {
        eprintln!("error: index schema v{v_disk} is older than this binary (v{v_code}).");
        eprintln!("Run `nexum migrate` to update, then re-run.");
        Some(ExitCode::from(exit_codes::MIGRATION_REQUIRED))
    } else {
        None
    }
}

/// Translate an [`ApiError::Query(QueryError::Trust(TrustError::TrustSchemaUnsupported))`]
/// into the dedicated CLI exit code. The materializer raises this when
/// `events.yml`'s `schema_version` is newer than the binary understands —
/// older binaries reading a newer notebook need the user-facing
/// "upgrade nexum" hint, not the generic store-integrity bucket.
pub(crate) fn handle_trust_schema_unsupported(err: &ApiError) -> Option<ExitCode> {
    if let ApiError::Query(QueryError::Trust(TrustError::TrustSchemaUnsupported { found })) = err {
        eprintln!("error: trust events schema v{found} is newer than this binary understands.");
        eprintln!("Upgrade nexum to a build that supports the new schema, then re-run.");
        Some(ExitCode::from(exit_codes::TRUST_SCHEMA_UNSUPPORTED))
    } else {
        None
    }
}

/// Map any read-verb [`ApiError`] to the matching exit code with the
/// appropriate user-facing message. Folds the per-variant translators
/// (`IndexMissing` / `MigrationRequired` / `TrustSchemaUnsupported`) so the
/// 5 read verbs share one fallthrough contract.
pub(crate) fn handle_read_verb_error(err: &ApiError) -> ExitCode {
    if let ApiError::Query(QueryError::IndexMissing { path }) = err {
        return handle_index_missing(path);
    }
    if let Some(code) = handle_migration_required(err) {
        return code;
    }
    if let Some(code) = handle_trust_schema_unsupported(err) {
        return code;
    }
    eprintln!("error: {err}");
    ExitCode::from(exit_codes::STORE_INTEGRITY)
}
