//! Shared CLI handler helpers — runtime resolution and common error responses.

use std::{path::Path, process::ExitCode};

use nexum_core::{
    api::ApiError,
    config::{io::load as load_config, types::Config},
    paths::Paths,
};

use super::exit_codes;

/// Resolve `Paths` and load the config. Returns the runtime context shared
/// by every read-side CLI verb (`index`, `search`, `get`, `list`, `recent`,
/// `by_session`, `project`).
///
/// On `Paths::resolve` failure prints an init-suggestion hint and returns
/// `ExitCode::from(exit_codes::NOT_INITIALIZED)`. On `load_config` failure
/// prints the underlying error and returns the same code.
pub(crate) fn resolve_runtime() -> Result<(Paths, Config), ExitCode> {
    let paths = Paths::resolve().map_err(|e| {
        eprintln!("error: {e}\nDid you run `nexum init`?");
        ExitCode::from(exit_codes::NOT_INITIALIZED)
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
#[allow(dead_code)]
pub(crate) fn handle_migration_required(err: &ApiError) -> Option<ExitCode> {
    if let ApiError::MigrationRequired { v_disk, v_code } = err {
        eprintln!("error: index schema v{v_disk} is older than this binary (v{v_code}).");
        eprintln!("Run `nexum migrate` to update, then re-run.");
        Some(ExitCode::from(exit_codes::MIGRATION_REQUIRED))
    } else {
        None
    }
}
