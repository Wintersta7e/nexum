//! Shared CLI handler helpers — runtime resolution.

use std::process::ExitCode;

use nexum_core::{
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
