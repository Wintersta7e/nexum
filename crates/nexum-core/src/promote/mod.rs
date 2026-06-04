//! Commit-promotion plumbing.
//!
//! Exposes git-correlation and evidence-assembly helpers consumed by the
//! promotion facade.

use std::path::PathBuf;

use crate::config::Config;
use crate::records::types::UnifiedRecord;

/// Commit-correlation plumbing.
pub(crate) mod fingerprint;

/// Correlation signals.
pub(crate) mod correlate;

/// Suggestion scan.
pub(crate) mod suggest;

/// Stale-recommendation identification.
pub(crate) mod reaper;

/// Resolve a record's project repo path from the config registry.
/// Thin wrapper over `crate::api::project_path_for` so `promote::*` submodules
/// don't need to reach into `api` directly.
///
/// Returns `None` when no path is registered for the record's project.
pub(crate) fn repo_path_for(rec: &UnifiedRecord, cfg: &Config) -> Option<PathBuf> {
    crate::api::project_path_for(&rec.project_id, cfg).map(PathBuf::from)
}
