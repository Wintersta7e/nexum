//! Commit-promotion plumbing.
//!
//! Exposes git-correlation and evidence-assembly helpers consumed by the
//! promotion facade (lands in a later change; the transitional `dead_code`
//! allows on submodules are removed then).

use std::path::PathBuf;

use crate::config::Config;
use crate::records::types::UnifiedRecord;

// Commit-correlation plumbing. Consumed by the promotion facade in a
// later change; the transitional dead_code allow is removed then.
#[allow(dead_code)]
pub(crate) mod fingerprint;

// Correlation signals. Consumed by the promotion facade in a later change;
// the transitional dead_code allow is removed then.
#[allow(dead_code)]
pub(crate) mod correlate;

// Suggestion scan. Consumed by the promotion facade in a later change;
// the transitional dead_code allow is removed then.
#[allow(dead_code)]
pub(crate) mod suggest;

/// Resolve a record's project repo path from the config registry.
/// Thin wrapper over `crate::api::project_path_for` so `promote::*` submodules
/// don't need to reach into `api` directly.
///
/// Returns `None` when no path is registered for the record's project.
// Consumed by suggest::scan; the allow is removed when the facade lands.
#[allow(dead_code)]
pub(crate) fn repo_path_for(rec: &UnifiedRecord, cfg: &Config) -> Option<PathBuf> {
    crate::api::project_path_for(&rec.project_id, cfg).map(PathBuf::from)
}
