//! Git hook installation for `nexum init`.
//! Full implementation in Task 9.

use std::path::Path;

use super::options::InitError;

/// Install the `pre-merge-commit` hook that prevents merges touching `.trust/*`.
///
/// # Errors
///
/// Returns `InitError::Io` on write failure.
pub fn install_pre_merge_commit_hook(repo: &Path) -> Result<(), InitError> {
    let _ = repo;
    unimplemented!("install_pre_merge_commit_hook — Task 9")
}
