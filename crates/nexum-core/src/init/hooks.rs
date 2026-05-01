//! Git hook installation for `nexum init`.
//!
//! The `pre-merge-commit` hook (§9 linear-history requirement) rejects any
//! merge that would touch paths under `.trust/`. This prevents merge commits
//! from creating a non-linear history for `events.yml`, which would make
//! topological-order trust verification ambiguous.

use std::path::Path;

use super::options::InitError;

/// The shell script for the `pre-merge-commit` hook.
///
/// Reads `MERGE_HEAD`, diffs it against `HEAD`, and exits 1 if any path
/// under `.trust/` is touched.
const PRE_MERGE_COMMIT_HOOK: &str = r#"#!/bin/sh
# nexum pre-merge-commit hook — installed by `nexum init`.
# Rejects any merge that touches .trust/* paths to preserve linear history
# on the events.yml trust chain (§9 linear-history requirement).
set -e
if git diff --name-only HEAD MERGE_HEAD 2>/dev/null | grep -q '^\.trust/'; then
    echo "nexum: merge rejected — this merge touches .trust/ paths." >&2
    echo "The trust chain must remain linear. Rebase instead of merging." >&2
    exit 1
fi
"#;

/// Install the `pre-merge-commit` hook into `<repo>/.git/hooks/`.
///
/// Creates the hooks directory if absent, writes the script, and sets it
/// executable (Unix: mode 0755).
///
/// # Errors
///
/// Returns `InitError::Io` on any filesystem or permission error.
pub fn install_pre_merge_commit_hook(repo: &Path) -> Result<(), InitError> {
    let hooks_dir = repo.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).map_err(|e| InitError::Io {
        path: hooks_dir.display().to_string(),
        source: e,
    })?;

    let hook_path = hooks_dir.join("pre-merge-commit");
    std::fs::write(&hook_path, PRE_MERGE_COMMIT_HOOK).map_err(|e| InitError::Io {
        path: hook_path.display().to_string(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755)).map_err(
            |e| InitError::Io {
                path: hook_path.display().to_string(),
                source: e,
            },
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::git_ops::git_init;
    use tempfile::tempdir;

    #[test]
    fn hook_file_is_written() {
        let dir = tempdir().unwrap();
        git_init(dir.path()).unwrap();
        install_pre_merge_commit_hook(dir.path()).unwrap();
        let hook_path = dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-merge-commit");
        assert!(hook_path.exists(), "hook file must exist");
    }

    #[test]
    fn hook_content_contains_trust_path_check() {
        let dir = tempdir().unwrap();
        git_init(dir.path()).unwrap();
        install_pre_merge_commit_hook(dir.path()).unwrap();
        let hook_path = dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-merge-commit");
        let content = std::fs::read_to_string(&hook_path).unwrap();
        assert!(
            content.contains(".trust/"),
            "hook must reference .trust/ path"
        );
        assert!(content.contains("exit 1"), "hook must exit 1 on rejection");
    }

    #[cfg(unix)]
    #[test]
    fn hook_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        git_init(dir.path()).unwrap();
        install_pre_merge_commit_hook(dir.path()).unwrap();
        let hook_path = dir
            .path()
            .join(".git")
            .join("hooks")
            .join("pre-merge-commit");
        let mode = std::fs::metadata(&hook_path).unwrap().permissions().mode();
        assert_ne!(
            mode & 0o111,
            0,
            "hook must be executable (mode & 0o111 != 0)"
        );
    }
}
