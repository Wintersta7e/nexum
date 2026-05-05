//! Git shell-out helpers for the events.yml history walker.
//!
//! All shell-outs use the env-clean / non-interactive pattern from the init
//! signing wrapper to avoid inheriting user state (`GIT_TERMINAL_PROMPT=0`,
//! `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`).

use std::path::Path;
use std::process::Command;

use crate::trust::events::TrustError;

/// Build a `git` command rooted in `notebook_git` with environment scrubbed
/// of inherited user state. Centralizes the env-clean policy so every helper
/// in this module shells out the same way.
fn git(notebook_git: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(notebook_git)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    cmd
}

/// Build a `TrustError::Io` mapper for shell-out failures, attributing the
/// error to the notebook path the helper is rooted in.
fn io_err(notebook_git: &Path) -> impl FnOnce(std::io::Error) -> TrustError + '_ {
    move |source| TrustError::Io {
        path: notebook_git.display().to_string(),
        source,
    }
}

/// Returns the list of commit SHAs that touched `.trust/events.yml`, oldest
/// first (topological order on a linear chain — the materializer requires a
/// linear history).
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if the underlying `git log` exits non-zero.
pub fn topo_walk_events_yml(notebook_git: &Path) -> Result<Vec<String>, TrustError> {
    let out = git(notebook_git)
        .args(["log", "--reverse", "--format=%H", "--", ".trust/events.yml"])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Returns true if any merge commit has touched `.trust/events.yml`.
///
/// The materializer requires a linear history on `.trust/events.yml` and
/// refuses to rebuild when this returns `true`.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if the underlying `git log --merges` exits
/// non-zero.
pub fn has_merges_on_events_yml(notebook_git: &Path) -> Result<bool, TrustError> {
    let out = git(notebook_git)
        .args(["log", "--merges", "--format=%H", "--", ".trust/events.yml"])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(!String::from_utf8_lossy(&out.stdout).trim().is_empty())
}

/// Reads the full blob contents of `.trust/events.yml` at a given commit.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if `git show` exits non-zero (e.g., the blob is
/// missing at that commit).
pub fn git_show_blob(notebook_git: &Path, commit_sha: &str) -> Result<String, TrustError> {
    let out = git(notebook_git)
        .args(["show", &format!("{commit_sha}:.trust/events.yml")])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Returns the SSH fingerprint that signed `commit_sha`, or `None` if the
/// commit is unsigned. Uses `git log -1 --format=%GF`.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if `git log` exits non-zero.
pub fn git_signer_fingerprint(
    notebook_git: &Path,
    commit_sha: &str,
) -> Result<Option<String>, TrustError> {
    let out = git(notebook_git)
        .args(["log", "-1", "--format=%GF", commit_sha])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let fp = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok(if fp.is_empty() { None } else { Some(fp) })
}

/// Returns the SHA of `revspec` (e.g., `HEAD`, `HEAD:.trust/events.yml`).
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if `git rev-parse` exits non-zero.
pub fn git_rev_parse(notebook_git: &Path, revspec: &str) -> Result<String, TrustError> {
    let out = git(notebook_git)
        .args(["rev-parse", revspec])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
