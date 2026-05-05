//! Git shell-out helpers for the events.yml history walker.
//!
//! All shell-outs use the env-clean / non-interactive pattern from the init
//! signing wrapper to avoid inheriting user state (`GIT_TERMINAL_PROMPT=0`,
//! `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`).

use std::path::Path;
use std::process::Command;

use crate::trust::events::TrustError;

/// One commit on the `.trust/events.yml` topology, with its SSH signer
/// fingerprint pre-extracted via `--format=%H%x00%GF` so the materializer
/// does not have to shell out per-commit to read `%GF`.
pub(crate) struct TopoCommit {
    pub sha: String,
    pub signer: Option<String>,
}

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

/// Returns the commits that touched `.trust/events.yml`, oldest first
/// (topological order on a linear chain — the materializer requires a linear
/// history). Each entry carries its own SSH signer fingerprint, extracted in
/// the same `git log` so the materializer doesn't pay a per-commit shell-out
/// to read `%GF`.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if the underlying `git log` exits non-zero.
pub(crate) fn topo_walk_events_yml(notebook_git: &Path) -> Result<Vec<TopoCommit>, TrustError> {
    // `%H%x00%GF`: the commit SHA, a NUL byte, the signer fingerprint (empty
    // when unsigned). NUL is collision-safe — it cannot appear inside either
    // field — so a simple `splitn(2, '\0')` recovers both.
    let out = git(notebook_git)
        .args([
            "log",
            "--reverse",
            "--format=%H%x00%GF",
            "--",
            ".trust/events.yml",
        ])
        .output()
        .map_err(io_err(notebook_git))?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let commits = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let mut parts = line.splitn(2, '\0');
            let sha = parts.next().unwrap_or("").to_owned();
            let signer = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            TopoCommit { sha, signer }
        })
        .collect();
    Ok(commits)
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
///
/// Adds `--full-history` to defeat git's default history simplification —
/// otherwise merge commits where the merge result's blob equals one parent's
/// blob can be silently dropped from `git log -- <path>`, hiding a real
/// linear-history violation.
pub(crate) fn has_merges_on_events_yml(notebook_git: &Path) -> Result<bool, TrustError> {
    let out = git(notebook_git)
        .args([
            "log",
            "--merges",
            "--full-history",
            "--format=%H",
            "--",
            ".trust/events.yml",
        ])
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
pub(crate) fn git_show_blob(notebook_git: &Path, commit_sha: &str) -> Result<String, TrustError> {
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
/// commit is unsigned. Uses `git log -1 --format=%GF`. Retained for one-off
/// lookups; the bulk path goes through [`topo_walk_events_yml`] which folds
/// `%GF` into the same shell-out as the SHA list.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if `git log` exits non-zero.
#[allow(dead_code)]
pub(crate) fn git_signer_fingerprint(
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

/// Resolve one or more revspecs in a single `git rev-parse` invocation.
/// `git rev-parse` accepts multiple arguments and emits one SHA per line in
/// the same order — folding `HEAD` and `HEAD:.trust/events.yml` into one
/// shell-out halves the per-call overhead for sentinel checks.
///
/// # Errors
///
/// Returns `TrustError::Io` if `git` cannot be invoked, or
/// `TrustError::GitCommand` if `git rev-parse` exits non-zero (e.g., a
/// revspec doesn't resolve).
pub(crate) fn git_rev_parse(
    notebook_git: &Path,
    revspecs: &[&str],
) -> Result<Vec<String>, TrustError> {
    let mut cmd = git(notebook_git);
    cmd.arg("rev-parse");
    for r in revspecs {
        cmd.arg(r);
    }
    let out = cmd.output().map_err(io_err(notebook_git))?;
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
