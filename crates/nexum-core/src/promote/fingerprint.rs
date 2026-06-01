//! Git-subprocess helpers for commit-correlation and evidence assembly.
//!
//! All git calls reuse the env-scrubbed `crate::trust::git_history::git`
//! builder so no user git config leaks into the queries.

use std::path::Path;

use crate::api::ApiError;
use crate::trust::git_history::git;

/// True iff `sha` peels to a commit object in `repo`.
pub(crate) fn commit_exists(repo: &Path, sha: &str) -> bool {
    git(repo)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("{sha}^{{commit}}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Resolve the repo's default branch ref for reachability checks. Tries
/// origin/HEAD, then the current branch, then probes main/master.
pub(crate) fn resolve_default_branch(repo: &Path) -> Result<String, ApiError> {
    // 1. origin/HEAD symref → "origin/main"
    if let Ok(o) = git(repo)
        .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .output()
        && o.status.success()
    {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    // 2. current branch (abbrev-ref HEAD), reject detached "HEAD"
    if let Ok(o) = git(repo)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        && o.status.success()
    {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        if !s.is_empty() && s != "HEAD" {
            return Ok(s);
        }
    }
    // 3. probe main, then master
    for cand in ["main", "master"] {
        if git(repo)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(cand)
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return Ok(cand.to_owned());
        }
    }
    Err(ApiError::RepoNoDefaultBranch {
        repo: repo.to_owned(),
    })
}

/// True iff `sha` is an ancestor of (reachable from) `branch`. `merge-base
/// --is-ancestor` exits 0 (yes) / 1 (no); any other exit is a real error.
pub(crate) fn is_reachable(repo: &Path, sha: &str, branch: &str) -> Result<bool, ApiError> {
    let status = git(repo)
        .args(["merge-base", "--is-ancestor", sha, branch])
        .status()
        .map_err(|e| ApiError::Other {
            message: format!("git merge-base: {e}"),
        })?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(ApiError::Other {
            message: format!("git merge-base failed for {sha}..{branch}"),
        }),
    }
}

/// Commit timestamp and message extracted from a single git invocation.
pub(crate) struct CommitMeta {
    pub commit_time: chrono::DateTime<chrono::Utc>,
    pub message: String,
    /// sha256 of the normalized commit message (trailing whitespace stripped,
    /// `\r\n` → `\n`).
    pub message_hash: String,
}

/// Read commit time + message via one NUL-delimited `git show`.
pub(crate) fn commit_metadata(repo: &Path, sha: &str) -> Result<CommitMeta, ApiError> {
    let out = git(repo)
        .args(["show", "-s", "--format=%cI%x00%B", sha])
        .output()
        .map_err(|e| ApiError::Other {
            message: format!("git show: {e}"),
        })?;
    if !out.status.success() {
        return Err(ApiError::CommitNotFound {
            sha: sha.to_owned(),
            repo: repo.to_owned(),
        });
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let mut parts = raw.splitn(2, '\0');
    let ctime = parts.next().unwrap_or("").trim();
    let message = parts.next().unwrap_or("").to_owned();
    let commit_time = chrono::DateTime::parse_from_rfc3339(ctime)
        .map_err(|e| ApiError::Other {
            message: format!("commit time parse: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let normalized = message.trim_end().replace("\r\n", "\n");
    Ok(CommitMeta {
        commit_time,
        message_hash: crate::records::hash::sha256_hex(normalized.as_bytes()),
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Build a throwaway git repo in `dir` with two commits on `main`.
    /// Returns `(sha1, sha2)` — sha1 is the parent, sha2 is HEAD.
    fn init_repo(dir: &std::path::Path) -> (String, String) {
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(dir)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(args)
                .status()
                .expect("git available");
            assert!(status.success(), "git {args:?} failed");
        };

        run(&["init", "-b", "main"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);

        // First commit
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        run(&["add", "a.txt"]);
        run(&["commit", "--no-gpg-sign", "-m", "first commit"]);

        let sha1 = sha_of(dir, "HEAD");

        // Second commit
        std::fs::write(dir.join("b.txt"), "world").unwrap();
        run(&["add", "b.txt"]);
        run(&["commit", "--no-gpg-sign", "-m", "second commit"]);

        let sha2 = sha_of(dir, "HEAD");

        (sha1, sha2)
    }

    fn sha_of(dir: &std::path::Path, rev: &str) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(["rev-parse", rev])
            .output()
            .expect("git rev-parse");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn commit_exists_true_for_real_sha() {
        let dir = tempfile::tempdir().unwrap();
        let (_, sha) = init_repo(dir.path());
        assert!(commit_exists(dir.path(), &sha));
    }

    #[test]
    fn commit_exists_false_for_bogus_sha() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        assert!(!commit_exists(
            dir.path(),
            "0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn resolve_default_branch_returns_main() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let branch = resolve_default_branch(dir.path()).unwrap();
        assert_eq!(branch, "main");
    }

    #[test]
    fn is_reachable_true_for_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let (sha1, _sha2) = init_repo(dir.path());
        // sha1 is parent of HEAD — it is reachable from "main"
        let result = is_reachable(dir.path(), &sha1, "main").unwrap();
        assert!(result);
    }

    #[test]
    fn is_reachable_false_for_unrelated_sha() {
        let dir = tempfile::tempdir().unwrap();
        let (_sha1, sha2) = init_repo(dir.path());
        // sha2 IS HEAD — is HEAD an ancestor of its own parent? No.
        let sha1_again = sha_of(dir.path(), "HEAD~1");
        // sha2 is not an ancestor of sha1 (sha1 is the parent, so sha2 is not
        // reachable FROM sha1 when we look at sha1 as the tip).
        let result = is_reachable(dir.path(), &sha2, &sha1_again).unwrap();
        assert!(!result);
    }

    #[test]
    fn commit_metadata_returns_correct_message_and_stable_hash() {
        let dir = tempfile::tempdir().unwrap();
        let (_sha1, sha2) = init_repo(dir.path());
        let meta = commit_metadata(dir.path(), &sha2).unwrap();
        assert_eq!(meta.message.trim(), "second commit");
        // hash is 64 lowercase hex chars
        assert_eq!(meta.message_hash.len(), 64);
        assert!(meta
            .message_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Stable: same sha produces the same hash
        let meta2 = commit_metadata(dir.path(), &sha2).unwrap();
        assert_eq!(meta.message_hash, meta2.message_hash);
    }
}
