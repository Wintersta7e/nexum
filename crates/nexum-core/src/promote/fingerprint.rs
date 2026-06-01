//! Git-subprocess helpers for commit-correlation and evidence assembly.
//!
//! All git calls reuse the env-scrubbed `crate::trust::git_history::git`
//! builder so no user git config leaks into the queries.

use std::fmt::Write as _;
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

/// Strict + loose tree fingerprints over the full tree at `sha`.
///
/// `strict` = sha256 over `"{mode}\0{blob_sha}\0{path}\n"` lines sorted by
/// path; `loose` = sha256 over `"{mode}\0{path}\n"` lines (content-agnostic,
/// so a rebase that rewrites blob SHAs but keeps content+structure still
/// matches loosely).
pub(crate) fn tree_fingerprint(
    repo: &Path,
    sha: &str,
) -> Result<crate::records::types::TreeFingerprint, ApiError> {
    let out = git(repo)
        .args(["ls-tree", "-r", "-z", "--full-tree", sha])
        .output()
        .map_err(|e| ApiError::Other {
            message: format!("git ls-tree: {e}"),
        })?;
    if !out.status.success() {
        return Err(ApiError::CommitNotFound {
            sha: sha.to_owned(),
            repo: repo.to_owned(),
        });
    }
    // Each NUL-terminated record: "<mode> <type> <objsha>\t<path>"
    let text = String::from_utf8_lossy(&out.stdout);
    let mut entries: Vec<(String, String, String)> = Vec::new(); // (path, mode, blob_sha)
    for rec in text.split('\0').filter(|s| !s.is_empty()) {
        let (meta, path) = rec.split_once('\t').ok_or_else(|| ApiError::Other {
            message: "malformed ls-tree record".into(),
        })?;
        let mut it = meta.split_whitespace(); // mode, type, objsha
        let mode = it.next().unwrap_or("").to_owned();
        let _ty = it.next().unwrap_or("");
        let blob = it.next().unwrap_or("").to_owned();
        entries.push((path.to_owned(), mode, blob));
    }
    entries.sort();
    let mut strict_buf = String::new();
    let mut loose_buf = String::new();
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for (path, mode, blob) in &entries {
        let _ = writeln!(strict_buf, "{mode}\0{blob}\0{path}");
        let _ = writeln!(loose_buf, "{mode}\0{path}");
        paths.push(std::path::PathBuf::from(path));
    }
    Ok(crate::records::types::TreeFingerprint {
        strict: crate::records::hash::sha256_hex(strict_buf.as_bytes()),
        loose: crate::records::hash::sha256_hex(loose_buf.as_bytes()),
        file_paths: paths,
    })
}

/// Canonical project identity string for `repo`.
///
/// Prefers `git:<16-hex>` derived from the `origin` remote URL (stable across
/// reclones). Falls back to `root:<sha>` using the repo's root commit hash
/// (works for repos with no remote). Returns `"root:unknown"` only when git
/// is entirely unavailable.
pub(crate) fn repo_identity(repo: &Path) -> String {
    if let Ok(o) = git(repo).args(["remote", "get-url", "origin"]).output()
        && o.status.success()
    {
        let url = String::from_utf8_lossy(&o.stdout).trim().to_owned();
        if !url.is_empty() {
            let canon = crate::project::canon::canonicalize_git_url(&url);
            return crate::project::canon::git_url_hint(&canon);
        }
    }
    // Offline: identify by root commit hash.
    git(repo)
        .args(["rev-list", "--max-parents=0", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "root:unknown".into(),
            |o| {
                let root = String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                format!("root:{root}")
            },
        )
}

/// ONLINE: assemble fully-verified `CommitEvidence` for `sha` in `repo`.
///
/// Reads the repo for commit metadata and tree fingerprint. Always produces
/// `VerificationStatus::Verified`. The caller must have already confirmed
/// that the commit exists and is reachable.
pub(crate) fn build_commit_evidence(
    repo: &Path,
    sha: &str,
    branch: &str,
) -> Result<crate::records::types::CommitEvidence, ApiError> {
    use crate::records::types::{CommitEvidence, VerificationStatus};
    let meta = commit_metadata(repo, sha)?;
    Ok(CommitEvidence {
        repo_identity: repo_identity(repo),
        branch: branch.to_owned(),
        commit_sha: sha.to_owned(),
        commit_time: meta.commit_time,
        commit_message_hash: meta.message_hash,
        tree_changes_fingerprint: tree_fingerprint(repo, sha)?,
        verification_status: VerificationStatus::Verified,
    })
}

/// OFFLINE: record the commit claim without touching any repo.
///
/// Used by `--skip-fingerprint` when the project repo is unreachable. Produces
/// `VerificationStatus::Unknown` with an empty fingerprint. `commit_time` is
/// set to `now` (the real commit time is unknowable offline). A later
/// verify-promotions pass can confirm against the live repo.
pub(crate) fn build_commit_evidence_offline(
    sha: &str,
    branch: Option<&str>,
    repo_identity: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::records::types::CommitEvidence {
    use crate::records::types::{CommitEvidence, TreeFingerprint, VerificationStatus};
    CommitEvidence {
        repo_identity: repo_identity.to_owned(),
        branch: branch.unwrap_or("unknown").to_owned(),
        commit_sha: sha.to_owned(),
        commit_time: now,
        commit_message_hash: String::new(),
        tree_changes_fingerprint: TreeFingerprint {
            strict: String::new(),
            loose: String::new(),
            file_paths: Vec::new(),
        },
        verification_status: VerificationStatus::Unknown,
    }
}

/// Paths changed by `sha` (new path for renames). `-M` enables rename
/// detection; `--root` makes the first (parentless) commit report its adds.
pub(crate) fn changed_paths(repo: &Path, sha: &str) -> Result<Vec<std::path::PathBuf>, ApiError> {
    let out = git(repo)
        .args([
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            "-M",
            "--root",
            sha,
        ])
        .output()
        .map_err(|e| ApiError::Other {
            message: format!("git diff-tree: {e}"),
        })?;
    if !out.status.success() {
        return Err(ApiError::CommitNotFound {
            sha: sha.to_owned(),
            repo: repo.to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .collect())
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
        assert!(
            meta.message_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Stable: same sha produces the same hash
        let meta2 = commit_metadata(dir.path(), &sha2).unwrap();
        assert_eq!(meta.message_hash, meta2.message_hash);
    }

    // ---- tree_fingerprint ----

    #[test]
    fn tree_fingerprint_stable_hashes_and_strict_ne_loose() {
        let dir = tempfile::tempdir().unwrap();
        let (_sha1, sha2) = init_repo(dir.path());
        let fp = tree_fingerprint(dir.path(), &sha2).unwrap();

        // Both are 64-char lowercase hex
        assert_eq!(fp.strict.len(), 64);
        assert_eq!(fp.loose.len(), 64);
        assert!(
            fp.strict
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(
            fp.loose
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        // strict includes blob SHA so it differs from loose
        assert_ne!(
            fp.strict, fp.loose,
            "strict and loose must differ (strict encodes blob SHA)"
        );

        // file_paths contains exactly the two committed files
        let mut paths: Vec<String> = fp
            .file_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        paths.sort();
        assert_eq!(paths, ["a.txt", "b.txt"]);

        // Stable: re-running yields the same hashes
        let fp2 = tree_fingerprint(dir.path(), &sha2).unwrap();
        assert_eq!(fp.strict, fp2.strict);
        assert_eq!(fp.loose, fp2.loose);
    }

    #[test]
    fn tree_fingerprint_first_commit_has_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let (sha1, _sha2) = init_repo(dir.path());
        let fp = tree_fingerprint(dir.path(), &sha1).unwrap();
        let paths: Vec<String> = fp
            .file_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths, ["a.txt"]);
    }

    // ---- changed_paths ----

    #[test]
    fn changed_paths_second_commit_returns_added_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_sha1, sha2) = init_repo(dir.path());
        let changed = changed_paths(dir.path(), &sha2).unwrap();
        let names: Vec<String> = changed
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["b.txt"]);
    }

    #[test]
    fn changed_paths_first_commit_via_root_reports_adds() {
        let dir = tempfile::tempdir().unwrap();
        let (sha1, _sha2) = init_repo(dir.path());
        // --root makes the parentless first commit report its adds
        let changed = changed_paths(dir.path(), &sha1).unwrap();
        let names: Vec<String> = changed
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.txt"]);
    }

    // ---- repo_identity ----

    #[test]
    fn repo_identity_with_origin_starts_with_git() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(dir.path())
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(args)
                .status()
                .expect("git available");
            assert!(status.success(), "git {args:?} failed");
        };
        init_repo(dir.path());
        run(&[
            "remote",
            "add",
            "origin",
            "https://example.com/owner/repo.git",
        ]);
        let id = repo_identity(dir.path());
        assert!(id.starts_with("git:"), "expected git: prefix, got {id:?}");
        assert_eq!(id.len(), 4 + 16, "expected git:<16-hex>, got {id:?}");
    }

    #[test]
    fn repo_identity_without_origin_starts_with_root() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        // No remote added — must fall back to root-commit hash.
        let id = repo_identity(dir.path());
        assert!(id.starts_with("root:"), "expected root: prefix, got {id:?}");
    }

    // ---- build_commit_evidence ----

    #[test]
    fn build_commit_evidence_online_verified_with_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(dir.path())
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(args)
                .status()
                .expect("git available");
            assert!(status.success(), "git {args:?} failed");
        };
        let (_sha1, sha2) = init_repo(dir.path());
        run(&[
            "remote",
            "add",
            "origin",
            "https://example.com/owner/repo.git",
        ]);
        let ev = build_commit_evidence(dir.path(), &sha2, "main").unwrap();
        assert_eq!(
            ev.verification_status,
            crate::records::types::VerificationStatus::Verified
        );
        assert!(!ev.tree_changes_fingerprint.strict.is_empty());
        assert_eq!(ev.commit_sha, sha2);
        assert_eq!(ev.branch, "main");
        assert!(
            ev.repo_identity.starts_with("git:"),
            "repo_identity should be git:<hex> when origin is set"
        );
    }

    // ---- build_commit_evidence_offline ----

    #[test]
    fn build_commit_evidence_offline_unknown_empty_fingerprint() {
        // Must not require a real repo — bogus sha must not error.
        let now = chrono::DateTime::from_timestamp(0, 0).unwrap();
        let ev = build_commit_evidence_offline(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            None,
            "git:abcdef1234567890",
            now,
        );
        assert_eq!(
            ev.verification_status,
            crate::records::types::VerificationStatus::Unknown
        );
        assert!(ev.tree_changes_fingerprint.strict.is_empty());
        assert!(ev.tree_changes_fingerprint.loose.is_empty());
        assert!(ev.tree_changes_fingerprint.file_paths.is_empty());
        assert!(ev.commit_message_hash.is_empty());
        assert_eq!(ev.branch, "unknown");
        assert_eq!(ev.commit_time, now);
    }

    #[test]
    fn build_commit_evidence_offline_branch_used_when_provided() {
        let now = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let ev = build_commit_evidence_offline("aaaa", Some("feature-x"), "root:abc123", now);
        assert_eq!(ev.branch, "feature-x");
        assert_eq!(ev.repo_identity, "root:abc123");
    }

    #[test]
    fn changed_paths_rename_surfaces_under_new_path() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(dir.path())
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

        // First commit: create original.txt
        std::fs::write(dir.path().join("original.txt"), "content").unwrap();
        run(&["add", "original.txt"]);
        run(&["commit", "--no-gpg-sign", "-m", "initial"]);

        // Second commit: rename original.txt → renamed.txt
        run(&["mv", "original.txt", "renamed.txt"]);
        run(&["commit", "--no-gpg-sign", "-m", "rename file"]);

        let rename_sha = sha_of(dir.path(), "HEAD");
        let changed = changed_paths(dir.path(), &rename_sha).unwrap();
        let names: Vec<String> = changed
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        // -M reports the new path (renamed.txt), not the old one
        assert!(
            names.contains(&"renamed.txt".to_owned()),
            "expected renamed.txt in changed paths, got {names:?}"
        );
    }
}
