//! Audit-log walker — reads notebook.git history newest-first and classifies
//! each commit by its message prefix.

use crate::{api::ApiError, paths::Paths};

/// One entry in the notebook audit log.
#[derive(Debug)]
pub struct AuditEntry {
    /// Full commit SHA.
    pub commit_sha: String,
    /// Lifecycle kind derived from the subject prefix before `:`.
    /// One of `promote`, `reject`, `stale`, `extract`, `trust`, `init`,
    /// `project`, or `other`.
    pub kind: String,
    /// Full commit subject (first line of the commit message).
    pub subject: String,
    /// SSH signing-key fingerprint (`%GF`). `None` when the commit is unsigned.
    pub signer_fingerprint: Option<String>,
    /// ISO-8601 committer timestamp (`%cI`).
    pub committed_at: String,
}

/// Walk `notebook.git` history newest-first, classifying each commit by its
/// message prefix.
///
/// Uses `git log --format=%H%x00%GF%x00%cI%x00%s` (four NUL-delimited fields
/// per line). When `limit` is `Some(n)`, passes `-n<n>` to cap the count.
///
/// # Errors
///
/// Returns `ApiError::Other` if `git` cannot be invoked or exits non-zero.
pub(crate) fn audit_log(paths: &Paths, limit: Option<usize>) -> Result<Vec<AuditEntry>, ApiError> {
    let mut args = vec![
        "log".to_owned(),
        "--format=%H%x00%GF%x00%cI%x00%s".to_owned(),
    ];
    if let Some(n) = limit {
        args.push(format!("-n{n}"));
    }
    let out = crate::trust::git_history::git(&paths.notebook_git)
        .args(&args)
        .output()
        .map_err(|e| ApiError::Other {
            message: format!("git log: {e}"),
        })?;
    if !out.status.success() {
        return Err(ApiError::Other {
            message: format!(
                "git log exited non-zero: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let entries = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            // splitn(4, '\0') -> [sha, signer_fp, committed_at, subject]
            let mut parts = line.splitn(4, '\0');
            let commit_sha = parts.next().unwrap_or("").to_owned();
            let signer_fingerprint = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let committed_at = parts.next().unwrap_or("").to_owned();
            let subject = parts.next().unwrap_or("").to_owned();
            let kind = classify_kind(&subject);
            AuditEntry {
                commit_sha,
                kind,
                subject,
                signer_fingerprint,
                committed_at,
            }
        })
        .collect();
    Ok(entries)
}

/// Derive a lifecycle kind from the commit subject prefix before `:`.
fn classify_kind(subject: &str) -> String {
    let prefix = subject.split_once(':').map_or("", |(p, _)| p.trim());
    match prefix {
        "promote" | "reject" | "stale" | "extract" | "trust" | "init" | "project" => {
            prefix.to_owned()
        }
        _ => "other".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    /// Create a minimal git repo under `path` with a known identity.
    fn git_init(path: &Path) {
        let run = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(path)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        run(&["init"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "test"]);
    }

    /// Add an unsigned empty commit with the given message to `path`.
    fn add_commit(path: &Path, message: &str) {
        let status = std::process::Command::new("git")
            .args(["commit", "--allow-empty", "-m", message])
            .current_dir(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .unwrap();
        assert!(status.success(), "git commit -m {message:?} failed");
    }

    /// Build a temp `Paths` whose `notebook_git` points at a real git repo
    /// pre-seeded with commits for the given subjects (oldest-first in the
    /// slice, so the first slice element is the oldest commit).
    fn make_notebook(subjects: &[&str]) -> (TempDir, Paths) {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        std::fs::create_dir_all(&nb).unwrap();
        git_init(&nb);
        for msg in subjects {
            add_commit(&nb, msg);
        }
        let paths = Paths::with_home(dir.path().to_owned());
        (dir, paths)
    }

    // ── classify_kind ──────────────────────────────────────────────────────────

    #[test]
    fn classify_known_prefixes() {
        for prefix in &[
            "promote", "reject", "stale", "extract", "trust", "init", "project",
        ] {
            let subject = format!("{prefix}: some detail");
            assert_eq!(classify_kind(&subject), *prefix, "prefix={prefix}");
        }
    }

    #[test]
    fn classify_unknown_prefix_is_other() {
        assert_eq!(classify_kind("chore: cleanup"), "other");
        assert_eq!(classify_kind("no colon at all"), "other");
        assert_eq!(classify_kind(""), "other");
    }

    // ── audit_log ──────────────────────────────────────────────────────────────

    #[test]
    fn audit_log_newest_first() {
        let (_dir, paths) = make_notebook(&["extract: oldest", "promote: middle", "trust: newest"]);
        let entries = audit_log(&paths, None).unwrap();
        assert_eq!(entries.len(), 3);
        // Newest-first: trust, promote, extract.
        assert_eq!(entries[0].kind, "trust");
        assert_eq!(entries[1].kind, "promote");
        assert_eq!(entries[2].kind, "extract");
    }

    #[test]
    fn audit_log_kind_classification() {
        let subjects = [
            "promote: a -> b via abc",
            "reject: dropped",
            "stale: timed out",
            "trust: rotate",
            "init: bootstrap",
            "project: add repo",
            "chore: unrelated",
        ];
        let (_dir, paths) = make_notebook(&subjects);
        let entries = audit_log(&paths, None).unwrap();
        // Reversed (newest-first).
        let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["other", "project", "init", "trust", "stale", "reject", "promote"]
        );
    }

    #[test]
    fn audit_log_empty_gf_maps_to_none() {
        // Plain (unsigned) commits produce an empty %GF field.
        let (_dir, paths) = make_notebook(&["promote: unsigned"]);
        let entries = audit_log(&paths, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].signer_fingerprint.is_none(),
            "unsigned commit must have signer_fingerprint=None"
        );
    }

    #[test]
    fn audit_log_limit_caps_count() {
        let (_dir, paths) = make_notebook(&[
            "promote: first",
            "reject: second",
            "stale: third",
            "trust: fourth",
        ]);
        let entries = audit_log(&paths, Some(2)).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "limit=2 must return at most 2 entries, got {}",
            entries.len()
        );
        // Still newest-first.
        assert_eq!(entries[0].kind, "trust");
        assert_eq!(entries[1].kind, "stale");
    }

    #[test]
    fn audit_log_limit_larger_than_history_returns_all() {
        let (_dir, paths) = make_notebook(&["init: bootstrap", "project: add"]);
        let entries = audit_log(&paths, Some(100)).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
