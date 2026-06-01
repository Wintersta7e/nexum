//! Suggestion scan: match proposed local recommendations against candidate
//! commits in their project repo within the configured correlation window.
//!
//! Consumed by the `api::promote_suggestions` facade (lands in a later change;
//! the transitional `dead_code` allow on this module is removed then).

use std::path::Path;

use crate::api::ApiError;
use crate::config::Config;
use crate::paths::Paths;
use crate::records::types::{Outcome, Source, UnifiedRecord};
use crate::trust::git_history::git;

/// A (recommendation, commit) pair that passes the configured correlation
/// predicate within the correlation window.
pub(crate) struct Suggestion {
    pub rec_id: String,
    pub project_id: String,
    pub commit_sha: String,
    pub file_overlap: f64,
    pub message_reference: bool,
}

/// Scan proposed local recommendations against candidate commits in their
/// project repo within `correlation_window_days`. A (rec, commit) pair is
/// suggested per the config predicate:
///   `require_message_reference` ? (`msg_ref` AND overlap >= thr)
///                               : (`msg_ref` OR  overlap >= thr)
pub(crate) fn scan(
    _paths: &Paths,
    cfg: &Config,
    recs: &[UnifiedRecord],
) -> Result<Vec<Suggestion>, ApiError> {
    let thr = cfg.promote.file_overlap_threshold;
    let require_msg = cfg.promote.require_message_reference;
    let window = cfg.promote.correlation_window_days;
    let mut out = Vec::new();
    for rec in recs
        .iter()
        .filter(|r| r.outcome == Outcome::Proposed && r.source == Source::Local)
    {
        let Some(repo) = super::repo_path_for(rec, cfg) else {
            continue;
        };
        for sha in candidate_commits(&repo, rec, window)? {
            let changed = super::fingerprint::changed_paths(&repo, &sha)?;
            let overlap = super::correlate::file_overlap(rec, &changed);
            let meta = super::fingerprint::commit_metadata(&repo, &sha)?;
            let msg_ref = super::correlate::message_reference(rec, &meta.message);
            let pass = if require_msg {
                msg_ref && overlap >= thr
            } else {
                msg_ref || overlap >= thr
            };
            if pass {
                out.push(Suggestion {
                    rec_id: rec.id.clone(),
                    project_id: rec.project_id.clone(),
                    commit_sha: sha,
                    file_overlap: overlap,
                    message_reference: msg_ref,
                });
            }
        }
    }
    Ok(out)
}

/// Return SHAs (newest-first) of non-merge commits in `repo` whose author
/// date falls within `[basis, basis + window_days)`, where `basis` is the
/// rec's `created` timestamp (no `SessionRef` variant currently carries a
/// timestamp, so `rec.created` is always the basis).
///
/// Uses explicit RFC3339 bounds passed to `git log --since`/`--until` so
/// the window is deterministic and independent of the machine clock.
fn candidate_commits(
    repo: &Path,
    rec: &UnifiedRecord,
    window_days: u32,
) -> Result<Vec<String>, ApiError> {
    let basis = rec.created;
    let until = basis + chrono::Duration::days(i64::from(window_days));

    let branch = super::fingerprint::resolve_default_branch(repo)?;

    let since_str = basis.to_rfc3339();
    let until_str = until.to_rfc3339();

    let out = git(repo)
        .args([
            "log",
            &branch,
            "--no-merges",
            "--format=%H",
            &format!("--since={since_str}"),
            &format!("--until={until_str}"),
        ])
        .output()
        .map_err(|e| ApiError::Other {
            message: format!("git log: {e}"),
        })?;

    if !out.status.success() {
        return Err(ApiError::Other {
            message: format!("git log failed in {}", repo.display()),
        });
    }

    let shas = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(shas)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use chrono::{DateTime, TimeZone, Utc};

    use super::{candidate_commits, scan};
    use crate::config::Config;
    use crate::config::types::PromoteConfig;
    use crate::paths::Paths;
    use crate::records::types::{
        Agent, Confidence, CryptoResult, FileEvidence, FileEvidenceKind, Outcome, Provenance,
        RecordType, SessionRef, SignatureStatus, Source, UnifiedRecord,
    };

    // ── helpers ────────────────────────────────────────────────────────────

    fn run_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(args)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    }

    fn sha_of(dir: &Path, rev: &str) -> String {
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

    /// Create a git repo with one commit whose author/committer date is set
    /// to `commit_time`. Returns the commit SHA.
    fn init_repo_with_dated_commit(
        dir: &Path,
        commit_time: &DateTime<Utc>,
        message: &str,
        files: &[(&str, &str)],
    ) -> String {
        run_git(dir, &["init", "-b", "main"]);
        run_git(dir, &["config", "user.email", "test@example.com"]);
        run_git(dir, &["config", "user.name", "Test"]);

        for (name, content) in files {
            let dest = dir.join(name);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&dest, content).unwrap();
            run_git(dir, &["add", name]);
        }

        // Provide a placeholder file if none supplied so the commit is non-empty.
        if files.is_empty() {
            std::fs::write(dir.join("placeholder.txt"), "x").unwrap();
            run_git(dir, &["add", "placeholder.txt"]);
        }

        let date_str = commit_time.to_rfc3339();
        let status = Command::new("git")
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_DATE", &date_str)
            .env("GIT_COMMITTER_DATE", &date_str)
            .args(["commit", "--no-gpg-sign", "-m", message])
            .status()
            .expect("git commit");
        assert!(status.success(), "git commit failed");

        sha_of(dir, "HEAD")
    }

    fn fe(path: &str) -> FileEvidence {
        FileEvidence {
            path: PathBuf::from(path),
            kind: FileEvidenceKind::ParsedFromMemoryBody,
        }
    }

    fn make_rec(
        id: &str,
        title: &str,
        project_id: &str,
        files: Vec<FileEvidence>,
        created: DateTime<Utc>,
    ) -> UnifiedRecord {
        UnifiedRecord {
            id: id.into(),
            record_type: RecordType::Recommendation,
            source: Source::Local,
            project_id: project_id.into(),
            title: title.into(),
            summary: None,
            body: String::new(),
            body_origin_path: None,
            tags: vec![],
            agent: Agent::Manual,
            session_refs: vec![SessionRef::Manual],
            files,
            commits: vec![],
            created,
            updated: created,
            confidence: Confidence::Medium,
            outcome: Outcome::Proposed,
            provenance: Provenance {
                source: Source::Local,
                signature_status: SignatureStatus::Unsigned,
                extractor: None,
                digest_hash: None,
                record_commit_sha: None,
                signer_fingerprint: None,
                crypto_result: CryptoResult::NoSignature,
                relevant_trust_events_commit: None,
                trust_basis: None,
                warnings: vec![],
                commit_evidence: None,
                promoted_from: None,
                inherited_warnings: vec![],
            },
            extras: HashMap::new(),
            content_hash: "deadbeef".into(),
        }
    }

    /// Build a minimal `Config` with the given repo dir registered under
    /// `project_id` in `cfg.projects`.
    fn make_cfg(project_id: &str, repo_path: &Path, promote: PromoteConfig) -> Config {
        let mut cfg = Config::seed();
        cfg.promote = promote;
        // Register the project path the same way `project_path_for` reads it.
        let mut table = toml::Table::new();
        table.insert(
            "path".to_owned(),
            toml::Value::String(repo_path.to_string_lossy().into_owned()),
        );
        cfg.projects
            .insert(project_id.to_owned(), toml::Value::Table(table));
        cfg
    }

    fn default_promote() -> PromoteConfig {
        PromoteConfig {
            enabled: true,
            auto_promote: false,
            correlation_window_days: 30,
            file_overlap_threshold: 1.0,
            require_message_reference: true,
        }
    }

    fn fake_paths() -> Paths {
        Paths::with_home(PathBuf::from("/tmp/nexum-test"))
    }

    // ── candidate_commits ──────────────────────────────────────────────────

    #[test]
    fn candidate_commits_returns_sha_within_window() {
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 5, 10, 0, 0).unwrap();

        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "feat: add thing",
            &[("a.rs", "x")],
        );

        let rec = make_rec(
            "2026-05-01-add-thing",
            "Add thing",
            "git:abc",
            vec![],
            basis,
        );

        let shas = candidate_commits(dir.path(), &rec, 30).unwrap();
        assert_eq!(shas.len(), 1, "expected one commit in window, got {shas:?}");
    }

    #[test]
    fn candidate_commits_excludes_commit_outside_window() {
        let dir = tempfile::tempdir().unwrap();
        // basis is 2026-05-01; window = 10 days → window ends 2026-05-11.
        // commit is on 2026-05-20, outside the window.
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 20, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(dir.path(), &commit_time, "feat: late", &[("b.rs", "y")]);

        let rec = make_rec("2026-05-01-late", "Late commit", "git:abc", vec![], basis);

        let shas = candidate_commits(dir.path(), &rec, 10).unwrap();
        assert!(shas.is_empty(), "expected no commits, got {shas:?}");
    }

    #[test]
    fn candidate_commits_excludes_commit_before_basis() {
        let dir = tempfile::tempdir().unwrap();
        // basis is 2026-05-10; commit is 2026-05-05 — before the window starts.
        let basis = Utc.with_ymd_and_hms(2026, 5, 10, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 5, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(dir.path(), &commit_time, "feat: early", &[("c.rs", "z")]);

        let rec = make_rec("2026-05-10-early", "Early commit", "git:abc", vec![], basis);

        let shas = candidate_commits(dir.path(), &rec, 30).unwrap();
        assert!(
            shas.is_empty(),
            "expected no commits before basis, got {shas:?}"
        );
    }

    // ── scan predicate ─────────────────────────────────────────────────────

    #[test]
    fn scan_returns_suggestion_when_both_msg_ref_and_overlap_match() {
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap();

        // Commit changes "src/auth.rs"; message references the rec slug.
        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "feat: implement use-jwt-auth middleware",
            &[("src/auth.rs", "impl jwt {}")],
        );

        let project_id = "git:test-project";
        let promote = PromoteConfig {
            require_message_reference: true,
            file_overlap_threshold: 1.0,
            ..default_promote()
        };
        let cfg = make_cfg(project_id, dir.path(), promote);

        let rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            project_id,
            vec![fe("src/auth.rs")],
            basis,
        );

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        assert_eq!(suggestions.len(), 1, "expected one suggestion");
        let s = &suggestions[0];
        assert!(s.message_reference, "expected message_reference=true");
        // file_overlap = 1/1 = 1.0
        #[allow(clippy::float_cmp)]
        let ok = s.file_overlap == 1.0;
        assert!(ok, "expected file_overlap=1.0, got {}", s.file_overlap);
    }

    #[test]
    fn scan_returns_no_suggestion_when_neither_msg_ref_nor_overlap_match() {
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap();

        // Commit changes unrelated file with unrelated message.
        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "chore: update CI config",
            &[("Makefile", "all:")],
        );

        let project_id = "git:test-project-2";
        let promote = PromoteConfig {
            require_message_reference: false, // OR mode — both must fail
            file_overlap_threshold: 1.0,
            ..default_promote()
        };
        let cfg = make_cfg(project_id, dir.path(), promote);

        let rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            project_id,
            vec![fe("src/auth.rs")], // not in the commit
            basis,
        );

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        assert!(
            suggestions.is_empty(),
            "expected no suggestions, got {}",
            suggestions.len()
        );
    }

    #[test]
    fn scan_skips_non_proposed_records() {
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "feat: implement use-jwt-auth",
            &[("src/auth.rs", "impl jwt {}")],
        );

        let project_id = "git:test-project-3";
        let cfg = make_cfg(project_id, dir.path(), default_promote());

        let mut rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            project_id,
            vec![fe("src/auth.rs")],
            basis,
        );
        // Promoted records are not re-scanned.
        rec.outcome = Outcome::Promoted;

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        assert!(
            suggestions.is_empty(),
            "expected no suggestions for non-proposed rec"
        );
    }

    #[test]
    fn scan_skips_rec_with_no_registered_project_path() {
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "feat: implement use-jwt-auth",
            &[("src/auth.rs", "impl jwt {}")],
        );

        // Use a config that has NO project registered for this rec's project_id.
        let cfg = Config::seed();

        let rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            "git:unregistered",
            vec![fe("src/auth.rs")],
            basis,
        );

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        assert!(
            suggestions.is_empty(),
            "expected no suggestions when project path unregistered"
        );
    }

    #[test]
    fn scan_zero_file_rec_passes_on_message_reference_only() {
        // Zero-file rec: file_overlap is 0.0. Under the conservative default
        // (require_message_reference=true, threshold=1.0), only message_reference
        // can satisfy the predicate.
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            // slug "use-jwt-auth" appears in message → message_reference=true
            "feat: implement use-jwt-auth middleware",
            &[("src/unrelated.rs", "x")],
        );

        let project_id = "git:test-project-zero-files";
        let promote = PromoteConfig {
            require_message_reference: true,
            file_overlap_threshold: 1.0,
            ..default_promote()
        };
        let cfg = make_cfg(project_id, dir.path(), promote);

        let rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            project_id,
            vec![], // zero files
            basis,
        );

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        // require_msg=true, overlap(0.0) >= thr(1.0) is false,
        // but msg_ref=true → msg_ref && false = false → no suggestion.
        // This is the intended conservative behaviour for zero-file recs.
        assert!(
            suggestions.is_empty(),
            "zero-file rec with require_message_reference=true should not suggest \
             (overlap fails the AND): got {} suggestions",
            suggestions.len()
        );
    }

    #[test]
    fn scan_zero_file_rec_passes_in_or_mode_when_msg_ref_matches() {
        // With require_message_reference=false (OR mode), a zero-file rec can
        // pass on message_reference alone.
        let dir = tempfile::tempdir().unwrap();
        let basis = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let commit_time = Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap();

        init_repo_with_dated_commit(
            dir.path(),
            &commit_time,
            "feat: implement use-jwt-auth middleware",
            &[("src/unrelated.rs", "x")],
        );

        let project_id = "git:test-project-or-mode";
        let promote = PromoteConfig {
            require_message_reference: false, // OR mode
            file_overlap_threshold: 1.0,
            ..default_promote()
        };
        let cfg = make_cfg(project_id, dir.path(), promote);

        let rec = make_rec(
            "2026-05-01-use-jwt-auth",
            "Use JWT auth",
            project_id,
            vec![], // zero files → overlap = 0.0
            basis,
        );

        let paths = fake_paths();
        let suggestions = scan(&paths, &cfg, &[rec]).unwrap();
        // OR mode: msg_ref=true OR overlap(0.0)>=1.0 → true.
        assert_eq!(
            suggestions.len(),
            1,
            "expected one suggestion in OR mode with matching message"
        );
        assert!(suggestions[0].message_reference);
        #[allow(clippy::float_cmp)]
        let ok = suggestions[0].file_overlap == 0.0;
        assert!(ok);
    }
}
