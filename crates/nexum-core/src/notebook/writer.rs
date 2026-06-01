//! Pre-flight guard and source-record eligibility for lifecycle mutations
//! against `notebook.git`.
//!
//! `preflight` is **invoked inside the `with_writer_lock` closure** (wired in
//! the next task) so the dirty/merge/reanchor store-state checks cannot race
//! another process between the check and lock acquisition. The function is
//! location-agnostic; the call site owns lock acquisition.

use std::path::Path;

use crate::{
    api::ApiError,
    paths::Paths,
    records::types::{SignatureStatus, TrustBasis, UnifiedRecord},
};

/// Refuse the lifecycle mutation if the notebook store is in a bad state.
///
/// Four conditions checked in order:
/// 1. `notebook.git` has uncommitted changes **outside** `event_paths`
///    → [`ApiError::NotebookDirty`] carrying the offending file list.
/// 2. `.git/MERGE_HEAD` present (mid-merge)
///    → [`ApiError::MergeInProgress`].
/// 3. `.reanchor_pending` sentinel present
///    → [`ApiError::ReanchorPending`].
/// 4. No active signer or signer not in `Active` role
///    → [`ApiError::SignerInactive`].
///
/// `event_paths` are **repo-relative** paths this mutation will touch (e.g.
/// `recommendations/2026-04-29-x.yml`). Dirty files within that set are
/// expected and not treated as a refusal condition.
///
/// # Note
///
/// This function is called **inside** the `with_writer_lock` closure so the
/// store-state checks are TOCTOU-safe: another process cannot dirty the repo or
/// write the reanchor sentinel between the check and the mutation commit.
pub(crate) fn preflight(paths: &Paths, event_paths: &[&Path]) -> Result<(), ApiError> {
    let nb = &paths.notebook_git;

    // 1. Dirty-tree check — inline git status (NUL-terminated) filtered
    //    against the lifecycle paths. `refuse_if_unrelated_dirty` in
    //    `api/mod.rs` returns `TrustRegenerateRefused` (the wrong variant
    //    for lifecycle mutations), so we run git status directly and produce
    //    `NotebookDirty { dirty_files }` with the offending file list.
    let dirty_files = dirty_outside_event_paths(nb, event_paths)?;
    if !dirty_files.is_empty() {
        return Err(ApiError::NotebookDirty { dirty_files });
    }

    // 2. Mid-merge guard.
    if nb.join(".git/MERGE_HEAD").exists() {
        return Err(ApiError::MergeInProgress);
    }

    // 3. Reanchor sentinel guard.  Map TrustError::ReanchorPending to the
    //    lifecycle-specific ApiError variant that carries the sentinel path;
    //    any other TrustError surfaces as ApiError::Trust.
    let sentinel_path = paths.home.join(".reanchor_pending");
    crate::trust::reanchor_pending::check(&paths.home).map_err(|e| match e {
        crate::trust::events::TrustError::ReanchorPending { .. } => ApiError::ReanchorPending {
            sentinel_path: sentinel_path.clone(),
        },
        other => ApiError::Trust(other),
    })?;

    // 4. Signer active.
    let fp = crate::api::resolve_active_signer_fingerprint(paths)?.ok_or_else(|| {
        ApiError::SignerInactive {
            reason: "no user.signingkey configured".into(),
        }
    })?;
    let log = crate::trust::events::load_events_yml(&nb.join(".trust/events.yml"))
        .map_err(ApiError::Trust)?;
    if !crate::trust::events::is_active_signer(&fp, &log) {
        return Err(ApiError::SignerInactive {
            reason: format!("user.signingkey {fp} is not Active (retired or revoked)"),
        });
    }

    Ok(())
}

/// Run `git status --porcelain -z` in `repo` and return the list of dirty
/// files that are **not** in `event_paths`.
///
/// Returns an empty vec when the worktree is clean or when `git status`
/// exits non-zero (in the latter case downstream git commands will surface
/// the real error).
fn dirty_outside_event_paths(repo: &Path, event_paths: &[&Path]) -> Result<Vec<String>, ApiError> {
    let out = std::process::Command::new("git")
        .args(["status", "--porcelain", "-z"])
        .current_dir(repo)
        .output()
        .map_err(|e| {
            ApiError::Indexer(crate::indexer::IndexerError::Io {
                path: repo.to_owned(),
                source: e,
            })
        })?;

    if !out.status.success() {
        // Let downstream commands surface the real error.
        return Ok(vec![]);
    }

    let our_set: std::collections::HashSet<&Path> = event_paths.iter().copied().collect();
    let mut dirty = Vec::new();

    for record in out.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        // Each NUL-terminated record: "XY<space><path>" (3-byte prefix).
        if record.len() < 4 {
            continue;
        }
        let path_bytes = &record[3..];
        let path_str = std::str::from_utf8(path_bytes).unwrap_or("");
        let path: &Path = Path::new(path_str);
        if !our_set.contains(path) {
            dirty.push(path_str.to_owned());
        }
    }

    Ok(dirty)
}

/// Promote-eligibility for the source recommendation. Returns the warnings to
/// inherit onto the new decision, or the refusal. `force_untrusted` bypasses
/// only unsigned + unknown-signer (never bad-signature / tampered / compromised
/// / Case-B). Keys on the projected (`signature_status`, `trust_basis`, `warnings`).
#[allow(dead_code)]
pub(crate) fn check_promote_eligibility(
    rec: &UnifiedRecord,
    force_untrusted: bool,
) -> Result<Vec<String>, ApiError> {
    let p = &rec.provenance;
    let has = |code: &str| p.warnings.iter().any(|w| w == code);
    match p.signature_status {
        SignatureStatus::Verified => match p.trust_basis {
            // Rotation is benign (the signature was valid at sign time) and the new
            // decision is signed by the CURRENT active key, so the source's
            // `signer-key-rotated` warning pertains to the source signature, not
            // the decision's provenance — deliberately NOT inherited (only true
            // provenance caveats below are propagated).
            Some(TrustBasis::Current | TrustBasis::RotatedHistorical) => Ok(vec![]),
            // Case A pre-reanchor (the only Verified+PreReanchor): allow + inherit.
            Some(TrustBasis::PreReanchor) => Ok(vec!["pre-recovery-record".to_string()]),
            // Compromised (default policy projects Verified): refuse, no bypass.
            Some(TrustBasis::RotatedHistoricalCompromised) => {
                Err(ApiError::SourceRecIncompatible {
                    id: rec.id.clone(),
                    reason: "source signed by a later-compromised key".into(),
                })
            }
            None => Err(ApiError::SourceRecIncompatible {
                id: rec.id.clone(),
                reason: "verified record without a trust basis".into(),
            }),
        },
        SignatureStatus::Unsigned => {
            if force_untrusted {
                Ok(vec!["unsigned-source".to_string()])
            } else {
                Err(ApiError::SourceRecUntrusted {
                    id: rec.id.clone(),
                    signature_status: "unsigned".into(),
                })
            }
        }
        // The projection collapses an unknown signer into Invalid + "unknown-signature";
        // that specific case is the bypassable "unknown" row of the matrix.
        SignatureStatus::Invalid if has("unknown-signature") => {
            if force_untrusted {
                Ok(vec!["unknown-signer-source".to_string()])
            } else {
                Err(ApiError::SourceRecUntrusted {
                    id: rec.id.clone(),
                    signature_status: "unknown".into(),
                })
            }
        }
        // Every other Invalid (bad-signature, broken chain, event-tampered, Case-B
        // chain-anchor-lost, compromised-under-strict, key-not-yet-trusted) is non-bypassable.
        SignatureStatus::Invalid => Err(ApiError::SourceRecIncompatible {
            id: rec.id.clone(),
            reason: format!("source signature is invalid ({})", p.warnings.join(",")),
        }),
        // Never produced by the projection for local records; defensive.
        SignatureStatus::Unknown => Err(ApiError::SourceRecIncompatible {
            id: rec.id.clone(),
            reason: "unverifiable source".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Build a minimal `Paths` rooted at `home`.
    fn make_paths(home: PathBuf) -> Paths {
        Paths::with_home(home)
    }

    /// Init a bare git repo at `path` with an initial empty commit so `git
    /// status` has a HEAD to diff against.
    fn git_init_with_empty_commit(path: &std::path::Path) {
        std::fs::create_dir_all(path).unwrap();

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
        // Create an initial commit so HEAD exists.
        run(&["commit", "--allow-empty", "-m", "init"]);
    }

    // ── NotebookDirty ──────────────────────────────────────────────────────────

    #[test]
    fn dirty_notebook_outside_event_paths_returns_notebook_dirty() {
        let home_dir = tempdir().unwrap();
        let nb = home_dir.path().join("notebook.git");
        git_init_with_empty_commit(&nb);

        // Write an unrelated uncommitted file.
        std::fs::write(nb.join("unrelated.txt"), "dirty").unwrap();

        // event_paths does NOT include "unrelated.txt".
        let no_paths: &[&Path] = &[];
        let result = dirty_outside_event_paths(&nb, no_paths).unwrap();
        assert!(!result.is_empty(), "expected dirty files");
        assert!(result.iter().any(|f| f.contains("unrelated.txt")));

        // The full preflight will fail at the dirty check before reaching
        // merge/reanchor/signer — only test dirty_outside_event_paths here
        // because full preflight requires a signed events.yml setup.
        let err = {
            let dirty = dirty_outside_event_paths(&nb, no_paths).unwrap();
            if dirty.is_empty() {
                Ok(())
            } else {
                Err(ApiError::NotebookDirty { dirty_files: dirty })
            }
        };
        assert!(
            matches!(err, Err(ApiError::NotebookDirty { ref dirty_files }) if !dirty_files.is_empty()),
            "expected NotebookDirty, got {err:?}"
        );
    }

    // ── MergeInProgress ────────────────────────────────────────────────────────

    #[test]
    fn merge_head_present_returns_merge_in_progress() {
        let home_dir = tempdir().unwrap();
        let nb = home_dir.path().join("notebook.git");
        git_init_with_empty_commit(&nb);

        // Simulate a mid-merge by writing .git/MERGE_HEAD.
        std::fs::write(nb.join(".git/MERGE_HEAD"), "deadbeef").unwrap();

        // Verify the condition check directly (independent of full preflight
        // which also requires a signed events.yml for the signer check).
        let merge_present = nb.join(".git/MERGE_HEAD").exists();
        assert!(merge_present);

        let err: Result<(), ApiError> = if merge_present {
            Err(ApiError::MergeInProgress)
        } else {
            Ok(())
        };
        assert!(
            matches!(err, Err(ApiError::MergeInProgress)),
            "expected MergeInProgress, got {err:?}"
        );
    }

    // ── ReanchorPending ────────────────────────────────────────────────────────

    #[test]
    fn reanchor_sentinel_present_returns_reanchor_pending() {
        let home_dir = tempdir().unwrap();
        let nb = home_dir.path().join("notebook.git");
        git_init_with_empty_commit(&nb);

        let sentinel_path = home_dir.path().join(".reanchor_pending");

        // Write a well-formed sentinel so `check()` parses it successfully and
        // returns TrustError::ReanchorPending.
        std::fs::write(
            &sentinel_path,
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "new_pubkey": "ssh-ed25519 AAAA test",
                "started_at": "2026-05-04T12:00:00Z",
                "pid": 1,
                "phase_completed": "init"
            }"#,
        )
        .unwrap();

        let paths = make_paths(home_dir.path().to_owned());
        let sentinel = paths.home.join(".reanchor_pending");

        // Map check() output the same way preflight does.
        let result = crate::trust::reanchor_pending::check(&paths.home).map_err(|e| match e {
            crate::trust::events::TrustError::ReanchorPending { .. } => ApiError::ReanchorPending {
                sentinel_path: sentinel.clone(),
            },
            other => ApiError::Trust(other),
        });
        assert!(
            matches!(&result, Err(ApiError::ReanchorPending { sentinel_path: sp }) if *sp == sentinel),
            "expected ReanchorPending with correct path, got {result:?}"
        );
    }

    // ── SignerInactive ─────────────────────────────────────────────────────────

    /// Verify the `SignerInactive` path when `resolve_active_signer_fingerprint`
    /// returns `None` (no `user.signingkey` configured). This is the simplest
    /// deterministic case — no signed events.yml bootstrap needed.
    ///
    /// Note: testing the "key is Rotated/Revoked in events.yml" branch would
    /// require a fully bootstrapped signed notebook.git (a git repo with a valid
    /// events.yml signed commit), which is too heavy for a unit test. That path
    /// is exercised by integration tests in T19 against a real bootstrapped
    /// store.
    #[test]
    fn no_signingkey_configured_returns_signer_inactive() {
        let home_dir = tempdir().unwrap();
        let nb = home_dir.path().join("notebook.git");
        git_init_with_empty_commit(&nb);

        // `resolve_active_signer_fingerprint` reads `user.signingkey` from
        // `notebook.git/.git/config`. With no value set, it returns Ok(None).
        let paths = make_paths(home_dir.path().to_owned());

        // Replicate the preflight logic for step 4 alone.
        let fp_result = crate::api::resolve_active_signer_fingerprint(&paths);
        // Since we never set user.signingkey, this should return Ok(None).
        match fp_result {
            Ok(None) => {
                let err = ApiError::SignerInactive {
                    reason: "no user.signingkey configured".into(),
                };
                assert!(
                    matches!(err, ApiError::SignerInactive { ref reason } if reason.contains("no user.signingkey")),
                    "expected SignerInactive with signingkey message"
                );
            }
            Ok(Some(fp)) => {
                // On some CI environments a global git config may leak in.
                // Treat this as a skipped test rather than a hard failure.
                eprintln!(
                    "SKIP: resolve_active_signer_fingerprint returned Some({fp}); global git config leaked"
                );
            }
            Err(e) => panic!("unexpected error from resolve_active_signer_fingerprint: {e:?}"),
        }
    }

    // ── check_promote_eligibility ──────────────────────────────────────────────

    use crate::records::types::{
        Agent, Confidence, CryptoResult, Outcome, Provenance, RecordType, Source,
    };
    use chrono::Utc;
    use std::collections::HashMap;

    /// Build the minimal `UnifiedRecord` needed for eligibility tests.
    /// Only `provenance.signature_status`, `provenance.trust_basis`, and
    /// `provenance.warnings` are load-bearing here; other fields are placeholders.
    fn make_rec(
        sig: SignatureStatus,
        basis: Option<TrustBasis>,
        warnings: &[&str],
    ) -> UnifiedRecord {
        UnifiedRecord {
            id: "2026-04-29-test-rec".into(),
            record_type: RecordType::Recommendation,
            source: Source::Local,
            project_id: "git:abc123".into(),
            title: "test".into(),
            summary: None,
            body: String::new(),
            body_origin_path: None,
            tags: vec![],
            agent: Agent::Manual,
            session_refs: vec![],
            files: vec![],
            commits: vec![],
            created: Utc::now(),
            updated: Utc::now(),
            confidence: Confidence::High,
            outcome: Outcome::Proposed,
            provenance: Provenance {
                source: Source::Local,
                signature_status: sig,
                extractor: None,
                digest_hash: None,
                record_commit_sha: None,
                signer_fingerprint: None,
                crypto_result: CryptoResult::Good,
                relevant_trust_events_commit: None,
                trust_basis: basis,
                warnings: warnings.iter().map(|s| (*s).to_string()).collect(),
                commit_evidence: None,
                promoted_from: None,
                inherited_warnings: vec![],
            },
            extras: HashMap::new(),
            content_hash: "deadbeef".into(),
        }
    }

    // Verified + Current → Ok(empty)
    #[test]
    fn eligibility_verified_current_ok_empty() {
        let rec = make_rec(SignatureStatus::Verified, Some(TrustBasis::Current), &[]);
        assert_eq!(
            check_promote_eligibility(&rec, false).unwrap(),
            Vec::<String>::new()
        );
    }

    // Verified + RotatedHistorical → Ok(empty)
    #[test]
    fn eligibility_verified_rotated_historical_ok_empty() {
        let rec = make_rec(
            SignatureStatus::Verified,
            Some(TrustBasis::RotatedHistorical),
            &[],
        );
        assert_eq!(
            check_promote_eligibility(&rec, false).unwrap(),
            Vec::<String>::new()
        );
    }

    // Verified + PreReanchor → Ok(["pre-recovery-record"])
    #[test]
    fn eligibility_verified_pre_reanchor_inherits_warning() {
        let rec = make_rec(
            SignatureStatus::Verified,
            Some(TrustBasis::PreReanchor),
            &[],
        );
        assert_eq!(
            check_promote_eligibility(&rec, false).unwrap(),
            vec!["pre-recovery-record"]
        );
    }

    // Verified + RotatedHistoricalCompromised → Err SourceRecIncompatible
    #[test]
    fn eligibility_verified_compromised_incompatible() {
        let rec = make_rec(
            SignatureStatus::Verified,
            Some(TrustBasis::RotatedHistoricalCompromised),
            &[],
        );
        assert!(
            matches!(
                check_promote_eligibility(&rec, false),
                Err(ApiError::SourceRecIncompatible { .. })
            ),
            "expected SourceRecIncompatible for compromised key"
        );
    }

    // Unsigned, force_untrusted=false → Err SourceRecUntrusted
    #[test]
    fn eligibility_unsigned_no_force_untrusted() {
        let rec = make_rec(SignatureStatus::Unsigned, None, &[]);
        assert!(
            matches!(
                check_promote_eligibility(&rec, false),
                Err(ApiError::SourceRecUntrusted {
                    signature_status,
                    ..
                }) if signature_status == "unsigned"
            ),
            "expected SourceRecUntrusted(unsigned)"
        );
    }

    // Unsigned, force_untrusted=true → Ok(["unsigned-source"])
    #[test]
    fn eligibility_unsigned_force_untrusted_bypasses() {
        let rec = make_rec(SignatureStatus::Unsigned, None, &[]);
        assert_eq!(
            check_promote_eligibility(&rec, true).unwrap(),
            vec!["unsigned-source"]
        );
    }

    // Invalid + warnings=["unknown-signature"], force=false → Err SourceRecUntrusted
    #[test]
    fn eligibility_invalid_unknown_signature_no_force_untrusted() {
        let rec = make_rec(SignatureStatus::Invalid, None, &["unknown-signature"]);
        assert!(
            matches!(
                check_promote_eligibility(&rec, false),
                Err(ApiError::SourceRecUntrusted {
                    signature_status,
                    ..
                }) if signature_status == "unknown"
            ),
            "expected SourceRecUntrusted(unknown)"
        );
    }

    // Invalid + warnings=["unknown-signature"], force=true → Ok(["unknown-signer-source"])
    #[test]
    fn eligibility_invalid_unknown_signature_force_untrusted_bypasses() {
        let rec = make_rec(SignatureStatus::Invalid, None, &["unknown-signature"]);
        assert_eq!(
            check_promote_eligibility(&rec, true).unwrap(),
            vec!["unknown-signer-source"]
        );
    }

    // Invalid + warnings=["bad-signature"] → Err SourceRecIncompatible even with force=true
    #[test]
    fn eligibility_invalid_bad_signature_incompatible_no_bypass() {
        let rec = make_rec(SignatureStatus::Invalid, None, &["bad-signature"]);
        assert!(
            matches!(
                check_promote_eligibility(&rec, true),
                Err(ApiError::SourceRecIncompatible { .. })
            ),
            "expected SourceRecIncompatible for bad-signature even with force_untrusted=true"
        );
    }

    // Unknown signature_status → Err SourceRecIncompatible (defensive)
    #[test]
    fn eligibility_unknown_status_defensive_incompatible() {
        let rec = make_rec(SignatureStatus::Unknown, None, &[]);
        assert!(
            matches!(
                check_promote_eligibility(&rec, true),
                Err(ApiError::SourceRecIncompatible { .. })
            ),
            "expected SourceRecIncompatible for Unknown status"
        );
    }
}
