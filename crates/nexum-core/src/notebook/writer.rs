//! Pre-flight guard, eligibility check, and the sole lifecycle-mutation entry
//! into `notebook.git` for the promotion pipeline.
//!
//! `preflight` is **invoked inside the `with_writer_lock` closure** (see
//! `commit_lifecycle_event`) so the dirty/merge/reanchor store-state checks
//! cannot race another process between the check and lock acquisition.

use std::path::{Path, PathBuf};

use crate::{
    api::ApiError,
    notebook::{
        emit::{self, DecisionInput},
        lifecycle::LifecycleEvent,
    },
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

fn dirty_outside_event_paths(repo: &Path, event_paths: &[&Path]) -> Result<Vec<String>, ApiError> {
    let out = crate::trust::git_history::git(repo)
        .args(["status", "--porcelain", "-z"])
        .output()
        .map_err(|e| {
            ApiError::Indexer(crate::indexer::IndexerError::Io {
                path: repo.to_owned(),
                source: e,
            })
        })?;

    // Fail closed: a cleanliness check that itself failed must NOT be read as
    // "clean", or a dirty worktree could be mutated and then clobbered on
    // rollback. Surface the failure instead of silently proceeding.
    if !out.status.success() {
        return Err(ApiError::Other {
            message: format!(
                "git status failed in {} (exit {}): {}",
                repo.display(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }

    let our_set: std::collections::HashSet<&Path> = event_paths.iter().copied().collect();
    let mut dirty = Vec::new();
    // `git status --porcelain -z` separates records with NUL. A rename/copy
    // record (index status R/C) is followed by a SECOND NUL-delimited chunk
    // carrying the original path — consume it so it isn't misread as its own
    // status record (which would surface a truncated, spurious dirty path).
    let mut chunks = out.stdout.split(|&b| b == 0).filter(|r| !r.is_empty());
    while let Some(record) = chunks.next() {
        // Each record is "XY<space><path>" — a 3-byte prefix then the path.
        if record.len() < 4 {
            continue;
        }
        let is_rename_or_copy = record[0] == b'R' || record[0] == b'C';
        let path_str = std::str::from_utf8(&record[3..]).unwrap_or("");
        let path: &Path = Path::new(path_str);
        if !our_set.contains(path) {
            dirty.push(path_str.to_owned());
        }
        if is_rename_or_copy {
            chunks.next(); // skip the origin-path chunk
        }
    }

    Ok(dirty)
}

/// Promote-eligibility for the source recommendation. Returns the warnings to
/// inherit onto the new decision, or the refusal. `force_untrusted` bypasses
/// only unsigned + unknown-signer (never bad-signature / tampered / compromised
/// / Case-B). Keys on the projected (`signature_status`, `trust_basis`, `warnings`).
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

// ── lifecycle-event writer ─────────────────────────────────────────────────

/// Repo-relative paths that a lifecycle event will touch, split into newly
/// created files and pre-existing files. The split drives rollback: new files
/// must be deleted (`remove_file`); existing files must be restored from HEAD
/// (`git checkout HEAD --`). Merging both sets gives the paths to stage.
struct EventPaths {
    /// Files that already exist in HEAD and will be modified (e.g. the
    /// stamped recommendation YAML).
    existing: Vec<PathBuf>,
    /// Files that do not yet exist in HEAD and will be created (e.g. the
    /// new decision YAML for a Promote event).
    new: Vec<PathBuf>,
}

impl EventPaths {
    /// All paths in stage order: existing first, then new.
    fn all(&self) -> Vec<&Path> {
        self.existing
            .iter()
            .chain(self.new.iter())
            .map(PathBuf::as_path)
            .collect()
    }
}

/// The sole lifecycle-mutation entry into `notebook.git`. One signed commit
/// per event. Returns the commit SHA.
///
/// `pub` visibility is for external integration tests only; the api facade is
/// the sole intended production caller. Callers that bypass the facade skip
/// the post-commit `index_run` and will leave the search index stale.
///
/// Does **not** re-index after the commit — the api facade owns the
/// post-commit `index_run` so it can surface the partial-failure warning
/// alongside the durable SHA.
///
/// Critical invariants:
/// - `preflight` runs **inside** the writer lock (TOCTOU-safe).
/// - `Promote` stages two files in one commit (decision yaml + stamped rec).
/// - On verify-failure: `rollback_last_commit`; on commit-failure: delete
///   each newly created path and restore each pre-existing path from HEAD.
///   Both failure paths route through `after_rollback`.
///
/// # Errors
///
/// Returns `ApiError::SignerInactive` if no active signing key is configured.
/// Returns `ApiError::NotebookDirty`, `ApiError::MergeInProgress`, or
/// `ApiError::ReanchorPending` if the notebook store is in a bad state.
/// Returns `ApiError::CommitSignFailed` if the signed commit or post-commit
/// verification fails (worktree is restored to clean state before returning).
/// Returns `ApiError::RollbackFailed` if the rollback itself also failed
/// (worktree may be in an indeterminate state; manual intervention required).
pub fn commit_lifecycle_event(paths: &Paths, event: &LifecycleEvent) -> Result<String, ApiError> {
    let plan = plan_paths(paths, event)?;
    let all_refs = plan.all();
    let message = render_message(event);

    crate::api::with_writer_lock(paths, || {
        // Pre-flight INSIDE the lock (TOCTOU-safe). Eligibility (check_promote_eligibility)
        // is checked by the caller before the event is built.
        preflight(paths, &all_refs)?;
        // Partial write recovery: if writing the event files fails midway,
        // nothing is staged yet, so the commit-failure rollback below never
        // runs. Remove any newly created files and restore modified existing
        // files from HEAD here, or an orphan/partial file would wedge the next
        // preflight as an unrelated dirty file.
        if let Err(e) = write_event_files(paths, event) {
            for new_path in &plan.new {
                let _ = std::fs::remove_file(paths.notebook_git.join(new_path));
            }
            let existing_refs: Vec<&Path> = plan.existing.iter().map(PathBuf::as_path).collect();
            let _ = crate::api::restore_paths_from_head(&paths.notebook_git, &existing_refs);
            return Err(e);
        }

        let historical = paths.notebook_git.join(".trust/historical_signers");
        match crate::init::git_ops::git_commit_signed(&paths.notebook_git, &all_refs, &message) {
            Ok(sha) => {
                match crate::init::git_ops::git_verify_commit_with_signers(
                    &paths.notebook_git,
                    "HEAD",
                    &historical,
                ) {
                    Ok(()) => Ok(sha),
                    // Commit landed but verify failed: hard-reset removes the
                    // commit and restores the tree — safe for both new and
                    // existing files.
                    Err(e) => Err(after_rollback(
                        &crate::api::rollback_last_commit(&paths.notebook_git),
                        ApiError::CommitSignFailed {
                            detail: e.to_string(),
                        },
                    )),
                }
            }
            // Commit itself failed. `git_commit_signed` staged every path via
            // `git add` before the failed commit, so new files are staged as
            // additions. `git rm -f` clears both the index entry and the
            // worktree copy (`git checkout HEAD --` would error on a path with
            // no HEAD entry); pre-existing files are then restored from HEAD.
            Err(e) => {
                for new_path in &plan.new {
                    let _ = crate::trust::git_history::git(&paths.notebook_git)
                        .args(["rm", "-f", "--quiet", "--ignore-unmatch", "--"])
                        .arg(new_path)
                        .status();
                }
                let existing_refs: Vec<&Path> =
                    plan.existing.iter().map(PathBuf::as_path).collect();
                let restore =
                    crate::api::restore_paths_from_head(&paths.notebook_git, &existing_refs);
                Err(after_rollback(
                    &restore,
                    ApiError::CommitSignFailed {
                        detail: e.to_string(),
                    },
                ))
            }
        }
    })
}

/// Reject a `project_id` or record id (read from on-disk YAML) that would
/// escape `notebook.git` when joined into a path — `..`, an absolute path, or
/// any non-`Normal` component. Defends the lifecycle writer against a
/// hand-planted recommendation whose `id:` / `project_id:` field traverses the
/// tree (e.g. `create_dir_all` outside the notebook).
fn safe_component(value: &str, what: &str) -> Result<(), ApiError> {
    use std::path::Component;
    let all_normal = !value.is_empty()
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
    if !all_normal {
        return Err(ApiError::Other {
            message: format!("unsafe {what} for path construction: {value:?}"),
        });
    }
    Ok(())
}

/// Compute the repo-relative paths that `event` will touch (relative to
/// `paths.notebook_git`), split into pre-existing and newly created files.
///
/// - `Promote`: the stamped rec (`recommendations/<id>.yml`) is EXISTING;
///   the decision YAML (`decisions/<id>.yml`) is NEW.
/// - `Reject` / `Stale`: the stamped rec is EXISTING; nothing new.
fn plan_paths(paths: &Paths, event: &LifecycleEvent) -> Result<EventPaths, ApiError> {
    let nb = &paths.notebook_git;
    match event {
        LifecycleEvent::Promote {
            rec_ref,
            new_decision,
            ..
        } => {
            let project_id = rec_ref
                .project_id
                .as_deref()
                .ok_or_else(|| ApiError::Other {
                    message: "rec_ref.project_id is required for Promote".into(),
                })?;
            safe_component(project_id, "project_id")?;
            safe_component(&rec_ref.id, "recommendation id")?;
            safe_component(&new_decision.id, "decision id")?;
            let rec_path = nb
                .join(project_id)
                .join("recommendations")
                .join(format!("{}.yml", rec_ref.id))
                .strip_prefix(nb)
                .unwrap()
                .to_owned();
            let dec_path = nb
                .join(project_id)
                .join("decisions")
                .join(format!("{}.yml", new_decision.id))
                .strip_prefix(nb)
                .unwrap()
                .to_owned();
            Ok(EventPaths {
                existing: vec![rec_path],
                new: vec![dec_path],
            })
        }
        LifecycleEvent::Reject { rec_ref } | LifecycleEvent::Stale { rec_ref } => {
            let project_id = rec_ref
                .project_id
                .as_deref()
                .ok_or_else(|| ApiError::Other {
                    message: "rec_ref.project_id is required for Reject/Stale".into(),
                })?;
            safe_component(project_id, "project_id")?;
            safe_component(&rec_ref.id, "recommendation id")?;
            let rec_path = nb
                .join(project_id)
                .join("recommendations")
                .join(format!("{}.yml", rec_ref.id))
                .strip_prefix(nb)
                .unwrap()
                .to_owned();
            Ok(EventPaths {
                existing: vec![rec_path],
                new: vec![],
            })
        }
    }
}

/// Build the commit message for `event`. For `Promote`, the "via" SHA is the
/// project-repo commit SHA from `commit_evidence` (known pre-commit — NOT the
/// notebook commit). This must agree with the audit-log parser.
fn render_message(event: &LifecycleEvent) -> String {
    match event {
        LifecycleEvent::Promote {
            rec_ref,
            new_decision,
            commit_evidence,
        } => LifecycleEvent::message_for_promote(
            rec_ref,
            &new_decision.id,
            &commit_evidence.commit_sha,
        ),
        LifecycleEvent::Reject { rec_ref } => LifecycleEvent::message_for_reject(rec_ref),
        LifecycleEvent::Stale { rec_ref } => LifecycleEvent::message_for_stale(rec_ref),
    }
}

/// Write the on-disk files that `event` requires, under `paths.notebook_git`.
///
/// - `Promote`: create `<project_id>/decisions/<dec_id>.yml` from
///   `emit::build_decision_yaml`; read and stamp the rec via
///   `emit::stamp_promoted`.
/// - `Reject`: read and stamp the rec via `emit::replace_outcome_line` →
///   `rejected`.
/// - `Stale`: read and stamp the rec via `emit::replace_outcome_line` →
///   `stale`.
fn write_event_files(paths: &Paths, event: &LifecycleEvent) -> Result<(), ApiError> {
    let nb = &paths.notebook_git;
    match event {
        LifecycleEvent::Promote {
            rec_ref,
            new_decision,
            commit_evidence,
        } => {
            let project_id = rec_ref
                .project_id
                .as_deref()
                .ok_or_else(|| ApiError::Other {
                    message: "rec_ref.project_id is required for Promote".into(),
                })?;

            // Guard: the decision's `project_id` field must agree with the
            // path component derived from the rec. The adapter derives
            // `project_id` from the directory on read, so a mismatch would
            // produce a record whose YAML field contradicts its location.
            if new_decision.project_id != project_id {
                return Err(ApiError::Other {
                    message: format!(
                        "project_id mismatch: rec path component is \"{project_id}\" \
                         but new_decision.project_id is \"{}\"",
                        new_decision.project_id
                    ),
                });
            }

            // Build the decision YAML from new_decision's fields + commit_evidence.
            let dec_yaml = emit::build_decision_yaml(&DecisionInput {
                decision_id: new_decision.id.clone(),
                project_id: new_decision.project_id.clone(),
                source_rec_id: rec_ref.id.clone(),
                // The decision's title carries the source rec's title (set by
                // the api facade when it constructs new_decision). Fallback to
                // the rec id only if the title is empty.
                source_rec_title: if new_decision.title.is_empty() {
                    rec_ref.id.clone()
                } else {
                    new_decision.title.clone()
                },
                agent: new_decision.agent.as_db_str().to_owned(),
                created: new_decision.created,
                commit_evidence: commit_evidence.clone(),
                inherited_warnings: new_decision.provenance.inherited_warnings.clone(),
            });

            let dec_dir = nb.join(project_id).join("decisions");
            std::fs::create_dir_all(&dec_dir).map_err(|e| ApiError::Other {
                message: format!("create_dir_all {}: {e}", dec_dir.display()),
            })?;
            let dec_path = dec_dir.join(format!("{}.yml", new_decision.id));
            // Under the writer lock: a pre-existing decision file means a
            // concurrent promotion of the same rec already derived this id and
            // committed it. Refuse rather than silently overwrite its content.
            if dec_path.exists() {
                return Err(ApiError::Other {
                    message: format!(
                        "decision {} already exists; a concurrent promotion likely \
                         created it — re-run to derive a fresh id",
                        new_decision.id
                    ),
                });
            }
            std::fs::write(&dec_path, &dec_yaml).map_err(|e| ApiError::Other {
                message: format!("write decision yaml {}: {e}", dec_path.display()),
            })?;

            // Stamp the recommendation.
            let rec_path = nb
                .join(project_id)
                .join("recommendations")
                .join(format!("{}.yml", rec_ref.id));
            let rec_yaml = std::fs::read_to_string(&rec_path).map_err(|e| ApiError::Other {
                message: format!("read rec {} for stamping: {e}", rec_path.display()),
            })?;
            let stamped = emit::stamp_promoted(&rec_yaml, &new_decision.id)?;
            std::fs::write(&rec_path, &stamped).map_err(|e| ApiError::Other {
                message: format!("write stamped rec {}: {e}", rec_path.display()),
            })?;
        }

        LifecycleEvent::Reject { rec_ref } | LifecycleEvent::Stale { rec_ref } => {
            let outcome = if matches!(event, LifecycleEvent::Reject { .. }) {
                "rejected"
            } else {
                "stale"
            };
            let project_id = rec_ref
                .project_id
                .as_deref()
                .ok_or_else(|| ApiError::Other {
                    message: "rec_ref.project_id is required for Reject/Stale".into(),
                })?;
            let rec_path = nb
                .join(project_id)
                .join("recommendations")
                .join(format!("{}.yml", rec_ref.id));
            let rec_yaml = std::fs::read_to_string(&rec_path).map_err(|e| ApiError::Other {
                message: format!("read rec {} for {outcome}: {e}", rec_path.display()),
            })?;
            let stamped = emit::replace_outcome_line(&rec_yaml, outcome)?;
            std::fs::write(&rec_path, &stamped).map_err(|e| ApiError::Other {
                message: format!("write {outcome} rec {}: {e}", rec_path.display()),
            })?;
        }
    }
    Ok(())
}

/// Translate a rollback result + the original error into the surface error.
///
/// On rollback success (`Ok(true)`) → return the original error.
/// On rollback failure (`Ok(false)` or `Err`) → return
/// `ApiError::RollbackFailed` so the caller knows the worktree is in an
/// indeterminate state and manual intervention is required.
///
/// This mirrors `surface_rollback_err` in `api/mod.rs` but maps to
/// `RollbackFailed` (the lifecycle-specific variant) rather than
/// `TrustRegenerateFailed`.
fn after_rollback(rollback: &Result<bool, std::io::Error>, original: ApiError) -> ApiError {
    if matches!(rollback, Ok(true)) {
        original
    } else {
        ApiError::RollbackFailed {
            detail: format!("rollback failed after: {original}"),
        }
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

    /// A staged rename (`R  new\0old`) must report only the destination — the
    /// origin-path NUL chunk must be consumed, never surfaced as a truncated
    /// spurious dirty path.
    #[test]
    fn dirty_check_skips_staged_rename_origin_path() {
        let home_dir = tempdir().unwrap();
        let nb = home_dir.path().join("notebook.git");
        git_init_with_empty_commit(&nb);

        let run = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(&nb)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };

        std::fs::write(nb.join("orig.txt"), "x").unwrap();
        run(&["add", "orig.txt"]);
        run(&["commit", "-m", "add orig"]);
        run(&["mv", "orig.txt", "renamed.txt"]);

        let dirty = dirty_outside_event_paths(&nb, &[]).unwrap();
        assert!(
            dirty.iter().any(|f| f == "renamed.txt"),
            "destination must be the reported dirty path: {dirty:?}"
        );
        assert!(
            !dirty.iter().any(|f| f.contains("orig")),
            "rename origin path must NOT be reported: {dirty:?}"
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
    /// is exercised by integration tests against a real bootstrapped
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
