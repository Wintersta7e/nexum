//! Backfill `project_id` on extracted records that landed in `_inbox/`.
//!
//! M2's extraction pipeline sets every record's `project_id` to `_inbox`
//! (see `extract/pipeline.rs` and `extract/record_io.rs`). This module
//! walks the inbox, re-resolves the project identity from each record's
//! `session_refs`, and re-commits the record under
//! `<project_id>/<type>/<id>.yml`.
//!
//! YAML body is updated via a line-level regex substitution (only the
//! `project_id:` line changes) so the rest of the file is byte-identical;
//! the record's `content_hash` drifts by exactly one line's worth, which is
//! a clean diff in the trust audit log.

use crate::api;
use crate::extract::record_io::INBOX_PROJECT_ID;
use crate::init::git_ops::{git_commit_signed, git_verify_commit_with_signers};
use crate::paths::Paths;
use crate::records::types::SessionRef;
use std::path::{Path, PathBuf};

/// Parse a record YAML and project its `session_refs` into a `ProjectInput`.
///
/// `state_5_db` is the Codex state DB path (typically
/// `~/.codex/state_5.sqlite`). When supplied AND the record carries a
/// `CodexThread` ref, we look up `git_origin_url` + `cwd` per `thread_id`.
///
/// Resolution preference:
///   1. `CodexThread` → `state_5` lookup: `git_origin_url`, `cwd`.
///   2. `CodexRollout` → `path` becomes `codex_cwd`.
///   3. `CcSession` → no signal carried in M2's wire shape today (the
///      session UUID alone doesn't encode the slug).
///   4. `Manual` → no signal.
///
/// # Errors
///
/// Returns `NormalizeError::YamlParse` if `yaml` is not valid YAML or the
/// `session_refs` sequence cannot be deserialized. Returns
/// `NormalizeError::Sqlite` if the `state_5_db` path is given but cannot be
/// opened or queried.
pub fn project_input_from_yaml(
    yaml: &str,
    state_5_db: Option<&Path>,
) -> Result<crate::project::ProjectInput, NormalizeError> {
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(NormalizeError::YamlParse)?;
    let refs_node = parsed
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("session_refs".to_owned())));
    let session_refs: Vec<SessionRef> = match refs_node {
        Some(v) => serde_yaml::from_value(v.clone()).map_err(NormalizeError::YamlParse)?,
        None => Vec::new(),
    };

    let cc_slug: Option<String> = None;
    let mut codex_cwd: Option<PathBuf> = None;
    let mut git_origin_url: Option<String> = None;

    for sref in &session_refs {
        match sref {
            SessionRef::CodexRollout { path } => {
                if codex_cwd.is_none() {
                    codex_cwd = Some(path.clone());
                }
            }
            SessionRef::CodexThread {
                thread_id,
                rollout_path,
            } => {
                if let Some(db) = state_5_db
                    && let Some((url, cwd)) = lookup_codex_thread(db, thread_id)?
                {
                    if git_origin_url.is_none() && !url.is_empty() {
                        git_origin_url = Some(url);
                    }
                    if codex_cwd.is_none() {
                        codex_cwd = Some(cwd);
                    }
                }
                if codex_cwd.is_none()
                    && let Some(p) = rollout_path
                {
                    codex_cwd = Some(p.clone());
                }
            }
            // M2 extract doesn't persist the CC slug; the session UUID alone
            // doesn't encode it. Manual carries no identifying signal either.
            // Both arms intentionally produce no output.
            SessionRef::CcSession { uuid: _ } | SessionRef::Manual => {}
        }
    }

    Ok(crate::project::ProjectInput {
        cc_slug,
        codex_cwd,
        git_origin_url,
        registered_name: None,
    })
}

/// Compute where an `_inbox` record should land after normalization.
/// Returns `None` if the resolver can't produce a single `project_id`
/// (Ambiguous / Unresolved); the caller leaves the record in place.
///
/// # Errors
///
/// Returns `NormalizeError::YamlParse` if the record body isn't valid YAML
/// or its `record_type` field can't be read.
pub fn plan_target_path(
    notebook_git: &Path,
    record_id: &str,
    yaml: &str,
    state_5_db: Option<&Path>,
) -> Result<Option<PathBuf>, NormalizeError> {
    use crate::project::ProjectResolution;
    use crate::project::resolve::resolve;

    let input = project_input_from_yaml(yaml, state_5_db)?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    let record_type_str = parsed
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("record_type".to_owned())))
        .and_then(|v| v.as_str())
        .unwrap_or("untyped");
    let type_subdir = match record_type_str {
        "decision" => "decisions",
        "recommendation" => "recommendations",
        "failure" => "failures",
        _ => "untyped",
    };

    let resolution = resolve(&input);
    let project_id = match resolution {
        ProjectResolution::Resolved { project_id, .. } => project_id,
        ProjectResolution::Ambiguous { .. } | ProjectResolution::Unresolved => {
            return Ok(None);
        }
    };

    Ok(Some(notebook_git.join(format!(
        "{project_id}/{type_subdir}/{record_id}.yml"
    ))))
}

/// Replace exactly the `project_id:` line in a YAML body with a new value,
/// preserving the rest of the body byte-for-byte. Returns the new body.
///
/// Why byte-preserving: the record's `content_hash` is computed over the
/// canonical body at extract time. A full serde round-trip would re-order
/// keys and drop comments, drifting the hash beyond the one field we
/// actually changed. With a line-level replace, the new `content_hash`
/// differs from the old by exactly one logical field — auditable and
/// minimal.
///
/// # Errors
///
/// Returns `NormalizeError::Api` if no `project_id:` line is found.
pub fn replace_project_id_line(yaml: &str, new_project_id: &str) -> Result<String, NormalizeError> {
    let mut found = false;
    let mut out_lines: Vec<String> = Vec::new();
    for line in yaml.lines() {
        if !found && line.trim_start().starts_with("project_id:") {
            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out_lines.push(format!("{indent}project_id: {new_project_id}"));
            found = true;
        } else {
            out_lines.push(line.to_owned());
        }
    }
    if !found {
        return Err(NormalizeError::Api(crate::api::ApiError::Other {
            message: "record YAML has no project_id line to replace".into(),
        }));
    }
    let mut out = out_lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    #[error("yaml parse: {0}")]
    YamlParse(#[from] serde_yaml::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("api: {0}")]
    Api(#[from] crate::api::ApiError),
}

fn lookup_codex_thread(
    db: &Path,
    thread_id: &str,
) -> Result<Option<(String, PathBuf)>, NormalizeError> {
    use rusqlite::OptionalExtension;
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare("SELECT git_origin_url, cwd FROM threads WHERE id = ?1 LIMIT 1")?;
    let row = stmt
        .query_row(rusqlite::params![thread_id], |r| {
            let url: Option<String> = r.get(0)?;
            let cwd: Option<String> = r.get(1)?;
            Ok((url.unwrap_or_default(), cwd.unwrap_or_default()))
        })
        .optional()?;
    Ok(row.map(|(u, c)| (u, PathBuf::from(c))))
}

/// Outcome of a single `normalize_inbox` invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizeOutcome {
    /// IDs of records moved out of `_inbox/`, in commit order.
    pub moved_ids: Vec<String>,
    /// Count of records that resolved ambiguously. Left in `_inbox/`.
    pub ambiguous: u32,
    /// IDs of records whose resolution was ambiguous.
    pub ambiguous_ids: Vec<String>,
    /// Count of records that produced no identifying signal. Left in `_inbox/`.
    pub unresolved: u32,
    /// IDs of records that were unresolved.
    pub unresolved_ids: Vec<String>,
}

/// Walk `_inbox/<type>/<id>.yml` records, resolve project identity for
/// each, and re-commit each resolvable record under
/// `<project_id>/<type>/<id>.yml` — one signed commit per record,
/// all under the writer lock.
///
/// Records that resolve `Ambiguous` or `Unresolved` are left in `_inbox/`
/// and counted in the returned `NormalizeOutcome`.
///
/// # Errors
///
/// Returns `NormalizeError::Api` on writer-lock contention, dirty worktree,
/// signing failures, or any other `ApiError`; `NormalizeError::Io` on
/// filesystem errors; `NormalizeError::YamlParse` on malformed records.
pub fn normalize_inbox(
    paths: &Paths,
    state_5_db: Option<&Path>,
) -> Result<NormalizeOutcome, NormalizeError> {
    let inbox_root = paths.notebook_git.join(INBOX_PROJECT_ID);
    if !inbox_root.exists() {
        return Ok(NormalizeOutcome::default());
    }

    api::refuse_if_unrelated_dirty(&paths.notebook_git, &[])?;

    let outcome = api::with_writer_lock(paths, || {
        let mut outcome = NormalizeOutcome::default();
        let inbox_root = paths.notebook_git.join(INBOX_PROJECT_ID);
        for type_subdir in &["decisions", "recommendations", "failures", "untyped"] {
            let dir = inbox_root.join(type_subdir);
            if !dir.exists() {
                continue;
            }
            // Materialize before iterating — POSIX readdir doesn't promise
            // stability across same-dir removals (observed skipping on
            // WSL2 9P).
            let yml_paths: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map_err(|e| api::ApiError::Other {
                    message: format!("read_dir {}: {e}", dir.display()),
                })?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yml"))
                .collect();

            for path in yml_paths {
                process_one(paths, &path, state_5_db, &mut outcome)?;
            }
        }
        Ok(outcome)
    })?;
    Ok(outcome)
}

fn process_one(
    paths: &Paths,
    inbox_path: &Path,
    state_5_db: Option<&Path>,
    outcome: &mut NormalizeOutcome,
) -> Result<(), api::ApiError> {
    use crate::project::ProjectResolution;
    use crate::project::resolve::resolve;

    let yaml = std::fs::read_to_string(inbox_path).map_err(|e| api::ApiError::Other {
        message: format!("read inbox file {}: {e}", inbox_path.display()),
    })?;
    let record_id = inbox_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();

    let plan =
        plan_target_path(&paths.notebook_git, &record_id, &yaml, state_5_db).map_err(|e| {
            api::ApiError::Other {
                message: format!("plan target for {record_id}: {e}"),
            }
        })?;

    let Some(target) = plan else {
        // Attribute the skip cause.
        let input =
            project_input_from_yaml(&yaml, state_5_db).map_err(|e| api::ApiError::Other {
                message: format!("re-resolve for {record_id}: {e}"),
            })?;
        if let ProjectResolution::Ambiguous { .. } = resolve(&input) {
            outcome.ambiguous += 1;
            outcome.ambiguous_ids.push(record_id);
        } else {
            outcome.unresolved += 1;
            outcome.unresolved_ids.push(record_id);
        }
        return Ok(());
    };

    let new_project_id = target
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();

    let rewritten =
        replace_project_id_line(&yaml, &new_project_id).map_err(|e| api::ApiError::Other {
            message: format!("rewrite project_id for {record_id}: {e}"),
        })?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| api::ApiError::Other {
            message: format!("create_dir_all {}: {e}", parent.display()),
        })?;
    }
    std::fs::write(&target, &rewritten).map_err(|e| api::ApiError::Other {
        message: format!("write target {}: {e}", target.display()),
    })?;

    let rel_added = target
        .strip_prefix(&paths.notebook_git)
        .unwrap_or(&target)
        .to_path_buf();
    let rel_removed = inbox_path
        .strip_prefix(&paths.notebook_git)
        .unwrap_or(inbox_path)
        .to_path_buf();

    // `git rm` the old inbox path (removes working-tree file + stages deletion).
    let rm_status = crate::trust::git_history::git(&paths.notebook_git)
        .args(["rm", "--quiet"])
        .arg(&rel_removed)
        .status()
        .map_err(|e| api::ApiError::Other {
            message: format!("git rm {}: {e}", rel_removed.display()),
        })?;
    if !rm_status.success() {
        return Err(api::ApiError::Other {
            message: format!(
                "git rm refused for {} (rm status {rm_status})",
                rel_removed.display()
            ),
        });
    }

    let message = format!("project: normalize {record_id} from _inbox to {new_project_id}");
    let historical_signers = paths.notebook_git.join(".trust/historical_signers");
    match git_commit_signed(&paths.notebook_git, &[&rel_added], &message) {
        Ok(_sha) => {
            // Post-commit signature verification.
            if let Err(e) =
                git_verify_commit_with_signers(&paths.notebook_git, "HEAD", &historical_signers)
            {
                let _ = api::rollback_last_commit(&paths.notebook_git);
                return Err(api::ApiError::Other {
                    message: format!("verify signed commit for {record_id}: {e}"),
                });
            }
            outcome.moved_ids.push(record_id);
            Ok(())
        }
        Err(e) => {
            // Rollback: remove the new file; restore the deleted inbox file.
            let _ = std::fs::remove_file(&target);
            let _ = api::restore_paths_from_head(&paths.notebook_git, &[&rel_removed]);
            Err(api::ApiError::Other {
                message: format!("git_commit_signed for {record_id}: {e}"),
            })
        }
    }
}

#[cfg(test)]
mod project_input_tests {
    use super::*;

    const SAMPLE_YAML_CODEX_THREAD: &str = r"
schema_version: 1
id: 2026-04-29-test
record_type: recommendation
project_id: _inbox
session_refs:
  - kind: codex_thread
    thread_id: t-1
    rollout_path: /tmp/rollouts/r1.jsonl
";

    #[test]
    fn project_input_from_yaml_codex_thread_no_state_db() {
        let input = project_input_from_yaml(SAMPLE_YAML_CODEX_THREAD, None).unwrap();
        // No state_5_db provided → no git_origin_url / cwd lookup possible.
        // Falls back to using rollout_path as codex_cwd.
        assert!(input.git_origin_url.is_none());
        assert_eq!(
            input.codex_cwd,
            Some(std::path::PathBuf::from("/tmp/rollouts/r1.jsonl"))
        );
        assert!(input.cc_slug.is_none());
    }
}

#[cfg(test)]
mod tests {
    use crate::project::resolve::resolve;
    use crate::project::{ProjectInput, ProjectResolution};

    #[test]
    fn resolve_with_git_url_succeeds() {
        let input = ProjectInput {
            cc_slug: None,
            codex_cwd: None,
            git_origin_url: Some("https://github.com/example/foo.git".into()),
            registered_name: None,
        };
        let res = resolve(&input);
        assert!(matches!(res, ProjectResolution::Resolved { .. }));
    }
}

#[cfg(test)]
mod plan_target_tests {
    use super::*;

    #[test]
    fn plan_target_path_returns_some_when_resolver_succeeds() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Use the tmp dir itself as the rollout path — it exists on disk so
        // canonicalize_path succeeds and the resolver produces a Resolved
        // identity via the Path branch.
        let rollout_path = tmp.path().to_string_lossy().into_owned();
        let yaml = format!(
            "schema_version: 1\nid: 2026-04-29-test\nrecord_type: recommendation\nproject_id: _inbox\nsession_refs:\n  - kind: codex_rollout\n    path: {rollout_path}\n"
        );
        // No git_origin_url, but codex_cwd is set → resolver returns
        // Resolved with Path identity (canon::path_hint produces a
        // deterministic path-based project_id).
        let target = plan_target_path(tmp.path(), "2026-04-29-test", &yaml, None).unwrap();
        assert!(target.is_some(), "expected a resolved target");
        let p = target.unwrap();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("/recommendations/2026-04-29-test.yml"),
            "unexpected target: {s}"
        );
    }

    #[test]
    fn replace_project_id_line_preserves_rest() {
        let yaml = "schema_version: 1\nproject_id: _inbox\ntags: [a, b]\n";
        let out = replace_project_id_line(yaml, "git:abc123").unwrap();
        assert_eq!(
            out,
            "schema_version: 1\nproject_id: git:abc123\ntags: [a, b]\n"
        );
    }

    #[test]
    fn replace_project_id_line_preserves_indent() {
        let yaml = "  project_id: _inbox\n";
        let out = replace_project_id_line(yaml, "git:xyz").unwrap();
        assert_eq!(out, "  project_id: git:xyz\n");
    }

    #[test]
    fn replace_project_id_line_errors_when_missing() {
        let yaml = "schema_version: 1\ntags: []\n";
        assert!(replace_project_id_line(yaml, "anything").is_err());
    }
}
