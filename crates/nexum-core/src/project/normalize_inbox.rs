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
