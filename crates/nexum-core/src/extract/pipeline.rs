//! End-to-end pipeline: digest → `ModelClient` → validate → commit → index.

use std::path::Path;

use crate::api::{
    self, ApiError, refuse_if_unrelated_dirty, restore_paths_from_head, rollback_last_commit,
    with_writer_lock,
};
use crate::config::types::Config;
use crate::extract::digest::{SessionDigest, SessionId};
use crate::extract::model::{ExtractError, ExtractionOutput, ModelClient};
use crate::extract::record_io::raw_to_unified;
use crate::extract::redaction::{append_redaction_log, default_engine};
use crate::init::git_ops::{git_commit_signed, git_verify_commit_with_signers};
use crate::paths::Paths;
use crate::records::{RecordType, UnifiedRecord};

/// Outcome of a single extraction pass. Carries the set of record ids that
/// landed as signed commits, an optional decline reason when the model
/// returned `NoRecords`, and a tally of redaction events observed in the
/// pre-flight pass over the digest text.
#[derive(Debug, Clone, Default)]
pub struct SessionOutcome {
    pub committed_record_ids: Vec<String>,
    pub declined_reason: Option<String>,
    pub redaction_event_count: u32,
}

/// Top-level entry: redact the digest, run it through `client`, validate every
/// emitted record, and commit each into `notebook.git` under the writer lock.
/// Triggers an incremental index pass on success so the new records are
/// immediately queryable.
///
/// # Errors
///
/// Returns `ApiError::Extraction` for model, redaction, validation, or
/// trust-chain commit failures. Returns `ApiError::Indexer` if the post-commit
/// index pass fails. Returns `ApiError::TrustRegenerateRefused` when the
/// `notebook.git` worktree is dirty outside the records about to land.
pub fn extract_session_with_client(
    paths: &Paths,
    cfg: &Config,
    digest: &SessionDigest,
    client: &dyn ModelClient,
) -> Result<SessionOutcome, ApiError> {
    // 1. Redact every text field in the digest before sending.
    let mut redacted = digest.clone();
    let engine = default_engine();
    let mut total_events: u32 = 0;
    let session_id = session_id_string(&digest.session_id);
    let log_path = paths.logs.join("redaction.jsonl");
    for turn in redacted
        .user_turns
        .iter_mut()
        .chain(redacted.assistant_turns.iter_mut())
    {
        let result = engine.redact(&turn.content);
        if !result.events.is_empty() {
            let _ = append_redaction_log(&result.events, &session_id, &log_path);
            total_events =
                total_events.saturating_add(u32::try_from(result.events.len()).unwrap_or(u32::MAX));
        }
        turn.content = result.text;
    }
    for call in &mut redacted.tool_calls {
        let args = engine.redact(&call.args_sketch);
        let out = engine.redact(&call.output_excerpt);
        let n = args.events.len() + out.events.len();
        if n > 0 {
            let mut events = args.events;
            events.extend(out.events);
            let _ = append_redaction_log(&events, &session_id, &log_path);
            total_events = total_events.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        }
        call.args_sketch = args.text;
        call.output_excerpt = out.text;
    }

    // 2. Call the model.
    let response = client.extract(&redacted).map_err(ApiError::from)?;
    let records = match response {
        ExtractionOutput::Records(r) => r,
        ExtractionOutput::NoRecords { reason } => {
            return Ok(SessionOutcome {
                committed_record_ids: Vec::new(),
                declined_reason: Some(reason),
                redaction_event_count: total_events,
            });
        }
    };

    // 3. Validate + convert (all-or-nothing before any commits).
    let unified: Vec<UnifiedRecord> = records
        .iter()
        .map(raw_to_unified)
        .collect::<Result<_, ExtractError>>()
        .map_err(ApiError::from)?;

    // 4. Commit under the writer lock.
    let committed_ids: Vec<String> = with_writer_lock(paths, || commit_records(paths, &unified))?;

    // 5. Incremental index.
    api::index_run(paths, cfg)?;

    Ok(SessionOutcome {
        committed_record_ids: committed_ids,
        declined_reason: None,
        redaction_event_count: total_events,
    })
}

fn commit_records(paths: &Paths, records: &[UnifiedRecord]) -> Result<Vec<String>, ApiError> {
    // Refuse if the worktree is dirty (no paths in the 'allowed dirty' set).
    refuse_if_unrelated_dirty(&paths.notebook_git, &[])?;

    let historical_signers = paths.notebook_git.join(".trust/historical_signers");
    let mut committed: Vec<String> = Vec::new();

    for record in records {
        let project_subdir: &str = if record.project_id.is_empty() {
            "_inbox"
        } else {
            &record.project_id
        };
        let type_subdir = match record.record_type {
            RecordType::Decision => "decisions",
            RecordType::Recommendation => "recommendations",
            RecordType::Failure => "failures",
            RecordType::Untyped => "untyped",
        };
        let relative = format!("{project_subdir}/{type_subdir}/{}.yml", record.id);
        let abs = paths.notebook_git.join(&relative);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).map_err(ExtractError::Io)?;
        }
        std::fs::write(&abs, &record.body).map_err(ExtractError::Io)?;

        let rel_path = Path::new(&relative);
        let message = format!("extract: {}", record.id);

        match commit_one(&paths.notebook_git, rel_path, &message, &historical_signers) {
            Ok(_sha) => committed.push(record.id.clone()),
            Err(e) => {
                // Restore the file we wrote so the worktree stays clean.
                let _ = restore_paths_from_head(&paths.notebook_git, &[rel_path]);
                return Err(e);
            }
        }
    }
    Ok(committed)
}

fn commit_one(
    repo_path: &Path,
    relative_path: &Path,
    message: &str,
    historical_signers: &Path,
) -> Result<String, ApiError> {
    let sha = git_commit_signed(repo_path, &[relative_path], message)
        .map_err(|e| ApiError::Extraction(ExtractError::Init(e)))?;
    if let Err(e) = git_verify_commit_with_signers(repo_path, &sha, historical_signers) {
        let _ = rollback_last_commit(repo_path);
        return Err(ApiError::Extraction(ExtractError::Init(e)));
    }
    Ok(sha)
}

fn session_id_string(id: &SessionId) -> String {
    match id {
        SessionId::Cc(uuid) => uuid.to_string(),
        SessionId::CodexRolloutPath(p) => p.display().to_string(),
        SessionId::CodexThread(t) => t.clone(),
    }
}
