//! `nexum extract` — drive the typed-extraction pipeline for one session
//! (`--session <id>`) or a recent batch (`--since <duration>`).
//!
//! Wires the synchronous CLI into the pipeline. The Anthropic client owns
//! its own worker tokio runtime, so the CLI itself stays sync. The
//! consent gate fires before any digest leaves the machine; the recorded
//! ack is scoped to (provider, model family).
//!
//! `--backfill` is recognized at the args layer so clap parses the flag
//! and its `--dry-run` / `--dry-run-id` modifiers, but the actual
//! backfill pathway lands in the follow-up CLI tasks; this verb returns
//! the `EXTRACT_DRY_RUN_REQUIRED` envelope (informative for agents:
//! "supply --dry-run first") until those land.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use nexum_core::api::error::ErrorEnvelope;
use nexum_core::config::types::Config;
use nexum_core::extract::consent::{
    AckedRecord, consent_required, model_family, read_ack, warning_text, write_ack,
};
use nexum_core::extract::digest::{SessionDigest, SessionId, build_cc_digest, build_codex_digest};
use nexum_core::extract::discovery::{
    Candidate, discover_cc_sessions, discover_codex_sessions, parse_since,
};
use nexum_core::extract::model::{
    AnthropicClient, ExtractError, ModelClient, OllamaClient, OpenAiClient, Provider,
};
use nexum_core::extract::pipeline::extract_session_with_client;
use nexum_core::paths::Paths;
use uuid::Uuid;

use crate::commands::exit_codes;
use crate::commands::json_emit;

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct ExtractArgs {
    /// One specific session: a CC `<uuid>`, a Codex `threads.id` string,
    /// or a Codex rollout file path.
    #[arg(long, group = "selector")]
    pub session: Option<String>,
    /// Discover every session whose mtime (CC) or `created_at_ms`
    /// (Codex) falls within the supplied window. Accepts `Nh`, `Nd`, or
    /// `Nm`.
    #[arg(long, group = "selector", value_name = "DURATION")]
    pub since: Option<String>,
    /// Run the deferred backfill pathway. In this build the verb refuses
    /// with `EXTRACT_DRY_RUN_REQUIRED` to keep the contract stable while
    /// the dedicated `--backfill --dry-run` and `--backfill` verbs land
    /// in follow-up tasks.
    #[arg(long, group = "selector")]
    pub backfill: bool,
    /// Pair with `--backfill`: produce a manifest without committing
    /// anything. Currently inert — see `--backfill`.
    #[arg(long, requires = "backfill")]
    pub dry_run: bool,
    /// Pair with `--backfill`: consume a manifest produced by an earlier
    /// `--dry-run` and commit its sessions. Currently inert — see
    /// `--backfill`.
    #[arg(
        long,
        requires = "backfill",
        conflicts_with = "dry_run",
        value_name = "ID"
    )]
    pub dry_run_id: Option<String>,
    /// Skip the interactive consent prompt; fail with
    /// `EXTRACT_NOT_ACKNOWLEDGED` when no prior ack covers the configured
    /// (provider, model family).
    #[arg(long)]
    pub quiet: bool,
    /// Emit the response (or `ErrorEnvelope`) as JSON on stdout instead
    /// of prose on stderr.
    #[arg(long)]
    pub json: bool,
}

/// Top-level entry. Resolves the runtime, applies the consent gate, then
/// dispatches by selector.
pub fn run(args: &ExtractArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };

    let provider = match Provider::from_config(&cfg.extractor.provider) {
        Ok(p) => p,
        Err(e) => return emit_error(&e, args.json),
    };

    let client = match build_client(provider, &cfg) {
        Ok(c) => c,
        Err(e) => return emit_error(&e, args.json),
    };

    if let Err(code) = enforce_consent(&paths, &cfg, client.as_ref(), args) {
        return code;
    }

    if let Some(sid) = args.session.as_deref() {
        return run_one_session(&paths, &cfg, sid, client.as_ref(), args.json);
    }
    if let Some(since) = args.since.as_deref() {
        return run_since(&paths, &cfg, since, client.as_ref(), args.json);
    }
    if args.backfill {
        if args.dry_run {
            return run_backfill_dry_run(&paths, &cfg, client.as_ref(), args.json);
        }
        // The commit path (`--backfill` alone) and the
        // `--dry-run-id`-supplied commit path land in a follow-up task;
        // until then, surface the same `DRY_RUN_REQUIRED` envelope so the
        // contract stays stable.
        return emit_error(&ExtractError::DryRunRequired, args.json);
    }
    emit_error(
        &ExtractError::Validation {
            reason: "supply one of --session, --since, or --backfill".to_owned(),
        },
        args.json,
    )
}

/// Construct the concrete [`ModelClient`] selected by `cfg.extractor.provider`.
/// Stub providers return `ProviderUnsupported` on their first real call;
/// the `CodexPhase1` reader is not a HTTP client and is rejected here so the
/// failure message points at the correct selector.
fn build_client(provider: Provider, cfg: &Config) -> Result<Box<dyn ModelClient>, ExtractError> {
    match provider {
        Provider::Anthropic => Ok(Box::new(AnthropicClient::from_env_with_model(
            &cfg.extractor.model,
            &cfg.extractor.anthropic.api_key_env,
        )?)),
        Provider::OpenAi => Ok(Box::new(OpenAiClient)),
        Provider::Ollama => Ok(Box::new(OllamaClient)),
        Provider::CodexPhase1 => Err(ExtractError::ProviderUnsupported {
            provider: "codex-phase1 is read-only; use a Codex thread id or rollout path with \
                       --session and a real provider"
                .to_owned(),
        }),
    }
}

/// Enforce the first-run consent gate. When `--quiet` is set the verb
/// fails with `EXTRACT_NOT_ACKNOWLEDGED` instead of prompting.
fn enforce_consent(
    paths: &Paths,
    cfg: &Config,
    client: &dyn ModelClient,
    args: &ExtractArgs,
) -> Result<(), ExitCode> {
    let ack_path = paths.state.join("extract_acked.json");
    let ack = match read_ack(&ack_path) {
        Ok(a) => a,
        Err(e) => return Err(emit_error(&ExtractError::Io(e), args.json)),
    };
    if !consent_required(ack.as_ref(), client.provider_name(), &cfg.extractor.model) {
        return Ok(());
    }
    if args.quiet {
        return Err(emit_error(&ExtractError::NotAcknowledged, args.json));
    }
    eprintln!("{}", warning_text(client.provider_name()));
    eprint!("Continue? [y/N]: ");
    if std::io::stderr().flush().is_err() {
        return Err(emit_error(&ExtractError::NotAcknowledged, args.json));
    }
    let mut buf = String::new();
    if std::io::stdin().lock().read_line(&mut buf).is_err() {
        return Err(emit_error(&ExtractError::NotAcknowledged, args.json));
    }
    if !buf.trim().eq_ignore_ascii_case("y") {
        return Err(emit_error(&ExtractError::NotAcknowledged, args.json));
    }
    let record = AckedRecord {
        acked_at: chrono::Utc::now(),
        acked_provider: client.provider_name().to_owned(),
        acked_model_family: model_family(&cfg.extractor.model),
    };
    if let Err(e) = write_ack(&ack_path, &record) {
        return Err(emit_error(&ExtractError::Io(e), args.json));
    }
    Ok(())
}

/// `nexum extract --session <id>`: drive one session through the pipeline.
/// Resolves the selector against three shapes (UUID, rollout path,
/// Codex thread id) before building the digest.
fn run_one_session(
    paths: &Paths,
    cfg: &Config,
    sid: &str,
    client: &dyn ModelClient,
    json: bool,
) -> ExitCode {
    let digest = match resolve_session(paths, cfg, sid) {
        Ok(d) => d,
        Err(e) => return emit_error(&e, json),
    };
    match extract_session_with_client(paths, cfg, &digest, client) {
        Ok(outcome) => {
            emit_session_outcome(
                json,
                &session_id_label(&digest.session_id),
                outcome.committed_record_ids.len(),
                outcome.declined_reason.as_deref(),
                outcome.redaction_event_count,
            );
            ExitCode::SUCCESS
        }
        Err(api_err) => {
            let env: ErrorEnvelope = (&api_err).into();
            let code = exit_codes::for_envelope(&env);
            if json {
                json_emit::emit_error(&env, code)
            } else {
                eprintln!("error: {api_err}");
                ExitCode::from(code)
            }
        }
    }
}

/// `nexum extract --since <duration>`: discover candidate sessions in
/// the window, build each digest, and run them through the pipeline.
/// Per-session digest failures are skipped (the batch never aborts because
/// one session is empty); the per-session arm of the summary records the
/// outcome either way.
fn run_since(
    paths: &Paths,
    cfg: &Config,
    since: &str,
    client: &dyn ModelClient,
    json: bool,
) -> ExitCode {
    let duration = match parse_since(since) {
        Ok(d) => d,
        Err(e) => return emit_error(&e, json),
    };
    let cutoff = chrono::Utc::now() - duration;
    let mut candidates: Vec<Candidate> = Vec::new();
    if cfg.adapters.cc.enabled {
        match discover_cc_sessions(Path::new(&cfg.adapters.cc.projects_dir), Some(cutoff)) {
            Ok(mut c) => candidates.append(&mut c),
            Err(e) => return emit_error(&e, json),
        }
    }
    if cfg.adapters.codex.enabled {
        match discover_codex_sessions(Path::new(&cfg.adapters.codex.state_db), Some(cutoff)) {
            Ok(mut c) => candidates.append(&mut c),
            Err(e) => return emit_error(&e, json),
        }
    }
    if candidates.is_empty() {
        return emit_error(&ExtractError::NoSessions, json);
    }
    let mut summary_rows: Vec<serde_json::Value> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let digest = match build_digest_for_candidate(&candidate) {
            Ok(d) => d,
            Err(e) => {
                summary_rows.push(serde_json::json!({
                    "session": session_id_label(&candidate.session_id),
                    "error": e.to_string(),
                }));
                continue;
            }
        };
        let outcome = extract_session_with_client(paths, cfg, &digest, client);
        let row = match outcome {
            Ok(o) => serde_json::json!({
                "session": session_id_label(&candidate.session_id),
                "committed": o.committed_record_ids.len(),
                "declined_reason": o.declined_reason,
                "redaction_event_count": o.redaction_event_count,
            }),
            Err(api_err) => {
                let env: ErrorEnvelope = (&api_err).into();
                serde_json::json!({
                    "session": session_id_label(&candidate.session_id),
                    "error_code": env.error_code,
                    "error": api_err.to_string(),
                })
            }
        };
        summary_rows.push(row);
    }
    let summary = serde_json::json!({ "per_session": summary_rows });
    if json {
        match serde_json::to_string_pretty(&summary) {
            Ok(s) => println!("{s}"),
            Err(e) => return json_emit::emit_serialize_failure(&e),
        }
    } else {
        for row in &summary_rows {
            let session = row
                .get("session")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            if let Some(err_msg) = row.get("error").and_then(|v| v.as_str()) {
                println!("{session}: error: {err_msg}");
            } else {
                let committed = row
                    .get("committed")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                println!("{session}: committed {committed} record(s)");
            }
        }
    }
    ExitCode::SUCCESS
}

/// `nexum extract --backfill --dry-run`: discover every candidate, count
/// tokens, estimate cost, and write a manifest under `paths.extract`. The
/// committed records are untouched; this verb is the read-side projection
/// the operator inspects before authorizing the commit pass.
fn run_backfill_dry_run(
    paths: &Paths,
    cfg: &Config,
    client: &dyn ModelClient,
    json: bool,
) -> ExitCode {
    let out_dir = paths.extract.clone();
    match nexum_core::api::extract_backfill_dry_run(paths, cfg, client, &out_dir) {
        Ok(manifest) => {
            if json {
                match serde_json::to_string_pretty(&manifest) {
                    Ok(s) => println!("{s}"),
                    Err(e) => return json_emit::emit_serialize_failure(&e),
                }
            } else {
                println!(
                    "dry_run_id: {}\ncandidate_count: {}\ntotal_estimated_cost_usd: {:.4}",
                    manifest.dry_run_id,
                    manifest.candidate_count,
                    manifest.total_estimated_cost_usd
                );
            }
            ExitCode::SUCCESS
        }
        Err(api_err) => {
            let env: ErrorEnvelope = (&api_err).into();
            let code = exit_codes::for_envelope(&env);
            if json {
                json_emit::emit_error(&env, code)
            } else {
                eprintln!("error: {api_err}");
                ExitCode::from(code)
            }
        }
    }
}

/// Resolve a `--session` selector to a [`SessionDigest`]. The three
/// shapes are: a CC UUID (resolved against `cfg.adapters.cc.projects_dir`),
/// a Codex rollout path (filesystem-existing), or a Codex `threads.id`
/// (looked up in `cfg.adapters.codex.state_db`).
fn resolve_session(paths: &Paths, cfg: &Config, sid: &str) -> Result<SessionDigest, ExtractError> {
    if let Ok(uuid) = Uuid::parse_str(sid) {
        let path = resolve_cc_transcript_path(cfg, paths, uuid).ok_or_else(|| {
            ExtractError::Validation {
                reason: format!(
                    "no CC transcript matching {uuid} under {}",
                    cfg.adapters.cc.projects_dir
                ),
            }
        })?;
        return build_cc_digest(&path, uuid).map_err(ExtractError::from);
    }
    let as_path = Path::new(sid);
    if as_path.exists() {
        return build_codex_digest(as_path).map_err(ExtractError::from);
    }
    let rollout = resolve_codex_thread_to_path(cfg, sid)?;
    build_codex_digest(&rollout).map_err(ExtractError::from)
}

/// Build a digest from a candidate discovered via `--since`. CC entries
/// carry a `Cc(uuid)` session id; Codex entries carry a `CodexThread`
/// id and a rollout-file path.
fn build_digest_for_candidate(candidate: &Candidate) -> Result<SessionDigest, ExtractError> {
    match &candidate.session_id {
        SessionId::Cc(uuid) => {
            build_cc_digest(&candidate.source_path, *uuid).map_err(ExtractError::from)
        }
        SessionId::CodexThread(_) | SessionId::CodexRolloutPath(_) => {
            build_codex_digest(&candidate.source_path).map_err(ExtractError::from)
        }
    }
}

/// Locate the on-disk `<uuid>.jsonl` for a CC session. CC stores
/// transcripts under `<projects_dir>/<cwd-slug>/<uuid>.jsonl`; the slug
/// is not stable, so we glob one level deep. Returns `None` when no
/// match is found (caller surfaces the appropriate `Validation` error).
///
/// `paths` is unused today but kept on the signature to leave room for a
/// future fall-through that resolves a transcript copy under
/// `paths.extract` once that path is wired.
fn resolve_cc_transcript_path(cfg: &Config, _paths: &Paths, uuid: Uuid) -> Option<PathBuf> {
    let projects_dir = Path::new(&cfg.adapters.cc.projects_dir);
    if !projects_dir.exists() {
        return None;
    }
    let filename = format!("{uuid}.jsonl");
    walkdir::WalkDir::new(projects_dir)
        .min_depth(2)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_str() == Some(filename.as_str()))
        .map(|e| e.path().to_path_buf())
}

/// Look up a Codex `threads.id` in `state_5.sqlite` and return its
/// `rollout_path`. Surfaces `Validation` (not `Io`) when the thread is
/// missing so the agent sees an actionable error code.
fn resolve_codex_thread_to_path(cfg: &Config, thread_id: &str) -> Result<PathBuf, ExtractError> {
    let state_db = Path::new(&cfg.adapters.codex.state_db);
    if !state_db.exists() {
        return Err(ExtractError::Validation {
            reason: format!(
                "Codex state DB not found at {} (and `{thread_id}` is not a file path or UUID)",
                cfg.adapters.codex.state_db
            ),
        });
    }
    let conn = rusqlite::Connection::open(state_db).map_err(|e| {
        ExtractError::Io(std::io::Error::other(format!(
            "open {}: {e}",
            cfg.adapters.codex.state_db
        )))
    })?;
    match conn.query_row(
        "SELECT rollout_path FROM threads WHERE id = ?1",
        [thread_id],
        |row| row.get::<_, String>(0),
    ) {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(ExtractError::Validation {
            reason: format!("no Codex thread with id `{thread_id}`"),
        }),
        Err(e) => Err(ExtractError::Io(std::io::Error::other(e.to_string()))),
    }
}

/// Emit a single-session outcome on the channel selected by `json`.
fn emit_session_outcome(
    json: bool,
    session_label: &str,
    committed: usize,
    declined: Option<&str>,
    redaction_events: u32,
) {
    if json {
        let body = serde_json::json!({
            "session": session_label,
            "committed": committed,
            "declined_reason": declined,
            "redaction_event_count": redaction_events,
        });
        match serde_json::to_string_pretty(&body) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("serialize: {e}"),
        }
    } else if let Some(reason) = declined {
        println!("{session_label}: declined ({reason})");
    } else {
        println!("{session_label}: committed {committed} record(s)");
    }
}

/// Stable text label for a [`SessionId`] — UUID for CC, rollout path for
/// Codex-by-path, thread id for Codex-by-thread. Used in operator-facing
/// summary lines and in the `--since` per-session JSON rows.
fn session_id_label(id: &SessionId) -> String {
    match id {
        SessionId::Cc(u) => u.to_string(),
        SessionId::CodexRolloutPath(p) => p.display().to_string(),
        SessionId::CodexThread(t) => t.clone(),
    }
    // SessionKind is intentionally not included — the digest renderer
    // already prefixes the upstream-source distinction where it matters.
}

/// Render an [`ExtractError`] through the wire-stable envelope. Builds
/// the envelope directly via [`nexum_core::api::error::extract_envelope`]
/// because `ExtractError` is not `Clone` and constructing the
/// `ApiError::Extraction` intermediary requires ownership.
fn emit_error(err: &ExtractError, json: bool) -> ExitCode {
    let env = nexum_core::api::error::extract_envelope(err);
    let code = exit_codes::for_envelope(&env);
    if json {
        json_emit::emit_error(&env, code)
    } else {
        eprintln!("error: {err}");
        ExitCode::from(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexum_core::extract::digest::SessionKind;

    #[test]
    fn session_id_label_cc_renders_uuid() {
        let uuid = uuid::Uuid::nil();
        assert_eq!(
            session_id_label(&SessionId::Cc(uuid)),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn session_id_label_codex_thread_renders_id() {
        assert_eq!(
            session_id_label(&SessionId::CodexThread("thread-xyz".into())),
            "thread-xyz"
        );
    }

    #[test]
    fn build_digest_for_candidate_dispatches_on_session_id_kind() {
        // We only verify the dispatch arm; the actual digest builders own
        // their own coverage. A nonexistent path makes both arms surface
        // a structured Digest error rather than panicking on the match.
        let cc = Candidate {
            session_id: SessionId::Cc(uuid::Uuid::nil()),
            kind: SessionKind::CcTranscript,
            source_path: PathBuf::from("/does/not/exist.jsonl"),
            estimated_size_bytes: 0,
        };
        let cc_err = build_digest_for_candidate(&cc).unwrap_err();
        assert!(matches!(cc_err, ExtractError::Digest(_)));

        let codex = Candidate {
            session_id: SessionId::CodexThread("t".into()),
            kind: SessionKind::CodexThread {
                thread_id: "t".into(),
            },
            source_path: PathBuf::from("/does/not/exist.jsonl"),
            estimated_size_bytes: 0,
        };
        let codex_err = build_digest_for_candidate(&codex).unwrap_err();
        assert!(matches!(codex_err, ExtractError::Digest(_)));
    }
}
