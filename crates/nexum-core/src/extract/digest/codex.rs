//! Codex JSONL → `SessionDigest`.
//!
//! Stream-parses one envelope per line: `{type, timestamp, payload}`. The
//! discriminant on `payload.type` selects how `response_item` payloads
//! contribute to the digest. The parser is forward-only and single-pass —
//! `function_call_output` lines reach back to their owning `function_call`
//! by `call_id` via a small `HashMap`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::types::{
    BuildDigestError, MessageTurn, PlanFinal, PlanStep, ProjectHint, SessionDigest, SessionId,
    SessionKind, SessionMetadata, ToolCallSummary, TurnRole,
};

/// Parse a Codex rollout JSONL file at `path` into a `SessionDigest`.
///
/// # Errors
/// `BuildDigestError::Io` for filesystem errors. `BuildDigestError::Malformed`
/// for syntactically invalid lines. `BuildDigestError::Empty` if no
/// extractable content remained after parsing.
pub fn build_codex_digest(path: &Path) -> Result<SessionDigest, BuildDigestError> {
    let file = File::open(path).map_err(|source| BuildDigestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);

    let mut digest = SessionDigest {
        session_kind: SessionKind::CodexRollout,
        session_id: SessionId::CodexRolloutPath(path.to_path_buf()),
        project_hint: None,
        metadata: SessionMetadata::default(),
        user_turns: Vec::new(),
        assistant_turns: Vec::new(),
        tool_calls: Vec::new(),
        plan_final: None,
        non_zero_exits: Vec::new(),
    };

    // call_id -> index into digest.tool_calls, so a function_call_output line
    // can fill in the matching call's output_excerpt and exit_code.
    let mut tool_index: HashMap<String, usize> = HashMap::new();
    // Track the most recent update_plan args so we can write plan_final at the end.
    let mut last_plan: Option<PlanFinal> = None;

    for (line_no_zero, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| BuildDigestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let line_no = line_no_zero + 1;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Envelope =
            serde_json::from_str(&line).map_err(|e| BuildDigestError::Malformed {
                path: path.to_path_buf(),
                line_no,
                reason: e.to_string(),
            })?;

        match envelope.kind.as_str() {
            "session_meta" => apply_session_meta(&envelope, &mut digest),
            "response_item" => {
                apply_response_item(&envelope, &mut digest, &mut tool_index, &mut last_plan);
            }
            _ => {} // turn_context, event_msg, unknown - ignore
        }
    }

    digest.plan_final = last_plan;
    if digest.is_empty() {
        return Err(BuildDigestError::Empty);
    }
    Ok(digest)
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    payload: serde_json::Value,
}

#[derive(Deserialize)]
struct SessionMetaPayload {
    cli_version: Option<String>,
    cwd: Option<String>,
    git: Option<SessionMetaGit>,
    id: Option<String>,
    model_provider: Option<String>,
    timestamp: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct SessionMetaGit {
    commit_hash: Option<String>,
    branch: Option<String>,
    repository_url: Option<String>,
}

fn apply_session_meta(env: &Envelope, digest: &mut SessionDigest) {
    let Ok(payload) = serde_json::from_value::<SessionMetaPayload>(env.payload.clone()) else {
        return; // tolerate shape drift - treat unknown shape as no metadata
    };
    digest.metadata.started = payload.timestamp.or(env.timestamp);
    digest.metadata.cli_version = payload.cli_version;
    digest.metadata.model = payload.model_provider;
    let cwd = payload.cwd.map(PathBuf::from);
    if let Some(git) = payload.git {
        digest.project_hint = Some(ProjectHint {
            git_repository_url: git.repository_url.clone(),
            cwd: cwd.clone(),
            project_id_guess: None,
        });
        digest.metadata.git_commit = git.commit_hash;
        digest.metadata.git_branch = git.branch;
        digest.metadata.git_repository_url = git.repository_url;
    }
    digest.metadata.cwd = cwd;
    if let Some(id) = payload.id {
        // Promote thread id to SessionKind::CodexThread if we found one.
        digest.session_kind = SessionKind::CodexThread { thread_id: id };
    }
}

fn apply_response_item(
    env: &Envelope,
    digest: &mut SessionDigest,
    tool_index: &mut HashMap<String, usize>,
    last_plan: &mut Option<PlanFinal>,
) {
    let Some(kind) = env.payload.get("type").and_then(serde_json::Value::as_str) else {
        return;
    };
    // "reasoning" payloads are encrypted to the upstream provider; they fall
    // through the wildcard arm and contribute nothing to the digest.
    match kind {
        "message" => apply_message(env, digest),
        "function_call" => apply_function_call(env, digest, tool_index, last_plan),
        "function_call_output" => apply_function_call_output(env, digest, tool_index),
        _ => {}
    }
}

fn apply_message(env: &Envelope, digest: &mut SessionDigest) {
    let role = env.payload.get("role").and_then(serde_json::Value::as_str);
    let content = env
        .payload
        .get("content")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let turn = MessageTurn {
        role: match role {
            Some("assistant") => TurnRole::Assistant,
            _ => TurnRole::User,
        },
        content,
        timestamp: env.timestamp,
    };
    match turn.role {
        TurnRole::User => digest.user_turns.push(turn),
        TurnRole::Assistant => digest.assistant_turns.push(turn),
    }
}

fn apply_function_call(
    env: &Envelope,
    digest: &mut SessionDigest,
    tool_index: &mut HashMap<String, usize>,
    last_plan: &mut Option<PlanFinal>,
) {
    let name = env
        .payload
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let args_str = env
        .payload
        .get("arguments")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let call_id = env
        .payload
        .get("call_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();

    if name == "update_plan"
        && let Some(plan) = parse_update_plan_args(&args_str)
    {
        *last_plan = Some(plan);
    }

    let summary = ToolCallSummary {
        name,
        args_sketch: ToolCallSummary::truncate_chars(
            &args_str,
            ToolCallSummary::ARGS_SKETCH_MAX_CHARS,
        ),
        output_excerpt: String::new(),
        exit_code: None,
    };
    // Skip an empty call_id so two id-less calls cannot overwrite each other in
    // the index; the call still gets recorded, it just cannot be back-filled.
    if !call_id.is_empty() {
        tool_index.insert(call_id, digest.tool_calls.len());
    }
    digest.tool_calls.push(summary);
}

fn apply_function_call_output(
    env: &Envelope,
    digest: &mut SessionDigest,
    tool_index: &HashMap<String, usize>,
) {
    let call_id = env
        .payload
        .get("call_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let output = env
        .payload
        .get("output")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    if let Some(&idx) = tool_index.get(call_id) {
        let call = &mut digest.tool_calls[idx];
        call.output_excerpt =
            ToolCallSummary::truncate_chars(output, ToolCallSummary::OUTPUT_EXCERPT_MAX_CHARS);
        if let Some(code) = parse_exit_code(output) {
            call.exit_code = Some(code);
            if code != 0 {
                digest
                    .non_zero_exits
                    .push(format!("{} exited code {code}", call.name));
            }
        }
    }
}

fn parse_exit_code(output: &str) -> Option<i32> {
    // Format observed in real Codex sessions:
    //   "...\nProcess exited with code N\n"
    output.lines().rev().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("Process exited with code ")
            .and_then(|rest| rest.parse().ok())
    })
}

#[derive(Deserialize)]
struct UpdatePlanArgs {
    plan: Vec<UpdatePlanStep>,
}

#[derive(Deserialize)]
struct UpdatePlanStep {
    step: String,
    status: String,
}

fn parse_update_plan_args(args: &str) -> Option<PlanFinal> {
    let parsed: UpdatePlanArgs = serde_json::from_str(args).ok()?;
    Some(PlanFinal {
        steps: parsed
            .plan
            .into_iter()
            .map(|s| PlanStep {
                text: s.step,
                status: s.status,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_exit_code;

    #[test]
    fn parse_exit_code_typical() {
        let output = "stdout\nstderr\nProcess exited with code 1\n";
        assert_eq!(parse_exit_code(output), Some(1));
    }

    #[test]
    fn parse_exit_code_negative() {
        let output = "Process exited with code -1\n";
        assert_eq!(parse_exit_code(output), Some(-1));
    }

    #[test]
    fn parse_exit_code_absent_returns_none() {
        assert_eq!(parse_exit_code("no exit line\n"), None);
    }
}
