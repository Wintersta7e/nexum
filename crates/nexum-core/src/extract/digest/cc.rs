//! CC transcript JSONL → `SessionDigest`.
//!
//! The CC line shape is `{type, timestamp?, message?, ...}`. `user` and
//! `assistant` lines carry an inner `message` whose `content` is either a
//! string or an array of typed blocks (`text`, `tool_use`, `tool_result`).
//! `tool_result` blocks live in `user` lines but reference an earlier
//! `assistant` line's `tool_use` block via `tool_use_id`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::types::{
    BuildDigestError, MessageTurn, SessionDigest, SessionId, SessionKind, SessionMetadata,
    ToolCallSummary, TurnRole, parse_exit_code,
};

/// Parse a CC transcript JSONL file at `path` into a `SessionDigest`.
///
/// `session_uuid` is the filename-minus-extension UUID. The caller resolves
/// this since the path-to-uuid mapping is filesystem-conventional and not
/// the parser's concern.
///
/// # Errors
/// `BuildDigestError::Io` for filesystem errors. `BuildDigestError::Malformed`
/// for syntactically invalid lines. `BuildDigestError::Empty` if no
/// extractable content remained.
pub fn build_cc_digest(path: &Path, session_uuid: Uuid) -> Result<SessionDigest, BuildDigestError> {
    let file = File::open(path).map_err(|source| BuildDigestError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);

    let mut digest = SessionDigest {
        session_kind: SessionKind::CcTranscript,
        session_id: SessionId::Cc(session_uuid),
        project_hint: None,
        metadata: SessionMetadata::default(),
        user_turns: Vec::new(),
        assistant_turns: Vec::new(),
        tool_calls: Vec::new(),
        plan_final: None,
        non_zero_exits: Vec::new(),
    };

    // tool_use.id -> index into digest.tool_calls, so a tool_result block on
    // a later user line can back-fill the matching call's output and exit code.
    let mut tool_index: HashMap<String, usize> = HashMap::new();
    let mut first_timestamp: Option<DateTime<Utc>> = None;
    let mut last_timestamp: Option<DateTime<Utc>> = None;

    for (line_no_zero, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| BuildDigestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let line_no = line_no_zero + 1;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| BuildDigestError::Malformed {
                path: path.to_path_buf(),
                line_no,
                reason: e.to_string(),
            })?;

        let kind = envelope.get("type").and_then(serde_json::Value::as_str);

        let ts = envelope
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        if let Some(t) = ts {
            first_timestamp.get_or_insert(t);
            last_timestamp = Some(t);
        }

        match kind {
            Some("user") => apply_user_line(&envelope, &mut digest, &tool_index, ts),
            Some("assistant") => apply_assistant_line(&envelope, &mut digest, &mut tool_index, ts),
            _ => {} // permission-mode, last-prompt, hook attachments, unknown
        }
    }

    digest.metadata.started = first_timestamp;
    digest.metadata.ended = last_timestamp;
    if digest.is_empty() {
        return Err(BuildDigestError::Empty);
    }
    Ok(digest)
}

#[derive(Deserialize)]
struct CcMessage {
    /// CC's content is either a single string or an array of typed blocks.
    /// `serde_json::Value` keeps the polymorphism without a custom visitor.
    content: serde_json::Value,
}

fn extract_message(value: &serde_json::Value) -> Option<CcMessage> {
    let msg = value.get("message")?;
    serde_json::from_value::<CcMessage>(msg.clone()).ok()
}

fn apply_user_line(
    line: &serde_json::Value,
    digest: &mut SessionDigest,
    tool_index: &HashMap<String, usize>,
    ts: Option<DateTime<Utc>>,
) {
    let Some(msg) = extract_message(line) else {
        return;
    };
    if let Some(text) = msg.content.as_str() {
        // Plain-string user message - verbatim user turn.
        digest.user_turns.push(MessageTurn {
            role: TurnRole::User,
            content: text.to_owned(),
            timestamp: ts,
        });
        return;
    }
    let Some(blocks) = msg.content.as_array() else {
        return;
    };
    let mut user_text_parts: Vec<String> = Vec::new();
    for block in blocks {
        let block_type = block.get("type").and_then(serde_json::Value::as_str);
        match block_type {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(serde_json::Value::as_str) {
                    user_text_parts.push(t.to_owned());
                }
            }
            Some("tool_result") => {
                if let (Some(tu_id), Some(content)) = (
                    block.get("tool_use_id").and_then(serde_json::Value::as_str),
                    block.get("content").and_then(content_as_string),
                ) && let Some(&idx) = tool_index.get(tu_id)
                {
                    let call = &mut digest.tool_calls[idx];
                    call.output_excerpt = ToolCallSummary::truncate_chars(
                        &content,
                        ToolCallSummary::OUTPUT_EXCERPT_MAX_CHARS,
                    );
                    if let Some(code) = parse_exit_code(&content) {
                        call.exit_code = Some(code);
                        if code != 0 {
                            digest
                                .non_zero_exits
                                .push(format!("{} exited code {code}", call.name));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !user_text_parts.is_empty() {
        digest.user_turns.push(MessageTurn {
            role: TurnRole::User,
            content: user_text_parts.join("\n"),
            timestamp: ts,
        });
    }
}

fn apply_assistant_line(
    line: &serde_json::Value,
    digest: &mut SessionDigest,
    tool_index: &mut HashMap<String, usize>,
    ts: Option<DateTime<Utc>>,
) {
    let Some(msg) = extract_message(line) else {
        return;
    };
    if let Some(text) = msg.content.as_str() {
        digest.assistant_turns.push(MessageTurn {
            role: TurnRole::Assistant,
            content: text.to_owned(),
            timestamp: ts,
        });
        return;
    }
    let Some(blocks) = msg.content.as_array() else {
        return;
    };
    let mut text_parts: Vec<String> = Vec::new();
    for block in blocks {
        let block_type = block.get("type").and_then(serde_json::Value::as_str);
        match block_type {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(serde_json::Value::as_str) {
                    text_parts.push(t.to_owned());
                }
            }
            Some("tool_use") => {
                let name = block
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let id = block
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let args = block
                    .get("input")
                    .map(serde_json::Value::to_string)
                    .unwrap_or_default();
                let summary = ToolCallSummary {
                    name,
                    args_sketch: ToolCallSummary::truncate_chars(
                        &args,
                        ToolCallSummary::ARGS_SKETCH_MAX_CHARS,
                    ),
                    output_excerpt: String::new(),
                    exit_code: None,
                };
                // Skip an empty id so two id-less calls cannot overwrite each
                // other in the index; the call still gets recorded.
                if !id.is_empty() {
                    tool_index.insert(id, digest.tool_calls.len());
                }
                digest.tool_calls.push(summary);
            }
            _ => {}
        }
    }
    if !text_parts.is_empty() {
        digest.assistant_turns.push(MessageTurn {
            role: TurnRole::Assistant,
            content: text_parts.join("\n"),
            timestamp: ts,
        });
    }
}

/// `tool_result.content` is either a plain string or `[{type: "text", text: "..."}, ...]`.
/// Collapse to a single string.
fn content_as_string(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_owned());
    }
    if let Some(arr) = v.as_array() {
        let parts: Vec<&str> = arr
            .iter()
            .filter_map(|b| b.get("text").and_then(serde_json::Value::as_str))
            .collect();
        return Some(parts.join("\n"));
    }
    None
}
