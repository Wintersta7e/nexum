//! Append-only JSONL log of redaction events. Each line is one redaction
//! event with the source session id attached. The plain text of the
//! matched substring is never written; only its sha256 prefix.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::types::RedactionEvent;

#[derive(Serialize)]
struct LogLine<'a> {
    redacted_at: DateTime<Utc>,
    session_id: &'a str,
    pattern: &'a str,
    before_hash: &'a str,
    context_window_hash: &'a str,
}

/// Append one entry per `event` to `log_path`. Creates the file (and parent
/// dir) on first call.
///
/// # Errors
/// Filesystem errors only.
///
/// # Panics
/// Panics only if the internal `LogLine` value fails to serialize to JSON;
/// every field is a borrowed primitive, so this is a programmer bug rather
/// than a runtime condition.
pub fn append_redaction_log(
    events: &[RedactionEvent],
    session_id: &str,
    log_path: &Path,
) -> io::Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let now = Utc::now();
    for event in events {
        let line = LogLine {
            redacted_at: now,
            session_id,
            pattern: event.pattern_name.as_str(),
            before_hash: event.before_hash.as_str(),
            context_window_hash: event.context_window_hash.as_str(),
        };
        let serialized = serde_json::to_string(&line).expect("LogLine serializes");
        writeln!(file, "{serialized}")?;
    }
    Ok(())
}
