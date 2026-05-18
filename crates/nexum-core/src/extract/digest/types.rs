//! Type definitions for the session-digest layer. All types are owned (no
//! borrows from the source JSONL), so a digest can outlive the file it was
//! built from. The `ModelClient` impls serialize this into the model's
//! request body and a `RedactionEngine` pass mutates `content` strings
//! in-place before transmission.

use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDigest {
    pub session_kind: SessionKind,
    pub session_id: SessionId,
    pub project_hint: Option<ProjectHint>,
    pub metadata: SessionMetadata,
    pub user_turns: Vec<MessageTurn>,
    pub assistant_turns: Vec<MessageTurn>,
    pub tool_calls: Vec<ToolCallSummary>,
    pub plan_final: Option<PlanFinal>,
    pub non_zero_exits: Vec<String>,
}

impl SessionDigest {
    /// True when the digest carries no user input, no assistant prose, no
    /// tool calls, no plan, and no non-zero exits. Such a digest is not
    /// worth sending — `BuildDigestError::Empty` is the canonical reject.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user_turns.is_empty()
            && self.assistant_turns.is_empty()
            && self.tool_calls.is_empty()
            && self.plan_final.is_none()
            && self.non_zero_exits.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    CodexRollout,
    CodexThread { thread_id: String },
    CcTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionId {
    /// CC transcript: filename UUID.
    Cc(Uuid),
    /// Codex rollout: full path to the `.jsonl` file.
    CodexRolloutPath(PathBuf),
    /// Codex thread row: `threads.id` from `state_5.sqlite`.
    CodexThread(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectHint {
    pub git_repository_url: Option<String>,
    pub cwd: Option<PathBuf>,
    pub project_id_guess: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionMetadata {
    pub started: Option<DateTime<Utc>>,
    pub ended: Option<DateTime<Utc>>,
    pub cwd: Option<PathBuf>,
    pub git_commit: Option<String>,
    pub git_branch: Option<String>,
    pub git_repository_url: Option<String>,
    pub model: Option<String>,
    pub cli_version: Option<String>,
    pub tokens_used: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTurn {
    pub role: TurnRole,
    /// The user/assistant text. Pre-redaction this is the verbatim source;
    /// post-redaction the `RedactionEngine` has replaced secret-shaped
    /// substrings with `[REDACTED:<type>]`. Either way it is owned.
    pub content: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallSummary {
    pub name: String,
    /// Truncated argument sketch — first `ARGS_SKETCH_MAX_CHARS` chars of the
    /// JSON-encoded arguments, with a trailing `…` marker if truncated.
    pub args_sketch: String,
    /// Truncated output excerpt — first `OUTPUT_EXCERPT_MAX_CHARS` chars.
    pub output_excerpt: String,
    pub exit_code: Option<i32>,
}

impl ToolCallSummary {
    pub const ARGS_SKETCH_MAX_CHARS: usize = 300;
    pub const OUTPUT_EXCERPT_MAX_CHARS: usize = 500;

    /// Truncate `s` to `max` chars, appending `…` if and only if the input
    /// exceeded `max` chars (not bytes — Rust's `char_indices` is the unit).
    #[must_use]
    pub fn truncate_chars(s: &str, max: usize) -> String {
        let mut out = String::new();
        for (i, ch) in s.chars().enumerate() {
            if i >= max {
                out.push('…');
                return out;
            }
            out.push(ch);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanFinal {
    pub steps: Vec<PlanStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub text: String,
    /// Preserved verbatim from the upstream session, so consumers can
    /// distinguish "in-progress" / "`in_progress`" / "in progress" without the
    /// digest enforcing a canonical spelling.
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BuildDigestError {
    #[error("I/O reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("malformed line {line_no} in {path}: {reason}")]
    Malformed {
        path: PathBuf,
        line_no: usize,
        reason: String,
    },
    #[error("session has no extractable content")]
    Empty,
}

#[cfg(test)]
mod truncate_tests {
    use super::ToolCallSummary;

    #[test]
    fn truncate_chars_passthrough_under_max() {
        assert_eq!(ToolCallSummary::truncate_chars("abc", 10), "abc");
    }

    #[test]
    fn truncate_chars_exact_max_no_ellipsis() {
        let input: String = (0..10).map(|_| 'a').collect();
        let out = ToolCallSummary::truncate_chars(&input, 10);
        assert_eq!(out, input);
    }

    #[test]
    fn truncate_chars_over_max_adds_ellipsis() {
        let input: String = (0..12).map(|_| 'a').collect();
        let out = ToolCallSummary::truncate_chars(&input, 10);
        assert_eq!(out.chars().count(), 11); // 10 + '…'
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_chars_unicode_safe() {
        let input = "α".repeat(15);
        let out = ToolCallSummary::truncate_chars(&input, 10);
        assert_eq!(out.chars().count(), 11);
        assert!(out.ends_with('…'));
    }
}
