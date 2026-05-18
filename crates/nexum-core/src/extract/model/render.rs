//! Render a `SessionDigest` into the user-message content string. Kept
//! provider-agnostic so the `OpenAI` / Ollama stubs can reuse it when they
//! grow real implementations.

use std::fmt::Write as _;

use crate::extract::digest::{MessageTurn, SessionDigest, SessionKind, ToolCallSummary};

#[must_use]
pub(crate) fn render_digest(digest: &SessionDigest) -> String {
    let mut out = String::with_capacity(8192);
    out.push_str("# Session digest\n\n");
    render_session_id(&mut out, digest);
    render_metadata(&mut out, digest);
    render_turns(&mut out, "## User messages", &digest.user_turns);
    render_turns(&mut out, "## Assistant messages", &digest.assistant_turns);
    render_tool_calls(&mut out, &digest.tool_calls);
    render_plan_final(&mut out, digest);
    render_non_zero_exits(&mut out, digest);
    out
}

fn render_session_id(out: &mut String, digest: &SessionDigest) {
    out.push_str("## Session reference\n\n");
    match &digest.session_kind {
        SessionKind::CcTranscript => out.push_str("- kind: cc_session\n"),
        SessionKind::CodexRollout => out.push_str("- kind: codex_rollout\n"),
        SessionKind::CodexThread { thread_id } => {
            let _ = writeln!(out, "- kind: codex_thread\n- thread_id: {thread_id}");
        }
    }
    out.push('\n');
}

fn render_metadata(out: &mut String, digest: &SessionDigest) {
    out.push_str("## Metadata\n\n");
    if let Some(t) = digest.metadata.started {
        let _ = writeln!(out, "- started: {t}");
    }
    if let Some(t) = digest.metadata.ended {
        let _ = writeln!(out, "- ended: {t}");
    }
    if let Some(cwd) = &digest.metadata.cwd {
        let _ = writeln!(out, "- cwd: {}", cwd.display());
    }
    if let Some(sha) = &digest.metadata.git_commit {
        let _ = writeln!(out, "- git_commit: {sha}");
    }
    if let Some(b) = &digest.metadata.git_branch {
        let _ = writeln!(out, "- git_branch: {b}");
    }
    if let Some(u) = &digest.metadata.git_repository_url {
        let _ = writeln!(out, "- git_repository_url: {u}");
    }
    out.push('\n');
}

fn render_turns(out: &mut String, heading: &str, turns: &[MessageTurn]) {
    if turns.is_empty() {
        return;
    }
    out.push_str(heading);
    out.push_str("\n\n");
    for turn in turns {
        out.push_str("---\n");
        out.push_str(&turn.content);
        if !turn.content.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push('\n');
}

fn render_tool_calls(out: &mut String, calls: &[ToolCallSummary]) {
    if calls.is_empty() {
        return;
    }
    out.push_str("## Tool calls (compressed)\n\n");
    for call in calls {
        let _ = writeln!(out, "- name: {}", call.name);
        let _ = writeln!(out, "  args: {}", call.args_sketch);
        if !call.output_excerpt.is_empty() {
            let _ = writeln!(out, "  output: {}", call.output_excerpt);
        }
        if let Some(code) = call.exit_code {
            let _ = writeln!(out, "  exit_code: {code}");
        }
    }
    out.push('\n');
}

fn render_plan_final(out: &mut String, digest: &SessionDigest) {
    if let Some(plan) = &digest.plan_final {
        out.push_str("## Final plan\n\n");
        for step in &plan.steps {
            let _ = writeln!(out, "- [{}] {}", step.status, step.text);
        }
        out.push('\n');
    }
}

fn render_non_zero_exits(out: &mut String, digest: &SessionDigest) {
    if digest.non_zero_exits.is_empty() {
        return;
    }
    out.push_str("## Non-zero exits\n\n");
    for line in &digest.non_zero_exits {
        let _ = writeln!(out, "- {line}");
    }
    out.push('\n');
}
