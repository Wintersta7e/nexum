//! End-to-end tests for the Codex JSONL → `SessionDigest` parser.

use std::path::PathBuf;

use nexum_core::extract::digest::{BuildDigestError, TurnRole, build_codex_digest};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/extract/codex")
        .join(name)
}

#[test]
fn empty_session_returns_empty_error() {
    let err = build_codex_digest(&fixture("empty.jsonl")).unwrap_err();
    assert!(matches!(err, BuildDigestError::Empty));
}

#[test]
fn rich_session_populates_metadata_from_session_meta() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    assert_eq!(digest.metadata.cli_version.as_deref(), Some("0.130.0"));
    assert_eq!(digest.metadata.git_commit.as_deref(), Some("abc1234"));
    assert_eq!(digest.metadata.git_branch.as_deref(), Some("main"));
    assert_eq!(
        digest.metadata.git_repository_url.as_deref(),
        Some("https://example.invalid/repo"),
    );
}

#[test]
fn rich_session_collects_user_and_assistant_turns() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    assert_eq!(digest.user_turns.len(), 1);
    assert_eq!(digest.assistant_turns.len(), 1);
    assert_eq!(digest.user_turns[0].role, TurnRole::User);
    assert!(digest.user_turns[0].content.starts_with("please fix"));
    assert_eq!(digest.assistant_turns[0].role, TurnRole::Assistant);
}

#[test]
fn rich_session_pairs_calls_with_outputs() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    // Two shell_command + two update_plan = four tool calls (reasoning excluded).
    assert_eq!(digest.tool_calls.len(), 4);
    let shells: Vec<_> = digest
        .tool_calls
        .iter()
        .filter(|t| t.name == "shell_command")
        .collect();
    assert_eq!(shells.len(), 2);
    assert_eq!(shells[0].exit_code, Some(1));
    assert_eq!(shells[1].exit_code, Some(0));
}

#[test]
fn rich_session_captures_last_update_plan_as_plan_final() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    let plan = digest.plan_final.as_ref().expect("plan_final present");
    assert_eq!(plan.steps.len(), 3);
    // The last update_plan has all steps completed.
    assert!(plan.steps.iter().all(|s| s.status == "completed"));
}

#[test]
fn rich_session_records_non_zero_exits() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    assert_eq!(digest.non_zero_exits.len(), 1);
    assert!(digest.non_zero_exits[0].contains("shell_command"));
    assert!(digest.non_zero_exits[0].contains('1'));
}

#[test]
fn rich_session_skips_reasoning_payload() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    // No tool call named "reasoning"; reasoning payloads are dropped wholesale.
    assert!(digest.tool_calls.iter().all(|t| t.name != "reasoning"));
}

#[test]
fn session_id_is_codex_rollout_path_for_file_path_input() {
    let digest = build_codex_digest(&fixture("rich.jsonl")).expect("build");
    let id = format!("{:?}", digest.session_id);
    assert!(id.contains("CodexRolloutPath"));
}

#[test]
fn malformed_line_surfaces_typed_error() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), b"{\"type\":\"session_meta\"\n").unwrap();
    let err = build_codex_digest(tmp.path()).unwrap_err();
    assert!(matches!(
        err,
        BuildDigestError::Malformed { line_no: 1, .. }
    ));
}
