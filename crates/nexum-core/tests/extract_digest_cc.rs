//! End-to-end tests for the CC transcript JSONL → `SessionDigest` parser.

use std::path::PathBuf;
use std::str::FromStr;

use nexum_core::extract::digest::{
    BuildDigestError, SessionId, SessionKind, TurnRole, build_cc_digest,
};
use uuid::Uuid;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/extract/cc")
        .join(name)
}

const RICH_UUID: &str = "11111111-2222-4333-8444-555555555555";
const EMPTY_UUID: &str = "00000000-0000-4000-8000-000000000000";

#[test]
fn empty_session_returns_empty_error() {
    // `empty.jsonl` holds only a `last-prompt` and a `permission-mode` line.
    // Both must be skipped by the parser, leaving nothing to digest.
    let uuid = Uuid::from_str(EMPTY_UUID).unwrap();
    let err = build_cc_digest(&fixture("empty.jsonl"), uuid).unwrap_err();
    assert!(matches!(err, BuildDigestError::Empty));
}

#[test]
fn rich_session_kind_is_cc_transcript() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    assert!(matches!(digest.session_kind, SessionKind::CcTranscript));
    assert!(matches!(digest.session_id, SessionId::Cc(_)));
}

#[test]
fn rich_session_collects_user_turns_with_string_content() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    // Only the first user message is actual user text. The other two `user`
    // lines carry tool_result blocks and should NOT become user turns.
    assert_eq!(digest.user_turns.len(), 1);
    assert!(digest.user_turns[0].content.contains("retry backoff"));
}

#[test]
fn rich_session_collects_assistant_text_blocks() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    assert_eq!(digest.assistant_turns.len(), 3);
    assert_eq!(digest.assistant_turns[0].role, TurnRole::Assistant);
    assert!(
        digest.assistant_turns[0]
            .content
            .contains("flag and a unit test")
    );
    assert!(
        digest.assistant_turns[2]
            .content
            .contains("wrap it in Option")
    );
}

#[test]
fn rich_session_pairs_tool_use_blocks_with_tool_results() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    assert_eq!(digest.tool_calls.len(), 2);
    assert_eq!(digest.tool_calls[0].name, "Edit");
    assert_eq!(digest.tool_calls[1].name, "Bash");
    assert!(digest.tool_calls[0].output_excerpt.contains("applied edit"));
    assert!(digest.tool_calls[1].output_excerpt.contains("FAILED 1"));
}

#[test]
fn rich_session_captures_non_zero_exit_from_tool_result() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    // The Bash tool_result contains "Process exited with code 101".
    let bash_call = digest.tool_calls.iter().find(|c| c.name == "Bash").unwrap();
    assert_eq!(bash_call.exit_code, Some(101));
    assert_eq!(digest.non_zero_exits.len(), 1);
    assert!(digest.non_zero_exits[0].contains("Bash"));
    assert!(digest.non_zero_exits[0].contains("101"));
}

#[test]
fn rich_session_populates_started_and_ended() {
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let digest = build_cc_digest(&fixture("rich.jsonl"), uuid).expect("build");
    assert!(digest.metadata.started.is_some());
    assert!(digest.metadata.ended.is_some());
    assert!(digest.metadata.started.unwrap() <= digest.metadata.ended.unwrap());
}

#[test]
fn malformed_line_surfaces_typed_error() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), b"{\"type\":\"user\",\"timestamp\"\n").unwrap();
    let uuid = Uuid::from_str(RICH_UUID).unwrap();
    let err = build_cc_digest(tmp.path(), uuid).unwrap_err();
    assert!(matches!(
        err,
        BuildDigestError::Malformed { line_no: 1, .. }
    ));
}
