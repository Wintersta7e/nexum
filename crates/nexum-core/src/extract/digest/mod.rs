//! Session-digest construction. A `SessionDigest` is the 10-30 KB structured
//! view a `ModelClient` sees: user prompts, assistant prose, a compressed
//! tool-call summary, the final plan state, and git metadata.

mod types;

pub use types::{
    BuildDigestError, MessageTurn, PlanFinal, PlanStep, SessionDigest, SessionId, SessionKind,
    SessionMetadata, ToolCallSummary, TurnRole,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn session_id_cc_round_trips_uuid() {
        let id = Uuid::now_v7();
        let session_id = SessionId::Cc(id);
        if let SessionId::Cc(back) = session_id {
            assert_eq!(back, id);
        } else {
            panic!("variant mismatch");
        }
    }

    #[test]
    fn session_id_codex_rollout_path_round_trips() {
        let path = PathBuf::from("/tmp/rollout-x.jsonl");
        let session_id = SessionId::CodexRolloutPath(path.clone());
        if let SessionId::CodexRolloutPath(back) = session_id {
            assert_eq!(back, path);
        } else {
            panic!("variant mismatch");
        }
    }

    #[test]
    fn tool_call_summary_truncation_caps_match_constants() {
        assert_eq!(ToolCallSummary::ARGS_SKETCH_MAX_CHARS, 300);
        assert_eq!(ToolCallSummary::OUTPUT_EXCERPT_MAX_CHARS, 500);
    }

    #[test]
    fn build_digest_error_empty_displays_human_message() {
        let err = BuildDigestError::Empty;
        assert!(err.to_string().contains("no extractable content"));
    }

    #[test]
    fn session_digest_is_empty_returns_true_when_all_collections_empty() {
        let digest = SessionDigest {
            session_kind: SessionKind::CcTranscript,
            session_id: SessionId::Cc(Uuid::nil()),
            project_hint: None,
            metadata: SessionMetadata::default(),
            user_turns: vec![],
            assistant_turns: vec![],
            tool_calls: vec![],
            plan_final: None,
            non_zero_exits: vec![],
        };
        assert!(digest.is_empty());
    }

    #[test]
    fn session_digest_is_empty_false_when_one_user_turn() {
        let digest = SessionDigest {
            session_kind: SessionKind::CcTranscript,
            session_id: SessionId::Cc(Uuid::nil()),
            project_hint: None,
            metadata: SessionMetadata::default(),
            user_turns: vec![MessageTurn {
                role: TurnRole::User,
                content: "anything".into(),
                timestamp: None,
            }],
            assistant_turns: vec![],
            tool_calls: vec![],
            plan_final: None,
            non_zero_exits: vec![],
        };
        assert!(!digest.is_empty());
    }
}
