//! Session-digest construction. A `SessionDigest` is the 10-30 KB structured
//! view a `ModelClient` sees: user prompts, assistant prose, a compressed
//! tool-call summary, the final plan state, and git metadata.

mod types;

mod codex;

pub use codex::build_codex_digest;

mod cc;

pub use cc::build_cc_digest;
pub use types::{
    BuildDigestError, MessageTurn, PlanFinal, PlanStep, ProjectHint, SessionDigest, SessionId,
    SessionKind, SessionMetadata, ToolCallSummary, TurnRole,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn session_id_cc_round_trips_uuid() {
        let id = Uuid::now_v7();
        let SessionId::Cc(back) = SessionId::Cc(id) else {
            panic!("variant mismatch");
        };
        assert_eq!(back, id);
    }

    #[test]
    fn session_id_codex_rollout_path_round_trips() {
        let path = PathBuf::from("/tmp/rollout-x.jsonl");
        let SessionId::CodexRolloutPath(back) = SessionId::CodexRolloutPath(path.clone()) else {
            panic!("variant mismatch");
        };
        assert_eq!(back, path);
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
