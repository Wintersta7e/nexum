//! `ModelClient` implementations and shared types.

mod anthropic;
mod codex_phase1;
mod ollama_stub;
mod openai_stub;
mod render;
mod types;

pub use anthropic::AnthropicClient;
pub use codex_phase1::CodexPhase1Reader;
pub use ollama_stub::OllamaClient;
pub use openai_stub::OpenAiClient;
pub use types::{ExtractError, ExtractionOutput, ModelClient, Provider, RawRecord};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::digest::SessionDigest;

    struct MockClient {
        canned: Result<ExtractionOutput, ExtractError>,
    }

    impl ModelClient for MockClient {
        fn provider_name(&self) -> &'static str {
            "mock"
        }
        fn extract(&self, _digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
            match &self.canned {
                Ok(out) => Ok(out.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }
        fn count_input_tokens(&self, _digest: &SessionDigest) -> Result<u32, ExtractError> {
            Ok(1234)
        }
    }

    fn clone_err(e: &ExtractError) -> ExtractError {
        // Tests want a no-fail clone; use the Display string as the body.
        ExtractError::Http {
            status: 500,
            body: e.to_string(),
        }
    }

    #[test]
    fn extraction_output_no_records_carries_reason() {
        let out = ExtractionOutput::NoRecords {
            reason: "no decision substance".into(),
        };
        match out {
            ExtractionOutput::NoRecords { reason } => {
                assert!(reason.contains("decision"));
            }
            ExtractionOutput::Records(_) => panic!("wrong variant"),
        }
    }

    #[test]
    fn mock_client_round_trips_through_trait_object() {
        let client: Box<dyn ModelClient> = Box::new(MockClient {
            canned: Ok(ExtractionOutput::NoRecords {
                reason: "ok".into(),
            }),
        });
        assert_eq!(client.provider_name(), "mock");
        let digest = test_digest();
        let out = client.extract(&digest).expect("extract");
        assert!(matches!(out, ExtractionOutput::NoRecords { .. }));
        assert_eq!(client.count_input_tokens(&digest).unwrap(), 1234);
    }

    #[test]
    fn extract_error_codes_match_design() {
        // Sanity: variant Display contains the expected discriminator.
        let no_api = ExtractError::NoApiKey {
            env_var: "ANTHROPIC_API_KEY".into(),
        };
        assert!(no_api.to_string().contains("ANTHROPIC_API_KEY"));

        let mismatch = ExtractError::DryRunMismatch {
            expected: "sha256:aaa".into(),
            actual: "sha256:bbb".into(),
        };
        let display = mismatch.to_string();
        assert!(display.contains("sha256:aaa"));
        assert!(display.contains("sha256:bbb"));
    }

    fn test_digest() -> SessionDigest {
        use crate::extract::digest::{
            MessageTurn, SessionId, SessionKind, SessionMetadata, TurnRole,
        };
        SessionDigest {
            session_kind: SessionKind::CcTranscript,
            session_id: SessionId::Cc(uuid::Uuid::nil()),
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
        }
    }
}
