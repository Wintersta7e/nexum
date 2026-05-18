//! HTTP-driven tests against a wiremock-stubbed Anthropic endpoint.

use std::env;
use std::sync::{Mutex, PoisonError};

use nexum_core::extract::digest::{
    MessageTurn, SessionDigest, SessionId, SessionKind, SessionMetadata, TurnRole,
};
use nexum_core::extract::model::{AnthropicClient, ExtractError, ExtractionOutput, ModelClient};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Serialize tests that mutate process-global env vars. `tokio::test` runs
// each test on its own runtime but multiple test functions still execute in
// parallel within the same crate, so unsynchronized env_var writes are a
// data race. The guard is only held across the synchronous env-set +
// client-construction window — never across `.await` — so the lock is a
// `std::sync::Mutex`, not a `tokio::sync::Mutex`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Hold `ENV_LOCK`, install the env vars, build the client, drop the guard.
/// Returns the constructed client (or the error from
/// `from_env_with_model`). All work inside this fn is synchronous so no
/// await point ever observes the lock.
fn locked_build(
    base_url: Option<&str>,
    api_key: Option<&str>,
) -> Result<AnthropicClient, ExtractError> {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: serialized via ENV_LOCK; never observed across an await.
    unsafe {
        if let Some(v) = base_url {
            env::set_var("NEXUM_ANTHROPIC_BASE_URL", v);
        } else {
            env::remove_var("NEXUM_ANTHROPIC_BASE_URL");
        }
        if let Some(v) = api_key {
            env::set_var("ANTHROPIC_API_KEY", v);
        } else {
            env::remove_var("ANTHROPIC_API_KEY");
        }
    }
    AnthropicClient::from_env_with_model("claude-opus-4-7", "ANTHROPIC_API_KEY")
}

fn synthetic_digest() -> SessionDigest {
    SessionDigest {
        session_kind: SessionKind::CcTranscript,
        session_id: SessionId::Cc(Uuid::nil()),
        project_hint: None,
        metadata: SessionMetadata::default(),
        user_turns: vec![MessageTurn {
            role: TurnRole::User,
            content: "please add a retry-backoff config knob".into(),
            timestamp: None,
        }],
        assistant_turns: vec![MessageTurn {
            role: TurnRole::Assistant,
            content: "added under config.toml [retry]".into(),
            timestamp: None,
        }],
        tool_calls: vec![],
        plan_final: None,
        non_zero_exits: vec![],
    }
}

#[tokio::test]
async fn extract_round_trips_through_mock_anthropic() {
    let server = MockServer::start().await;
    let body_text = "- schema_version: 1\n  id: 2026-04-15-retry-backoff-knob\n  record_type: recommendation\n  outcome: proposed\n  agent: claude-code\n  problem: noisy retry behavior\n  chosen: add a retry-backoff knob\n";
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": body_text}],
            "usage": {"input_tokens": 100, "output_tokens": 50}
        })))
        .mount(&server)
        .await;

    let client = locked_build(Some(&server.uri()), Some("test-key")).expect("build client");
    let out = client.extract(&synthetic_digest()).expect("extract");
    let records = match out {
        ExtractionOutput::Records(r) => r,
        ExtractionOutput::NoRecords { reason } => {
            panic!("expected records, got NoRecords: {reason}")
        }
    };
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].yaml.get("id").and_then(|v| v.as_str()),
        Some("2026-04-15-retry-backoff-knob"),
    );
}

#[tokio::test]
async fn no_records_response_is_a_clean_decline() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": "NO RECORDS — pure scaffold-following"}],
            "usage": {"input_tokens": 100, "output_tokens": 10}
        })))
        .mount(&server)
        .await;

    let client = locked_build(Some(&server.uri()), Some("test-key")).expect("build");
    let out = client.extract(&synthetic_digest()).expect("extract");
    assert!(matches!(out, ExtractionOutput::NoRecords { .. }));
}

#[tokio::test]
async fn http_error_surfaces_as_typed_extracterror() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limited"))
        .mount(&server)
        .await;

    let client = locked_build(Some(&server.uri()), Some("test-key")).expect("build");
    let err = client.extract(&synthetic_digest()).unwrap_err();
    let display = err.to_string();
    assert!(display.contains("429"));
    assert!(display.contains("Rate limited"));
}

#[tokio::test]
async fn count_input_tokens_hits_the_count_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages/count_tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "input_tokens": 1234
        })))
        .mount(&server)
        .await;

    let client = locked_build(Some(&server.uri()), Some("test-key")).expect("build");
    let count = client
        .count_input_tokens(&synthetic_digest())
        .expect("count");
    assert_eq!(count, 1234);
}

#[test]
fn missing_api_key_returns_typed_error() {
    let err = locked_build(None, None).unwrap_err();
    let display = err.to_string();
    assert!(display.contains("ANTHROPIC_API_KEY"));
}
