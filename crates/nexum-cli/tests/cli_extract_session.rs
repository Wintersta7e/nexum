//! End-to-end test for `nexum extract --session <uuid> --json` against a
//! wiremock-stubbed Anthropic endpoint.
//!
//! Seeds a CC transcript fixture, points the config at it, pre-seeds the
//! consent ack, then runs the real binary with the mock as its
//! `NEXUM_ANTHROPIC_BASE_URL`. Asserts the response carries one committed
//! record id.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::TestHome;

fn cc_transcript_jsonl() -> String {
    // Minimal valid CC JSONL: one user line + one assistant line so the
    // digest is non-empty and `build_cc_digest` returns Ok.
    [
        r#"{"type":"user","timestamp":"2026-05-17T10:00:00Z","message":{"role":"user","content":"add a retry-backoff knob"}}"#,
        r#"{"type":"assistant","timestamp":"2026-05-17T10:00:01Z","message":{"role":"assistant","content":"added under config.toml [retry]"}}"#,
    ]
    .join("\n")
}

fn mock_recommendation_yaml(session_uuid: Uuid) -> String {
    // Two-space-indented YAML list item; the Anthropic client unwraps the
    // outer `content[0].text` and parses it through serde_yaml. The shape
    // mirrors what record_io::validate_raw_record requires.
    format!(
        "- schema_version: 1\n  \
         id: 2026-05-17-retry-backoff\n  \
         record_type: recommendation\n  \
         outcome: proposed\n  \
         agent: claude-code\n  \
         confidence: medium\n  \
         tags: [tooling]\n  \
         session_refs:\n    \
         - kind: cc_session\n      \
         uuid: {session_uuid}\n  \
         created: 2026-05-17T10:00:00Z\n  \
         updated: 2026-05-17T10:00:00Z\n  \
         problem: noisy retry behavior\n  \
         chosen: add a retry-backoff knob\n  \
         options_considered: []\n  \
         rationale: []\n  \
         files: []\n  \
         commits: []\n"
    )
}

/// Update the seed `config.toml` to point `[adapters.cc].projects_dir` at
/// `dir` and disable the codex adapter (we are testing the CC path).
fn rewrite_cc_projects_dir(home: &std::path::Path, projects_dir: &std::path::Path) {
    let cfg_path = home.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).expect("read config.toml");
    let mut doc: toml::Value = toml::from_str(&raw).expect("parse config.toml");
    let adapters = doc
        .as_table_mut()
        .and_then(|t| t.get_mut("adapters"))
        .and_then(toml::Value::as_table_mut)
        .expect("config.toml missing [adapters]");
    let cc = adapters
        .get_mut("cc")
        .and_then(toml::Value::as_table_mut)
        .expect("config.toml missing [adapters.cc]");
    cc.insert(
        "projects_dir".into(),
        toml::Value::String(projects_dir.to_string_lossy().into_owned()),
    );
    let codex = adapters
        .get_mut("codex")
        .and_then(toml::Value::as_table_mut)
        .expect("config.toml missing [adapters.codex]");
    codex.insert("enabled".into(), toml::Value::Boolean(false));
    let serialized = toml::to_string(&doc).expect("serialize config.toml");
    std::fs::write(&cfg_path, serialized).expect("write config.toml");
}

#[tokio::test]
async fn extract_session_commits_one_record() {
    let server = MockServer::start().await;
    let session_uuid = Uuid::now_v7();
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": [{"type": "text", "text": mock_recommendation_yaml(session_uuid)}],
            "usage": {"input_tokens": 100, "output_tokens": 50}
        })))
        .mount(&server)
        .await;

    let home = TestHome::initialized_no_index();

    // Seed a CC-style transcript at <home>/cc-projects/test-slug/<uuid>.jsonl
    // and point config.toml's [adapters.cc].projects_dir at the parent.
    let projects_dir = home.path().join("cc-projects");
    let session_dir = projects_dir.join("test-slug");
    std::fs::create_dir_all(&session_dir).expect("mkdir cc projects fixture");
    let transcript_path = session_dir.join(format!("{session_uuid}.jsonl"));
    std::fs::write(&transcript_path, cc_transcript_jsonl()).expect("write transcript");
    rewrite_cc_projects_dir(home.path(), &projects_dir);

    // Pre-seed the consent ack so the CLI does not prompt.
    home.write_extract_ack("anthropic", "claude-opus")
        .expect("write extract ack");

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_nexum"));
    let output = Command::new(&exe)
        .args([
            "extract",
            "--session",
            &session_uuid.to_string(),
            "--json",
            "--quiet",
        ])
        .env("NEXUM_HOME", home.nexum_home())
        .env("HOME", home.ssh_home())
        .env("ANTHROPIC_API_KEY", "test-key")
        .env("NEXUM_ANTHROPIC_BASE_URL", server.uri())
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("spawn nexum");

    assert!(
        output.status.success(),
        "exit={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(parsed["committed"].as_u64(), Some(1), "{parsed}");
    assert_eq!(
        parsed["session"].as_str(),
        Some(session_uuid.to_string().as_str())
    );
}
