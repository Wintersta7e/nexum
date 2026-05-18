//! Full-stack test: `nexum init` -> drop synthetic transcript -> `nexum
//! extract` against a wiremock-stubbed Anthropic endpoint -> verify the
//! YAML body landed on disk under `notebook.git` and was signed-committed
//! by the pipeline.
//!
//! Extends the existing single-session extract test by inspecting the
//! committed artifact directly. The on-disk shape (`project_subdir` /
//! `type_subdir` / `<id>.yml`) is the contract between the commit
//! pipeline and the local adapter, so a regression here would silently
//! break both read-back and reindex.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::TestHome;

fn cc_transcript_jsonl() -> String {
    [
        r#"{"type":"user","timestamp":"2026-05-17T10:00:00Z","message":{"role":"user","content":"add a retry-backoff knob"}}"#,
        r#"{"type":"assistant","timestamp":"2026-05-17T10:00:01Z","message":{"role":"assistant","content":"added under config.toml [retry]"}}"#,
    ]
    .join("\n")
}

fn mock_recommendation_yaml(session_uuid: Uuid, record_id: &str) -> String {
    format!(
        "- schema_version: 1\n  \
         id: {record_id}\n  \
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
async fn extract_session_writes_committed_yaml_on_disk() {
    let record_id = "2026-05-17-retry-backoff";
    let server = MockServer::start().await;
    let session_uuid = Uuid::now_v7();
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": [{"type": "text", "text": mock_recommendation_yaml(session_uuid, record_id)}],
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
    let extract_out = Command::new(&exe)
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
        .expect("spawn nexum extract");

    assert!(
        extract_out.status.success(),
        "extract exit={}\nstdout={}\nstderr={}",
        extract_out.status,
        String::from_utf8_lossy(&extract_out.stdout),
        String::from_utf8_lossy(&extract_out.stderr)
    );
    let extract_json: Value = serde_json::from_slice(&extract_out.stdout).unwrap_or_else(|e| {
        panic!(
            "extract stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&extract_out.stdout)
        )
    });
    assert_eq!(
        extract_json["committed"].as_u64(),
        Some(1),
        "extract should commit one record: {extract_json}"
    );

    // Inspect the on-disk artifact the pipeline writes. The local
    // commit shape is `<project_subdir>/<type_subdir>/<id>.yml`; for
    // extracted records with no project attribution the project subdir
    // is the inbox bucket and the type subdir is the record type.
    let expected_path = home
        .nexum_home()
        .join("notebook.git")
        .join("_inbox")
        .join("recommendations")
        .join(format!("{record_id}.yml"));
    assert!(
        expected_path.exists(),
        "expected committed YAML at {}",
        expected_path.display()
    );
    let body = std::fs::read_to_string(&expected_path).expect("read committed YAML");
    assert!(
        body.contains(&format!("id: {record_id}")),
        "committed YAML missing record id; body: {body}"
    );
    assert!(
        body.contains("record_type: recommendation"),
        "committed YAML missing record_type; body: {body}"
    );

    // The commit pipeline runs the signed-commit + verify loop; if it
    // succeeded the worktree must be clean (no stray files, no rollback
    // residue). Check via the git status porcelain on the notebook repo.
    let notebook_git = home.nexum_home().join("notebook.git");
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&notebook_git)
        .env("HOME", home.ssh_home())
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("spawn git status");
    assert!(
        status.status.success() && status.stdout.is_empty(),
        "worktree dirty after extract: stdout={}, stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}
