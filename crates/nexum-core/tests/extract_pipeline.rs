//! End-to-end pipeline test: mock `ModelClient` → commit → read back via `api::get`.

mod common;

use nexum_core::api;
use nexum_core::config::types::Config;
use nexum_core::extract::digest::{
    MessageTurn, SessionDigest, SessionId, SessionKind, SessionMetadata, TurnRole,
};
use nexum_core::extract::model::{ExtractError, ExtractionOutput, ModelClient, RawRecord};
use nexum_core::extract::pipeline::extract_session_with_client;
use nexum_core::init::{InitOpts, run};
use nexum_core::paths::Paths;
use nexum_core::query::GetOpts;
use nexum_core::records::RecordKey;
use uuid::Uuid;

fn init_home() -> (common::NexumTestHome, Paths, Config) {
    let home = common::NexumTestHome::new().unwrap();
    // Keep the ephemeral key under the test home so it survives every commit
    // the pipeline makes; nested TempDirs drop independently and would yank
    // the key file out from under git.
    let key_dir = home.path().join("keys");
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let priv_path = common::write_ephemeral_keypair(&key_dir);
    let nexum_root = home.path().join(".nexum");
    run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(nexum_root.clone()),
        force: false,
    })
    .expect("init must succeed");
    let paths = Paths::with_home(nexum_root);
    let cfg = common::test_cfg_local_only();
    (home, paths, cfg)
}

fn synthetic_digest() -> SessionDigest {
    SessionDigest {
        session_kind: SessionKind::CcTranscript,
        session_id: SessionId::Cc(Uuid::nil()),
        project_hint: None,
        metadata: SessionMetadata::default(),
        user_turns: vec![MessageTurn {
            role: TurnRole::User,
            content: "X".into(),
            timestamp: None,
        }],
        assistant_turns: vec![],
        tool_calls: vec![],
        plan_final: None,
        non_zero_exits: vec![],
    }
}

struct CannedClient {
    yaml: String,
}

impl ModelClient for CannedClient {
    fn provider_name(&self) -> &'static str {
        "canned"
    }
    fn extract(&self, _digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
        let docs: Vec<serde_yaml::Value> = serde_yaml::from_str(&self.yaml).unwrap();
        Ok(ExtractionOutput::Records(
            docs.into_iter().map(|y| RawRecord { yaml: y }).collect(),
        ))
    }
    fn count_input_tokens(&self, _digest: &SessionDigest) -> Result<u32, ExtractError> {
        Ok(100)
    }
}

#[test]
fn committed_records_are_readable_via_api_get() {
    let (_home, paths, cfg) = init_home();
    let yaml = "- schema_version: 1\n  id: 2026-04-15-retry-backoff-knob\n  record_type: recommendation\n  outcome: proposed\n  agent: claude-code\n  confidence: medium\n  tags: [config, networking]\n  session_refs:\n    - kind: cc_session\n      uuid: 00000000-0000-4000-8000-000000000000\n  files: []\n  commits: []\n  created: 2026-04-15T10:00:00Z\n  updated: 2026-04-15T10:00:00Z\n  problem: noisy retry behavior\n  chosen: add a retry-backoff knob\n  options_considered: []\n  rationale: []\n";
    let client = CannedClient { yaml: yaml.into() };
    let outcome =
        extract_session_with_client(&paths, &cfg, &synthetic_digest(), &client).expect("extract");
    assert_eq!(outcome.committed_record_ids.len(), 1);

    let key = RecordKey::bare("2026-04-15-retry-backoff-knob");
    let _got = api::get(&paths, &cfg, &key, &GetOpts::default()).expect("get");
    // Existence proves the index picked it up; full record-shape coverage is
    // in api::get's own tests.
}

struct NoRecsClient;

impl ModelClient for NoRecsClient {
    fn provider_name(&self) -> &'static str {
        "norec"
    }
    fn extract(&self, _: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
        Ok(ExtractionOutput::NoRecords {
            reason: "decline".into(),
        })
    }
    fn count_input_tokens(&self, _: &SessionDigest) -> Result<u32, ExtractError> {
        Ok(0)
    }
}

#[test]
fn no_records_output_returns_zero_committed() {
    let (_home, paths, cfg) = init_home();
    let outcome = extract_session_with_client(&paths, &cfg, &synthetic_digest(), &NoRecsClient)
        .expect("extract");
    assert_eq!(outcome.committed_record_ids.len(), 0);
    assert_eq!(outcome.declined_reason.as_deref(), Some("decline"));
}

#[test]
fn validation_failure_does_not_commit_anything() {
    let (_home, paths, cfg) = init_home();
    let yaml = "- schema_version: 1\n  id: BAD_ID\n  record_type: recommendation\n";
    let client = CannedClient { yaml: yaml.into() };
    let err = extract_session_with_client(&paths, &cfg, &synthetic_digest(), &client).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("validation"));
    // Validation runs before any commit step. Confirm by listing files under
    // the notebook.git worktree — only `.git/` and `.trust/` should exist.
    let entries: Vec<_> = std::fs::read_dir(&paths.notebook_git)
        .expect("notebook.git exists")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".git" && n != ".trust" && n != "META.yml")
        .collect();
    assert!(
        entries.is_empty(),
        "expected no record files committed; found {entries:?}"
    );
}
