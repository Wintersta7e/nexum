//! End-to-end tests that the CLI's `--json` mode emits a structured
//! `ErrorEnvelope` on stdout for every read verb that fails. Default mode
//! (no `--json`) is covered by the older per-verb test files and is not
//! re-asserted here.

mod common;

use crate::common::{TestHome, run_json};
use serde_json::Value;

#[test]
fn search_emits_not_indexed_envelope_when_index_missing() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(&home, &["search", "anything", "--json"]);
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert_eq!(env["remediation"]["command"], "nexum index");
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn search_default_mode_still_emits_prose_to_stderr() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["search", "anything"]);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no index database"));
    assert!(out.stdout.is_empty());
    assert_eq!(out.status.code().unwrap_or(-1), 10);
}

#[test]
fn get_emits_not_found_envelope() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(&home, &["get", "definitely-does-not-exist", "--json"]);
    assert_eq!(env["error_code"], "NOT_FOUND");
    assert_eq!(env["context"]["requested_id"], "definitely-does-not-exist");
    assert_eq!(code, 11);
}

#[test]
fn get_emits_ambiguous_envelope_with_matches() {
    let home = TestHome::initialized_with_two_records_sharing_id("dup-id");
    let (env, code) = run_json(&home, &["get", "dup-id", "--json"]);
    assert_eq!(env["error_code"], "AMBIGUOUS_KEY");
    assert_eq!(code, 13);
    let matches = env["context"]["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn get_emits_hidden_by_policy_envelope_under_hide() {
    let home = TestHome::initialized_with_unsigned_record_under_hide("hidden-id");
    let (env, code) = run_json(&home, &["get", "hidden-id", "--json"]);
    assert_eq!(env["error_code"], "HIDDEN_BY_POLICY");
    assert_eq!(code, 12);
    assert!(env["context"]["signature_status"].as_str().is_some());
}

#[test]
fn get_emits_not_indexed_envelope_when_index_missing() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(&home, &["get", "anything", "--json"]);
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn list_emits_not_indexed_envelope() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(&home, &["list", "--json"]);
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn recent_emits_not_indexed_envelope() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(&home, &["recent", "--json"]);
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn by_session_emits_not_indexed_envelope() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(
        &home,
        &[
            "by-session",
            "00000000-0000-0000-0000-000000000000",
            "--json",
        ],
    );
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn index_emits_not_initialized_envelope_when_home_missing() {
    let home = TestHome::uninitialized();
    let (env, code) = run_json(&home, &["index", "--json"]);
    assert_eq!(env["error_code"], "NOT_INITIALIZED");
    assert_eq!(code, 3);
    assert_eq!(env["context"]["phase"], "load_config");
}

#[test]
fn trust_validate_events_emits_tampering_envelope_when_detected() {
    let home = TestHome::initialized_with_tampered_events_yml();
    let out = home.run(&["trust", "validate-events", "--json"]);
    let env: Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    assert_eq!(env["error_code"], "TAMPERING_DETECTED");
    assert_eq!(out.status.code().unwrap_or(-1), 4);
    let events = env["context"]["events"]
        .as_array()
        .expect("context.events array");
    assert!(!events.is_empty(), "at least one tampering row expected");
}

#[test]
fn trust_validate_events_emits_envelope_on_underlying_error() {
    let home = TestHome::initialized_with_corrupt_events_yml();
    let out = home.run(&["trust", "validate-events", "--json"]);
    let env: Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    assert_eq!(env["error_code"], "STORE_INTEGRITY");
    assert_eq!(out.status.code().unwrap_or(-1), 4);
    assert_eq!(env["context"]["kind"], "trust");
    // TrustError::Parse preserves the events.yml path in context.
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn trust_validate_events_emits_empty_array_when_clean() {
    let home = TestHome::initialized_clean();
    let out = home.run(&["trust", "validate-events", "--json"]);
    // Clean case keeps the existing array-shape success output for back-compat
    // with agents that already key on `exit 0 + [] on stdout = clean`.
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON");
    assert!(v.is_array());
    assert_eq!(v.as_array().unwrap().len(), 0);
    assert_eq!(out.status.code().unwrap_or(-1), 0);
}
