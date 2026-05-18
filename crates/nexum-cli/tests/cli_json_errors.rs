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
fn project_list_emits_envelope_on_error() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(&home, &["project", "list", "--json"]);
    assert_eq!(env["error_code"], "NOT_INDEXED");
    assert_eq!(code, 10);
    assert_eq!(env["remediation"]["command"], "nexum index");
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn project_list_emits_results_and_meta_on_success() {
    // A seeded, indexed home has at least the `seed` record, so
    // `project list --json` produces a non-error `{ results, _meta }` payload.
    let home = TestHome::initialized_with_seeded_index();
    let out = home.run(&["project", "list", "--json"]);
    assert!(
        out.status.success(),
        "project list --json should succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON");
    let results = v["results"]
        .as_array()
        .expect("`results` must be a JSON array");
    assert!(!results.is_empty(), "seeded index must list >=1 project");
    // `_meta` is the shared envelope, carried straight off `ProjectListing`.
    assert!(
        v["_meta"].is_object(),
        "`_meta` must be present and an object"
    );
    assert!(
        v["_meta"]["source_counts"].is_object(),
        "`_meta.source_counts` must be present"
    );
    assert!(
        v["_meta"]["trust_policy"].is_string(),
        "`_meta.trust_policy` must be present"
    );
}

#[test]
fn project_resolve_emits_usage_envelope_for_missing_path() {
    let home = TestHome::initialized_no_index();
    let (env, code) = run_json(
        &home,
        &["project", "resolve", "/path/that/does/not/exist", "--json"],
    );
    assert_eq!(env["error_code"], "USAGE");
    assert_eq!(code, 2);
    assert!(env["context"]["path"].as_str().is_some());
}

#[test]
fn search_emits_reanchor_pending_envelope_under_json() {
    let home = TestHome::initialized_with_reanchor_pending_sentinel();
    let out = home.run(&["search", "anything", "--json"]);
    let env: Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    assert_eq!(env["error_code"], "REANCHOR_PENDING");
    assert_eq!(out.status.code().unwrap_or(-1), 8);
    assert!(
        env["message"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("reanchor")
    );
}

#[test]
fn search_emits_trust_schema_unsupported_envelope() {
    // The materializer walks every `.trust/events.yml` revision; the
    // second commit declares `schema_version: 99`, which the binary does
    // not understand. The first read verb after the second commit
    // triggers the rebuild and surfaces `TrustSchemaUnsupported` as a
    // structured envelope on stdout.
    let home = TestHome::initialized_with_future_trust_schema();
    let out = home.run(&["search", "anything", "--json"]);
    let env: Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    assert_eq!(env["error_code"], "TRUST_SCHEMA_UNSUPPORTED");
    assert_eq!(out.status.code().unwrap_or(-1), 9);
    assert!(env["context"]["schema_version"].is_number());
}

#[test]
fn recent_emits_invalid_filter_envelope_for_unknown_source() {
    // `nexum recent --source <s>` validates `s` via
    // `Source::try_from_user_str` and lifts an unknown value to
    // `QueryError::InvalidFilter`. (Plan-source drift: the original
    // task draft proposed `search --since=<bad-iso>`, but `since_iso`
    // is passed verbatim into the SQL `>=` comparison and is not
    // validated; `recent --source` is the reachable trigger.)
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(&home, &["recent", "--source", "not-a-source", "--json"]);
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "unknown source: not-a-source");
}

#[test]
fn search_emits_invalid_filter_envelope_for_unknown_source() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(
        &home,
        &["search", "anything", "--source", "not-a-source", "--json"],
    );
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "--source=not-a-source");
}

#[test]
fn search_emits_invalid_filter_envelope_for_unknown_type() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(
        &home,
        &["search", "anything", "--type", "no-such-type", "--json"],
    );
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "--type=no-such-type");
}

#[test]
fn search_emits_invalid_filter_envelope_for_unknown_min_confidence() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(
        &home,
        &[
            "search",
            "anything",
            "--min-confidence",
            "very-high",
            "--json",
        ],
    );
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "--min-confidence=very-high");
}

#[test]
fn list_emits_invalid_filter_envelope_for_unknown_source() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(&home, &["list", "--source", "not-a-source", "--json"]);
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "--source=not-a-source");
}

#[test]
fn list_emits_invalid_filter_envelope_for_unknown_type() {
    let home = TestHome::initialized_with_seeded_index();
    let (env, code) = run_json(&home, &["list", "--type", "no-such-type", "--json"]);
    assert_eq!(env["error_code"], "INVALID_FILTER");
    assert_eq!(code, 4);
    assert_eq!(env["context"]["detail"], "--type=no-such-type");
}

#[test]
fn search_emits_store_integrity_envelope_on_corrupt_index() {
    // Truncate `index.db` to a few non-magic bytes so any SQL issued
    // through the connection fails with "file is not a database". The
    // read-open helper now reads `PRAGMA user_version` before handing
    // the connection to the query layer, so the rusqlite error surfaces
    // there and routes through `query_envelope` as `context.kind =
    // "rusqlite"`. The `error_code` and exit code are unchanged.
    let home = TestHome::initialized_with_corrupt_index_db();
    let out = home.run(&["search", "anything", "--json"]);
    let env: Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    assert_eq!(env["error_code"], "STORE_INTEGRITY");
    assert_eq!(out.status.code().unwrap_or(-1), 4);
    assert_eq!(env["context"]["kind"], "rusqlite");
    assert!(env["context"]["message"].as_str().is_some());
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
