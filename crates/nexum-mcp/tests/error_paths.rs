//! Error-path suite for the MCP read tools.
//!
//! Three families of errors travel different channels:
//!
//! - **Domain conditions** (no index, ambiguous bare key) — surfaced as
//!   `CallToolResult { is_error: true }` carrying the wire-stable
//!   `ErrorEnvelope` the CLI `--json` path also emits.
//! - **Malformed calls** (zero session refs, unknown enum-strings) —
//!   surfaced as `Err(rmcp::ErrorData)` with JSON-RPC code `-32602`
//!   (`invalid_params`), the protocol-error channel.
//!
//! All assertions run over the in-process duplex harness — no real
//! subprocess. The stdio smoke test (separate file) covers the
//! child-process path.
//!
//! Triggers reused from the per-tool tests: missing index, two records
//! sharing the bare id under distinct `project_id`s, zero session refs,
//! unknown `record_type` enum-string.

mod common;

use common::{McpTestHome, expect_error_code};
use nexum_core::api::error::error_codes;
use rmcp::model::CallToolRequestParams;
use rmcp::service::ServiceError;

#[tokio::test]
async fn recent_on_uninitialized_index_returns_not_indexed() {
    // `nexum init` ran, `nexum index` did NOT — `Paths` + `Config`
    // resolve cleanly, so the server starts `Ready`, but the
    // `index.db` file is absent. The api layer maps the missing DB to
    // `NOT_INDEXED`, which the MCP layer surfaces verbatim.
    let connected = McpTestHome::ready_without_index().connect().await;

    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent"))
        .await
        .expect("call_tool dispatch must not raise a protocol error");

    assert_eq!(
        expect_error_code(&result),
        error_codes::NOT_INDEXED,
        "a missing index.db must surface as NOT_INDEXED, not a panic"
    );
    let envelope = result
        .structured_content
        .as_ref()
        .expect("error result carries a structured envelope");
    // The envelope's `remediation.command` steers the agent at the fix.
    let remediation_command = envelope["remediation"]["command"].as_str();
    assert_eq!(
        remediation_command,
        Some("nexum index"),
        "remediation should name the missing-index fix command, got: {remediation_command:?}"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn get_bare_id_matching_multiple_records_returns_ambiguous_key() {
    // Two YAML files share the bare id `dup` under distinct
    // `project_id`s. A bare-key `get` cannot disambiguate, so the
    // verb returns `AMBIGUOUS_KEY` with both fully-qualified
    // candidate keys in `context.matches`.
    let connected = McpTestHome::ready_with_two_records_same_id("dup")
        .connect()
        .await;

    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("dup"));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect("ambiguity is a domain envelope, not a protocol error");

    assert_eq!(
        expect_error_code(&result),
        error_codes::AMBIGUOUS_KEY,
        "two rows share the bare key, so the verb cannot pick one"
    );
    let envelope = result
        .structured_content
        .as_ref()
        .expect("error result carries a structured envelope");
    let matches = envelope["context"]["matches"]
        .as_array()
        .expect("AMBIGUOUS_KEY envelope carries the candidate list");
    assert_eq!(
        matches.len(),
        2,
        "both colliding records are surfaced so the agent can re-call with a \
         fully-qualified key"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn by_session_with_zero_session_refs_is_invalid_params() {
    // `by_session` requires exactly one of `cc_session_id`,
    // `codex_rollout_path`, or `codex_thread_id`. Zero refs is a
    // malformed call, not a domain condition.
    let connected = McpTestHome::indexed_empty().connect().await;

    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("by_session"))
        .await
        .expect_err("zero refs is a protocol error, not a domain envelope");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "zero session refs -> invalid_params");

    connected.shutdown().await;
}

#[tokio::test]
async fn search_with_unknown_record_type_enum_is_invalid_params() {
    // Enum-string fields parse through the typed `try_from_user_str`
    // companions. An unrecognized value is a protocol error, never
    // silently dropped or downgraded to "no filter".
    let connected = McpTestHome::indexed_empty().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("query".into(), serde_json::Value::from("anything"));
    args.insert(
        "record_type".into(),
        serde_json::Value::from("not-a-real-type"),
    );
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("search").with_arguments(args))
        .await
        .expect_err("an unknown enum-string is a protocol error");

    let (code, message) = match err {
        ServiceError::McpError(ref e) => (e.code.0, e.message.clone()),
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "unknown enum-string -> invalid_params");
    assert!(
        message.contains("record_type"),
        "the protocol error names the offending field; got: {message}"
    );

    connected.shutdown().await;
}
