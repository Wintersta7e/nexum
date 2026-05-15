//! Harness self-test: `connect()` against a `ready()` home completes the MCP
//! `initialize` handshake and a `list_tools` round-trip. If this fails, the
//! duplex wiring is broken and every tool test is unreliable — so it runs
//! first and asserts the minimum. The third test pins the uninitialized-home
//! path: a tool call against a server with no resolved home returns a
//! structured `NOT_INITIALIZED` error rather than the process having crashed.

mod common;

use common::{McpTestHome, expect_error_code, expect_structured};
use nexum_core::api::error::error_codes;
use rmcp::model::CallToolRequestParams;
use rmcp::service::ServiceError;

#[tokio::test]
async fn ready_home_connects_and_lists_tools() {
    let connected = McpTestHome::ready().connect().await;

    let tools = connected
        .client
        .list_tools(None)
        .await
        .expect("list_tools over the duplex transport must succeed");

    // The full six handlers land across the tool tasks; at this point the
    // `recent` handler exists and more will follow. Assert the floor (>= 1,
    // `recent` present), not an exact count, so this self-test does not need
    // editing as each tool task lands.
    assert!(
        !tools.tools.is_empty(),
        "a ready server must expose at least the `recent` tool"
    );
    assert!(
        tools.tools.iter().any(|t| t.name == "recent"),
        "`recent` must be among the listed tools"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn unavailable_home_still_connects() {
    // The `unavailable` fixture has no nexum home; the server must still
    // complete `initialize` — it always starts, even uninitialized. Tool
    // *registration* is independent of runtime availability.
    let connected = McpTestHome::unavailable().connect().await;
    let tools = connected
        .client
        .list_tools(None)
        .await
        .expect("an unavailable server still completes initialize + list_tools");
    assert!(
        !tools.tools.is_empty(),
        "tool registration is independent of runtime availability"
    );
    connected.shutdown().await;
}

#[tokio::test]
async fn recent_on_unavailable_home_returns_not_initialized() {
    // A `recent` tool call against a server with no resolved home returns a
    // structured `NOT_INITIALIZED` error: the server is alive, the agent gets
    // actionable remediation, the process never crashed before the handshake.
    let connected = McpTestHome::unavailable().connect().await;

    let result = connected
        .client
        .call_tool(rmcp::model::CallToolRequestParams::new("recent"))
        .await
        .expect("call_tool dispatch must not raise a protocol error");

    assert_eq!(
        expect_error_code(&result),
        error_codes::NOT_INITIALIZED,
        "a tool call on an unavailable runtime must yield a NOT_INITIALIZED structured error"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn recent_on_ready_fixture_returns_structured_result_set() {
    // A `Ready` fixture has one seeded record; `recent` returns a structured
    // ResultSet with the standard wire shape (`results` + `_meta`), capped at
    // the `limit` argument the agent passed.
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("limit".into(), serde_json::Value::from(5));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent").with_arguments(args))
        .await
        .expect("recent tool call must dispatch without a protocol error");

    let structured = expect_structured(&result);
    assert!(
        structured.get("results").is_some(),
        "structured payload carries `results`"
    );
    assert!(
        structured.get("_meta").is_some(),
        "structured payload carries the `_meta` envelope"
    );
    let results = structured["results"]
        .as_array()
        .expect("`results` is an array");
    assert!(results.len() <= 5, "limit=5 caps the returned rows");

    connected.shutdown().await;
}

#[tokio::test]
async fn recent_on_indexed_but_empty_returns_empty_result_set() {
    // An indexed-but-empty home is a *success*, not an error: the wire shape
    // is intact — `total_matched = 0` and an empty `results` array.
    let connected = McpTestHome::indexed_empty().connect().await;

    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent"))
        .await
        .expect("recent tool call must dispatch");

    let structured = expect_structured(&result);
    assert_eq!(structured["total_matched"], 0, "no records indexed");
    assert_eq!(
        structured["results"]
            .as_array()
            .expect("`results` is an array")
            .len(),
        0,
        "the results array is empty"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn search_on_ready_fixture_returns_structured_result_set() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    // The ready fixture seeds a `decisions/seed.yml` record — "seed" matches.
    args.insert("query".into(), serde_json::Value::from("seed"));
    args.insert("top_k".into(), serde_json::Value::from(3));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("search").with_arguments(args))
        .await
        .expect("search tool call must dispatch");

    let structured = expect_structured(&result);
    assert!(structured.get("results").is_some());
    assert!(structured.get("_meta").is_some());
    assert!(
        structured["results"]
            .as_array()
            .expect("results array")
            .len()
            <= 3
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn search_unknown_record_type_is_invalid_params() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("query".into(), serde_json::Value::from("x"));
    args.insert("record_type".into(), serde_json::Value::from("not-a-type"));
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("search").with_arguments(args))
        .await
        .expect_err("unknown record_type is a protocol error (Err), not a domain envelope");

    // The handler returns `Err(rmcp::ErrorData)` which surfaces on the client
    // as `Err(ServiceError::McpError(ErrorData))`. The `code` field on
    // `ErrorData` is `ErrorCode(i32)` with a public `.0` accessor; -32602 is
    // JSON-RPC `invalid_params`.
    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "unknown enum-string -> invalid_params");

    connected.shutdown().await;
}

#[tokio::test]
async fn by_session_with_thread_id_returns_structured_result_set() {
    // The ready fixture has no session-tagged records, but the handler must
    // succeed (empty results is a success, not an error) when given one valid ref.
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert(
        "codex_thread_id".into(),
        serde_json::Value::from("thread-abc123"),
    );
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("by_session").with_arguments(args))
        .await
        .expect("by_session tool call must dispatch");

    let structured = expect_structured(&result);
    assert!(
        structured.get("results").is_some(),
        "structured payload carries `results`"
    );
    assert!(
        structured.get("_meta").is_some(),
        "structured payload carries `_meta`"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn by_session_zero_refs_is_invalid_params() {
    let connected = McpTestHome::ready().connect().await;

    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("by_session"))
        .await
        .expect_err("zero refs must be a protocol error, not a domain envelope");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "zero session refs -> invalid_params");

    connected.shutdown().await;
}

#[tokio::test]
async fn by_session_multiple_refs_is_invalid_params() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert(
        "codex_thread_id".into(),
        serde_json::Value::from("thread-abc"),
    );
    args.insert(
        "codex_rollout_path".into(),
        serde_json::Value::from("/some/path"),
    );
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("by_session").with_arguments(args))
        .await
        .expect_err("multiple refs must be a protocol error, not a domain envelope");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "multiple session refs -> invalid_params");

    connected.shutdown().await;
}

#[tokio::test]
async fn by_session_malformed_uuid_is_invalid_params() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert(
        "cc_session_id".into(),
        serde_json::Value::from("not-a-uuid"),
    );
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("by_session").with_arguments(args))
        .await
        .expect_err("malformed UUID must be a protocol error, not a domain envelope");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(
        code, -32602,
        "malformed cc_session_id UUID -> invalid_params"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn list_on_ready_fixture_returns_structured_result_set() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("limit".into(), serde_json::Value::from(5));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("list").with_arguments(args))
        .await
        .expect("list tool call must dispatch");

    let structured = expect_structured(&result);
    assert!(
        structured.get("results").is_some(),
        "structured payload carries `results`"
    );
    assert!(
        structured.get("_meta").is_some(),
        "structured payload carries `_meta`"
    );
    assert!(
        structured["results"]
            .as_array()
            .expect("results array")
            .len()
            <= 5,
        "limit=5 caps the returned rows"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn list_unknown_source_is_invalid_params() {
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("source".into(), serde_json::Value::from("not-a-source"));
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("list").with_arguments(args))
        .await
        .expect_err("unknown source is a protocol error (Err), not a domain envelope");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "unknown enum-string -> invalid_params");

    connected.shutdown().await;
}

#[tokio::test]
async fn get_found_returns_record_and_meta() {
    // The ready fixture seeds `decisions/seed.yml` with id `seed`; a
    // bare-id `get` returns the record (success) with the `_meta` envelope.
    let connected = McpTestHome::ready().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("seed"));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect("get tool call must dispatch");

    let structured = expect_structured(&result);
    assert_eq!(
        structured["record"]["id"], "seed",
        "the returned record carries the requested id"
    );
    assert!(
        structured["_meta"]["trust_policy"].is_string(),
        "_meta carries a `trust_policy` string"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn get_missing_id_returns_not_found_envelope() {
    // An indexed-but-empty home has no records; `get` returns the
    // structured `NOT_FOUND` envelope, not a protocol error.
    let connected = McpTestHome::indexed_empty().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("missing"));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect("get tool call must dispatch");

    assert_eq!(result.is_error, Some(true), "no record -> is_error = true");
    assert_eq!(
        expect_error_code(&result),
        error_codes::NOT_FOUND,
        "missing id must surface as NOT_FOUND"
    );
    let envelope = result
        .structured_content
        .as_ref()
        .expect("error result carries a structured envelope");
    assert_eq!(
        envelope["context"]["requested_id"], "missing",
        "context echoes the requested id back"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn get_unsigned_under_hide_policy_returns_hidden_envelope() {
    // First call: hide policy is active and the seeded record is unsigned,
    // so `get` returns the `HIDDEN_BY_POLICY` envelope. Second call: the
    // `include_unsigned` override bypasses the policy and surfaces the
    // record as a success.
    let connected = McpTestHome::ready_hide_policy_with_unsigned_record("u")
        .connect()
        .await;

    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("u"));
    let hidden = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect("get tool call must dispatch");
    assert_eq!(
        hidden.is_error,
        Some(true),
        "hide policy -> is_error = true"
    );
    assert_eq!(
        expect_error_code(&hidden),
        error_codes::HIDDEN_BY_POLICY,
        "unsigned record under hide policy -> HIDDEN_BY_POLICY"
    );

    let mut override_args = serde_json::Map::new();
    override_args.insert("id".into(), serde_json::Value::from("u"));
    override_args.insert("include_unsigned".into(), serde_json::Value::from(true));
    let shown = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(override_args))
        .await
        .expect("get tool call must dispatch");
    let structured = expect_structured(&shown);
    assert_eq!(
        structured["record"]["id"], "u",
        "include_unsigned=true returns the record verbatim"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn get_malformed_qualified_id_is_invalid_params() {
    // A colon-bearing id that doesn't parse as `<source>:<project_id>:<id>`
    // is a malformed call, not a domain condition — the handler returns
    // `invalid_params` rather than silently falling back to a bare id.
    let connected = McpTestHome::indexed_empty().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("local:foo"));
    let err = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect_err("a malformed qualified id is a protocol error");

    let code = match err {
        ServiceError::McpError(ref e) => e.code.0,
        _ => panic!("expected ServiceError::McpError, got: {err:?}"),
    };
    assert_eq!(code, -32602, "malformed qualified id -> invalid_params");

    connected.shutdown().await;
}
