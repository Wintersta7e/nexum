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
    assert!(structured["results"].as_array().expect("results array").len() <= 3);

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
    assert!(structured.get("results").is_some(), "structured payload carries `results`");
    assert!(structured.get("_meta").is_some(), "structured payload carries `_meta`");
    assert!(
        structured["results"].as_array().expect("results array").len() <= 5,
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
