//! Harness self-test: `connect()` against a `ready()` home completes the MCP
//! `initialize` handshake and a `list_tools` round-trip. If this fails, the
//! duplex wiring is broken and every tool test is unreliable — so it runs
//! first and asserts the minimum. The third test pins the uninitialized-home
//! path: a tool call against a server with no resolved home returns a
//! structured `NOT_INITIALIZED` error rather than the process having crashed.

mod common;

use common::{McpTestHome, expect_error_code};
use nexum_core::api::error::error_codes;

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
