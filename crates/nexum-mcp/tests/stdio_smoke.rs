//! Child-process stdio smoke test.
//!
//! The in-process duplex harness cannot catch what only a real
//! subprocess can:
//!
//! - stdout pollution — the JSON-RPC stream owns stdout; any logging
//!   that leaks there breaks framing on the very first message.
//! - the manual `tokio::runtime::Builder` wiring in the binary entry
//!   point.
//! - EOF-driven shutdown when the parent closes the child's stdin.
//!
//! This test spawns the real `nexum-mcp` binary, runs `initialize` +
//! one tool call + drops the client to trigger an EOF shutdown. The
//! handshake succeeding is the canary for stdout cleanliness: if
//! anything writes to stdout outside the JSON-RPC stream, `serve` fails
//! to parse and the test fails with a transport error.

mod common;

use common::McpTestHome;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::TokioChildProcess;
use tokio::process::Command;

#[tokio::test(flavor = "multi_thread")]
async fn child_process_initialize_and_tool_call_over_real_stdio() {
    // Stand up a real on-disk nexum home — initialized + indexed but
    // empty. Pointing the child at it via `NEXUM_HOME` mirrors how an
    // agent host launches the server in production.
    let fx = McpTestHome::indexed_empty();
    let home = fx.home_root();

    // `CARGO_BIN_EXE_<name>` is the cargo-set env var pointing at the
    // freshly built binary for an integration test in the same crate;
    // the `[[bin]]` entry in `Cargo.toml` is `nexum-mcp`.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nexum-mcp"));
    cmd.env("NEXUM_HOME", &home);
    // Keep stderr quiet so the test output stays scannable; the
    // child's stderr is inherited by default (the `tracing_subscriber`
    // setup in `run()` writes to stderr, not stdout).
    cmd.env("RUST_LOG", "warn");

    // `TokioChildProcess::new` is a 1.7 convenience that wraps the
    // builder with default piped stdio; the more granular form is
    // `TokioChildProcess::builder(cmd).spawn()`.
    let transport = TokioChildProcess::new(cmd).expect("spawn nexum-mcp child process");

    // `()` is rmcp's no-op client handler. `serve` drives the MCP
    // `initialize` handshake; a stdout-logging regression would make
    // it fail to parse the first JSON-RPC frame and surface as an
    // `expect` panic here — the smoke test's primary canary.
    let client = ()
        .serve(transport)
        .await
        .expect("MCP initialize handshake must complete over real stdio");

    // List the tools exposed by the real server. The handler module
    // registers six read tools (search, get, list, recent, by_session,
    // list_projects), so the count is a stable shape assertion.
    let tools = client
        .list_tools(None)
        .await
        .expect("list_tools over real stdio");
    assert_eq!(
        tools.tools.len(),
        6,
        "the server must expose all six read tools over the real stdio transport"
    );

    // One real tool call end-to-end. `list_projects` takes no args, so
    // it exercises the registration + dispatch path without DTO
    // parsing distractions. An empty index returns `results = []` —
    // not an error — which proves a successful round-trip.
    let result = client
        .call_tool(CallToolRequestParams::new("list_projects"))
        .await
        .expect("list_projects must dispatch over real stdio");
    assert_ne!(
        result.is_error,
        Some(true),
        "list_projects against an empty index is a success, not a tool error: {result:?}"
    );
    assert!(
        result.structured_content.is_some(),
        "the response carries structured content — stdout is clean"
    );

    // Dropping the client closes the child's stdin; the server sees
    // EOF and returns `QuitReason::Closed`, exiting clean. `cancel`
    // makes the shutdown explicit instead of relying on Drop ordering.
    client
        .cancel()
        .await
        .expect("clean EOF-driven shutdown over real stdio");

    // Hold the fixture's temp dir until shutdown completes — dropping
    // it earlier would delete the home out from under the server mid-
    // call. Explicit drop documents the intent.
    drop(fx);
}
