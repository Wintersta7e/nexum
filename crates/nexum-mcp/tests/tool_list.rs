#![cfg(feature = "server-skeleton")]
//! Tool-catalog conformance: the server exposes exactly the six read-only
//! tools, each with read-only annotations and a description within the
//! token budget.
//!
//! This test is RED until the server skeleton lands `NexumServer` and the
//! six `#[tool]` handlers. It compiles against the public surface of
//! `nexum_mcp` (`NexumServer::tool_router()`), which the `#[tool_router]`
//! macro generates.

use nexum_mcp::NexumServer;

/// The six read-only tools, in no particular order.
const EXPECTED_TOOLS: [&str; 6] = [
    "search",
    "get",
    "list",
    "recent",
    "by_session",
    "list_projects",
];

/// Coarse token estimate: MCP tool descriptions are billed per token, and
/// the budget is <=80 tokens each. A whitespace-split word count
/// overestimates slightly versus a real BPE tokenizer, so passing this
/// bound is a safe proxy for the real budget.
fn approx_tokens(s: &str) -> usize {
    s.split_whitespace().count()
}

#[test]
fn server_exposes_exactly_the_six_read_tools() {
    let router = NexumServer::tool_router();
    let mut names: Vec<&str> = router.list_all().iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    let mut expected = EXPECTED_TOOLS;
    expected.sort_unstable();
    assert_eq!(
        names, expected,
        "MCP server must expose exactly the six read tools"
    );
}

#[test]
fn every_tool_carries_read_only_annotations() {
    let router = NexumServer::tool_router();
    for tool in router.list_all() {
        let ann = tool
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("tool `{}` has no annotations", tool.name));
        assert_eq!(
            ann.read_only_hint,
            Some(true),
            "tool `{}` must set read_only_hint = true",
            tool.name
        );
        assert_eq!(
            ann.idempotent_hint,
            Some(true),
            "tool `{}` must set idempotent_hint = true",
            tool.name
        );
        assert_eq!(
            ann.destructive_hint,
            Some(false),
            "tool `{}` must set destructive_hint = false",
            tool.name
        );
        assert_eq!(
            ann.open_world_hint,
            Some(false),
            "tool `{}` must set open_world_hint = false",
            tool.name
        );
    }
}

#[test]
fn every_tool_description_is_within_the_token_budget() {
    let router = NexumServer::tool_router();
    for tool in router.list_all() {
        let desc = tool
            .description
            .as_ref()
            .unwrap_or_else(|| panic!("tool `{}` has no description", tool.name));
        let tokens = approx_tokens(desc);
        assert!(
            tokens <= 80,
            "tool `{}` description is ~{tokens} tokens; budget is <=80",
            tool.name
        );
    }
}
