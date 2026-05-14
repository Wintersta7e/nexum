#![cfg(feature = "server-skeleton")]
//! Tool-catalog conformance: the server exposes exactly the six read-only
//! tools, each with read-only annotations and a description within the
//! token budget.
//!
//! The suite exercises `NexumServer::tool_router()` — the tool registry
//! the `#[tool_router]` macro generates on the server type.

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

/// Coarse token estimate: a whitespace-split word count. A real BPE
/// tokenizer emits more tokens than this (it splits punctuation and
/// subwords further), so this is a loose lower bound — it catches a
/// description that has obviously ballooned, not one marginally over the
/// 80-token budget.
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
