//! `nexum-mcp` — the stdio MCP server wrapping `nexum-core`'s read surface.
//!
//! # Module layout
//!
//! - [`server`] — the [`NexumServer`] handler, the [`RuntimeState`] it carries,
//!   the `#[tool_router]` tool registry, the `#[tool_handler] impl ServerHandler`,
//!   and the [`run`] entry point (manual tokio runtime + stderr logging +
//!   one-shot runtime resolution + `serve(stdio())` + `waiting()`).
//! - `dto` (added with the first tool handler) — the
//!   `#[derive(Deserialize, JsonSchema)]` input DTOs.
//!
//! `src/main.rs` is a three-line binary that calls [`run`]; everything testable
//! lives here in the library so the integration tests under `tests/` can drive
//! [`NexumServer`] in-process.
//!
//! The server is a transport wrapper: every tool is a thin DTO → `nexum_core::api`
//! call wrapped in `tokio::task::spawn_blocking`. No domain logic lives here.

#![forbid(unsafe_code)]

mod dto;
mod server;

pub use server::{NexumServer, RuntimeState, run};
