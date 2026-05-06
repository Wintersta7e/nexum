//! `nexum-mcp` — stdio MCP server binary.
//!
//! Stub. The MCP server implementation is not yet wired up.

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    eprintln!(
        "nexum-mcp {} — stub. MCP server not yet implemented.",
        nexum_core::version()
    );
    Ok(())
}
