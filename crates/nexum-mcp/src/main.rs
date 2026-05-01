//! `nexum-mcp` — stdio MCP server binary.
//!
//! Stub for the design at `docs/spec/2026-04-29-nexum-design.md` §6.
//! M1 implementation is gated on the pre-M1 stack-validation spike (§3.6).

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
        "nexum-mcp {} — pre-M1 stub. See docs/spec/ for the design; MCP server not yet implemented.",
        nexum_core::version()
    );
    Ok(())
}
