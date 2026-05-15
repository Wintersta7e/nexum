//! `nexum-mcp` — stdio MCP server binary.
//!
//! All logic lives in the `nexum_mcp` library so the integration tests can
//! drive the server in-process; this binary just calls [`nexum_mcp::run`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    nexum_mcp::run()
}
