//! `nexum-mcp` — stdio MCP server binary.
//!
//! All logic lives in the `nexum_mcp` library so the integration tests can
//! drive the server in-process; this binary just calls [`nexum_mcp::run`].

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    install_pipe_friendly_panic_hook();
    nexum_mcp::run()
}

/// Mirror of `nexum-cli`'s broken-pipe panic hook so an MCP client that
/// drops the stdio JSON-RPC stream sees exit 0 instead of a 101 panic.
fn install_pipe_friendly_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&'static str>().copied())
            .unwrap_or("");
        if msg.starts_with("failed printing to ")
            && (msg.contains("Broken pipe") || msg.contains("broken pipe"))
        {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}
