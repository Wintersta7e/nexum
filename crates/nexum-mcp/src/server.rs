//! The `NexumServer` MCP handler, its runtime state, and the process entry point.

use std::process::ExitCode;
use std::sync::Arc;

use nexum_core::api::error::ErrorEnvelope;
use nexum_core::config::types::Config;
use nexum_core::paths::Paths;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool_handler, tool_router};

/// Resolved-once runtime context for the server process.
///
/// `run` resolves `Paths` + `Config` a single time at startup. Success →
/// [`RuntimeState::Ready`]; any resolution failure → [`RuntimeState::Unavailable`]
/// carrying the `ErrorEnvelope` so every subsequent tool call can return a
/// structured error rather than the process exiting before MCP `initialize` —
/// which an agent would see as "server crashed", not as actionable remediation.
#[derive(Debug)]
// The `Ready` variant (resolved `Paths` + `Config`) is much larger than
// `Unavailable`, but the enum is built once at startup, moved by value
// exactly once (into the `Arc` in `NexumServer::new`), and only ever read
// through that `Arc` thereafter — the size delta is immaterial.
#[allow(clippy::large_enum_variant)]
pub enum RuntimeState {
    /// `Paths` + `Config` resolved cleanly. The index DB may still be absent —
    /// that surfaces per-call as `NOT_INDEXED` from the api layer, not here.
    Ready { paths: Paths, cfg: Config },
    /// Startup resolution failed. Every tool call returns this envelope as a
    /// `CallToolResult { is_error: true }`.
    Unavailable(ErrorEnvelope),
}

/// The MCP server handler. Cloned by rmcp once per connection, so the
/// (immutable, shared) runtime state sits behind an `Arc` to keep `Clone`
/// cheap.
#[derive(Clone)]
pub struct NexumServer {
    // Unused until the first tool handler reads it via `runtime()`.
    #[allow(dead_code)]
    runtime: Arc<RuntimeState>,
    tool_router: ToolRouter<NexumServer>,
}

#[tool_router(vis = "pub")]
impl NexumServer {
    /// Construct a server over an already-resolved runtime state.
    pub fn new(runtime: RuntimeState) -> Self {
        Self {
            runtime: Arc::new(runtime),
            tool_router: Self::tool_router(),
        }
    }

    /// Borrow the runtime state. Tool handlers match on this to either
    /// dispatch into `nexum_core::api` (`Ready`) or short-circuit to the
    /// startup envelope (`Unavailable`). Unused until the first handler lands.
    #[allow(dead_code)]
    pub(crate) fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }

    // The six `#[tool]` handlers land with the per-tool tasks; the router
    // is empty for now so the skeleton compiles and serves. Each handler
    // will have the shape:
    //   #[tool(description = "...")]    // read-only annotations, concise text
    //   async fn verb(&self, Parameters(params): Parameters<VerbParams>)
    //       -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> { ... }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NexumServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                nexum_core::version(),
            ))
            .with_instructions(
                "nexum exposes a read-only memory index over six tools: \
                 search, get, list, recent, by_session, list_projects. \
                 All results carry the trust-contract fields \
                 (signature_status, trust_basis, warnings).",
            )
    }
}

/// Build the runtime, resolve `Paths` + `Config` once, serve over stdio.
///
/// Returns [`ExitCode::SUCCESS`] on a clean stdin-EOF shutdown and
/// [`ExitCode::FAILURE`] only if the runtime cannot be built or `serve`
/// itself fails the MCP `initialize` handshake — *not* on a missing nexum
/// home (that becomes [`RuntimeState::Unavailable`] and the server still
/// serves).
pub fn run() -> ExitCode {
    // Logging → stderr. The MCP JSON-RPC stream owns stdout; a subscriber
    // left on its stdout default would corrupt every frame.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Manual runtime (not `#[tokio::main]`) so `max_blocking_threads` honors
    // the `2 * num_cpus` cap: every tool handler runs its synchronous
    // `nexum_core::api` call inside `spawn_blocking`, and an unbounded
    // blocking pool would let a burst of tool calls oversubscribe the CPU.
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(2 * cpus)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async {
        // A failed resolution is not fatal — it becomes `Unavailable` so
        // the server still serves and every tool call returns a structured
        // error rather than the process having crashed.
        let state = match nexum_core::session::resolve_runtime() {
            Ok((paths, cfg)) => {
                tracing::info!(home = %paths.home.display(), "runtime resolved");
                RuntimeState::Ready { paths, cfg }
            }
            Err(envelope) => {
                tracing::warn!(
                    error_code = %envelope.error_code,
                    "runtime unavailable; server will return structured errors"
                );
                RuntimeState::Unavailable(envelope)
            }
        };

        let server = NexumServer::new(state);

        // `serve` runs the MCP `initialize` handshake over stdio, then the
        // request loop. `waiting()` resolves when stdin hits EOF
        // (`QuitReason::Closed`) or the loop is cancelled.
        let running = match server.serve(rmcp::transport::stdio()).await {
            Ok(running) => running,
            Err(e) => {
                tracing::error!(error = %e, "MCP serve/initialize failed");
                return ExitCode::FAILURE;
            }
        };

        match running.waiting().await {
            Ok(reason) => {
                tracing::info!(?reason, "MCP server shut down");
                ExitCode::SUCCESS
            }
            Err(e) => {
                tracing::error!(error = %e, "MCP server task join failed");
                ExitCode::FAILURE
            }
        }
    })
}
