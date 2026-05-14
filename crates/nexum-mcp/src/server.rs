//! The `NexumServer` MCP handler, its runtime state, and the process entry point.

use std::process::ExitCode;
use std::sync::Arc;

use nexum_core::api::error::ErrorEnvelope;
use nexum_core::config::types::Config;
use nexum_core::paths::Paths;
use nexum_core::query::Filters;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};

use crate::dto::RecentParams;

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
    /// startup envelope (`Unavailable`).
    pub(crate) fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }

    /// Most-recently-updated records, newest first.
    ///
    /// Read-only. Each row carries the trust contract (`signature_status`,
    /// `trust_basis`, warnings). Filter by source adapter with `source`;
    /// `require_signed` drops unverified rows.
    #[tool(
        description = "List the most recently updated memory records, newest \
                       first. Read-only. Each row includes trust fields \
                       (signature_status, trust_basis, warnings). Optional \
                       `source` filters to one adapter; `require_signed` \
                       returns only verified records.",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn recent(
        &self,
        Parameters(params): Parameters<RecentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // The core call runs inside `spawn_blocking` — never on a runtime
        // worker — because the `nexum_core::api` verbs are synchronous and
        // do blocking SQLite I/O.
        let (paths, cfg) = match self.runtime() {
            // Cloning `Paths` + `Config` per call is cheap next to the SQLite
            // open + query the core verb then runs; if profiling ever shows
            // otherwise, hold them as `Arc` inside `RuntimeState::Ready`.
            RuntimeState::Ready { paths, cfg } => (paths.clone(), cfg.clone()),
            RuntimeState::Unavailable(envelope) => {
                return Ok(unavailable_result(envelope));
            }
        };

        let filters = Filters {
            require_signed: params.require_signed,
            strict_revocation: params.strict_revocation,
            ..Filters::default()
        };
        let limit = params.limit;
        let source = params.source;

        let result = tokio::task::spawn_blocking(move || {
            nexum_core::api::recent(&paths, &cfg, &filters, limit, source.as_deref())
        })
        .await;

        match result {
            Ok(Ok(result_set)) => {
                let value = serde_json::to_value(&result_set).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize recent result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("recent task panicked: {join_err}"),
                None,
            )),
        }
    }
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

// ───── Domain-error channel ────────────────────────────────────────────────
//
// Domain errors — including a server with no resolved nexum home — travel as
// `CallToolResult { is_error: true }` carrying the wire-stable `ErrorEnvelope`,
// NOT as `rmcp::ErrorData`. `ErrorData` is reserved for protocol-level failures
// (a malformed call: bad JSON, bad arity, unparseable key) — see the per-tool
// handlers. The agent gets the same `error_code` + `remediation` the CLI's
// `--json` path emits, so one trust contract spans both surfaces.

/// Render an [`ErrorEnvelope`] as a structured tool error. The
/// `unwrap_or_else` degrades to a minimal object rather than panicking
/// inside an async handler if the (flat, derived-`Serialize`) envelope
/// somehow fails to serialize.
fn envelope_to_result(envelope: &ErrorEnvelope) -> CallToolResult {
    CallToolResult::structured_error(
        serde_json::to_value(envelope)
            .unwrap_or_else(|_| serde_json::json!({ "error_code": envelope.error_code })),
    )
}

/// The startup envelope as a structured tool error. Used by every handler's
/// `RuntimeState::Unavailable` arm: the server resolved no nexum home, so the
/// call cannot be answered, but the process is alive and the agent gets
/// actionable remediation (`NOT_INITIALIZED` + `nexum init`) rather than a
/// dropped connection.
pub(crate) fn unavailable_result(envelope: &ErrorEnvelope) -> CallToolResult {
    envelope_to_result(envelope)
}

/// Any `ApiError` raised by a `nexum_core::api` verb as a structured tool
/// error. Reuses the existing `From<&ApiError> for ErrorEnvelope` builder so
/// the MCP surface emits exactly the CLI `--json` envelope — same stable
/// `error_code`, same `remediation`, same `context` discriminators.
pub(crate) fn api_error_result(err: &nexum_core::api::ApiError) -> CallToolResult {
    let envelope: ErrorEnvelope = err.into();
    envelope_to_result(&envelope)
}
