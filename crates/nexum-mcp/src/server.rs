//! The `NexumServer` MCP handler, its runtime state, and the process entry point.

use std::process::ExitCode;
use std::sync::Arc;

use nexum_core::api::error::{ErrorEnvelope, Remediation, error_codes};
use nexum_core::config::types::Config;
use nexum_core::paths::Paths;
use nexum_core::query::{Filters, GetOpts, GetSuccess, SearchOpts, SessionLookup};
use nexum_core::records::{Confidence, GetOutcome, RecordKey, RecordType, Source};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};

use crate::dto::{BySessionParams, GetParams, ListParams, RecentParams, SearchParams};

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

    /// Full-text ranked search across memory records.
    ///
    /// Results are FTS-ranked, newest-first within the same score band.
    /// Each row carries the trust contract (`signature_status`, `trust_basis`,
    /// warnings). Optional filters narrow by `record_type`, `source`, and
    /// `min_confidence`; `require_signed` drops unverified rows.
    #[tool(
        description = "Full-text ranked search across memory records. Results are \
                       FTS-ranked, newest-first within the same score band. Each \
                       row includes trust fields (signature_status, trust_basis, \
                       warnings). Optional filters: record_type \
                       (decision|recommendation|failure|untyped), source \
                       (cc-native|codex-native|local), min_confidence \
                       (high|medium|low), require_signed.",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn search(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Enum-string fields are parsed before the runtime gate so a malformed
        // call fails fast with invalid_params, not NOT_INDEXED or UNAVAILABLE.
        let record_type = parse_record_type(params.record_type.as_deref())?;
        let source = parse_source(params.source.as_deref())?;
        let min_confidence = parse_min_confidence(params.min_confidence.as_deref())?;

        let (paths, cfg) = match self.runtime() {
            RuntimeState::Ready { paths, cfg } => (paths.clone(), cfg.clone()),
            RuntimeState::Unavailable(envelope) => {
                return Ok(unavailable_result(envelope));
            }
        };

        let filters = Filters {
            require_signed: params.require_signed,
            strict_revocation: params.strict_revocation,
            record_type,
            source,
            min_confidence,
            ..Filters::default()
        };
        let mut opts = SearchOpts::new(params.query);
        opts.top_k = params.top_k;
        opts.trust_policy = cfg.trust.unsigned_default;
        opts.filters = filters;

        let result =
            tokio::task::spawn_blocking(move || nexum_core::api::search(&paths, &cfg, &opts)).await;

        match result {
            Ok(Ok(result_set)) => {
                let value = serde_json::to_value(&result_set).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize search result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("search task panicked: {join_err}"),
                None,
            )),
        }
    }

    /// Filtered, paginated listing of memory records.
    ///
    /// No FTS ranking — results are newest-first. Each row carries the trust
    /// contract (`signature_status`, `trust_basis`, warnings). Optional
    /// filters narrow by `record_type` and `source`; `limit` and `cursor`
    /// control pagination.
    #[tool(
        description = "Filtered, paginated listing of memory records, newest \
                       first. No FTS ranking. Each row includes trust fields \
                       (signature_status, trust_basis, warnings). Optional \
                       filters: record_type \
                       (decision|recommendation|failure|untyped), source \
                       (cc-native|codex-native|local), require_signed. \
                       Use cursor from _meta.next_cursor for subsequent pages.",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list(
        &self,
        Parameters(params): Parameters<ListParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let record_type = parse_record_type(params.record_type.as_deref())?;
        let source = parse_source(params.source.as_deref())?;

        let (paths, cfg) = match self.runtime() {
            RuntimeState::Ready { paths, cfg } => (paths.clone(), cfg.clone()),
            RuntimeState::Unavailable(envelope) => {
                return Ok(unavailable_result(envelope));
            }
        };

        let filters = Filters {
            require_signed: params.require_signed,
            strict_revocation: params.strict_revocation,
            record_type,
            source,
            ..Filters::default()
        };
        let limit = params.limit;
        let cursor = params.cursor;

        let result = tokio::task::spawn_blocking(move || {
            nexum_core::api::list(&paths, &cfg, &filters, limit, cursor.as_deref())
        })
        .await;

        match result {
            Ok(Ok(result_set)) => {
                let value = serde_json::to_value(&result_set).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize list result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("list task panicked: {join_err}"),
                None,
            )),
        }
    }

    /// Records associated with a specific session.
    ///
    /// Exactly one of `cc_session_id`, `codex_rollout_path`, or
    /// `codex_thread_id` must be supplied. Zero or multiple refs produce an
    /// `invalid_params` protocol error. Each row carries the trust contract
    /// (`signature_status`, `trust_basis`, warnings).
    #[tool(
        description = "Records associated with a specific session. Supply \
                       exactly one of: cc_session_id (UUID string), \
                       codex_rollout_path (absolute path string), or \
                       codex_thread_id (thread identifier string). Zero or \
                       multiple refs produce an invalid_params error. Each row \
                       includes trust fields (signature_status, trust_basis, \
                       warnings).",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn by_session(
        &self,
        Parameters(params): Parameters<BySessionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Enforce "exactly one ref" arity before touching the runtime — a
        // malformed call fails fast with invalid_params.
        let lookup = build_session_lookup(
            params.cc_session_id.as_deref(),
            params.codex_rollout_path.as_deref(),
            params.codex_thread_id.as_deref(),
        )?;

        let (paths, cfg) = match self.runtime() {
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

        let result = tokio::task::spawn_blocking(move || {
            nexum_core::api::by_session(&paths, &cfg, &filters, &lookup)
        })
        .await;

        match result {
            Ok(Ok(result_set)) => {
                let value = serde_json::to_value(&result_set).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize by_session result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("by_session task panicked: {join_err}"),
                None,
            )),
        }
    }

    /// Fetch one full record by id.
    ///
    /// `id` accepts a bare id or `<source>:<project_id>:<id>`. A bare id that
    /// matches multiple rows returns an `AMBIGUOUS_KEY` envelope with the
    /// candidate list. Records suppressed by trust policy return
    /// `HIDDEN_BY_POLICY`; retry with `include_unsigned: true` to inspect.
    #[tool(
        description = "Fetch one full record by id. `id` accepts a bare id or \
                       qualified key `<source>:<project_id>:<id>`. A bare id \
                       matching multiple rows returns AMBIGUOUS_KEY with the \
                       candidate list. Records suppressed by trust policy \
                       return HIDDEN_BY_POLICY; retry with \
                       include_unsigned=true to inspect. Each row includes \
                       trust fields (signature_status, trust_basis, warnings).",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get(
        &self,
        Parameters(params): Parameters<GetParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Mirror the CLI: a colon-bearing id must parse as the qualified form,
        // a bare id always resolves to a bare key. A colon-bearing id that
        // fails to parse is a malformed call (`invalid_params`), not a domain
        // condition — we won't silently fall back to bare.
        let key = if params.id.contains(':') {
            match RecordKey::parse_qualified(&params.id) {
                Some(k) => k,
                None => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!(
                            "`{}` looks like a qualified key but isn't valid \
                             `<source>:<project_id>:<id>`",
                            params.id
                        ),
                        Some(serde_json::json!({ "field": "id", "value": params.id })),
                    ));
                }
            }
        } else {
            RecordKey::bare(params.id.clone())
        };

        let (paths, cfg) = match self.runtime() {
            RuntimeState::Ready { paths, cfg } => (paths.clone(), cfg.clone()),
            RuntimeState::Unavailable(envelope) => {
                return Ok(unavailable_result(envelope));
            }
        };

        let opts = GetOpts {
            include_unsigned: params.include_unsigned,
            trust_policy: cfg.trust.unsigned_default,
            strict_revocation: params.strict_revocation,
        };
        let requested_id = params.id.clone();

        // The synchronous core verb runs on a blocking thread so the async
        // runtime worker is not parked on SQLite I/O.
        let result =
            tokio::task::spawn_blocking(move || nexum_core::api::get(&paths, &cfg, &key, &opts))
                .await;

        match result {
            Ok(Ok(GetOutcome::Found { record, meta })) => {
                let envelope = GetSuccess { record, meta };
                let value = serde_json::to_value(&envelope).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize get result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Ok(GetOutcome::NotFound)) => {
                let env = ErrorEnvelope {
                    error_code: error_codes::NOT_FOUND,
                    message: format!("no record matches `{requested_id}`"),
                    remediation: Some(Remediation {
                        command: None,
                        rationale: "Verify the id is correct, or call `search` \
                                    to find candidate records."
                            .into(),
                    }),
                    context: serde_json::json!({ "requested_id": requested_id }),
                };
                Ok(envelope_to_result(&env))
            }
            Ok(Ok(GetOutcome::HiddenByPolicy { signature_status })) => {
                let env = ErrorEnvelope {
                    error_code: error_codes::HIDDEN_BY_POLICY,
                    message: format!(
                        "record exists but hidden by trust policy (status: {signature_status})"
                    ),
                    remediation: Some(Remediation {
                        command: None,
                        rationale: "Retry with `include_unsigned: true` to inspect the record \
                                    deliberately."
                            .into(),
                    }),
                    context: serde_json::json!({
                        "signature_status": signature_status.to_string(),
                        "requested_id": requested_id,
                    }),
                };
                Ok(envelope_to_result(&env))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("get task panicked: {join_err}"),
                None,
            )),
        }
    }

    /// Per-project record counts + identity + registered path.
    ///
    /// Read-only. Returns every distinct `project_id` in the index with its
    /// record / signed-record counts and identity kind. `path` is the
    /// registered filesystem path for `name:`-identity projects and `null`
    /// otherwise.
    #[tool(
        description = "List every project in the index with its record count, \
                       signed-record count, and identity kind. `path` is the \
                       registered filesystem path for `name:`-identity \
                       projects and null for `git:` / `cc-slug:` / \
                       `codex-cwd:` identities. Takes no parameters.",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_projects(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (paths, cfg) = match self.runtime() {
            RuntimeState::Ready { paths, cfg } => (paths.clone(), cfg.clone()),
            RuntimeState::Unavailable(envelope) => {
                return Ok(unavailable_result(envelope));
            }
        };

        let result =
            tokio::task::spawn_blocking(move || nexum_core::api::list_projects(&paths, &cfg)).await;

        match result {
            Ok(Ok(listing)) => {
                // `ProjectListing` already serializes as `{ results, _meta }` —
                // the `_meta` rename lives on the core type, so the MCP layer
                // serializes it straight through.
                let value = serde_json::to_value(&listing).map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("failed to serialize list_projects result: {e}"),
                        None,
                    )
                })?;
                Ok(CallToolResult::structured(value))
            }
            Ok(Err(api_err)) => Ok(api_error_result(&api_err)),
            Err(join_err) => Err(rmcp::ErrorData::internal_error(
                format!("list_projects task panicked: {join_err}"),
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

// ───── Protocol-error helpers: enum-string parsing ─────────────────────────
//
// `record_type` / `source` / `min_confidence` arrive as JSON strings and
// become typed `Filters` fields. An unrecognized value is a malformed call,
// not a domain condition — it travels as `rmcp::ErrorData::invalid_params`,
// the protocol-error channel, NOT as a `CallToolResult` domain envelope.
// (`recent`'s `source` is the exception — it is passed through to the core
// verb unparsed, so an unknown value there surfaces as an INVALID_FILTER
// domain envelope. `search`/`list` parse up front because the value reaches
// `Filters` as a typed enum, which cannot carry an unknown string.)

/// Parse the optional `record_type` enum-string. `None` input → `Ok(None)`
/// (no filter); a present-but-unrecognized value → `Err(invalid_params)`.
fn parse_record_type(raw: Option<&str>) -> Result<Option<RecordType>, rmcp::ErrorData> {
    match raw {
        None => Ok(None),
        Some(s) => RecordType::try_from_user_str(s)
            .map(Some)
            .ok_or_else(|| invalid_enum_string("record_type", s)),
    }
}

/// Parse the optional `source` enum-string. See [`parse_record_type`].
fn parse_source(raw: Option<&str>) -> Result<Option<Source>, rmcp::ErrorData> {
    match raw {
        None => Ok(None),
        Some(s) => Source::try_from_user_str(s)
            .map(Some)
            .ok_or_else(|| invalid_enum_string("source", s)),
    }
}

/// Parse the optional `min_confidence` enum-string. See [`parse_record_type`].
fn parse_min_confidence(raw: Option<&str>) -> Result<Option<Confidence>, rmcp::ErrorData> {
    match raw {
        None => Ok(None),
        Some(s) => Confidence::try_from_user_str(s)
            .map(Some)
            .ok_or_else(|| invalid_enum_string("min_confidence", s)),
    }
}

/// Build an `invalid_params` error naming the offending field + value, so the
/// agent can correct the call without re-parsing English. The `data` payload
/// carries the field/value pair as structured JSON.
fn invalid_enum_string(field: &str, value: &str) -> rmcp::ErrorData {
    rmcp::ErrorData::invalid_params(
        format!("unknown value `{value}` for `{field}`"),
        Some(serde_json::json!({ "field": field, "value": value })),
    )
}

// ───── Protocol-error helper: by_session arity ─────────────────────────────

/// Build a `SessionLookup` from the three optional `by_session` ref fields,
/// enforcing the "exactly one of" arity.
///
/// - zero refs set → `invalid_params` ("provide exactly one ...").
/// - two or three set → `invalid_params` naming the conflict.
/// - exactly one set → the matching `SessionLookup` variant. A `cc_session_id`
///   that is present but not a parseable UUID is itself an `invalid_params`
///   (the field is structurally wrong, not a missing match).
///
/// Zero/multiple/bad-UUID are all malformed *calls*, not domain conditions —
/// hence the protocol-error channel, never a `CallToolResult` envelope.
fn build_session_lookup(
    cc_session_id: Option<&str>,
    codex_rollout_path: Option<&str>,
    codex_thread_id: Option<&str>,
) -> Result<SessionLookup, rmcp::ErrorData> {
    match (cc_session_id, codex_rollout_path, codex_thread_id) {
        (Some(raw), None, None) => {
            let uuid = uuid::Uuid::parse_str(raw).map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    format!("`cc_session_id` is not a valid UUID: {e}"),
                    Some(serde_json::json!({ "field": "cc_session_id", "value": raw })),
                )
            })?;
            Ok(SessionLookup::CcSession { uuid })
        }
        (None, Some(path), None) => Ok(SessionLookup::CodexRollout {
            path: std::path::PathBuf::from(path),
        }),
        (None, None, Some(thread_id)) => Ok(SessionLookup::CodexThread {
            thread_id: thread_id.to_string(),
        }),
        (None, None, None) => Err(rmcp::ErrorData::invalid_params(
            "provide exactly one of `cc_session_id`, `codex_rollout_path`, \
             or `codex_thread_id`",
            Some(serde_json::json!({ "supplied": serde_json::Value::Array(vec![]) })),
        )),
        (cc, rollout, thread) => {
            let supplied: Vec<&str> = [
                cc.map(|_| "cc_session_id"),
                rollout.map(|_| "codex_rollout_path"),
                thread.map(|_| "codex_thread_id"),
            ]
            .into_iter()
            .flatten()
            .collect();
            Err(rmcp::ErrorData::invalid_params(
                "provide exactly one session ref, not multiple",
                Some(serde_json::json!({ "supplied": supplied })),
            ))
        }
    }
}
