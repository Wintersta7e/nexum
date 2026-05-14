//! Shared runtime resolution: `Paths` + `Config` for any nexum entry point.
//!
//! Both the CLI and the MCP server need the same startup sequence —
//! resolve the nexum home, run the global trust pre-check, load the
//! config — and the same structured failure shape. This module owns that
//! sequence and returns a wire-stable [`ErrorEnvelope`] on failure so each
//! entry point only has to decide *how* to surface it (the CLI maps it to
//! an `ExitCode` + stdout/stderr rendering; the MCP server stores it in
//! an unavailable-runtime state and replays it on every tool call).
//!
//! The helper deliberately returns the envelope rather than an exit code
//! or a printed message: exit codes and stdout are CLI concerns, and the
//! MCP server must keep stdout clean for the JSON-RPC stream.

use crate::api::error::{ErrorEnvelope, Remediation, error_codes};
use crate::config::io::load as load_config;
use crate::config::types::Config;
use crate::paths::Paths;
use crate::session::startup::{StartupError, pre_check};
use crate::trust::events::TrustError;

/// Resolve `Paths`, run the global session pre-check, and load the config.
///
/// Returns the `(Paths, Config)` pair every entry point needs, or a
/// wire-stable [`ErrorEnvelope`] describing the first failure:
///
/// - `Paths::resolve` failure → `NOT_INITIALIZED`, `context.phase =
///   "paths_resolve"`.
/// - `pre_check` raising `ReanchorPending` → `REANCHOR_PENDING`,
///   `context.phase = "pre_check"`.
/// - `pre_check` raising any other trust error → routed through the
///   `From<&ApiError>` envelope builder (a `STORE_INTEGRITY` envelope in
///   practice), so the trust-error detail is preserved verbatim.
/// - `load_config` failure → `NOT_INITIALIZED`, `context.phase =
///   "load_config"`.
///
/// The pipeline short-circuits on the first failure; the order
/// (`Paths::resolve` → `pre_check` → `load_config`) is the same one
/// `session::startup::pre_check`'s doc comment specifies — `pre_check`
/// needs `paths.home` and must run before any state-loading work.
///
/// # Errors
///
/// Returns an [`ErrorEnvelope`] as described above. The envelope is the
/// failure channel — callers decide how to surface it.
pub fn resolve_runtime() -> Result<(Paths, Config), ErrorEnvelope> {
    let paths = Paths::resolve().map_err(|e| ErrorEnvelope {
        error_code: error_codes::NOT_INITIALIZED,
        message: format!("{e}"),
        remediation: Some(Remediation {
            command: Some("nexum init".into()),
            rationale: "Initialize a nexum home (notebook.git + config + signing key).".into(),
        }),
        context: serde_json::json!({ "phase": "paths_resolve" }),
    })?;
    resolve_from(paths)
}

/// Run the pre-check + load-config sequence against an already-resolved
/// [`Paths`]. Returns the same envelope shapes as [`resolve_runtime`] for
/// the `pre_check` and `load_config` failure points.
///
/// Split from [`resolve_runtime`] so callers can supply a `Paths` directly
/// instead of resolving it from the process environment — the unit tests
/// rely on this to run hermetically.
fn resolve_from(paths: Paths) -> Result<(Paths, Config), ErrorEnvelope> {
    pre_check(&paths.home).map_err(|e| match e {
        StartupError::Trust(TrustError::ReanchorPending { message }) => ErrorEnvelope {
            error_code: error_codes::REANCHOR_PENDING,
            message,
            remediation: Some(Remediation {
                command: None,
                rationale: "Resolve the pending reanchor before continuing. \
                            Run `nexum doctor --resolve-pending-reanchor` once \
                            that command lands."
                    .into(),
            }),
            context: serde_json::json!({ "phase": "pre_check" }),
        },
        // Any other trust-layer pre-check failure routes through the
        // canonical `From<&ApiError>` envelope builder so the trust-error
        // detail (path, subkind, message) is preserved verbatim — the same
        // envelope the read verbs would produce for that `TrustError`.
        StartupError::Trust(other) => {
            let api_err = crate::api::ApiError::Query(crate::query::QueryError::Trust(other));
            ErrorEnvelope::from(&api_err)
        }
    })?;

    let cfg = load_config(&paths.config).map_err(|e| ErrorEnvelope {
        error_code: error_codes::NOT_INITIALIZED,
        message: format!("{e}"),
        remediation: Some(Remediation {
            command: Some("nexum init".into()),
            rationale: "Re-running `nexum init` heals a missing or malformed config.toml.".into(),
        }),
        context: serde_json::json!({ "phase": "load_config" }),
    })?;

    Ok((paths, cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_config_yields_not_initialized_with_load_config_phase() {
        // A bare temp dir as the nexum home: pre_check succeeds (no
        // .reanchor_pending sentinel), load_config fails because config.toml
        // does not exist. Uses resolve_from directly to avoid mutating the
        // process-global environment (nexum-core denies unsafe_code).
        let dir = TempDir::new().unwrap();
        let paths = Paths::with_home(dir.path().to_path_buf());
        let env = resolve_from(paths).unwrap_err();
        assert_eq!(env.error_code, error_codes::NOT_INITIALIZED);
        assert_eq!(env.context["phase"], "load_config");
        let r = env.remediation.unwrap();
        assert_eq!(r.command.as_deref(), Some("nexum init"));
    }

    #[test]
    fn reanchor_pending_sentinel_yields_reanchor_pending_envelope() {
        // Plant a non-empty .reanchor_pending sentinel; pre_check trips
        // before load_config is ever reached.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".reanchor_pending"),
            r#"{
                "case": "A",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "init"
            }"#,
        )
        .unwrap();
        let paths = Paths::with_home(dir.path().to_path_buf());
        let env = resolve_from(paths).unwrap_err();
        assert_eq!(env.error_code, error_codes::REANCHOR_PENDING);
        assert_eq!(env.context["phase"], "pre_check");
    }
}
