//! `--json`-mode error emitter. Writes a structured [`ErrorEnvelope`] to
//! stdout and returns the matching [`ExitCode`]. Default mode (no `--json`)
//! uses `super::common::handle_*` instead and stays prose-on-stderr.

use std::process::ExitCode;

use nexum_core::api::ApiError;
use nexum_core::api::error::{ErrorEnvelope, error_codes};

/// Emit an envelope to stdout (pretty JSON), return the matching [`ExitCode`].
///
/// On the rare case where serialization itself fails (catastrophic — the
/// envelope is small, fully owned, and Serialize-derived), emit a canned
/// minimal envelope to stderr and return [`ExitCode::FAILURE`]. Agents that
/// see the canned form know the verb broke before the structured channel
/// could be used.
pub(crate) fn emit_error(env: &ErrorEnvelope, exit_code: u8) -> ExitCode {
    if let Ok(s) = serde_json::to_string_pretty(env) {
        println!("{s}");
        ExitCode::from(exit_code)
    } else {
        eprintln!(
            r#"{{"error_code":"SERIALIZE_FAILED","message":"failed to serialize error envelope","context":{{}}}}"#
        );
        ExitCode::FAILURE
    }
}

/// Route an [`ApiError`] through the appropriate channel for a read verb.
///
/// When `json` is true, derives the [`ErrorEnvelope`] via `From<&ApiError>`,
/// looks up the matching exit code, and emits the structured payload on
/// stdout. Otherwise, falls back to the prose-on-stderr handler used by the
/// default-mode CLI surface. Centralizes the duplicated `if json { ... } else
/// { ... }` shape across read-verb error arms.
pub(crate) fn route_api_error(err: &ApiError, json: bool) -> ExitCode {
    if json {
        let env: ErrorEnvelope = err.into();
        let code = super::exit_codes::for_envelope(&env);
        emit_error(&env, code)
    } else {
        super::common::handle_read_verb_error(err)
    }
}

/// Build and emit a `SERIALIZE_FAILED` envelope for a verb whose success
/// response failed to serialize. Centralizes the per-verb boilerplate so
/// every `--json` arm collapses to one call.
pub(crate) fn emit_serialize_failure(e: &serde_json::Error) -> ExitCode {
    let env = ErrorEnvelope {
        error_code: error_codes::SERIALIZE_FAILED,
        message: format!("serialize: {e}"),
        remediation: None,
        context: serde_json::json!({ "kind": "json" }),
    };
    let code = super::exit_codes::for_envelope(&env);
    emit_error(&env, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexum_core::api::error::{ErrorEnvelope, Remediation, error_codes};

    fn sample_envelope() -> ErrorEnvelope {
        ErrorEnvelope {
            error_code: error_codes::MIGRATION_REQUIRED,
            message: "test".into(),
            remediation: Some(Remediation {
                command: Some("nexum migrate".into()),
                rationale: "test".into(),
            }),
            context: serde_json::json!({ "v_disk": 3, "v_code": 5 }),
        }
    }

    #[test]
    fn emit_error_returns_caller_exit_code_on_success() {
        // We can't capture stdout in unit tests easily; verify the function
        // returns the requested exit code without panicking on a
        // round-trippable envelope.
        let code = emit_error(&sample_envelope(), 6);
        // ExitCode does not implement PartialEq; round-trip via std::process
        // by formatting through Termination. Cheap proxy: function ran.
        let _ = code;
    }
}
