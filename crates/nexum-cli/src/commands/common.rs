//! Shared CLI handler helpers — runtime resolution and common error responses.

use std::{path::Path, process::ExitCode};

use nexum_core::{
    api::ApiError, api::error::error_codes, config::types::Config, paths::Paths, query::QueryError,
    trust::events::TrustError,
};

use super::exit_codes;

/// Resolve `Paths`, run the global session pre-check, and load the config.
/// Returns the runtime context shared by every read-side CLI verb (`index`,
/// `search`, `get`, `list`, `recent`, `by_session`, `project`).
///
/// Thin `ExitCode` adapter over [`nexum_core::session::resolve_runtime`],
/// which owns the resolution sequence and produces the wire-stable
/// [`ErrorEnvelope`]. This fn only decides *how* the CLI surfaces a failure:
///
/// `json` selects the failure rendering channel: `true` emits the
/// [`ErrorEnvelope`] on stdout via [`super::json_emit::emit_error`] and
/// returns the matching exit code; `false` renders the envelope's `message`
/// as prose on stderr (with the legacy `init` hint appended for the
/// `NOT_INITIALIZED` case so existing string-compare integration tests stay
/// green).
///
/// Exit-code mapping is `super::exit_codes::for_envelope` over the envelope
/// the core helper returns — identical across both channels.
/// Carrier for an invalid CLI enum filter — `(flag, value)`. Surfaces as
/// the `INVALID_FILTER` wire-stable error envelope via
/// `json_emit::emit_invalid_filter`. Centralised so every read verb that
/// accepts enum-string filters routes failures the same way.
pub(crate) struct InvalidFilter {
    pub flag: &'static str,
    pub value: String,
}

/// Parse one optional enum-string CLI argument strictly.
///
/// `None` (no flag) stays `None`. `Some(value)` parses via `parser`; a
/// parser that returns `None` triggers an `InvalidFilter` rather than the
/// previous silent-drop behaviour.
pub(crate) fn parse_enum_filter<T>(
    flag: &'static str,
    raw: Option<&str>,
    parser: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, InvalidFilter> {
    match raw {
        None => Ok(None),
        Some(s) => match parser(s) {
            Some(parsed) => Ok(Some(parsed)),
            None => Err(InvalidFilter {
                flag,
                value: s.to_owned(),
            }),
        },
    }
}

pub(crate) fn resolve_runtime(json: bool) -> Result<(Paths, Config), ExitCode> {
    nexum_core::session::resolve_runtime().map_err(|env| {
        let code = exit_codes::for_envelope(&env);
        if json {
            return super::json_emit::emit_error(&env, code);
        }
        // `NOT_INITIALIZED` gets the legacy `nexum init` hint appended —
        // pre-refactor string-compare tests assert this exact prose.
        if env.error_code == error_codes::NOT_INITIALIZED {
            eprintln!("error: {}\nDid you run `nexum init`?", env.message);
        } else {
            eprintln!("error: {}", env.message);
        }
        ExitCode::from(code)
    })
}

/// Print the "no index database" error and return the appropriate exit code.
/// Used by every read-side verb to handle `QueryError::IndexMissing`.
pub(crate) fn handle_index_missing(path: &Path) -> ExitCode {
    eprintln!(
        "error: no index database at `{}`; run `nexum index` to populate it",
        path.display()
    );
    ExitCode::from(exit_codes::NOT_INDEXED)
}

/// Translate an [`ApiError::MigrationRequired`] into the dedicated CLI exit
/// code. Other `ApiError` variants are caller-specific and stay with their
/// per-verb handlers; centralizing this one keeps the user-facing message
/// consistent.
pub(crate) fn handle_migration_required(err: &ApiError) -> Option<ExitCode> {
    if let ApiError::MigrationRequired { v_disk, v_code } = err {
        eprintln!("error: index schema v{v_disk} is older than this binary (v{v_code}).");
        eprintln!("Run `nexum migrate` to update, then re-run.");
        Some(ExitCode::from(exit_codes::MIGRATION_REQUIRED))
    } else {
        None
    }
}

/// Translate an [`ApiError::Query(QueryError::Trust(TrustError::TrustSchemaUnsupported))`]
/// into the dedicated CLI exit code. The materializer raises this when
/// `events.yml`'s `schema_version` is newer than the binary understands —
/// older binaries reading a newer notebook need the user-facing
/// "upgrade nexum" hint, not the generic store-integrity bucket.
pub(crate) fn handle_trust_schema_unsupported(err: &ApiError) -> Option<ExitCode> {
    if let ApiError::Query(QueryError::Trust(TrustError::TrustSchemaUnsupported { found })) = err {
        eprintln!("error: trust events schema v{found} is newer than this binary understands.");
        eprintln!("Upgrade nexum to a build that supports the new schema, then re-run.");
        Some(ExitCode::from(exit_codes::TRUST_SCHEMA_UNSUPPORTED))
    } else {
        None
    }
}

/// Map any read-verb [`ApiError`] to the matching exit code with the
/// appropriate user-facing message. Folds the per-variant translators
/// (`IndexMissing` / `MigrationRequired` / `TrustSchemaUnsupported`) so the
/// 5 read verbs share one fallthrough contract.
pub(crate) fn handle_read_verb_error(err: &ApiError) -> ExitCode {
    if let ApiError::Query(QueryError::IndexMissing { path }) = err {
        return handle_index_missing(path);
    }
    if let Some(code) = handle_migration_required(err) {
        return code;
    }
    if let Some(code) = handle_trust_schema_unsupported(err) {
        return code;
    }
    eprintln!("error: {err}");
    ExitCode::from(exit_codes::STORE_INTEGRITY)
}
