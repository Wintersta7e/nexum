//! Input DTOs for the MCP tools.
//!
//! Each is `#[derive(Deserialize, JsonSchema)]` — flat, with **explicit**
//! `#[serde(default = "...")]` defaults because `JsonSchema` defaults are
//! advisory only and are not applied at deserialize time. DTOs live in
//! `nexum-mcp` (not `nexum-core`) so the core crate never takes a
//! `schemars` dependency just for transport schemas.
//!
//! `schemars` is a direct dependency — the `#[derive(JsonSchema)]` macro
//! expands to a bare `schemars` path — and its major version must stay
//! aligned with the `schemars` `rmcp` re-exports, or the generated schema
//! and what `rmcp`'s `#[tool]` macro expects will drift.
//!
//! `RecentParams` lands first; the other tools' params follow with their
//! handlers. `SearchParams`, `ListParams`, and `BySessionParams` follow the
//! same conventions and ship with their handlers.

use schemars::JsonSchema;
use serde::Deserialize;

/// Params for the `recent` tool — most-recently-updated records, newest first.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecentParams {
    /// Max rows to return. Defaults to 10.
    #[serde(default = "default_recent_limit")]
    pub limit: u32,
    /// Restrict to one source adapter: `cc-native`, `codex-native`, or `local`.
    /// Omit for all sources.
    #[serde(default)]
    pub source: Option<String>,
    /// Return only records carrying a verified signature.
    #[serde(default)]
    pub require_signed: bool,
    /// Force strict-revocation checking on for this call (cannot relax a
    /// `true` config default — "stricter prevails").
    #[serde(default)]
    pub strict_revocation: bool,
}

fn default_recent_limit() -> u32 {
    10
}

// ───── search ──────────────────────────────────────────────────────────────

/// Params for the `search` tool — FTS-ranked full-text search.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Full-text query string. Required.
    pub query: String,
    /// Maximum results to return. Defaults to 5.
    #[serde(default = "default_search_top_k")]
    pub top_k: u32,
    /// Restrict to one record type: `decision`, `recommendation`, `failure`,
    /// or `untyped`. Omit for all types.
    #[serde(default)]
    pub record_type: Option<String>,
    /// Restrict to one source adapter: `cc-native`, `codex-native`, or
    /// `local`. Omit for all sources.
    #[serde(default)]
    pub source: Option<String>,
    /// Minimum confidence to include: `high`, `medium`, or `low`.
    /// Omit for all confidence levels.
    #[serde(default)]
    pub min_confidence: Option<String>,
    /// Return only records carrying a verified signature.
    #[serde(default)]
    pub require_signed: bool,
    /// Force strict-revocation checking on for this call.
    #[serde(default)]
    pub strict_revocation: bool,
}

fn default_search_top_k() -> u32 {
    5
}

// ───── list ────────────────────────────────────────────────────────────────

/// Params for the `list` tool — filtered, paginated listing.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListParams {
    /// Maximum rows to return. Defaults to 50.
    #[serde(default = "default_list_limit")]
    pub limit: u32,
    /// Opaque pagination cursor from a previous result's `_meta.next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Restrict to one record type: `decision`, `recommendation`, `failure`,
    /// or `untyped`. Omit for all types.
    #[serde(default)]
    pub record_type: Option<String>,
    /// Restrict to one source adapter: `cc-native`, `codex-native`, or
    /// `local`. Omit for all sources.
    #[serde(default)]
    pub source: Option<String>,
    /// Return only records carrying a verified signature.
    #[serde(default)]
    pub require_signed: bool,
    /// Force strict-revocation checking on for this call.
    #[serde(default)]
    pub strict_revocation: bool,
}

fn default_list_limit() -> u32 {
    50
}

// ───── by_session ──────────────────────────────────────────────────────────

/// Params for the `by_session` tool — records associated with one session ref.
///
/// Exactly one of `cc_session_id`, `codex_rollout_path`, or
/// `codex_thread_id` must be supplied. Zero or multiple refs produce an
/// `invalid_params` protocol error at the handler level, not here (the JSON
/// schema cannot express mutual exclusion, so deserialize accepts any
/// combination and the handler enforces the arity).
// Suppressed until the `by_session` handler lands and constructs this in the same compile unit.
#[allow(dead_code)]
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BySessionParams {
    /// A Claude Code session UUID (e.g. `"01912c3a-..."`). Exactly one of the
    /// three ref fields must be supplied.
    #[serde(default)]
    pub cc_session_id: Option<String>,
    /// An absolute path to a Codex rollout directory. Exactly one of the three
    /// ref fields must be supplied.
    #[serde(default)]
    pub codex_rollout_path: Option<String>,
    /// A Codex thread identifier string. Exactly one of the three ref fields
    /// must be supplied.
    #[serde(default)]
    pub codex_thread_id: Option<String>,
    /// Return only records carrying a verified signature.
    #[serde(default)]
    pub require_signed: bool,
    /// Force strict-revocation checking on for this call.
    #[serde(default)]
    pub strict_revocation: bool,
}

#[cfg(test)]
mod tests {
    use super::{BySessionParams, ListParams, RecentParams, SearchParams};

    #[test]
    fn empty_object_deserializes_to_documented_defaults() {
        // An MCP `recent` call with no arguments must produce the defaults
        // the field docs advertise — `JsonSchema` defaults are advisory, so
        // the `#[serde(default)]` attributes are what apply at deserialize
        // time.
        let params: RecentParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.limit, 10);
        assert_eq!(params.source, None);
        assert!(!params.require_signed);
        assert!(!params.strict_revocation);
    }

    #[test]
    fn search_params_required_query_optional_rest() {
        // Minimal call — only `query` supplied; all optional fields default.
        let params: SearchParams = serde_json::from_str(r#"{"query":"jwt rotation"}"#).unwrap();
        assert_eq!(params.query, "jwt rotation");
        assert_eq!(params.top_k, 5, "default top_k");
        assert_eq!(params.record_type, None);
        assert_eq!(params.source, None);
        assert_eq!(params.min_confidence, None);
        assert!(!params.require_signed);
        assert!(!params.strict_revocation);

        // Missing `query` must fail — it has no default.
        let result: Result<SearchParams, _> = serde_json::from_str("{}");
        assert!(
            result.is_err(),
            "missing required `query` field must be Err"
        );
    }

    #[test]
    fn list_params_all_optional() {
        // An empty object is a valid `list` call — all fields are optional.
        let params: ListParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.limit, 50, "default limit");
        assert_eq!(params.cursor, None);
        assert_eq!(params.record_type, None);
        assert_eq!(params.source, None);
        assert!(!params.require_signed);
        assert!(!params.strict_revocation);
    }

    #[test]
    fn by_session_params_all_optional_at_deserialize_time() {
        // `BySessionParams` intentionally accepts any combination of refs at
        // deserialize time — the handler enforces the "exactly one" arity so
        // that the error message can name the conflicting fields.
        let params: BySessionParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.cc_session_id, None);
        assert_eq!(params.codex_rollout_path, None);
        assert_eq!(params.codex_thread_id, None);
        assert!(!params.require_signed);
        assert!(!params.strict_revocation);
    }
}
