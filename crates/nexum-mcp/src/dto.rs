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
//! handlers.

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

#[cfg(test)]
mod tests {
    use super::RecentParams;

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
}
