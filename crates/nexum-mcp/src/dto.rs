//! Input DTOs for the MCP tools.
//!
//! Each is `#[derive(Deserialize, JsonSchema)]` — flat, with **explicit**
//! `#[serde(default = "...")]` defaults because `JsonSchema` defaults are
//! advisory only and are not applied at deserialize time. DTOs live in
//! `nexum-mcp` (not `nexum-core`) so the core crate never takes a
//! `schemars` dependency just for transport schemas.
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
