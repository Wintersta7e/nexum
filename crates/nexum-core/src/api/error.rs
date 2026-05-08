//! Wire-stable error envelope consumed by both the CLI's `--json` mode and
//! (later) the MCP server.
//!
//! Agents key on the stable `error_code` to branch behavior; `remediation`
//! carries a structured action the agent can surface to the user; `context`
//! carries variant-specific structured fields (record matches, schema
//! versions, file paths, etc.) so the agent never has to re-parse English.

use serde::Serialize;

/// Wire-stable error envelope.
///
/// Field shape is part of the public agent-facing contract: never rename a
/// field, never remove one. Adding new optional fields is allowed.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    /// Stable wire identifier (one of `error_codes::*`). Agents branch on
    /// this; the `message` string is for human relay only.
    pub error_code: &'static str,
    /// Human-readable rendering. The CLI's default mode uses this verbatim
    /// to produce its `eprintln!` output, keeping the two surfaces in sync.
    pub message: String,
    /// Optional suggested action. `None` when the error is fatal with no
    /// caller-side fix (e.g., transient sqlite I/O).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
    /// Variant-specific structured fields. Always an object (possibly empty).
    pub context: serde_json::Value,
}

/// Carries an actionable next-step the agent can either execute (`command`)
/// or relay verbatim to the user (`rationale`). Decoupling the two lets the
/// agent route a structured remediation through its own UX without parsing
/// English back out of a free-form message.
#[derive(Debug, Clone, Serialize)]
pub struct Remediation {
    /// Concrete shell invocation that resolves the error, when applicable.
    /// `None` when the fix is something other than running a single command
    /// (e.g., "upgrade nexum to a newer build").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Why running this resolves the error. Always present.
    pub rationale: String,
}

/// Stable wire identifiers for `ErrorEnvelope::error_code`.
///
/// Once a constant is added here and ships, its string value is part of the
/// public agent-facing contract — never renamed. Adding new constants is
/// always allowed.
pub mod error_codes {
    /// Invalid argument combination (clap parse, per-verb arg validation).
    pub const USAGE: &str = "USAGE";
    /// nexum home / config missing or unreadable.
    pub const NOT_INITIALIZED: &str = "NOT_INITIALIZED";
    /// Catch-all for store-side failures during a verb's main work.
    pub const STORE_INTEGRITY: &str = "STORE_INTEGRITY";
    /// `index.db` schema older than this binary; remediation: `nexum migrate`.
    pub const MIGRATION_REQUIRED: &str = "MIGRATION_REQUIRED";
    /// `~/.nexum/.reanchor_pending` sentinel exists; trust state indeterminate.
    pub const REANCHOR_PENDING: &str = "REANCHOR_PENDING";
    /// `events.yml.schema_version` newer than this binary supports.
    pub const TRUST_SCHEMA_UNSUPPORTED: &str = "TRUST_SCHEMA_UNSUPPORTED";
    /// `index.db` does not exist yet; remediation: `nexum index`.
    pub const NOT_INDEXED: &str = "NOT_INDEXED";
    /// No record matches the requested id (`get` only).
    pub const NOT_FOUND: &str = "NOT_FOUND";
    /// Record exists but suppressed by trust policy (`get` only); remediation:
    /// retry with `--include-unsigned`.
    pub const HIDDEN_BY_POLICY: &str = "HIDDEN_BY_POLICY";
    /// Bare or partial key matched multiple records (`get` and `query` paths).
    pub const AMBIGUOUS_KEY: &str = "AMBIGUOUS_KEY";
    /// `serde_json::to_string_pretty` failed on the success-path response.
    pub const SERIALIZE_FAILED: &str = "SERIALIZE_FAILED";
    /// Filter argument failed validation.
    pub const INVALID_FILTER: &str = "INVALID_FILTER";
    /// `events.yml` history contains tampering events. Surfaced by
    /// `nexum trust validate-events` and `nexum index --check`.
    pub const TAMPERING_DETECTED: &str = "TAMPERING_DETECTED";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_serializes_with_required_fields() {
        let env = ErrorEnvelope {
            error_code: error_codes::MIGRATION_REQUIRED,
            message: "index schema v3 is older than this binary (v5)".into(),
            remediation: Some(Remediation {
                command: Some("nexum migrate".into()),
                rationale: "Upgrade the on-disk index.db schema to match the binary.".into(),
            }),
            context: json!({ "v_disk": 3, "v_code": 5 }),
        };
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(v["error_code"], "MIGRATION_REQUIRED");
        assert_eq!(
            v["message"],
            "index schema v3 is older than this binary (v5)"
        );
        assert_eq!(v["remediation"]["command"], "nexum migrate");
        assert_eq!(v["context"]["v_disk"], 3);
        assert_eq!(v["context"]["v_code"], 5);
    }

    #[test]
    fn envelope_omits_remediation_when_none() {
        let env = ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: "rusqlite error: database is locked".into(),
            remediation: None,
            context: json!({ "kind": "rusqlite" }),
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(!s.contains("remediation"));
    }

    #[test]
    fn error_codes_are_stable_strings() {
        // These literal values are part of the wire contract. If a future
        // change renames any of them, this test will break — re-read the
        // contract before changing.
        assert_eq!(error_codes::MIGRATION_REQUIRED, "MIGRATION_REQUIRED");
        assert_eq!(error_codes::NOT_INDEXED, "NOT_INDEXED");
        assert_eq!(error_codes::AMBIGUOUS_KEY, "AMBIGUOUS_KEY");
        assert_eq!(error_codes::TAMPERING_DETECTED, "TAMPERING_DETECTED");
    }
}
