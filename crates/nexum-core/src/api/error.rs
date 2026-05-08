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

// ───── ApiError → ErrorEnvelope builder (top-level dispatch) ────────────────

impl From<&crate::api::ApiError> for ErrorEnvelope {
    fn from(err: &crate::api::ApiError) -> Self {
        use crate::api::ApiError;
        match err {
            ApiError::MigrationRequired { v_disk, v_code } => {
                migration_required_envelope(*v_disk, *v_code)
            }
            ApiError::Query(e) => query_envelope(e),
            ApiError::Indexer(e) => indexer_envelope(e),
            ApiError::Config(e) => config_envelope(e),
        }
    }
}

fn migration_required_envelope(v_disk: u32, v_code: u32) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::MIGRATION_REQUIRED,
        message: format!("index schema v{v_disk} is older than this binary (v{v_code})"),
        remediation: Some(Remediation {
            command: Some("nexum migrate".into()),
            rationale: "Upgrade the on-disk index.db schema to match the binary.".into(),
        }),
        context: serde_json::json!({ "v_disk": v_disk, "v_code": v_code }),
    }
}

// ───── QueryError variant dispatch ──────────────────────────────────────────

fn query_envelope(err: &crate::query::QueryError) -> ErrorEnvelope {
    use crate::query::QueryError;
    match err {
        QueryError::IndexMissing { path } => not_indexed_envelope(path),
        QueryError::Ambiguous { matches } => ambiguous_envelope(matches),
        QueryError::InvalidFilter { detail } => invalid_filter_envelope(detail),
        QueryError::Trust(t) => trust_envelope(t),
        QueryError::Rusqlite(e) => store_integrity_foreign("rusqlite", e),
        QueryError::Json(e) => store_integrity_foreign("json", e),
    }
}

fn not_indexed_envelope(path: &std::path::Path) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::NOT_INDEXED,
        message: format!("index database not found at `{}`", path.display()),
        remediation: Some(Remediation {
            command: Some("nexum index".into()),
            rationale: "Build the index from the existing notebook.git.".into(),
        }),
        context: serde_json::json!({ "path": path.to_string_lossy() }),
    }
}

fn ambiguous_envelope(matches: &[crate::records::types::RecordKey]) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::AMBIGUOUS_KEY,
        message: format!("ambiguous record id; {} candidates match", matches.len()),
        remediation: Some(Remediation {
            command: None,
            rationale: "Re-run with the fully qualified key \
                        `<source>:<project_id>:<id>`."
                .into(),
        }),
        context: serde_json::json!({
            "matches": matches.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
    }
}

fn invalid_filter_envelope(detail: &str) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::INVALID_FILTER,
        message: format!("invalid filter value: {detail}"),
        remediation: Some(Remediation {
            command: None,
            rationale: "Adjust the offending filter argument and re-run.".into(),
        }),
        context: serde_json::json!({ "detail": detail }),
    }
}

// ───── IndexerError variant dispatch ────────────────────────────────────────

fn indexer_envelope(err: &crate::indexer::IndexerError) -> ErrorEnvelope {
    use crate::indexer::IndexerError;
    match err {
        IndexerError::Trust(t) => trust_envelope(t),
        IndexerError::Io { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("io error at {}: {source}", path.display()),
            remediation: None,
            context: serde_json::json!({
                "kind": "indexer",
                "subkind": "io",
                "path": path.to_string_lossy(),
                "message": format!("{source}"),
            }),
        },
        IndexerError::Rusqlite(e) => store_integrity_foreign("rusqlite", e),
        IndexerError::Schema(e) => store_integrity_foreign("schema", e),
        IndexerError::Adapter(e) => store_integrity_foreign("adapter", e),
        IndexerError::Config(s) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config error: {s}"),
            remediation: None,
            context: serde_json::json!({ "kind": "config", "message": s }),
        },
    }
}

// ───── ConfigError variant dispatch ─────────────────────────────────────────

fn config_envelope(err: &crate::config::ConfigError) -> ErrorEnvelope {
    use crate::config::ConfigError;
    match err {
        ConfigError::AlreadyExists { path } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config already exists at {path}: pass --force to overwrite"),
            remediation: None,
            context: serde_json::json!({
                "kind": "config",
                "subkind": "already_exists",
                "path": path,
            }),
        },
        ConfigError::Io { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config I/O error at {path}: {source}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "config",
                "subkind": "io",
                "path": path,
                "message": format!("{source}"),
            }),
        },
        ConfigError::Parse { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config parse error in {path}: {source}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "config",
                "subkind": "parse",
                "path": path,
                "message": format!("{source}"),
            }),
        },
        ConfigError::Serialize(e) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config serialize error: {e}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "config",
                "subkind": "serialize",
                "message": format!("{e}"),
            }),
        },
    }
}

// ───── TrustError variant dispatch ──────────────────────────────────────────

// Length is intrinsic to per-variant coverage: 11 TrustError variants, each
// with a hand-tuned envelope. Splitting per-variant into helpers would add
// ceremony without aiding readability — the match is the documentation.
#[allow(clippy::too_many_lines)]
fn trust_envelope(err: &crate::trust::events::TrustError) -> ErrorEnvelope {
    use crate::trust::events::TrustError;
    match err {
        TrustError::TrustSchemaUnsupported { found } => trust_schema_unsupported_envelope(*found),
        TrustError::ReanchorPending { message } => ErrorEnvelope {
            error_code: error_codes::REANCHOR_PENDING,
            message: format!("reanchor pending: {message}"),
            remediation: Some(Remediation {
                command: None,
                rationale: "Resolve the pending reanchor before continuing.".into(),
            }),
            context: serde_json::json!({ "message": message }),
        },
        TrustError::Io { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("trust I/O error at {path}: {source}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "io",
                "path": path,
                "message": format!("{source}"),
            }),
        },
        TrustError::Parse { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("trust YAML parse error in {path}: {source}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "parse",
                "path": path,
                "message": format!("{source}"),
            }),
        },
        TrustError::Serialize(e) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("trust YAML serialize error: {e}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "serialize",
                "message": format!("{e}"),
            }),
        },
        TrustError::ConfigParse { path, source } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config.toml parse error in {path}: {source}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "config_parse",
                "path": path,
                "message": format!("{source}"),
            }),
        },
        TrustError::BootstrapPinMissing => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: "bootstrap pin missing from config.toml".into(),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "bootstrap_pin_missing",
            }),
        },
        TrustError::GitCommand { stderr } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("git command failed: {stderr}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "git_command",
                "stderr": stderr,
            }),
        },
        TrustError::TrustHistoryNotLinear => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message:
                ".trust/events.yml has merge commits in its history (linear history is required)"
                    .into(),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "history_not_linear",
            }),
        },
        TrustError::MalformedBootstrap => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: "first events.yml revision must contain exactly one BootstrapKey event".into(),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "malformed_bootstrap",
            }),
        },
        TrustError::Sqlite(e) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("sqlite error during trust materialization: {e}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "sqlite",
                "message": format!("{e}"),
            }),
        },
    }
}

fn trust_schema_unsupported_envelope(found: u32) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::TRUST_SCHEMA_UNSUPPORTED,
        message: format!("trust events schema v{found} is newer than this binary understands"),
        remediation: Some(Remediation {
            command: None,
            rationale: "Upgrade nexum to a build that supports the new trust schema.".into(),
        }),
        context: serde_json::json!({ "schema_version": found }),
    }
}

fn store_integrity_foreign<E: std::fmt::Display>(kind: &'static str, e: E) -> ErrorEnvelope {
    ErrorEnvelope {
        error_code: error_codes::STORE_INTEGRITY,
        message: format!("{kind} error: {e}"),
        remediation: None,
        context: serde_json::json!({ "kind": kind, "message": format!("{e}") }),
    }
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

    use crate::{
        api::ApiError, config::ConfigError, indexer::IndexerError, query::QueryError,
        records::types::RecordKey, trust::events::TrustError,
    };
    use std::path::PathBuf;

    // ───── ApiError top-level ─────────────────────────────────────────────────

    #[test]
    fn from_migration_required_carries_versions() {
        let err = ApiError::MigrationRequired {
            v_disk: 3,
            v_code: 5,
        };
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::MIGRATION_REQUIRED);
        assert_eq!(env.context["v_disk"], 3);
        assert_eq!(env.context["v_code"], 5);
        let r = env.remediation.unwrap();
        assert_eq!(r.command.as_deref(), Some("nexum migrate"));
    }

    // ───── QueryError variants ───────────────────────────────────────────────

    #[test]
    fn from_index_missing_routes_to_not_indexed() {
        let path = PathBuf::from("/tmp/nx/index.db");
        let err = ApiError::Query(QueryError::IndexMissing { path: path.clone() });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::NOT_INDEXED);
        assert_eq!(env.context["path"], path.to_string_lossy().as_ref());
        let r = env.remediation.unwrap();
        assert_eq!(r.command.as_deref(), Some("nexum index"));
    }

    #[test]
    fn from_ambiguous_carries_matches() {
        let matches = vec![RecordKey::bare("foo"), RecordKey::bare("foo")];
        let err = ApiError::Query(QueryError::Ambiguous {
            matches: matches.clone(),
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::AMBIGUOUS_KEY);
        assert_eq!(env.context["matches"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn from_invalid_filter_carries_detail() {
        let err = ApiError::Query(QueryError::InvalidFilter {
            detail: "since: not ISO8601".into(),
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::INVALID_FILTER);
        assert_eq!(env.context["detail"], "since: not ISO8601");
    }

    #[test]
    fn from_query_rusqlite_routes_to_store_integrity() {
        let r = rusqlite::Connection::open_with_flags(
            "/this/path/does/not/exist/nx",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        );
        let err = ApiError::Query(QueryError::Rusqlite(r.unwrap_err()));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "rusqlite");
        assert!(!env.context["message"].as_str().unwrap().is_empty());
    }

    #[test]
    fn from_query_json_routes_to_store_integrity() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = ApiError::Query(QueryError::Json(json_err));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "json");
    }

    // ───── TrustError variants (reachable through both Query and Indexer) ────

    #[test]
    fn from_query_trust_schema_unsupported_routes() {
        let err = ApiError::Query(QueryError::Trust(TrustError::TrustSchemaUnsupported {
            found: 99,
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::TRUST_SCHEMA_UNSUPPORTED);
        assert_eq!(env.context["schema_version"], 99);
    }

    #[test]
    fn from_query_trust_io_preserves_path() {
        let err = ApiError::Query(QueryError::Trust(TrustError::Io {
            path: "/tmp/nx/notebook.git/.trust/events.yml".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "trust");
        assert_eq!(env.context["subkind"], "io");
        assert_eq!(
            env.context["path"],
            "/tmp/nx/notebook.git/.trust/events.yml"
        );
    }

    #[test]
    fn from_query_trust_parse_preserves_path() {
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(": : :").unwrap_err();
        let err = ApiError::Query(QueryError::Trust(TrustError::Parse {
            path: "/tmp/events.yml".into(),
            source: yaml_err,
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "parse");
        assert_eq!(env.context["path"], "/tmp/events.yml");
    }

    #[test]
    fn from_query_trust_reanchor_pending_routes() {
        let err = ApiError::Query(QueryError::Trust(TrustError::ReanchorPending {
            message: "Reanchor pending: trust state indeterminate".into(),
        }));
        let env: ErrorEnvelope = (&err).into();
        // Reanchor-pending is special-cased to its own error_code even when
        // raised from the api read path.
        assert_eq!(env.error_code, error_codes::REANCHOR_PENDING);
        assert_eq!(
            env.context["message"],
            "Reanchor pending: trust state indeterminate"
        );
    }

    #[test]
    fn from_query_trust_git_command_preserves_stderr() {
        let err = ApiError::Query(QueryError::Trust(TrustError::GitCommand {
            stderr: "fatal: not a git repository".into(),
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "git_command");
        assert_eq!(env.context["stderr"], "fatal: not a git repository");
    }

    #[test]
    fn from_query_trust_history_not_linear_routes() {
        let err = ApiError::Query(QueryError::Trust(TrustError::TrustHistoryNotLinear));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "history_not_linear");
    }

    #[test]
    fn from_query_trust_bootstrap_pin_missing_routes() {
        let err = ApiError::Query(QueryError::Trust(TrustError::BootstrapPinMissing));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "bootstrap_pin_missing");
    }

    #[test]
    fn from_query_trust_malformed_bootstrap_routes() {
        let err = ApiError::Query(QueryError::Trust(TrustError::MalformedBootstrap));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "malformed_bootstrap");
    }

    #[test]
    fn from_query_trust_config_parse_preserves_path() {
        let parse_err: toml::de::Error =
            toml::from_str::<toml::Value>("not = valid = toml").unwrap_err();
        let err = ApiError::Query(QueryError::Trust(TrustError::ConfigParse {
            path: "/home/user/.nexum/config.toml".into(),
            source: parse_err,
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "config_parse");
        assert_eq!(env.context["path"], "/home/user/.nexum/config.toml");
    }

    // ───── IndexerError variants ─────────────────────────────────────────────

    #[test]
    fn from_indexer_trust_schema_unsupported_routes() {
        let err = ApiError::Indexer(IndexerError::Trust(TrustError::TrustSchemaUnsupported {
            found: 7,
        }));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::TRUST_SCHEMA_UNSUPPORTED);
        assert_eq!(env.context["schema_version"], 7);
    }

    #[test]
    fn from_indexer_io_carries_path() {
        let err = ApiError::Indexer(IndexerError::Io {
            path: PathBuf::from("/tmp/nx/notebook.git"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "indexer");
        assert_eq!(env.context["subkind"], "io");
        assert_eq!(env.context["path"], "/tmp/nx/notebook.git");
    }

    #[test]
    fn from_indexer_rusqlite_routes_to_store_integrity() {
        let r = rusqlite::Connection::open_with_flags(
            "/this/path/does/not/exist/nx",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        );
        let err = ApiError::Indexer(IndexerError::Rusqlite(r.unwrap_err()));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "rusqlite");
    }

    #[test]
    fn from_indexer_config_carries_message() {
        let err = ApiError::Indexer(IndexerError::Config("bad embedder".into()));
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "config");
        assert_eq!(env.context["message"], "bad embedder");
    }

    // ───── ConfigError variants (top-level) ──────────────────────────────────

    #[test]
    fn from_config_already_exists_preserves_path() {
        let err = ApiError::Config(ConfigError::AlreadyExists {
            path: "/home/user/.nexum/config.toml".into(),
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "config");
        assert_eq!(env.context["subkind"], "already_exists");
        assert_eq!(env.context["path"], "/home/user/.nexum/config.toml");
    }

    #[test]
    fn from_config_io_preserves_path() {
        let err = ApiError::Config(ConfigError::Io {
            path: "/home/user/.nexum/config.toml".into(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "io");
        assert_eq!(env.context["path"], "/home/user/.nexum/config.toml");
    }

    #[test]
    fn from_config_parse_preserves_path() {
        let parse_err: toml::de::Error =
            toml::from_str::<toml::Value>("not = valid = toml").unwrap_err();
        let err = ApiError::Config(ConfigError::Parse {
            path: "/home/user/.nexum/config.toml".into(),
            source: parse_err,
        });
        let env: ErrorEnvelope = (&err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["subkind"], "parse");
        assert_eq!(env.context["path"], "/home/user/.nexum/config.toml");
    }

    // ConfigError::Serialize wraps a toml::ser::Error which is hard to
    // synthesize cleanly (toml's serializer is permissive). Coverage for
    // this variant is provided by the exhaustive match in `config_envelope`
    // — adding the variant forces a compile error if it is ever forgotten.
}
