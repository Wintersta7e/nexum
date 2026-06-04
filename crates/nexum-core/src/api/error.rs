//! Wire-stable error envelope consumed by both the CLI's `--json` mode and
//! (later) the MCP server.
//!
//! Agents key on the stable `error_code` to branch behavior; `remediation`
//! carries a structured action the agent can surface to the user; `context`
//! carries variant-specific structured fields (record matches, schema
//! versions, file paths, etc.) so the agent never has to re-parse English.

use serde::Serialize;

/// Lifecycle-mutation failure severity. Absent on read-path / pre-lifecycle
/// envelopes.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Pre-flight or mid-commit refusal; no durable state changed.
    Refused,
    /// Commit landed but a side-effect (e.g. post-commit reindex) failed.
    Partial,
    /// Mutation that cannot be auto-recovered; surfaced by `nexum doctor`.
    Inconsistent,
}

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
    /// Mutation severity. `None` on read-path and pre-lifecycle envelopes;
    /// set by lifecycle verbs (write, index, trust mutations) to let agents
    /// decide how aggressively to retry or escalate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Whether durable state was mutated before the failure. `None` on
    /// read-path envelopes; `Some(false)` means a clean refusal with no
    /// side-effects, `Some(true)` means partial progress was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_mutated: Option<bool>,
    /// Whether the caller should trigger a reindex after this failure.
    /// `None` on read-path envelopes; `Some(true)` signals that the index
    /// may be stale because the mutation landed partially.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_reindex: Option<bool>,
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
///
/// **Discriminator fields in `context`** (load-bearing convention for agents
/// pattern-matching on envelope shape):
/// - `kind` — the `ApiError` variant family (`"trust"`, `"config"`,
///   `"indexer"`, `"rusqlite"`, `"json"`, `"schema"`, `"adapter"`, `"io"`,
///   `"migration"`). Set by the `From<&ApiError>` builder.
/// - `subkind` — the specific variant within a `kind` family (e.g.
///   `"io"`/`"parse"`/`"config_parse"` under `kind: "trust"`). Set per arm.
/// - `phase` — used by CLI shim envelopes built BEFORE any `ApiError` could
///   be constructed (e.g. `commands::common::resolve_runtime` emits
///   `phase: "paths_resolve" | "pre_check" | "load_config"`). Lives in the
///   same `context` namespace but identifies the pipeline stage that
///   failed rather than an inner-error variant.
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
    /// Dense-embedding compute failed (ORT init, tokenizer, inference,
    /// or output-shape mismatch). The store itself is intact; the
    /// embedder is the broken component. Remediation: reinstall the
    /// embedding model.
    pub const EMBED_FAILED: &str = "EMBED_FAILED";
    /// First-run consent missing; user must run `nexum extract --session
    /// <id>` interactively once before automated extraction proceeds.
    pub const EXTRACT_NOT_ACKNOWLEDGED: &str = "EXTRACT_NOT_ACKNOWLEDGED";
    /// `--backfill` invoked without a prior `--dry-run` manifest.
    pub const EXTRACT_DRY_RUN_REQUIRED: &str = "EXTRACT_DRY_RUN_REQUIRED";
    /// Recomputed dry-run id differs from the manifest's recorded id
    /// (basis shifted between dry-run and backfill).
    pub const EXTRACT_DRY_RUN_MISMATCH: &str = "EXTRACT_DRY_RUN_MISMATCH";
    /// Provider API key environment variable was not set.
    pub const EXTRACT_NO_API_KEY: &str = "EXTRACT_NO_API_KEY";
    /// Configured provider is not implemented in this build.
    pub const EXTRACT_PROVIDER_UNSUPPORTED: &str = "EXTRACT_PROVIDER_UNSUPPORTED";
    /// Catch-all for transport, redaction, digest, I/O, JSON, YAML, and git
    /// failures that surface during extraction. Operator inspects the
    /// `message` field for the underlying cause.
    pub const EXTRACT_MODEL_ERROR: &str = "EXTRACT_MODEL_ERROR";
    /// Model returned content that could not be parsed as YAML.
    pub const EXTRACT_PARSE: &str = "EXTRACT_PARSE";
    /// Parsed YAML record failed schema validation.
    pub const EXTRACT_VALIDATION: &str = "EXTRACT_VALIDATION";
    /// Session selector matched no sessions.
    pub const EXTRACT_NO_SESSIONS: &str = "EXTRACT_NO_SESSIONS";
    /// Tried to append a trust event whose `(kind, fingerprint)` pair is
    /// already present in events.yml.
    pub const TRUST_DUPLICATE_EVENT: &str = "TRUST_DUPLICATE_EVENT";
    /// Tried to operate on a fingerprint that no `BootstrapKey` or
    /// `KeyAdded` event has ever introduced into the trust state.
    pub const TRUST_FINGERPRINT_NOT_KNOWN: &str = "TRUST_FINGERPRINT_NOT_KNOWN";
    /// `nexum keys revoke` refused because the target is the sole
    /// remaining `Active`-role key; revoking it would leave the trust
    /// store unsignable.
    pub const KEYS_REVOKE_WOULD_UNSIGN_STORE: &str = "KEYS_REVOKE_WOULD_UNSIGN_STORE";
    /// `nexum keys revoke` refused because the revoke target equals
    /// the key git would sign the revoke commit with.
    pub const KEYS_REVOKE_WOULD_SIGN_OWN_REVOCATION: &str = "KEYS_REVOKE_WOULD_SIGN_OWN_REVOCATION";
    /// `nexum keys revoke` refused because the resolved git signer is
    /// not in `Active` role (rotated, compromised, reanchored, or has
    /// no `KeyStateView` row).
    pub const KEYS_REVOKE_SIGNER_NOT_ACTIVE: &str = "KEYS_REVOKE_SIGNER_NOT_ACTIVE";
    /// `nexum keys recover` refused because `old_fingerprint` doesn't
    /// match the chain's current bootstrap key.
    pub const RECOVER_OLD_FP_MISMATCH: &str = "RECOVER_OLD_FP_MISMATCH";
    /// `nexum keys recover` refused because a `BootstrapReanchor` event
    /// for the same `(old_fp, new_fp)` pair already exists.
    pub const RECOVER_DUPLICATE_CHAIN: &str = "RECOVER_DUPLICATE_CHAIN";
    /// Another nexum process holds the global mutation lock; the verb cannot
    /// proceed until the other process releases it.
    pub const CONCURRENT: &str = "CONCURRENT";
    /// `nexum keys recover` refused because `--acknowledge-chain-break`
    /// was not passed.
    pub const KEYS_RECOVER_CHAIN_BREAK_NOT_ACKNOWLEDGED: &str =
        "KEYS_RECOVER_CHAIN_BREAK_NOT_ACKNOWLEDGED";
    /// `nexum keys recover` (Case A) refused because the bootstrap pin file
    /// is missing or its fingerprint doesn't match the chain's current
    /// bootstrap.
    pub const KEYS_RECOVER_PIN_MISSING_FOR_CASE_A: &str = "KEYS_RECOVER_PIN_MISSING_FOR_CASE_A";
    /// `nexum keys recover` (Case A) refused because the pin file's
    /// fingerprint doesn't match the chain's current bootstrap.
    pub const KEYS_RECOVER_PIN_MISMATCH_FOR_CASE_A: &str = "KEYS_RECOVER_PIN_MISMATCH_FOR_CASE_A";
    /// `nexum keys recover` refused because a sentinel is already present.
    pub const KEYS_RECOVER_IN_PROGRESS: &str = "KEYS_RECOVER_IN_PROGRESS";
    /// `nexum keys recover` refused because the new key fingerprint already
    /// appears in `events.yml`.
    pub const KEYS_RECOVER_NEW_KEY_ALREADY_KNOWN: &str = "KEYS_RECOVER_NEW_KEY_ALREADY_KNOWN";
    /// `nexum keys recover` refused because the ssh-agent was unavailable
    /// when trying to sign the reanchor commit.
    pub const KEYS_RECOVER_AGENT_UNAVAILABLE: &str = "KEYS_RECOVER_AGENT_UNAVAILABLE";
    /// `nexum keys recover` failed mid-flight after writing the sentinel.
    pub const KEYS_RECOVER_FAILED: &str = "KEYS_RECOVER_FAILED";
    /// `~/.nexum/state/trust_warnings_acked.json` exists but is not valid JSON.
    /// Delete the file to reset acked warnings, or inspect and repair it by hand.
    pub const PRE_RECOVERY_ACK_FILE_MALFORMED: &str = "PRE_RECOVERY_ACK_FILE_MALFORMED";
    /// `nexum project set-path` refused because the repo at the supplied path
    /// has an origin URL that canonicalizes to a different `git:` `project_id`
    /// than the one supplied, or because no `origin` remote exists.
    pub const REPO_IDENTITY_MISMATCH: &str = "REPO_IDENTITY_MISMATCH";
    /// Generic catch-all for logical errors that don't fit a more specific
    /// variant (e.g. missing required YAML field detected at runtime).
    pub const INTERNAL: &str = "INTERNAL";

    // ── Lifecycle-mutation error codes (promote / write path) ─────────────
    // Note: REPO_IDENTITY_MISMATCH and REANCHOR_PENDING already exist above
    // and are reused by the corresponding lifecycle variants.

    /// `notebook.git` has uncommitted changes outside the lifecycle paths;
    /// operator must commit or revert before retrying.
    pub const NOTEBOOK_DIRTY: &str = "NOTEBOOK_DIRTY";
    /// `notebook.git` is mid-merge; the operator must abort or complete it.
    pub const MERGE_IN_PROGRESS: &str = "MERGE_IN_PROGRESS";
    /// The resolved current git signer is not in `Active` role.
    pub const SIGNER_INACTIVE: &str = "SIGNER_INACTIVE";
    /// The source recommendation's signature is untrusted.
    pub const SOURCE_REC_UNTRUSTED: &str = "SOURCE_REC_UNTRUSTED";
    /// The source recommendation exists but cannot be promoted for a
    /// structural reason (wrong type, already promoted, etc.).
    pub const SOURCE_REC_INCOMPATIBLE: &str = "SOURCE_REC_INCOMPATIBLE";
    /// The requested commit SHA does not exist in the project repo.
    pub const COMMIT_NOT_FOUND: &str = "COMMIT_NOT_FOUND";
    /// The commit SHA exists but is not reachable from the default branch.
    pub const COMMIT_UNREACHABLE_FROM_DEFAULT: &str = "COMMIT_UNREACHABLE_FROM_DEFAULT";
    /// The project repo has no resolvable default branch.
    pub const REPO_NO_DEFAULT_BRANCH: &str = "REPO_NO_DEFAULT_BRANCH";
    /// Signing the lifecycle commit failed.
    pub const COMMIT_SIGN_FAILED: &str = "COMMIT_SIGN_FAILED";
    /// A `notebook.git` pre-commit hook rejected the lifecycle commit.
    pub const COMMIT_REJECTED_BY_HOOK: &str = "COMMIT_REJECTED_BY_HOOK";
    /// The lifecycle commit landed but the post-commit index refresh failed.
    pub const INDEX_REFRESH_FAILED: &str = "INDEX_REFRESH_FAILED";
    /// The lifecycle commit failed and rollback itself failed; manual
    /// intervention required.
    pub const ROLLBACK_FAILED: &str = "ROLLBACK_FAILED";
}

// ───── ApiError → ErrorEnvelope builder (top-level dispatch) ────────────────

#[allow(clippy::too_many_lines)]
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
            ApiError::Trust(e) => trust_envelope(e),
            ApiError::Extraction(e) => extract_envelope(e),
            ApiError::TrustRegenerateRefused { reason } => ErrorEnvelope {
                // Refusals (merge in progress, dirty worktree, pending
                // reanchor) are operator-fixable conditions — they belong
                // in the USAGE bucket, not STORE_INTEGRITY which the spec
                // reserves for actual store damage.
                error_code: error_codes::USAGE,
                message: format!("trust regenerate refused: {reason}"),
                remediation: None,
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "regenerate_refused",
                    "reason": reason,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::TrustRegenerateFailed { stderr } => ErrorEnvelope {
                error_code: error_codes::STORE_INTEGRITY,
                message: format!("trust regenerate verification failed: {stderr}"),
                remediation: None,
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "regenerate_failed",
                    "stderr": stderr,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRevokeWouldUnsignStore { fingerprint } => ErrorEnvelope {
                error_code: error_codes::KEYS_REVOKE_WOULD_UNSIGN_STORE,
                message: format!(
                    "revoking {fingerprint} would leave no Active signer for the trust store"
                ),
                remediation: Some(Remediation {
                    command: Some("nexum keys rotate --new-key <path>".to_owned()),
                    rationale: "Add a second signing key first, then re-run the revoke.".to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "keys_revoke_would_unsign_store",
                    "fingerprint": fingerprint,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRevokeWouldSignOwnRevocation {
                fingerprint,
                current_signer_fingerprint,
            } => ErrorEnvelope {
                error_code: error_codes::KEYS_REVOKE_WOULD_SIGN_OWN_REVOCATION,
                message: format!(
                    "revoke target {fingerprint} equals the current git signer {current_signer_fingerprint}"
                ),
                remediation: Some(Remediation {
                    command: Some(
                        "git -C notebook.git config --local user.signingkey \
                         <path-to-different-Active-key>"
                            .to_owned(),
                    ),
                    rationale:
                        "Swap user.signingkey to a different Active key, then re-run the revoke."
                            .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "keys_revoke_would_sign_own_revocation",
                    "fingerprint": fingerprint,
                    "current_signer_fingerprint": current_signer_fingerprint,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRevokeSignerNotActive {
                signer_fingerprint,
                signer_role,
            } => ErrorEnvelope {
                error_code: error_codes::KEYS_REVOKE_SIGNER_NOT_ACTIVE,
                message: format!(
                    "git signer {signer_fingerprint} has role {signer_role}, not Active"
                ),
                remediation: Some(Remediation {
                    command: Some("nexum keys list".to_owned()),
                    rationale: "Run `nexum keys list` to see which keys qualify, then \
                                swap user.signingkey to an Active key."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "keys_revoke_signer_not_active",
                    "signer_fingerprint": signer_fingerprint,
                    "signer_role": signer_role,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::Concurrent { lock_path } => ErrorEnvelope {
                error_code: error_codes::CONCURRENT,
                message: format!(
                    "another nexum process holds the writer lock at {}",
                    lock_path.display()
                ),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Wait for the other nexum process to finish before retrying. \
                                If you believe the holder has exited, inspect running nexum \
                                processes and the lockfile listed in `context.lock_path` \
                                before any manual cleanup."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "writer_lock",
                    "lock_path": lock_path.display().to_string(),
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverChainBreakNotAcknowledged => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_CHAIN_BREAK_NOT_ACKNOWLEDGED,
                message: "recovery requires explicit chain-break acknowledgement; \
                          pass `--acknowledge-chain-break` to proceed"
                    .to_owned(),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Re-run with `--acknowledge-chain-break` to confirm \
                                that the old signing key can no longer be retrieved."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_chain_break_not_acknowledged",
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverPinMissingForCaseA { path } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_PIN_MISSING_FOR_CASE_A,
                message: format!(
                    "Case A recovery requires an intact bootstrap pin; \
                     pin file missing or unreadable at {}",
                    path.display()
                ),
                remediation: Some(Remediation {
                    command: Some("nexum doctor".to_owned()),
                    rationale: "Run `nexum doctor` to investigate the bootstrap pin state."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_pin_missing_for_case_a",
                    "path": path.display().to_string(),
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverPinMismatchForCaseA { expected, found } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_PIN_MISMATCH_FOR_CASE_A,
                message: format!(
                    "Case A pin fingerprint {found} doesn't match the chain's \
                     current bootstrap {expected}"
                ),
                remediation: Some(Remediation {
                    command: Some("nexum doctor".to_owned()),
                    rationale: "Run `nexum doctor` to investigate the pin and bootstrap state."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_pin_mismatch_for_case_a",
                    "expected": expected,
                    "found": found,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverInProgress { sentinel_path } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_IN_PROGRESS,
                message: format!(
                    "a pending reanchor is already in progress (sentinel at {}); \
                     resolve it via `nexum doctor --resolve-pending-reanchor` first",
                    sentinel_path.display()
                ),
                remediation: Some(Remediation {
                    command: Some("nexum doctor --resolve-pending-reanchor --continue".to_owned()),
                    rationale: "Resolve or revert the existing pending reanchor before \
                                starting a new recovery."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_in_progress",
                    "sentinel_path": sentinel_path.display().to_string(),
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverNewKeyAlreadyKnown { fingerprint } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_NEW_KEY_ALREADY_KNOWN,
                message: format!(
                    "new key fingerprint {fingerprint} already appears in events.yml; \
                     supply a key that has never been added to this notebook"
                ),
                remediation: Some(Remediation {
                    command: Some("nexum keys list".to_owned()),
                    rationale: "Run `nexum keys list` to see all known fingerprints.".to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_new_key_already_known",
                    "fingerprint": fingerprint,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverAgentUnavailable { fingerprint } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_AGENT_UNAVAILABLE,
                message: format!(
                    "ssh-agent unavailable when trying to sign with {fingerprint}; \
                     load the new key into the agent first"
                ),
                remediation: Some(Remediation {
                    command: Some(format!("ssh-add <path-to-key-for-{fingerprint}>")),
                    rationale: "Add the new private key to the ssh-agent and retry.".to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_agent_unavailable",
                    "fingerprint": fingerprint,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::KeysRecoverFailed { stderr } => ErrorEnvelope {
                error_code: error_codes::KEYS_RECOVER_FAILED,
                message: format!("recovery failed mid-flight: {stderr}"),
                remediation: Some(Remediation {
                    command: Some("nexum doctor --resolve-pending-reanchor --revert".to_owned()),
                    rationale: "Run `nexum doctor --resolve-pending-reanchor --revert` \
                                to clean up the partial sentinel state."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "api",
                    "subkind": "keys_recover_failed",
                    "stderr": stderr,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::PreRecoveryAckFileMalformed { path, reason } => ErrorEnvelope {
                error_code: error_codes::PRE_RECOVERY_ACK_FILE_MALFORMED,
                message: format!(
                    "trust warnings ack file at {} is malformed: {reason}",
                    path.display()
                ),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Inspect the file by hand; delete it to reset acked warnings."
                        .to_owned(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "dismiss_pre_recovery_warning",
                    "path": path.display().to_string(),
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },
            ApiError::Other { message } => ErrorEnvelope {
                error_code: error_codes::INTERNAL,
                message: message.clone(),
                remediation: None,
                context: serde_json::json!({ "kind": "other" }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            },

            // ── Lifecycle-mutation: refused (state_mutated=false, requires_reindex=false) ──

            ApiError::NotebookDirty { dirty_files } => ErrorEnvelope {
                error_code: error_codes::NOTEBOOK_DIRTY,
                message: "notebook.git has uncommitted changes outside the lifecycle paths".into(),
                remediation: Some(Remediation {
                    command: Some("git -C ~/.nexum/notebook.git status".into()),
                    rationale: "Commit or revert the dirty files, then retry.".into(),
                }),
                context: serde_json::json!({
                    "kind": "notebook",
                    "subkind": "dirty",
                    "dirty_files": dirty_files,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::MergeInProgress => ErrorEnvelope {
                error_code: error_codes::MERGE_IN_PROGRESS,
                message: "notebook.git is mid-merge".into(),
                remediation: Some(Remediation {
                    command: Some("git -C ~/.nexum/notebook.git merge --abort".into()),
                    rationale: "Abort or complete the in-progress merge, then retry.".into(),
                }),
                context: serde_json::json!({
                    "kind": "notebook",
                    "subkind": "merge_in_progress",
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::ReanchorPending { sentinel_path } => ErrorEnvelope {
                error_code: error_codes::REANCHOR_PENDING,
                message: "a reanchor is pending; run `nexum doctor --resolve-pending-reanchor` first".into(),
                remediation: Some(Remediation {
                    command: Some("nexum doctor --resolve-pending-reanchor".into()),
                    rationale: "Resolve the pending reanchor before attempting lifecycle mutations.".into(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "reanchor_pending",
                    "sentinel_path": sentinel_path.display().to_string(),
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::SignerInactive { reason } => ErrorEnvelope {
                error_code: error_codes::SIGNER_INACTIVE,
                message: format!("current git signer is not Active: {reason}"),
                remediation: Some(Remediation {
                    command: Some("nexum keys list".into()),
                    rationale: "Run `nexum keys list` to see which keys are Active, then swap user.signingkey.".into(),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "signer_inactive",
                    "reason": reason,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::SourceRecUntrusted { id, signature_status } => ErrorEnvelope {
                error_code: error_codes::SOURCE_REC_UNTRUSTED,
                message: format!("source recommendation {id} is untrusted ({signature_status})"),
                remediation: Some(Remediation {
                    command: Some(format!("nexum get {id}")),
                    rationale: "Inspect the record's trust state and resolve before promoting.".into(),
                }),
                context: serde_json::json!({
                    "kind": "record",
                    "subkind": "source_rec_untrusted",
                    "id": id,
                    "signature_status": signature_status,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::SourceRecIncompatible { id, reason } => ErrorEnvelope {
                error_code: error_codes::SOURCE_REC_INCOMPATIBLE,
                message: format!("source recommendation {id} cannot be promoted: {reason}"),
                remediation: None,
                context: serde_json::json!({
                    "kind": "record",
                    "subkind": "source_rec_incompatible",
                    "id": id,
                    "reason": reason,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::RepoIdentityMismatch { expected, observed, path } => ErrorEnvelope {
                error_code: error_codes::REPO_IDENTITY_MISMATCH,
                message: format!("repo identity mismatch: expected {expected}, observed {observed}"),
                remediation: Some(Remediation {
                    command: Some("nexum project set-path <path>".into()),
                    rationale: "Verify the project path points to the correct repo.".into(),
                }),
                context: serde_json::json!({
                    "kind": "repo",
                    "subkind": "identity_mismatch",
                    "expected": expected,
                    "observed": observed,
                    "path": path.display().to_string(),
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::CommitNotFound { sha, repo } => ErrorEnvelope {
                error_code: error_codes::COMMIT_NOT_FOUND,
                message: format!("commit {sha} not found in {}", repo.display()),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "The commit may have been force-pushed away or the repo path may be wrong.".into(),
                }),
                context: serde_json::json!({
                    "kind": "repo",
                    "subkind": "commit_not_found",
                    "sha": sha,
                    "repo": repo.display().to_string(),
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::CommitUnreachableFromDefault { sha, branch } => ErrorEnvelope {
                error_code: error_codes::COMMIT_UNREACHABLE_FROM_DEFAULT,
                message: format!("commit {sha} is not reachable from {branch}"),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "The commit may have been rebased away. Verify it is merged into the default branch.".into(),
                }),
                context: serde_json::json!({
                    "kind": "repo",
                    "subkind": "commit_unreachable_from_default",
                    "sha": sha,
                    "branch": branch,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::RepoNoDefaultBranch { repo } => ErrorEnvelope {
                error_code: error_codes::REPO_NO_DEFAULT_BRANCH,
                message: format!("no default branch resolvable in {}", repo.display()),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Ensure the repo has a default branch (main or master) or configure one.".into(),
                }),
                context: serde_json::json!({
                    "kind": "repo",
                    "subkind": "no_default_branch",
                    "repo": repo.display().to_string(),
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::CommitSignFailed { detail } => ErrorEnvelope {
                error_code: error_codes::COMMIT_SIGN_FAILED,
                message: format!("signing the lifecycle commit failed: {detail}"),
                remediation: Some(Remediation {
                    command: Some("ssh-add <signing-key-path>".into()),
                    rationale: "Ensure the signing key is loaded in the ssh-agent and retry.".into(),
                }),
                context: serde_json::json!({
                    "kind": "notebook",
                    "subkind": "commit_sign_failed",
                    "detail": detail,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },
            ApiError::CommitRejectedByHook { detail } => ErrorEnvelope {
                error_code: error_codes::COMMIT_REJECTED_BY_HOOK,
                message: format!("a notebook.git pre-commit hook rejected the lifecycle commit: {detail}"),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Inspect the hook output in `detail`, fix the underlying issue, and retry.".into(),
                }),
                context: serde_json::json!({
                    "kind": "notebook",
                    "subkind": "commit_rejected_by_hook",
                    "detail": detail,
                }),
                severity: Some(Severity::Refused),
                state_mutated: Some(false),
                requires_reindex: Some(false),
            },

            // ── Lifecycle-mutation: partial (state_mutated=true, requires_reindex=true) ──

            ApiError::IndexRefreshFailed { detail } => ErrorEnvelope {
                error_code: error_codes::INDEX_REFRESH_FAILED,
                message: format!("post-commit index refresh failed: {detail}"),
                remediation: Some(Remediation {
                    command: Some("nexum index".into()),
                    rationale: "The lifecycle commit landed; run `nexum index` to bring the index back in sync.".into(),
                }),
                context: serde_json::json!({
                    "kind": "indexer",
                    "subkind": "index_refresh_failed",
                    "detail": detail,
                }),
                severity: Some(Severity::Partial),
                state_mutated: Some(true),
                requires_reindex: Some(true),
            },

            // ── Lifecycle-mutation: inconsistent (state_mutated=true, requires_reindex=false) ──

            ApiError::RollbackFailed { detail } => ErrorEnvelope {
                error_code: error_codes::ROLLBACK_FAILED,
                message: format!("rollback after a failed lifecycle commit itself failed: {detail}"),
                remediation: Some(Remediation {
                    command: Some("nexum doctor".into()),
                    rationale: "Run `nexum doctor` to assess the notebook state; manual intervention may be required.".into(),
                }),
                context: serde_json::json!({
                    "kind": "notebook",
                    "subkind": "rollback_failed",
                    "detail": detail,
                }),
                severity: Some(Severity::Inconsistent),
                state_mutated: Some(true),
                requires_reindex: Some(false),
            },
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
        context: serde_json::json!({ "kind": "migration", "v_disk": v_disk, "v_code": v_code }),
        severity: None,
        state_mutated: None,
        requires_reindex: None,
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
        // Lifted to ApiError::MigrationRequired by From<QueryError> on every
        // production path. If a future caller hand-constructs the variant and
        // skips the lift, route through the proper migration envelope rather
        // than panicking — agents must always see a structured envelope, not
        // a binary crash.
        QueryError::MigrationRequired { v_disk } => {
            migration_required_envelope(*v_disk, crate::migrate::index_db::INDEX_DB_LATEST_VERSION)
        }
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
        severity: None,
        state_mutated: None,
        requires_reindex: None,
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
        severity: None,
        state_mutated: None,
        requires_reindex: None,
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
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    }
}

/// Build a `STORE_INTEGRITY` envelope for variants that own a path + a source
/// error. `message` is the verbatim Display rendering of the source variant
/// (constructed once and reused as both the envelope's `message` and the
/// `context.message` field, so the two channels never drift).
fn path_envelope_str(
    kind: &'static str,
    subkind: &'static str,
    path: &str,
    message: String,
) -> ErrorEnvelope {
    let context = serde_json::json!({
        "kind": kind,
        "subkind": subkind,
        "path": path,
        "message": &message,
    });
    ErrorEnvelope {
        error_code: error_codes::STORE_INTEGRITY,
        message,
        remediation: None,
        context,
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    }
}

// ───── IndexerError variant dispatch ────────────────────────────────────────

fn indexer_envelope(err: &crate::indexer::IndexerError) -> ErrorEnvelope {
    use crate::indexer::IndexerError;
    match err {
        IndexerError::Trust(t) => trust_envelope(t),
        IndexerError::Io { path, source } => path_envelope_str(
            "indexer",
            "io",
            &path.to_string_lossy(),
            format!("io error at {}: {source}", path.display()),
        ),
        IndexerError::Rusqlite(e) => store_integrity_foreign("rusqlite", e),
        IndexerError::Schema(e) => store_integrity_foreign("schema", e),
        IndexerError::Adapter(e) => store_integrity_foreign("adapter", e),
        IndexerError::Config(s) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config error: {s}"),
            remediation: None,
            context: serde_json::json!({ "kind": "config", "message": s }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        IndexerError::Embed(e) => embed_envelope(e),
        IndexerError::Migration(e) => migration_error_envelope(e),
    }
}

/// Build an `EMBED_FAILED` envelope for a `crate::embed::EmbedError`. The
/// store remains intact; only the embedder is broken, so the suggested
/// remediation is to reinstall the model and retry indexing.
fn embed_envelope(err: &crate::embed::EmbedError) -> ErrorEnvelope {
    let message = err.to_string();
    let context = serde_json::json!({
        "kind": "embed",
        "message": &message,
    });
    ErrorEnvelope {
        error_code: error_codes::EMBED_FAILED,
        message,
        remediation: Some(Remediation {
            command: Some("nexum models install bge-m3".into()),
            rationale: "Reinstall the embedding model and retry indexing.".into(),
        }),
        context,
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    }
}

/// Map a `MigrationError` to an `ErrorEnvelope`.
///
/// `IncompatibleStore` (`v_disk` > `v_code`) surfaces as `STORE_INTEGRITY` because
/// the store cannot be recovered by any command the current binary offers —
/// the operator needs a newer binary. Every other variant is a recoverable or
/// structural migration failure and also routes to `STORE_INTEGRITY` with an
/// appropriate `subkind` tag so agents can discriminate without matching on
/// the human-readable message.
fn migration_error_envelope(err: &crate::migrate::MigrationError) -> ErrorEnvelope {
    use crate::migrate::MigrationError;
    let message = err.to_string();
    let context = match err {
        MigrationError::IncompatibleStore { v_disk, v_code } => serde_json::json!({
            "kind": "migration",
            "subkind": "incompatible_store",
            "v_disk": v_disk,
            "v_code": v_code,
        }),
        MigrationError::StepFailed { from, to, cause } => serde_json::json!({
            "kind": "migration",
            "subkind": "step_failed",
            "from": from,
            "to": to,
            "cause": cause,
        }),
        MigrationError::MigrationRequired { v_disk, v_code } => serde_json::json!({
            "kind": "migration",
            "subkind": "migration_required",
            "v_disk": v_disk,
            "v_code": v_code,
        }),
        MigrationError::Sqlite(e) => serde_json::json!({
            "kind": "migration",
            "subkind": "sqlite",
            "message": e.to_string(),
        }),
        MigrationError::Io(e) => serde_json::json!({
            "kind": "migration",
            "subkind": "io",
            "message": e.to_string(),
        }),
        MigrationError::Schema(e) => serde_json::json!({
            "kind": "migration",
            "subkind": "schema",
            "message": e.to_string(),
        }),
    };
    ErrorEnvelope {
        error_code: error_codes::STORE_INTEGRITY,
        message,
        remediation: None,
        context,
        severity: None,
        state_mutated: None,
        requires_reindex: None,
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        ConfigError::Io { path, source } => path_envelope_str(
            "config",
            "io",
            path,
            format!("config I/O error at {path}: {source}"),
        ),
        ConfigError::Parse { path, source } => path_envelope_str(
            "config",
            "parse",
            path,
            format!("config parse error in {path}: {source}"),
        ),
        ConfigError::Serialize(e) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("config serialize error: {e}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "config",
                "subkind": "serialize",
                "message": format!("{e}"),
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        ConfigError::Invalid { field, reason } => ErrorEnvelope {
            error_code: error_codes::USAGE,
            message: format!("invalid config at {field}: {reason}"),
            remediation: Some(Remediation {
                command: None,
                rationale: format!("Fix the config field `{field}` and retry."),
            }),
            context: serde_json::json!({
                "kind": "config",
                "subkind": "invalid",
                "field": field,
                "reason": reason,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
    }
}

// ───── TrustError variant dispatch ──────────────────────────────────────────

// Flat dispatcher over every `TrustError` variant: each arm is a short
// literal `ErrorEnvelope` and the per-arm bodies are deliberately
// inlined for readability over any factoring that would hide the
// envelope shape behind a helper-call indirection.
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::Io { path, source } => path_envelope_str(
            "trust",
            "io",
            path,
            format!("trust I/O error at {path}: {source}"),
        ),
        TrustError::Parse { path, source } => path_envelope_str(
            "trust",
            "parse",
            path,
            format!("trust YAML parse error in {path}: {source}"),
        ),
        TrustError::Serialize(e) => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("trust YAML serialize error: {e}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "serialize",
                "message": format!("{e}"),
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::ConfigParse { path, source } => path_envelope_str(
            "trust",
            "config_parse",
            path,
            format!("config.toml parse error in {path}: {source}"),
        ),
        TrustError::BootstrapPinMissing => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: "bootstrap pin missing from config.toml".into(),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "bootstrap_pin_missing",
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::MalformedBootstrap => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: "first events.yml revision must contain exactly one BootstrapKey event".into(),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "malformed_bootstrap",
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::DuplicateKey { fingerprint } => ErrorEnvelope {
            error_code: error_codes::STORE_INTEGRITY,
            message: format!("duplicate key fingerprint in events.yml: {fingerprint}"),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "duplicate_key",
                "fingerprint": fingerprint,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::DuplicateEvent { kind, fingerprint } => ErrorEnvelope {
            error_code: error_codes::TRUST_DUPLICATE_EVENT,
            message: format!("a {kind} event for fingerprint {fingerprint} already exists"),
            remediation: Some(Remediation {
                command: None,
                rationale: format!(
                    "Run `nexum keys list` to see the existing trust state; \
                     if the {kind} classification is wrong, the operator must \
                     rebuild from a backup of events.yml."
                ),
            }),
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "duplicate_event",
                "event_kind": kind,
                "fingerprint": fingerprint,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::FingerprintNotKnown { fingerprint } => ErrorEnvelope {
            error_code: error_codes::TRUST_FINGERPRINT_NOT_KNOWN,
            message: format!("fingerprint not known to the trust state: {fingerprint}"),
            remediation: Some(Remediation {
                command: Some("nexum keys list".to_owned()),
                rationale: "Run `nexum keys list` to see the known fingerprints; \
                            the operator may have a typo or stale clipboard."
                    .to_owned(),
            }),
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "fingerprint_not_known",
                "fingerprint": fingerprint,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::RecoverOldFpMismatch { expected, supplied } => ErrorEnvelope {
            error_code: error_codes::RECOVER_OLD_FP_MISMATCH,
            message: format!(
                "recovery old_fingerprint {supplied} doesn't match the chain's current bootstrap {expected}"
            ),
            remediation: Some(Remediation {
                command: Some("nexum keys list".to_owned()),
                rationale: "Verify the current bootstrap fingerprint with `nexum keys list` \
                            and resubmit with the correct old_fingerprint."
                    .to_owned(),
            }),
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "recover_old_fp_mismatch",
                "expected": expected,
                "supplied": supplied,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        TrustError::RecoverDuplicateChain { old_fp, new_fp } => ErrorEnvelope {
            error_code: error_codes::RECOVER_DUPLICATE_CHAIN,
            message: format!(
                "a BootstrapReanchor event for ({old_fp} -> {new_fp}) already exists in events.yml"
            ),
            remediation: None,
            context: serde_json::json!({
                "kind": "trust",
                "subkind": "recover_duplicate_chain",
                "old_fp": old_fp,
                "new_fp": new_fp,
            }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    }
}

fn store_integrity_foreign(kind: &'static str, e: &dyn std::fmt::Display) -> ErrorEnvelope {
    let inner = e.to_string();
    let context = serde_json::json!({ "kind": kind, "message": &inner });
    ErrorEnvelope {
        error_code: error_codes::STORE_INTEGRITY,
        message: format!("{kind} error: {inner}"),
        remediation: None,
        context,
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    }
}

// ───── ExtractError variant dispatch ────────────────────────────────────────

/// Build the [`ErrorEnvelope`] for an [`ExtractError`]. Exposed so the
/// `nexum extract` CLI verb can render envelopes from a borrowed
/// `ExtractError` without first having to wrap it in an owned
/// `ApiError::Extraction` (`ExtractError` is not `Clone`, so a borrow is
/// the only available carrier at the CLI's error-emission site).
///
/// [`ExtractError`]: crate::extract::model::ExtractError
#[allow(clippy::too_many_lines)] // flat exhaustive match over all ExtractError variants
pub fn extract_envelope(err: &crate::extract::model::ExtractError) -> ErrorEnvelope {
    use crate::extract::model::ExtractError as E;
    match err {
        E::NoApiKey { env_var } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_NO_API_KEY,
            message: format!("set {env_var} in the environment and re-run"),
            remediation: Some(Remediation {
                command: Some(format!("export {env_var}=...")),
                rationale: format!("set {env_var} before invoking the command"),
            }),
            context: serde_json::json!({ "env_var": env_var }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::ProviderUnsupported { provider } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_PROVIDER_UNSUPPORTED,
            message: format!("provider `{provider}` is not implemented in this build"),
            remediation: None,
            context: serde_json::json!({ "provider": provider }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::Http { status, body } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_MODEL_ERROR,
            message: format!("HTTP {status}: {body}"),
            remediation: None,
            context: serde_json::json!({ "status": status, "body": body }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::MalformedResponse { reason } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_PARSE,
            message: format!("model response was not parseable as YAML: {reason}"),
            remediation: None,
            context: serde_json::json!({ "reason": reason }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::Validation { reason } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_VALIDATION,
            message: format!("record failed schema validation: {reason}"),
            remediation: None,
            context: serde_json::json!({ "reason": reason }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::DryRunRequired => ErrorEnvelope {
            error_code: error_codes::EXTRACT_DRY_RUN_REQUIRED,
            message: "run `nexum extract --backfill --dry-run` first to write a manifest"
                .to_owned(),
            remediation: Some(Remediation {
                command: Some("nexum extract --backfill --dry-run".to_owned()),
                rationale: "the backfill path requires a manifest from a dry-run pass first"
                    .to_owned(),
            }),
            context: serde_json::json!({}),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::DryRunMismatch { expected, actual } => ErrorEnvelope {
            error_code: error_codes::EXTRACT_DRY_RUN_MISMATCH,
            message: format!("dry-run id mismatch: expected {expected}, recomputed {actual}"),
            remediation: Some(Remediation {
                command: Some("nexum extract --backfill --dry-run".to_owned()),
                rationale: "the basis shifted; re-run --dry-run and supply the new id".to_owned(),
            }),
            context: serde_json::json!({ "expected": expected, "actual": actual }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::NotAcknowledged => ErrorEnvelope {
            error_code: error_codes::EXTRACT_NOT_ACKNOWLEDGED,
            message: "run `nexum extract --session <any-id>` interactively once to record consent"
                .to_owned(),
            remediation: Some(Remediation {
                command: Some("nexum extract --session <any-id>".to_owned()),
                rationale: "first run records the consent ack so subsequent runs can proceed"
                    .to_owned(),
            }),
            context: serde_json::json!({}),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::NoSessions => ErrorEnvelope {
            error_code: error_codes::EXTRACT_NO_SESSIONS,
            message: "the supplied selector matched no sessions".to_owned(),
            remediation: None,
            context: serde_json::json!({}),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        },
        E::Redaction(_)
        | E::Digest(_)
        | E::Init(_)
        | E::Io(_)
        | E::Json(_)
        | E::Yaml(_)
        | E::Git(_) => {
            let kind = match err {
                E::Redaction(_) => "redaction",
                E::Digest(_) => "digest",
                E::Init(_) => "init",
                E::Io(_) => "io",
                E::Json(_) => "json",
                E::Yaml(_) => "yaml",
                E::Git(_) => "git",
                _ => unreachable!(),
            };
            ErrorEnvelope {
                error_code: error_codes::EXTRACT_MODEL_ERROR,
                message: err.to_string(),
                remediation: None,
                context: serde_json::json!({ "kind": kind, "message": err.to_string() }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            }
        }
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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
            severity: None,
            state_mutated: None,
            requires_reindex: None,
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

    // ──── MigrationError subkind dispatch ─────────────────────────────────
    //
    // The wire-stable `subkind` discriminator under `context.kind = "migration"`
    // is the agent-facing branch for `nexum migrate` failures. Pin each
    // variant's mapping so a future rename breaks the test before it breaks
    // the contract.

    #[test]
    fn migration_incompatible_store_carries_subkind_and_versions() {
        let err = crate::indexer::db::IndexerError::Migration(
            crate::migrate::MigrationError::IncompatibleStore {
                v_disk: 9,
                v_code: 3,
            },
        );
        let api_err = crate::api::ApiError::Indexer(err);
        let env: ErrorEnvelope = (&api_err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "migration");
        assert_eq!(env.context["subkind"], "incompatible_store");
        assert_eq!(env.context["v_disk"], 9);
        assert_eq!(env.context["v_code"], 3);
    }

    #[test]
    fn migration_step_failed_carries_from_to_cause() {
        let err = crate::indexer::db::IndexerError::Migration(
            crate::migrate::MigrationError::StepFailed {
                from: 1,
                to: 2,
                cause: "synthetic step failure".into(),
            },
        );
        let api_err = crate::api::ApiError::Indexer(err);
        let env: ErrorEnvelope = (&api_err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "migration");
        assert_eq!(env.context["subkind"], "step_failed");
        assert_eq!(env.context["from"], 1);
        assert_eq!(env.context["to"], 2);
        assert_eq!(env.context["cause"], "synthetic step failure");
    }

    #[test]
    fn migration_required_via_indexer_routes_to_subkind() {
        let err = crate::indexer::db::IndexerError::Migration(
            crate::migrate::MigrationError::MigrationRequired {
                v_disk: 1,
                v_code: 2,
            },
        );
        let api_err = crate::api::ApiError::Indexer(err);
        let env: ErrorEnvelope = (&api_err).into();
        assert_eq!(env.error_code, error_codes::STORE_INTEGRITY);
        assert_eq!(env.context["kind"], "migration");
        assert_eq!(env.context["subkind"], "migration_required");
        assert_eq!(env.context["v_disk"], 1);
        assert_eq!(env.context["v_code"], 2);
    }

    #[test]
    fn query_migration_required_direct_construction_emits_migration_envelope() {
        // From<QueryError> lifts MigrationRequired to ApiError::MigrationRequired
        // before query_envelope ever sees it; this test bypasses the lift to
        // confirm the safety arm in query_envelope still emits a structured
        // envelope rather than panicking.
        let api_err =
            crate::api::ApiError::Query(crate::query::QueryError::MigrationRequired { v_disk: 1 });
        let env: ErrorEnvelope = (&api_err).into();
        assert_eq!(env.error_code, error_codes::MIGRATION_REQUIRED);
        assert_eq!(env.context["kind"], "migration");
        assert_eq!(env.context["v_disk"], 1);
    }

    // ───── ExtractError variants ─────────────────────────────────────────────

    #[test]
    fn from_extract_no_api_key_routes_with_env_var_context() {
        let err = crate::api::ApiError::Extraction(crate::extract::model::ExtractError::NoApiKey {
            env_var: "ANTHROPIC_API_KEY".to_owned(),
        });
        let env = ErrorEnvelope::from(&err);
        assert_eq!(env.error_code, error_codes::EXTRACT_NO_API_KEY);
        assert!(env.message.contains("ANTHROPIC_API_KEY"));
        assert!(env.remediation.is_some());
        assert_eq!(
            env.context.get("env_var").and_then(|v| v.as_str()),
            Some("ANTHROPIC_API_KEY")
        );
    }

    #[test]
    fn from_extract_dry_run_mismatch_carries_expected_and_actual() {
        let err =
            crate::api::ApiError::Extraction(crate::extract::model::ExtractError::DryRunMismatch {
                expected: "sha256:aaa".to_owned(),
                actual: "sha256:bbb".to_owned(),
            });
        let env = ErrorEnvelope::from(&err);
        assert_eq!(env.error_code, error_codes::EXTRACT_DRY_RUN_MISMATCH);
        assert_eq!(
            env.context.get("expected").and_then(|v| v.as_str()),
            Some("sha256:aaa")
        );
        assert_eq!(
            env.context.get("actual").and_then(|v| v.as_str()),
            Some("sha256:bbb")
        );
    }

    #[test]
    fn from_extract_validation_routes_to_extract_validation() {
        let err =
            crate::api::ApiError::Extraction(crate::extract::model::ExtractError::Validation {
                reason: "missing project_id".to_owned(),
            });
        let env = ErrorEnvelope::from(&err);
        assert_eq!(env.error_code, error_codes::EXTRACT_VALIDATION);
        assert!(env.message.contains("missing project_id"));
    }

    #[test]
    fn from_extract_io_routes_to_model_error_with_kind() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no perms");
        let err = crate::api::ApiError::Extraction(crate::extract::model::ExtractError::Io(io_err));
        let env = ErrorEnvelope::from(&err);
        assert_eq!(env.error_code, error_codes::EXTRACT_MODEL_ERROR);
        assert_eq!(env.context.get("kind").and_then(|v| v.as_str()), Some("io"));
    }

    #[test]
    fn extract_envelope_not_acknowledged_has_session_command() {
        let api_err =
            crate::api::ApiError::Extraction(crate::extract::model::ExtractError::NotAcknowledged);
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_NOT_ACKNOWLEDGED);
        let rem = env.remediation.expect("remediation");
        assert!(rem.rationale.contains("consent") || rem.command.is_some());
    }

    #[test]
    fn extract_envelope_no_sessions_routes_cleanly() {
        let api_err =
            crate::api::ApiError::Extraction(crate::extract::model::ExtractError::NoSessions);
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_NO_SESSIONS);
    }

    #[test]
    fn extract_envelope_provider_unsupported_names_provider() {
        let api_err = crate::api::ApiError::Extraction(
            crate::extract::model::ExtractError::ProviderUnsupported {
                provider: "openai".into(),
            },
        );
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_PROVIDER_UNSUPPORTED);
        assert!(env.message.contains("openai"));
    }

    #[test]
    fn extract_envelope_dry_run_required_suggests_dry_run() {
        let api_err =
            crate::api::ApiError::Extraction(crate::extract::model::ExtractError::DryRunRequired);
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_DRY_RUN_REQUIRED);
    }

    #[test]
    fn extract_envelope_http_carries_status_in_context() {
        let api_err = crate::api::ApiError::Extraction(crate::extract::model::ExtractError::Http {
            status: 429,
            body: "Rate limited".into(),
        });
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_MODEL_ERROR);
        assert_eq!(
            env.context
                .get("status")
                .and_then(serde_json::Value::as_u64),
            Some(429)
        );
    }

    #[test]
    fn extract_envelope_malformed_response_routes_to_extract_parse() {
        let api_err = crate::api::ApiError::Extraction(
            crate::extract::model::ExtractError::MalformedResponse {
                reason: "expected mapping".into(),
            },
        );
        let env = ErrorEnvelope::from(&api_err);
        assert_eq!(env.error_code, error_codes::EXTRACT_PARSE);
        assert!(env.message.contains("expected mapping"));
    }

    #[test]
    fn severity_fields_optional_and_skipped() {
        let plain = ErrorEnvelope {
            error_code: "USAGE",
            message: "x".into(),
            remediation: None,
            context: serde_json::json!({}),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        };
        let v = serde_json::to_value(&plain).unwrap();
        assert!(v.get("severity").is_none());
        assert!(v.get("state_mutated").is_none());
        assert!(v.get("requires_reindex").is_none());

        let m3 = ErrorEnvelope {
            error_code: "NOTEBOOK_DIRTY",
            message: "dirty".into(),
            remediation: None,
            context: serde_json::json!({}),
            severity: Some(Severity::Refused),
            state_mutated: Some(false),
            requires_reindex: Some(false),
        };
        let v = serde_json::to_value(&m3).unwrap();
        assert_eq!(v["severity"], "refused");
        assert_eq!(v["state_mutated"], false);
    }

    // ── Lifecycle-mutation routing tests ─────────────────────────────────────

    #[test]
    fn notebook_dirty_routes_to_envelope() {
        let e = crate::api::ApiError::NotebookDirty {
            dirty_files: vec!["x.yml".into()],
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::NOTEBOOK_DIRTY);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
        assert_eq!(env.requires_reindex, Some(false));
    }

    #[test]
    fn merge_in_progress_routes_refused() {
        let e = crate::api::ApiError::MergeInProgress;
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::MERGE_IN_PROGRESS);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
        assert_eq!(env.requires_reindex, Some(false));
    }

    #[test]
    fn reanchor_pending_lifecycle_routes_refused() {
        let e = crate::api::ApiError::ReanchorPending {
            sentinel_path: std::path::PathBuf::from("/tmp/.reanchor_pending"),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::REANCHOR_PENDING);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn signer_inactive_routes_refused() {
        let e = crate::api::ApiError::SignerInactive {
            reason: "key is rotated".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::SIGNER_INACTIVE);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn source_rec_untrusted_routes_refused() {
        let e = crate::api::ApiError::SourceRecUntrusted {
            id: "rec:proj:abc".into(),
            signature_status: "Unsigned".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::SOURCE_REC_UNTRUSTED);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn source_rec_incompatible_routes_refused() {
        let e = crate::api::ApiError::SourceRecIncompatible {
            id: "rec:proj:abc".into(),
            reason: "already promoted".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::SOURCE_REC_INCOMPATIBLE);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn repo_identity_mismatch_routes_refused() {
        let e = crate::api::ApiError::RepoIdentityMismatch {
            expected: "git:abc".into(),
            observed: "git:def".into(),
            path: std::path::PathBuf::from("/tmp/repo"),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::REPO_IDENTITY_MISMATCH);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn commit_not_found_routes_refused() {
        let e = crate::api::ApiError::CommitNotFound {
            sha: "deadbeef".into(),
            repo: std::path::PathBuf::from("/tmp/repo"),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::COMMIT_NOT_FOUND);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn commit_unreachable_from_default_routes_refused() {
        let e = crate::api::ApiError::CommitUnreachableFromDefault {
            sha: "deadbeef".into(),
            branch: "main".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::COMMIT_UNREACHABLE_FROM_DEFAULT);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn repo_no_default_branch_routes_refused() {
        let e = crate::api::ApiError::RepoNoDefaultBranch {
            repo: std::path::PathBuf::from("/tmp/repo"),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::REPO_NO_DEFAULT_BRANCH);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn commit_sign_failed_routes_refused() {
        let e = crate::api::ApiError::CommitSignFailed {
            detail: "ssh-agent not running".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::COMMIT_SIGN_FAILED);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn commit_rejected_by_hook_routes_refused() {
        let e = crate::api::ApiError::CommitRejectedByHook {
            detail: "pre-commit: lint failed".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::COMMIT_REJECTED_BY_HOOK);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("refused"))
        );
        assert_eq!(env.state_mutated, Some(false));
    }

    #[test]
    fn index_refresh_failed_routes_partial() {
        let e = crate::api::ApiError::IndexRefreshFailed {
            detail: "sqlite locked".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::INDEX_REFRESH_FAILED);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("partial"))
        );
        assert_eq!(env.state_mutated, Some(true));
        assert_eq!(env.requires_reindex, Some(true));
    }

    #[test]
    fn rollback_failed_routes_inconsistent() {
        let e = crate::api::ApiError::RollbackFailed {
            detail: "git reset failed".into(),
        };
        let env: ErrorEnvelope = (&e).into();
        assert_eq!(env.error_code, error_codes::ROLLBACK_FAILED);
        assert_eq!(
            env.severity.map(|s| serde_json::to_value(s).unwrap()),
            Some(serde_json::json!("inconsistent"))
        );
        assert_eq!(env.state_mutated, Some(true));
        assert_eq!(env.requires_reindex, Some(false));
    }
}
