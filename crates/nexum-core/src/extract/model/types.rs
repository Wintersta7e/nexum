//! `ModelClient` trait + shared types.

use std::io;

use serde::{Deserialize, Serialize};

use crate::extract::digest::{BuildDigestError, SessionDigest};
use crate::extract::redaction::RedactionError;

pub trait ModelClient: Send + Sync {
    /// Stable identifier used in manifests and error envelopes.
    fn provider_name(&self) -> &'static str;

    /// Send `digest` to the provider and parse the response into typed records.
    ///
    /// # Errors
    /// Returns `ExtractError::Http` for transport/server errors,
    /// `ExtractError::MalformedResponse` if the model emitted invalid YAML,
    /// other variants for upstream-specific failures.
    fn extract(&self, digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError>;

    /// Count the input tokens this digest would consume on this provider.
    /// Used by the dry-run path to estimate cost without sending the full request.
    ///
    /// # Errors
    /// Returns `ExtractError` if token counting fails (e.g., tokenizer load
    /// failure or provider-side error).
    fn count_input_tokens(&self, digest: &SessionDigest) -> Result<u32, ExtractError>;
}

#[derive(Debug, Clone)]
pub enum ExtractionOutput {
    Records(Vec<RawRecord>),
    NoRecords { reason: String },
}

/// One record as the model emitted it — pre-validation. The YAML may contain
/// fields the schema doesn't know about (model drift). Validation in a later
/// step builds a typed `UnifiedRecord` from this.
#[derive(Debug, Clone)]
pub struct RawRecord {
    pub yaml: serde_yaml::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "codex-phase1")]
    CodexPhase1,
}

impl Provider {
    /// Parse the lowercase string form used in `config.toml`.
    ///
    /// # Errors
    /// Returns `ExtractError::ProviderUnsupported` for any other string.
    pub fn from_config(s: &str) -> Result<Self, ExtractError> {
        match s {
            "anthropic" => Ok(Self::Anthropic),
            "openai" => Ok(Self::OpenAi),
            "ollama" => Ok(Self::Ollama),
            "codex-phase1" => Ok(Self::CodexPhase1),
            other => Err(ExtractError::ProviderUnsupported {
                provider: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("no API key in env var {env_var}")]
    NoApiKey { env_var: String },
    #[error("provider `{provider}` is not implemented in this build")]
    ProviderUnsupported { provider: String },
    #[error("model HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("model returned malformed YAML: {reason}")]
    MalformedResponse { reason: String },
    #[error("record validation failed: {reason}")]
    Validation { reason: String },
    #[error("dry-run required first; re-run with --dry-run to produce a manifest")]
    DryRunRequired,
    #[error(
        "dry-run id mismatch (expected {expected}, recomputed {actual}); re-run --dry-run and supply the new id"
    )]
    DryRunMismatch { expected: String, actual: String },
    #[error("first-run consent missing; run `nexum extract --session <any-id>` interactively once")]
    NotAcknowledged,
    #[error("no sessions matched the selector")]
    NoSessions,
    #[error("redaction: {0}")]
    Redaction(#[from] RedactionError),
    #[error("digest: {0}")]
    Digest(#[from] BuildDigestError),
    #[error("init/git_ops: {0}")]
    Init(#[from] crate::init::InitError),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("git: {0}")]
    Git(#[from] git2::Error),
}
