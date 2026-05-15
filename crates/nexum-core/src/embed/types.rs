//! Public types for the embed module.

use std::path::PathBuf;

/// All embed-layer failure modes. Surfaces both install-time errors
/// (download / verify / smoke) and runtime errors (tokenize / inference).
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("model not installed: {reason}")]
    ModelNotInstalled { reason: String },

    #[error("io error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("download failed for {file}: {source}")]
    Download {
        file: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("checksum mismatch for {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("tokenizer error: {0}")]
    Tokenize(String),

    #[error("ORT initialization failed: {0}")]
    OrtInit(String),

    #[error("ORT inference failed: {0}")]
    OrtRun(String),

    #[error("output shape mismatch: expected {expected:?}, got {actual:?}")]
    OutputShapeMismatch {
        expected: Vec<usize>,
        actual: Vec<usize>,
    },
}

impl EmbedError {
    /// Stable per-variant exit code for the model install command. Agents
    /// orchestrating the install branch on these to decide retry policy
    /// without parsing stderr (e.g. checksum mismatch -> retry, ORT init
    /// failure -> reinstall binary). Values are deliberately disjoint from
    /// `ExitCode::SUCCESS` (`0`) and reuse `1` for generic IO so a default
    /// failure still surfaces as `FAILURE` for callers that don't care
    /// about the variant.
    #[must_use]
    pub fn install_exit_code(&self) -> u8 {
        match self {
            EmbedError::ModelNotInstalled { .. } => 9,
            EmbedError::Io { .. } => 1,
            EmbedError::Download { .. } => 11,
            EmbedError::ChecksumMismatch { .. } => 12,
            EmbedError::Tokenize(_) => 13,
            EmbedError::OrtInit(_) => 14,
            EmbedError::OrtRun(_) => 15,
            EmbedError::OutputShapeMismatch { .. } => 16,
        }
    }

    /// Short `snake_case` identifier for the variant. Used as the `kind`
    /// field in the install command's JSON envelope so agents can branch
    /// on structured data instead of parsing the error message.
    #[must_use]
    pub fn variant_kind(&self) -> &'static str {
        match self {
            EmbedError::ModelNotInstalled { .. } => "model_not_installed",
            EmbedError::Io { .. } => "io",
            EmbedError::Download { .. } => "download",
            EmbedError::ChecksumMismatch { .. } => "checksum_mismatch",
            EmbedError::Tokenize(_) => "tokenize",
            EmbedError::OrtInit(_) => "ort_init",
            EmbedError::OrtRun(_) => "ort_run",
            EmbedError::OutputShapeMismatch { .. } => "output_shape_mismatch",
        }
    }
}

/// Static dimension of the dense bge-m3 embedding. Mirrors the schema's
/// `FLOAT[1024]`. If a future model bumps this, both must move together.
pub const EMBED_DIM: usize = 1024;
