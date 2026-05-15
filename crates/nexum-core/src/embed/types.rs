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

/// Static dimension of the dense bge-m3 embedding. Mirrors the schema's
/// `FLOAT[1024]`. If a future model bumps this, both must move together.
pub const EMBED_DIM: usize = 1024;
