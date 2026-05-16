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

    #[error("tokenizer error: {message}")]
    Tokenize {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("ORT initialization failed: {message}")]
    OrtInit {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("ORT inference failed: {message}")]
    OrtRun {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("output shape mismatch: expected {expected:?}, got {actual:?}")]
    OutputShapeMismatch {
        expected: Vec<usize>,
        actual: Vec<usize>,
    },
}

impl EmbedError {
    /// Build an `OrtInit` from any concrete error, capturing it as the
    /// `#[source]` chain and reusing its `Display` as the human message.
    pub(crate) fn ort_init<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::OrtInit {
            message: err.to_string(),
            source: Box::new(err),
        }
    }

    /// Build an `OrtRun` from any concrete error. Same shape as
    /// [`Self::ort_init`].
    pub(crate) fn ort_run<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::OrtRun {
            message: err.to_string(),
            source: Box::new(err),
        }
    }

    /// Build a `Tokenize` from a free-form message. Tokenizer errors arrive
    /// as a `Box<dyn Error + Send + Sync>` alias that won't sit behind a
    /// generic `E: Error` bound, and mutex-poison / shape-mismatch sites
    /// don't have a concrete source error either; the message is duplicated
    /// into the source chain so the wire shape stays consistent with the
    /// typed constructors above.
    pub(crate) fn tokenize_from_message(message: String) -> Self {
        Self::Tokenize {
            source: Box::<dyn std::error::Error + Send + Sync>::from(message.clone()),
            message,
        }
    }

    /// Build an `OrtRun` from a free-form message. See
    /// [`Self::tokenize_from_message`] for the rationale.
    pub(crate) fn ort_run_from_message(message: String) -> Self {
        Self::OrtRun {
            source: Box::<dyn std::error::Error + Send + Sync>::from(message.clone()),
            message,
        }
    }

    /// Build an `OrtInit` from a free-form message. See
    /// [`Self::tokenize_from_message`] for the rationale.
    pub(crate) fn ort_init_from_message(message: String) -> Self {
        Self::OrtInit {
            source: Box::<dyn std::error::Error + Send + Sync>::from(message.clone()),
            message,
        }
    }

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
            EmbedError::Tokenize { .. } => 13,
            EmbedError::OrtInit { .. } => 14,
            EmbedError::OrtRun { .. } => 15,
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
            EmbedError::Tokenize { .. } => "tokenize",
            EmbedError::OrtInit { .. } => "ort_init",
            EmbedError::OrtRun { .. } => "ort_run",
            EmbedError::OutputShapeMismatch { .. } => "output_shape_mismatch",
        }
    }
}

/// Static dimension of the dense bge-m3 embedding. Mirrors the schema's
/// `FLOAT[1024]`. If a future model bumps this, both must move together.
pub const EMBED_DIM: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ort_run_carries_the_source_chain() {
        use std::error::Error as _;
        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::<dyn std::error::Error + Send + Sync>::from("inner-cause");
        let err = EmbedError::OrtRun {
            message: "outer".into(),
            source: inner,
        };
        assert_eq!(err.to_string(), "ORT inference failed: outer");
        let cause = err.source().expect("source chain populated");
        assert_eq!(cause.to_string(), "inner-cause");
    }
}
