//! The Embedder — a shared handle wrapping the ONNX runtime session
//! and tokenizer. This module currently ships a load-failing stub;
//! the real ORT integration lands in a follow-up change.

use std::path::Path;

use super::types::EmbedError;

/// Dense-embedding handle. Cheap to clone (internals will be
/// `Arc`-wrapped once the real ORT session lands). Designed for
/// `Send + Sync` so a single handle can be shared across rayon
/// workers and tokio tasks.
#[derive(Clone)]
pub struct Embedder {
    // Real fields land alongside the ORT integration:
    //   session: Arc<Mutex<ort::Session>>,
    //   tokenizer: Arc<tokenizers::Tokenizer>,
    _marker: (),
}

impl Embedder {
    /// Load the bge-m3 ONNX export from `model_dir`. Expects
    /// `model.onnx` + the external-data sidecars + `tokenizer.json`
    /// to all be siblings in this directory.
    ///
    /// # Errors
    /// `EmbedError::ModelNotInstalled` if any expected file is absent.
    /// `EmbedError::OrtInit` on session-builder failure.
    /// `EmbedError::Tokenize` on tokenizer parse failure.
    pub fn load(_model_dir: &Path) -> Result<Self, EmbedError> {
        // Placeholder until ORT integration ships; always errs so
        // callers degrade gracefully to FTS-only.
        Err(EmbedError::ModelNotInstalled {
            reason: "embedder is not yet wired to a runtime; rerun once the ORT integration ships"
                .into(),
        })
    }

    /// Compute the dense embedding for one text. Returns a 1024-dim
    /// L2-normalized float vector.
    ///
    /// # Errors
    /// `EmbedError::Tokenize` on tokenization failure.
    /// `EmbedError::OrtRun` on inference failure.
    /// `EmbedError::OutputShapeMismatch` on unexpected output shape.
    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    pub fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedError> {
        // Unreachable while `load` always errs. Replaced when ORT
        // integration lands.
        unreachable!("Embedder::load currently always errs, so Self can't be constructed yet")
    }
}
