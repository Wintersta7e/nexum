//! Dense-embedding integration: bge-m3 ONNX runtime, install pipeline,
//! and the public `Embedder` handle. Disabled by default; turned on
//! per-install by `nexum models install bge-m3`.

pub mod embedder;
pub mod install;
pub mod manifest;
pub mod reporter;
pub mod types;

pub use embedder::Embedder;
pub use install::{InstallReport, download_bge_m3, install_bge_m3, verify_and_smoke};
pub use manifest::{BGE_M3_FILES, ManifestEntry, bge_m3_total_bytes};
pub use reporter::{NullReporter, Reporter};
pub use types::{EMBED_DIM, EmbedError};

/// Convert a dense embedding to the raw little-endian byte representation
/// `sqlite-vec` accepts under `vec_f32(?)`. Output length is
/// `embedding.len() * 4`. The allocation is pre-sized so callers don't pay
/// the reallocation cost of `flat_map(...).collect()`.
#[must_use]
pub fn f32_slice_to_le_bytes(embedding: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(embedding.len() * 4);
    for f in embedding {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

/// Try to construct an `Embedder` from a runtime config. Returns:
/// - `Ok(None)` when `cfg.embed.enabled` is false, or when the model isn't
///   installed yet (logs a warning).
/// - `Ok(Some(...))` when the load succeeds.
/// - `Err(...)` on any other load failure (treat as fatal).
///
/// The indexer maps `Err` to `IndexerError::Embed`; the query facade maps
/// `Err` to a warn-and-fallback-to-FTS-only path.
///
/// # Errors
/// Returns `EmbedError` for non-`ModelNotInstalled` load failures (ORT
/// init, tokenizer load, etc.). `ModelNotInstalled` is treated as a
/// non-fatal degrade and surfaces as `Ok(None)`.
pub fn try_load_from_config(cfg: &crate::config::Config) -> Result<Option<Embedder>, EmbedError> {
    if !cfg.embed.enabled {
        return Ok(None);
    }
    let model_path = std::path::Path::new(&cfg.embed.model_path);
    let Some(model_dir) = model_path.parent() else {
        return Err(EmbedError::ModelNotInstalled {
            reason: format!(
                "embed.model_path '{}' has no parent directory",
                cfg.embed.model_path
            ),
        });
    };
    match Embedder::load(model_dir) {
        Ok(e) => Ok(Some(e)),
        Err(EmbedError::ModelNotInstalled { reason }) => {
            tracing::warn!(
                target: "nexum::embed",
                reason,
                "embed.enabled=true but model not installed; degrading to no-embed",
            );
            Ok(None)
        }
        Err(other) => Err(other),
    }
}
