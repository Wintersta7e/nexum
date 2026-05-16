//! Dense-embedding integration: bge-m3 ONNX runtime, install pipeline,
//! and the public `Embedder` handle. Disabled by default; turned on
//! per-install by `nexum models install bge-m3`.

pub mod embedder;
mod inference_cell;
pub mod install;
pub mod manifest;
pub mod reporter;
pub mod types;

use std::sync::OnceLock;

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

/// Cached form of [`try_load_from_config`]. The bge-m3 ONNX session is a
/// multi-second cold load and ~MB of allocation; the MCP `search` tool runs
/// per-call, so loading per query is unacceptable. This caches the first
/// successful load (or first error kind) in a process-wide `OnceLock` and
/// hands subsequent callers a cheap `Embedder::clone()`.
///
/// The disabled path is NOT cached — flipping `cfg.embed.enabled` to false
/// returns immediately with `Ok(None)` so disabling the feature is instant.
///
/// # M1 assumption
///
/// The cache is keyed on the first load attempt; `cfg.embed.model_path` is
/// assumed not to change at runtime within one process. A future
/// admin-recovery surface that swaps model paths in-process must invalidate
/// the cache (or accept the stale handle until restart). The CLI and MCP
/// server both load the model path once at startup and don't mutate it,
/// so the assumption holds for every M1 caller.
///
/// # Errors
/// Returns the same error variants as [`try_load_from_config`]. The cached
/// error chain loses its original `#[source]` (the kind enum is `Clone` but
/// thiserror sources are not), but load-time errors carry their own
/// `reason` string so the surface stays diagnosable.
pub fn try_load_from_config_cached(
    cfg: &crate::config::Config,
) -> Result<Option<Embedder>, EmbedError> {
    static CACHE: OnceLock<Result<Option<Embedder>, EmbedErrorKind>> = OnceLock::new();
    if !cfg.embed.enabled {
        return Ok(None);
    }
    let cached = CACHE.get_or_init(|| try_load_from_config(cfg).map_err(EmbedErrorKind::from));
    match cached {
        Ok(opt) => Ok(opt.clone()),
        Err(kind) => Err(kind.materialize()),
    }
}

/// Cache-friendly mirror of the [`EmbedError`] variants we cache. The full
/// error type isn't `Clone` (the `Io` / `Download` sources aren't either),
/// and `OnceLock` requires the stored value to be reachable from every call
/// site that follows. Round-tripping through this thin enum loses the
/// `#[source]` chain but preserves the variant + the human-readable
/// reason string — sufficient for the load-only path that
/// `try_load_from_config` actually returns errors from.
#[derive(Debug, Clone)]
enum EmbedErrorKind {
    ModelNotInstalled(String),
    Tokenize(String),
    OrtInit(String),
    OrtRun(String),
    /// Catch-all: variants that aren't reachable from the load path today
    /// but stay routable rather than panicking if they ever surface.
    Other(String),
}

impl EmbedErrorKind {
    fn materialize(&self) -> EmbedError {
        match self {
            Self::ModelNotInstalled(reason) => EmbedError::ModelNotInstalled {
                reason: reason.clone(),
            },
            // `Other` rolls into Tokenize so the variant stays diagnosable
            // (the message string survives the round-trip) without adding a
            // new EmbedError variant for a path that is unreachable from
            // `try_load_from_config` today.
            Self::Tokenize(msg) | Self::Other(msg) => EmbedError::Tokenize(msg.clone()),
            Self::OrtInit(msg) => EmbedError::OrtInit(msg.clone()),
            Self::OrtRun(msg) => EmbedError::OrtRun(msg.clone()),
        }
    }
}

impl From<EmbedError> for EmbedErrorKind {
    fn from(err: EmbedError) -> Self {
        match err {
            EmbedError::ModelNotInstalled { reason } => Self::ModelNotInstalled(reason),
            EmbedError::Tokenize(msg) => Self::Tokenize(msg),
            EmbedError::OrtInit(msg) => Self::OrtInit(msg),
            EmbedError::OrtRun(msg) => Self::OrtRun(msg),
            other => Self::Other(other.to_string()),
        }
    }
}
