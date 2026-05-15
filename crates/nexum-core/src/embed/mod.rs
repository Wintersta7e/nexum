//! Dense-embedding integration: bge-m3 ONNX runtime, install pipeline,
//! and the public `Embedder` handle. Disabled by default; turned on
//! per-install by `nexum models install bge-m3`.

pub mod embedder;
pub mod manifest;
pub mod types;

pub use embedder::Embedder;
pub use manifest::{BGE_M3_FILES, ManifestEntry, bge_m3_total_bytes};
pub use types::{EMBED_DIM, EmbedError};
