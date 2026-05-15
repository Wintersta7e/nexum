//! Dense-embedding integration: bge-m3 ONNX runtime, install pipeline,
//! and the public `Embedder` handle. Disabled by default; turned on
//! per-install by `nexum models install bge-m3`.

pub mod embedder;
pub mod install;
pub mod manifest;
pub mod reporter;
pub mod types;

pub use embedder::Embedder;
pub use install::{InstallReport, download_bge_m3, verify_and_smoke};
pub use manifest::{BGE_M3_FILES, ManifestEntry, bge_m3_total_bytes};
pub use reporter::{NullReporter, Reporter};
pub use types::{EMBED_DIM, EmbedError};
