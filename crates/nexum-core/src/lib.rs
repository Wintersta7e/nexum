//! `nexum-core` — core library for nexum.
//!
//! Wires the read path (`adapter::*`), the indexer (`indexer::*`), the query
//! layer (`query::*`), and the API facade (`api::*`). Semantic embeddings
//! and the MCP surface are not yet wired.

// Relaxed `forbid` → `deny` to permit the single justified
// `#[allow(unsafe_code)]` on `indexer::db::register_sqlite_vec_once`.
// sqlite-vec's auto-extension registration requires unsafe FFI; no other
// unsafe is introduced. Every other file in this crate stays unsafe-free.
#![deny(unsafe_code)]

pub mod adapter;
pub mod api;
pub mod config;
pub mod index;
pub mod indexer;
pub mod init;
pub mod migrate;
pub mod paths;
pub mod project;
pub mod query;
pub mod records;
pub mod session;
pub mod ssh_key;
pub mod trust;

/// Crate version.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
