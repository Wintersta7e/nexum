//! `nexum-core` — core library for nexum.
//!
//! This crate is currently a stub. See `docs/spec/2026-04-29-nexum-design.md`
//! for the design that this crate will implement after the mandatory pre-M1
//! stack-validation spike completes (§3.6).

#![forbid(unsafe_code)]

pub mod paths;

/// Placeholder so the crate compiles. Replaced as M1 implementation lands.
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
