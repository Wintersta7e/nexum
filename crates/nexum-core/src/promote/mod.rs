//! Commit-promotion plumbing.
//!
//! Exposes git-correlation and evidence-assembly helpers consumed by the
//! promotion facade (lands in a later change; the transitional `dead_code`
//! allows on submodules are removed then).

// Commit-correlation plumbing. Consumed by the promotion facade in a
// later change; the transitional dead_code allow is removed then.
#[allow(dead_code)]
pub(crate) mod fingerprint;
