//! SSH key detection and fingerprint computation for `nexum init`.
//!
//! `detect_signing_key` probes the standard SSH key locations and returns the
//! first usable signing key. `compute_fingerprint` converts an OpenSSH public
//! key line to the canonical `SHA256:<base64>` format used throughout the trust
//! state machine.

pub mod detect;
pub mod fingerprint;

pub use detect::{DetectedKey, SshKeyError, detect_signing_key};
pub use fingerprint::compute_fingerprint;
