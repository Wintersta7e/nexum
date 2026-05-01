//! SSH key detection and fingerprint computation for §8 init flow.
//!
//! `detect_signing_key` implements the §8 step 2 lookup order.
//! `compute_fingerprint` converts an OpenSSH public key line to the
//! canonical `SHA256:<base64>` format used throughout the trust state machine.

pub mod detect;
pub mod fingerprint;

pub use detect::{DetectedKey, SshKeyError, detect_signing_key};
pub use fingerprint::compute_fingerprint;
