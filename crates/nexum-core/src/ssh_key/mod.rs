//! SSH key detection and fingerprint computation for `nexum init`.
//!
//! `detect_signing_key` probes the standard SSH key locations and returns the
//! first usable signing key. `compute_fingerprint` converts an OpenSSH public
//! key line to the canonical `SHA256:<base64>` format used throughout the trust
//! state machine.

use std::path::{Path, PathBuf};

pub mod detect;
pub mod fingerprint;

pub use detect::{DetectedKey, SshKeyError, detect_signing_key};
pub use fingerprint::compute_fingerprint;

/// Return the OpenSSH `<keyfile>.pub` sibling for a private-key path.
///
/// Appends `.pub` literally rather than using `with_extension("pub")` so that
/// keys with existing extensions (e.g. `id.pem`) yield `id.pem.pub`, not
/// `id.pub`.
pub fn pub_path_for(private_key: &Path) -> PathBuf {
    let mut s = private_key.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}
