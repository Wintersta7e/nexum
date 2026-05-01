//! SSH key detection — §8 step 2 lookup order.
//! Full implementation in Task 5.

use std::path::{Path, PathBuf};

/// Errors from SSH key detection and parsing.
#[derive(Debug, thiserror::Error)]
pub enum SshKeyError {
    /// A public key line could not be parsed.
    #[error("failed to parse public key: {0}")]
    ParsePublicKey(String),
    /// No SSH key was found in the §8 step 2 lookup chain.
    #[error("no SSH key found — generate one via `ssh-keygen -t ed25519`, then re-run")]
    NoKeyFound,
    /// The key at the specified override path does not exist.
    #[error("SSH key not found at override path {path}")]
    OverridePathNotFound { path: String },
    /// A filesystem error while reading a key file.
    #[error("SSH key I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// A detected SSH key and its derived metadata.
#[derive(Debug, Clone)]
pub struct DetectedKey {
    /// Path to the private key file.
    pub private_key_path: PathBuf,
    /// Path to the public key file (`<private>.pub`).
    pub public_key_path: PathBuf,
    /// SHA-256 fingerprint in `SHA256:<base64>` form.
    pub fingerprint: String,
    /// Algorithm string, e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// Full OpenSSH public key line: `<type> <base64> <comment>`.
    pub public_key_blob: String,
}

/// Detect the SSH signing key to use for `nexum init`.
///
/// Lookup order (§8 step 2):
/// 1. `override_path` if provided.
/// 2. `<home>/.ssh/id_ed25519`
/// 3. `<home>/.ssh/id_rsa`
/// 4. `<home>/.ssh/id_ecdsa`
///
/// # Errors
///
/// Returns `SshKeyError::OverridePathNotFound` if an override path is given
/// but the corresponding `.pub` file does not exist.
/// Returns `SshKeyError::NoKeyFound` if no key is found in the lookup chain.
/// Returns `SshKeyError::Io` on filesystem read errors.
/// Returns `SshKeyError::ParsePublicKey` if the public key file cannot be parsed.
pub fn detect_signing_key(
    home: &Path,
    override_path: Option<&Path>,
) -> Result<DetectedKey, SshKeyError> {
    let _ = (home, override_path);
    unimplemented!("detect_signing_key — Task 5")
}
