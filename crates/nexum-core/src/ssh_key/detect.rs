//! SSH key detection — §8 step 2 lookup order.

use std::path::{Path, PathBuf};

use super::fingerprint::compute_fingerprint;

#[derive(Debug, Clone)]
pub struct DetectedKey {
    /// Path to the private key file.
    pub private_key_path: PathBuf,
    /// Path to the public key file.
    pub public_key_path: PathBuf,
    /// SHA-256 fingerprint in `SHA256:<base64>` form.
    pub fingerprint: String,
    /// Algorithm string, e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// Full OpenSSH public key line (`<type> <base64> <comment>`).
    pub public_key_blob: String,
}

/// Errors from SSH key detection and parsing.
#[derive(Debug, thiserror::Error)]
pub enum SshKeyError {
    /// A public key line could not be parsed.
    #[error("failed to parse public key: {0}")]
    ParsePublicKey(String),
    /// No SSH key was found in the §8 step 2 lookup chain.
    #[error("no SSH key found — generate one via `ssh-keygen -t ed25519`, then re-run")]
    NoKeyFound,
    /// The override path's `.pub` file does not exist.
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

/// Detect the SSH signing key to use for `nexum init`.
///
/// Lookup order (§8 step 2):
/// 1. `override_path` (private key path; derives `.pub` by appending `.pub`).
/// 2. `<home>/.ssh/id_ed25519`
/// 3. `<home>/.ssh/id_rsa`
/// 4. `<home>/.ssh/id_ecdsa`
///
/// # Errors
///
/// Returns `SshKeyError::OverridePathNotFound` if an override path is given but
/// the corresponding `.pub` file does not exist.
/// Returns `SshKeyError::NoKeyFound` if no standard key exists in the lookup chain.
/// Returns `SshKeyError::Io` on read errors.
/// Returns `SshKeyError::ParsePublicKey` if the public key file content is malformed.
pub fn detect_signing_key(
    home: &Path,
    override_path: Option<&Path>,
) -> Result<DetectedKey, SshKeyError> {
    if let Some(priv_path) = override_path {
        let pub_path = pub_path_for(priv_path);
        if !pub_path.exists() {
            return Err(SshKeyError::OverridePathNotFound {
                path: pub_path.display().to_string(),
            });
        }
        return load_key(priv_path.to_path_buf(), pub_path);
    }

    let ssh_dir = home.join(".ssh");
    for name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
        let priv_path = ssh_dir.join(name);
        let pub_path = pub_path_for(&priv_path);
        if pub_path.exists() {
            return load_key(priv_path, pub_path);
        }
    }

    Err(SshKeyError::NoKeyFound)
}

fn pub_path_for(private: &Path) -> PathBuf {
    let mut p = private.to_path_buf();
    if private.extension().is_none() {
        p.set_extension("pub");
    } else {
        let ext = p
            .extension()
            .map_or_else(|| "pub".into(), |e| format!("{}.pub", e.to_string_lossy()));
        p.set_extension(ext);
    }
    p
}

fn load_key(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<DetectedKey, SshKeyError> {
    let blob = std::fs::read_to_string(&public_key_path).map_err(|e| SshKeyError::Io {
        path: public_key_path.display().to_string(),
        source: e,
    })?;
    let blob = blob.trim().to_owned();
    let fingerprint = compute_fingerprint(&blob)?;
    let key_type = blob
        .split_ascii_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_owned();
    Ok(DetectedKey {
        private_key_path,
        public_key_path,
        fingerprint,
        key_type,
        public_key_blob: blob,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};
    use tempfile::tempdir;

    fn write_keypair(dir: &std::path::Path, name: &str) -> (PathBuf, PathBuf) {
        use ssh_key::rand_core::OsRng;
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pub_line = private.public_key().to_openssh().unwrap();
        let priv_path = dir.join(name);
        let pub_path = dir.join(format!("{name}.pub"));
        std::fs::write(&priv_path, "PLACEHOLDER_PRIVATE").unwrap();
        std::fs::write(&pub_path, &pub_line).unwrap();
        (priv_path, pub_path)
    }

    #[test]
    fn override_path_takes_precedence() {
        let dir = tempdir().unwrap();
        let (priv_path, _pub_path) = write_keypair(dir.path(), "my_key");
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        write_keypair(&ssh_dir, "id_ed25519");

        let key = detect_signing_key(dir.path(), Some(&priv_path)).unwrap();
        assert_eq!(key.private_key_path, priv_path);
    }

    #[test]
    fn fallthrough_detects_id_ed25519() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let (priv_path, _) = write_keypair(&ssh_dir, "id_ed25519");

        let key = detect_signing_key(dir.path(), None).unwrap();
        assert_eq!(key.private_key_path, priv_path);
        assert_eq!(key.key_type, "ssh-ed25519");
    }

    #[test]
    fn fallthrough_skips_missing_ed25519_finds_rsa() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let (priv_path, _) = write_keypair(&ssh_dir, "id_rsa");

        let key = detect_signing_key(dir.path(), None).unwrap();
        assert_eq!(key.private_key_path, priv_path);
    }

    #[test]
    fn no_keys_returns_no_key_found() {
        let dir = tempdir().unwrap();
        let err = detect_signing_key(dir.path(), None).unwrap_err();
        assert!(matches!(err, SshKeyError::NoKeyFound));
    }

    #[test]
    fn override_with_missing_pub_returns_error() {
        let dir = tempdir().unwrap();
        let priv_path = dir.path().join("ghost_key");
        std::fs::write(&priv_path, "PLACEHOLDER").unwrap();
        let err = detect_signing_key(dir.path(), Some(&priv_path)).unwrap_err();
        assert!(matches!(err, SshKeyError::OverridePathNotFound { .. }));
    }

    #[test]
    fn fingerprint_sha256_prefix() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        write_keypair(&ssh_dir, "id_ed25519");

        let key = detect_signing_key(dir.path(), None).unwrap();
        assert!(key.fingerprint.starts_with("SHA256:"));
    }
}
