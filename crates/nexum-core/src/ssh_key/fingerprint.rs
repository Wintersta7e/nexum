//! Compute the canonical `SHA256:<base64>` fingerprint from an OpenSSH public key line.

use ssh_key::PublicKey;

use super::SshKeyError;

/// Parse an OpenSSH public key line (`ssh-ed25519 AAAA... comment`) and return
/// its SHA-256 fingerprint in the canonical `SHA256:<base64>` form used by
/// OpenSSH and throughout the nexum trust state machine (§9).
///
/// # Errors
///
/// Returns `SshKeyError::ParsePublicKey` if the key line cannot be parsed.
pub fn compute_fingerprint(pubkey_line: &str) -> Result<String, SshKeyError> {
    let key = pubkey_line
        .parse::<PublicKey>()
        .map_err(|e| SshKeyError::ParsePublicKey(e.to_string()))?;
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};

    fn generate_ed25519_pubkey_line() -> String {
        use ssh_key::rand_core::OsRng;
        let private =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate ed25519 key");
        let pub_key = private.public_key();
        pub_key.to_openssh().expect("pubkey to openssh")
    }

    #[test]
    fn fingerprint_starts_with_sha256_prefix() {
        let line = generate_ed25519_pubkey_line();
        let fp = compute_fingerprint(&line).unwrap();
        assert!(fp.starts_with("SHA256:"), "fingerprint = {fp}");
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let line = generate_ed25519_pubkey_line();
        let fp1 = compute_fingerprint(&line).unwrap();
        let fp2 = compute_fingerprint(&line).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let line1 = generate_ed25519_pubkey_line();
        let line2 = generate_ed25519_pubkey_line();
        let fp1 = compute_fingerprint(&line1).unwrap();
        let fp2 = compute_fingerprint(&line2).unwrap();
        assert_ne!(
            fp1, fp2,
            "two distinct keys must have distinct fingerprints"
        );
    }

    #[test]
    fn invalid_pubkey_line_returns_error() {
        let err = compute_fingerprint("not-a-valid-pubkey-line").unwrap_err();
        assert!(matches!(err, SshKeyError::ParsePublicKey(_)));
    }

    #[test]
    fn empty_line_returns_error() {
        let err = compute_fingerprint("").unwrap_err();
        assert!(matches!(err, SshKeyError::ParsePublicKey(_)));
    }
}
