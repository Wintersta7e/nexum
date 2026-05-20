//! Resolve the SSH fingerprint of the key git will use for the NEXT
//! commit against `notebook.git`. Reads `user.signingkey` from the
//! notebook-local git config only (NOT the operator's global
//! `~/.gitconfig`) and resolves it to a fingerprint via three
//! recognized value shapes: `key::<pubkey>` literal, filesystem path,
//! and (refused) bare fingerprint.

use std::path::PathBuf;
use std::process::Command;

use crate::indexer::db::IndexerError;
use crate::paths::Paths;
use crate::ssh_key;

use super::ApiError;

/// Read `notebook.git/.git/config user.signingkey` (LOCAL only) and
/// resolve it to a SHA256 fingerprint.
///
/// # Returns
///
/// - `Ok(Some(fingerprint))` — `user.signingkey` is set and resolves
///   cleanly to a public-key fingerprint.
/// - `Ok(None)` — `user.signingkey` is not set in the local config
///   (`git config --local --get` exited with status 1).
/// - `Err(ApiError::TrustRegenerateRefused)` — `user.signingkey` is set
///   to an unsupported shape (a bare fingerprint that we can't resolve
///   without consulting the agent) OR `git config` failed for an
///   unrelated reason OR the path branch's `.pub` file is unreadable.
///
/// # Errors
///
/// See above.
pub fn resolve_active_signer_fingerprint(paths: &Paths) -> Result<Option<String>, ApiError> {
    let out = Command::new("git")
        .arg("-C")
        .arg(&paths.notebook_git)
        .args(["config", "--local", "--get", "user.signingkey"])
        .output()
        .map_err(|e| {
            ApiError::Indexer(IndexerError::Io {
                path: paths.notebook_git.clone(),
                source: e,
            })
        })?;

    match out.status.code() {
        Some(0) => {}
        Some(1) => return Ok(None),
        Some(other) => {
            return Err(ApiError::TrustRegenerateRefused {
                reason: format!(
                    "git config failed with status {other}: {stderr}",
                    stderr = String::from_utf8_lossy(&out.stderr).trim(),
                ),
            });
        }
        None => {
            return Err(ApiError::TrustRegenerateRefused {
                reason: "git config terminated without exit status".to_owned(),
            });
        }
    }

    let value = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if value.is_empty() {
        return Ok(None);
    }

    classify_signingkey(&value)
}

fn classify_signingkey(value: &str) -> Result<Option<String>, ApiError> {
    // Branch 1: key::<full-pubkey> literal.
    if let Some(pubkey) = value.strip_prefix("key::") {
        return ssh_key::compute_fingerprint(pubkey).map(Some).map_err(|e| {
            ApiError::TrustRegenerateRefused {
                reason: format!(
                    "user.signingkey = 'key::...' literal failed to compute fingerprint: {e}",
                ),
            }
        });
    }

    // Branch 2: bare fingerprint shapes — refuse (operator must use
    // path or literal). Whole-string anchors prevent false positives
    // on paths that happen to contain SHA256_ in their name.
    if is_bare_sha256_fingerprint(value) || is_bare_md5_fingerprint(value) {
        return Err(ApiError::TrustRegenerateRefused {
            reason: format!(
                "user.signingkey = '{value}' is a bare fingerprint; \
                 nexum's signing wrapper requires a path or key::<pubkey> literal. \
                 Set notebook.git/.git/config user.signingkey to either form."
            ),
        });
    }

    // Branch 3: filesystem path. Expand a leading `~/` against $HOME
    // before deriving the .pub sibling.
    let expanded_path = expand_tilde(value);
    let pub_path = ssh_key::pub_path_for(&expanded_path);
    let Ok(pub_text) = std::fs::read_to_string(&pub_path) else {
        return Err(ApiError::TrustRegenerateRefused {
            reason: format!(
                "user.signingkey = '{value}' is neither a key::<pubkey> literal, \
                 a bare fingerprint, nor a path whose .pub sibling ('{}') is readable",
                pub_path.display(),
            ),
        });
    };

    ssh_key::compute_fingerprint(pub_text.trim())
        .map(Some)
        .map_err(|e| ApiError::TrustRegenerateRefused {
            reason: format!("user.signingkey path '{value}' has unreadable pubkey: {e}"),
        })
}

fn expand_tilde(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        let mut p = PathBuf::from(home);
        p.push(rest);
        return p;
    }
    PathBuf::from(value)
}

/// Whole-string match: `SHA256:` followed by exactly 43 base64 chars,
/// optional trailing `=`.
fn is_bare_sha256_fingerprint(value: &str) -> bool {
    let Some(body) = value.strip_prefix("SHA256:") else {
        return false;
    };
    let trimmed = body.trim_end_matches('=');
    trimmed.len() == 43
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Whole-string match: `MD5:` followed by 16 hex-pair groups, colon-separated.
fn is_bare_md5_fingerprint(value: &str) -> bool {
    let Some(body) = value.strip_prefix("MD5:") else {
        return false;
    };
    let groups: Vec<&str> = body.split(':').collect();
    groups.len() == 16
        && groups
            .iter()
            .all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an ephemeral ed25519 pubkey using the `ssh_key` crate
    /// directly (no `ssh-keygen` subprocess). Writes the private + public
    /// files to `dir` and returns `(priv_path, pub_text)`.
    fn write_ephemeral_pub(dir: &std::path::Path, basename: &str) -> (PathBuf, String) {
        use ::ssh_key::rand_core::OsRng;
        let private = ::ssh_key::PrivateKey::random(&mut OsRng, ::ssh_key::Algorithm::Ed25519)
            .expect("generate ed25519");
        let priv_pem = private
            .to_openssh(::ssh_key::LineEnding::LF)
            .expect("to_openssh");
        let pub_line = private.public_key().to_openssh().expect("pub to_openssh");
        let priv_path = dir.join(basename);
        std::fs::write(&priv_path, priv_pem.as_bytes()).expect("write priv");
        std::fs::write(format!("{}.pub", priv_path.display()), pub_line.as_bytes())
            .expect("write pub");
        (priv_path, pub_line)
    }

    #[test]
    fn classify_key_literal_resolves() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let (_key, pub_text) = write_ephemeral_pub(dir.path(), "k1");
        let value = format!("key::{pub_text}");
        let out = classify_signingkey(&value).expect("classify");
        assert!(out.is_some(), "key:: literal should resolve");
    }

    #[test]
    fn classify_bare_sha256_refuses() {
        // 43-char base64 body that happens to be the SHA256 of an empty input.
        let value = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let out = classify_signingkey(value);
        match out {
            Err(ApiError::TrustRegenerateRefused { reason }) => {
                assert!(reason.contains("bare fingerprint"), "reason: {reason}");
            }
            other => panic!("expected refusal; got {other:?}"),
        }
    }

    #[test]
    fn classify_bare_md5_refuses() {
        let value = "MD5:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        let out = classify_signingkey(value);
        assert!(
            matches!(out, Err(ApiError::TrustRegenerateRefused { .. })),
            "expected refusal; got {out:?}",
        );
    }

    #[test]
    fn classify_path_with_unreadable_pubkey_refuses() {
        let value = "/nonexistent/path/to/id_ed25519";
        let out = classify_signingkey(value);
        match out {
            Err(ApiError::TrustRegenerateRefused { reason }) => {
                assert!(reason.contains("neither"), "reason: {reason}");
            }
            other => panic!("expected refusal; got {other:?}"),
        }
    }

    #[test]
    fn classify_path_resolves() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let (key, _pub) = write_ephemeral_pub(dir.path(), "k1");
        let out = classify_signingkey(key.to_str().expect("utf8 path"))
            .expect("path branch should resolve");
        assert!(out.is_some());
    }
}
