//! Bootstrap pin reader.
//!
//! `~/.nexum/config.toml` `[trust.bootstrap]` is the authoritative source.
//! `~/.nexum/.bootstrap-fingerprint` is a cache file used by tooling that
//! reads the pin without parsing TOML. On inconsistency the reader trusts
//! `config.toml` and surfaces a `cache_inconsistent` flag for the doctor
//! flow to act on (rewriting the cache).

use std::path::Path;

use serde::Deserialize;

use crate::trust::events::TrustError;

/// Bootstrap key pin loaded from `~/.nexum/config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPin {
    /// SSH key fingerprint (e.g. `SHA256:abc...`).
    pub fingerprint: String,
    /// SSH key type (e.g. `ssh-ed25519`).
    pub key_type: String,
    /// SSH public key line as stored in `config.toml`.
    pub public_key: String,
    /// RFC3339 timestamp recorded when the pin was first established.
    pub established_at: Option<String>,
    /// True if `.bootstrap-fingerprint` cache file is missing or differs from
    /// `config.toml`. Caller should re-emit a warning via `nexum doctor`.
    pub cache_inconsistent: bool,
}

#[derive(Deserialize)]
struct ConfigToml {
    trust: Option<TrustSection>,
}

#[derive(Deserialize)]
struct TrustSection {
    bootstrap: Option<BootstrapSection>,
}

#[derive(Deserialize)]
struct BootstrapSection {
    fingerprint: String,
    #[serde(default)]
    key_type: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    established_at: Option<String>,
}

/// Read the bootstrap pin from `home/config.toml` and validate against the
/// `home/.bootstrap-fingerprint` cache file.
///
/// `config.toml` is authoritative. The returned `cache_inconsistent` flag is
/// `true` when the cache file is missing or its trimmed contents differ from
/// the fingerprint in `config.toml`; doctor rewrites the cache to match.
///
/// # Errors
///
/// - `TrustError::Io` when `config.toml` cannot be read.
/// - `TrustError::ConfigParse` when `config.toml` is not valid TOML.
/// - `TrustError::BootstrapPinMissing` when `[trust.bootstrap]` is absent.
pub fn read_pin(home: &Path) -> Result<BootstrapPin, TrustError> {
    let config_path = home.join("config.toml");
    let cache_path = home.join(".bootstrap-fingerprint");

    let config_str = std::fs::read_to_string(&config_path).map_err(|e| TrustError::Io {
        path: config_path.display().to_string(),
        source: e,
    })?;
    let config: ConfigToml = toml::from_str(&config_str).map_err(|e| TrustError::ConfigParse {
        path: config_path.display().to_string(),
        cause: e.to_string(),
    })?;
    let bootstrap = config
        .trust
        .and_then(|t| t.bootstrap)
        .ok_or(TrustError::BootstrapPinMissing)?;

    let cache_inconsistent = match std::fs::read_to_string(&cache_path) {
        Ok(s) => s.trim() != bootstrap.fingerprint,
        // Missing cache → flag as inconsistent (doctor rewrites it).
        Err(_) => true,
    };

    Ok(BootstrapPin {
        fingerprint: bootstrap.fingerprint,
        key_type: bootstrap.key_type,
        public_key: bootstrap.public_key,
        established_at: bootstrap.established_at,
        cache_inconsistent,
    })
}

#[cfg(test)]
mod tests {
    use super::{TrustError, read_pin};
    use std::path::Path;
    use tempfile::tempdir;

    fn write(home: &Path, name: &str, body: &str) {
        std::fs::write(home.join(name), body).unwrap();
    }

    #[test]
    fn read_pin_returns_fingerprint_when_cache_matches() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "config.toml",
            "[trust.bootstrap]\n\
             fingerprint = \"SHA256:abc\"\n\
             key_type = \"ssh-ed25519\"\n\
             public_key = \"ssh-ed25519 AAAA test\"\n",
        );
        write(dir.path(), ".bootstrap-fingerprint", "SHA256:abc\n");
        let pin = read_pin(dir.path()).unwrap();
        assert_eq!(pin.fingerprint, "SHA256:abc");
        assert!(!pin.cache_inconsistent);
    }

    #[test]
    fn read_pin_flags_inconsistent_when_cache_missing() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "config.toml",
            "[trust.bootstrap]\nfingerprint = \"SHA256:abc\"\n",
        );
        let pin = read_pin(dir.path()).unwrap();
        assert!(pin.cache_inconsistent);
    }

    #[test]
    fn read_pin_flags_inconsistent_when_cache_differs() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            "config.toml",
            "[trust.bootstrap]\nfingerprint = \"SHA256:abc\"\n",
        );
        write(dir.path(), ".bootstrap-fingerprint", "SHA256:xyz\n");
        let pin = read_pin(dir.path()).unwrap();
        assert!(pin.cache_inconsistent);
    }

    #[test]
    fn read_pin_errors_when_config_missing() {
        let dir = tempdir().unwrap();
        assert!(matches!(read_pin(dir.path()), Err(TrustError::Io { .. })));
    }

    #[test]
    fn read_pin_errors_when_bootstrap_section_absent() {
        let dir = tempdir().unwrap();
        write(dir.path(), "config.toml", "[other]\nfoo = 1\n");
        assert!(matches!(
            read_pin(dir.path()),
            Err(TrustError::BootstrapPinMissing)
        ));
    }
}
