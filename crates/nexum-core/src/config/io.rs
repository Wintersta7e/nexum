//! File I/O for `~/.nexum/config.toml`.
//!
//! `write_seed` is called once by `nexum init` to write the initial file.
//! `load` is called on every subsequent nexum invocation.

use std::path::Path;

use super::types::Config;

/// Errors from config I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file already exists and `force` was not set.
    #[error("config already exists at {path}: pass --force to overwrite")]
    AlreadyExists { path: String },
    /// A filesystem error (read, write, create).
    #[error("config I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// TOML parse error (load path).
    #[error("config parse error in {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    /// TOML serialization error (write path).
    #[error("config serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Write the seed `config.toml`.
///
/// # Errors
///
/// Returns `ConfigError::AlreadyExists` if the file exists and `force` is `false`.
/// Returns `ConfigError::Io` on filesystem errors.
/// Returns `ConfigError::Serialize` if the config cannot be serialized.
pub fn write_seed(path: &Path, config: &Config, force: bool) -> Result<(), ConfigError> {
    if path.exists() && !force {
        return Err(ConfigError::AlreadyExists {
            path: path.display().to_string(),
        });
    }
    let toml_str = toml::to_string_pretty(config)?;
    std::fs::write(path, toml_str).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

/// Load `config.toml` from `path`.
///
/// # Errors
///
/// Returns `ConfigError::Io` if the file cannot be read.
/// Returns `ConfigError::Parse` if TOML deserialization fails.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    toml::from_str(&raw).map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        source: e,
    })
}

/// Unconditionally write `cfg` to `path` (TOML pretty-printed). Used by the
/// `nexum project register` write-back path.
///
/// # Errors
///
/// Returns `ConfigError::Serialize` if TOML serialization fails;
/// `ConfigError::Io` if the file cannot be written.
pub fn save(path: &Path, cfg: &Config) -> Result<(), ConfigError> {
    let serialized = toml::to_string_pretty(cfg)?;
    std::fs::write(path, &serialized).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::Config;
    use tempfile::tempdir;

    #[test]
    fn write_and_load_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config::seed();
        write_seed(&path, &cfg, false).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(cfg, loaded);
    }

    #[test]
    fn write_seed_errors_when_file_exists_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config::seed();
        write_seed(&path, &cfg, false).unwrap();
        let err = write_seed(&path, &cfg, false).unwrap_err();
        assert!(matches!(err, ConfigError::AlreadyExists { .. }));
    }

    #[test]
    fn write_seed_with_force_overwrites() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config::seed();
        write_seed(&path, &cfg, false).unwrap();
        write_seed(&path, &cfg, true).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(cfg, loaded);
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        let err = load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn load_invalid_toml_returns_parse_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "not valid toml ][").unwrap();
        let err = load(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }
}

#[cfg(test)]
mod save_tests {
    use super::*;
    use crate::config::types::{Config, RuntimeConfig};
    use tempfile::TempDir;

    #[test]
    fn save_overwrites_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = Config::seed();
        save(&path, &cfg).unwrap();
        cfg.runtime = RuntimeConfig {
            worker_threads: 4,
            max_blocking_threads: 8,
            embed_threads: 2,
        };
        save(&path, &cfg).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let back: Config = toml::from_str(&raw).unwrap();
        assert_eq!(back.runtime.worker_threads, 4);
    }

    #[test]
    fn save_round_trips_projects_table() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = Config::seed();
        let mut entry = toml::Table::new();
        entry.insert("path".into(), toml::Value::String("/path/to/projx".into()));
        cfg.projects
            .insert("projx".into(), toml::Value::Table(entry));
        save(&path, &cfg).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let back: Config = toml::from_str(&raw).unwrap();
        let entry_back = back
            .projects
            .get("projx")
            .and_then(|v| v.as_table())
            .unwrap();
        assert_eq!(
            entry_back.get("path").and_then(|v| v.as_str()),
            Some("/path/to/projx")
        );
    }
}
