//! Types for the `nexum init` orchestrator.

use std::path::PathBuf;

/// Options for `nexum init`, populated from CLI flags.
#[derive(Debug, Clone)]
pub struct InitOpts {
    /// Override path to the SSH private key.
    pub ssh_key: Option<PathBuf>,
    /// Override the nexum root directory (default: `~/.nexum/`).
    pub root: Option<PathBuf>,
    /// Wipe and reinitialize if `~/.nexum/` already exists.
    pub force: bool,
}

/// Successful outcome of `nexum init`.
#[derive(Debug, Clone)]
pub struct InitOutcome {
    /// SHA of the bootstrap commit.
    pub bootstrap_commit_sha: String,
    /// `SHA256:<base64>` fingerprint of the bootstrap signing key.
    pub fingerprint: String,
    /// Absolute path to the nexum root that was initialized.
    pub root: PathBuf,
}

/// Errors from the `nexum init` flow.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// `~/.nexum/` already exists and `--force` was not passed.
    #[error("nexum home already exists at {path}: pass --force to reinitialize")]
    AlreadyInitialized { path: String },
    /// SSH key detection or loading failed.
    #[error("SSH key error: {0}")]
    SshKey(#[from] crate::ssh_key::detect::SshKeyError),
    /// Filesystem operation failed.
    #[error("filesystem error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A `git` shell-out failed.
    #[error("git command failed ({cmd}): {stderr}")]
    Git { cmd: String, stderr: String },
    /// Trust I/O or projection failed.
    #[error("trust error: {0}")]
    Trust(#[from] crate::trust::events::TrustError),
    /// Config I/O failed.
    #[error("config error: {0}")]
    Config(#[from] crate::config::io::ConfigError),
    /// Bootstrap commit verification failed.
    #[error("bootstrap commit verification failed: {detail}")]
    BootstrapVerifyFailed { detail: String },
    /// Could not acquire the writer lock.
    #[error("could not acquire nexum writer lock at {path}: {source}")]
    LockAcquire {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `$HOME` / `USERPROFILE` not set; cannot locate SSH keys.
    #[error("cannot determine home directory ($HOME / USERPROFILE not set)")]
    HomeNotFound,
}
