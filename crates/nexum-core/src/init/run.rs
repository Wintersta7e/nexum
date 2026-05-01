//! `nexum init` orchestrator — §8 10-step flow.
//!
//! Steps 1–5 (directory tree + git init + config) are implemented here.
//! Steps 6–10 (trust files + signing + verification) are added in Task 11.

use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::{
    init::git_ops::{git_config_signing, git_global_identity, git_init},
    init::hooks::install_pre_merge_commit_hook,
    paths::Paths,
    ssh_key::detect::detect_signing_key,
};

use super::options::{InitError, InitOpts, InitOutcome};

/// Run `nexum init` per §8.
///
/// Acquires `~/.nexum/.lock` before any writes, releases on return.
///
/// On failure after the directory tree has been created (step 4+), the
/// partial `~/.nexum/` tree is removed before returning the error unless
/// `opts.force` is set (in which case the user is assumed to own the tree).
///
/// # Errors
///
/// Returns `InitError::AlreadyInitialized` if `~/.nexum/` exists and
/// `opts.force` is false.
/// Returns other `InitError` variants describing which step failed.
// `opts` is taken by value as the public API contract; fields are accessed
// by move/borrow inside `run_steps`. Task 11 keeps the same signature.
#[allow(clippy::needless_pass_by_value)]
pub fn run(opts: InitOpts) -> Result<InitOutcome, InitError> {
    // Resolve nexum root.
    let root = match &opts.root {
        Some(r) => r.clone(),
        None => Paths::resolve()
            .map(|p| p.home)
            .map_err(|_| InitError::Io {
                path: "~/.nexum".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "could not resolve nexum home",
                ),
            })?,
    };

    // ── Step 1: Refuse if root exists (require --force to wipe) ──────────────
    if root.exists() {
        if opts.force {
            std::fs::remove_dir_all(&root).map_err(|e| InitError::Io {
                path: root.display().to_string(),
                source: e,
            })?;
        } else {
            return Err(InitError::AlreadyInitialized {
                path: root.display().to_string(),
            });
        }
    }

    // Create root first so we can acquire the lock.
    std::fs::create_dir_all(&root).map_err(|e| InitError::Io {
        path: root.display().to_string(),
        source: e,
    })?;

    // Acquire writer lock (§3.5 writer task pattern).
    let lock_path = root.join(".lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| InitError::LockAcquire {
            path: lock_path.display().to_string(),
            source: e,
        })?;
    lock_file
        .try_lock_exclusive()
        .map_err(|e| InitError::LockAcquire {
            path: lock_path.display().to_string(),
            source: e,
        })?;

    // Run the init steps; roll back on failure.
    match run_steps(&root, &opts) {
        Ok(outcome) => {
            lock_file.unlock().ok();
            Ok(outcome)
        }
        Err(e) => {
            lock_file.unlock().ok();
            // Best-effort rollback: remove the partial root tree.
            let _ = std::fs::remove_dir_all(&root);
            Err(e)
        }
    }
}

fn run_steps(root: &Path, opts: &InitOpts) -> Result<InitOutcome, InitError> {
    let paths = Paths::with_home(root.to_owned());

    // ── Step 2: Detect SSH signing key ────────────────────────────────────────
    // Resolve HOME from env — independent of opts.root. SSH keys live in
    // $HOME/.ssh/, not in the nexum root (which may be overridden via --root).
    let ssh_home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(InitError::HomeNotFound)?;
    let key = detect_signing_key(&ssh_home, opts.ssh_key.as_deref())?;

    // ── Steps 3 & 4: mkdir tree ───────────────────────────────────────────────
    for dir in [
        &paths.notebook_git,
        &paths.models,
        &paths.projects,
        &paths.logs,
    ] {
        std::fs::create_dir_all(dir).map_err(|e| InitError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
    }

    // ── Step 5: git init + config ─────────────────────────────────────────────
    git_init(&paths.notebook_git)?;
    install_pre_merge_commit_hook(&paths.notebook_git)?;

    let (user_name, user_email) = git_global_identity()?;

    // allowed_signers path (written in step 6; pass the final path now so git
    // config is correct from the start).
    let trust_dir = paths.notebook_git.join(".trust");
    let allowed_signers_path = trust_dir.join("allowed_signers");

    git_config_signing(
        &paths.notebook_git,
        &key.private_key_path,
        &allowed_signers_path,
        &user_name,
        &user_email,
    )?;

    // Steps 6–10 implemented in Task 11.
    run_steps_6_to_10(root, &paths, &key, &trust_dir)
}

fn run_steps_6_to_10(
    _root: &Path,
    _paths: &Paths,
    _key: &crate::ssh_key::detect::DetectedKey,
    _trust_dir: &Path,
) -> Result<InitOutcome, InitError> {
    // Replaced by Task 11.
    unimplemented!("init steps 6-10 — Task 11")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};
    use tempfile::tempdir;

    // Retained for Task 11 tests; unused in the single T10 test.
    #[allow(dead_code)]
    fn write_ephemeral_keypair(dir: &Path) -> PathBuf {
        use ssh_key::rand_core::OsRng;
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let pub_line = private.public_key().to_openssh().unwrap();
        let priv_path = dir.join("id_ed25519");
        let pub_path = dir.join("id_ed25519.pub");
        std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&pub_path, pub_line).unwrap();
        priv_path
    }

    #[test]
    fn already_initialized_without_force_returns_error() {
        let home = tempdir().unwrap();
        let root = home.path().join(".nexum");
        std::fs::create_dir_all(&root).unwrap();
        let err = run(InitOpts {
            ssh_key: None,
            root: Some(root),
            force: false,
        })
        .unwrap_err();
        assert!(matches!(err, InitError::AlreadyInitialized { .. }));
    }
    // NOTE: the partial-flow test (steps 1-5 only) was intentionally omitted.
    // `run_steps_6_to_10` is `unimplemented!()` in this task, so any test
    // that calls `run(...)` with a valid key would panic rather than return
    // `Err`, making `unwrap_err()` unreachable. Full coverage of the
    // steps-1-5 path is provided by Task 11's `successful_init_*` tests once
    // the complete implementation lands.
}
