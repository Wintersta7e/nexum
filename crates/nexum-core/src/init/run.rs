//! `nexum init` orchestrator — §8 10-step flow.

use std::path::{Path, PathBuf};

use chrono::Utc;
use fs2::FileExt;

use crate::{
    config::{
        io::write_seed as write_config,
        types::{BootstrapConfig, Config},
    },
    init::git_ops::{
        git_commit_signed, git_config_signing, git_global_identity, git_init,
        git_verify_commit_with_signers,
    },
    init::hooks::install_pre_merge_commit_hook,
    paths::Paths,
    ssh_key::detect::{detect_signing_key, DetectedKey},
    trust::{events::write_seed_yaml, regenerate::regenerate_files},
};

use super::options::{InitError, InitOpts, InitOutcome};

/// Run `nexum init` per §8.
///
/// Acquires `<root>/.lock` before any writes, releases on return.
/// On failure, removes the partial `<root>/` tree (best-effort).
///
/// # Errors
///
/// Returns `InitError::AlreadyInitialized` if root exists and `force` is false.
// `opts` is taken by value as the public API contract — callers construct InitOpts
// and pass ownership; the fields are moved/borrowed inside run_all_steps.
#[allow(clippy::needless_pass_by_value)]
pub fn run(opts: InitOpts) -> Result<InitOutcome, InitError> {
    let root = resolve_root(&opts)?;

    // Step 1: refuse if root exists without --force.
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

    std::fs::create_dir_all(&root).map_err(|e| InitError::Io {
        path: root.display().to_string(),
        source: e,
    })?;

    // Acquire writer lock (§3.5).
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

    match run_all_steps(&root, &opts) {
        Ok(outcome) => {
            lock_file.unlock().ok();
            Ok(outcome)
        }
        Err(e) => {
            lock_file.unlock().ok();
            let _ = std::fs::remove_dir_all(&root);
            Err(e)
        }
    }
}

fn resolve_root(opts: &InitOpts) -> Result<PathBuf, InitError> {
    match &opts.root {
        Some(r) => Ok(r.clone()),
        None => Paths::resolve().map(|p| p.home).map_err(|_| InitError::Io {
            path: "~/.nexum".into(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not resolve nexum home",
            ),
        }),
    }
}

fn run_all_steps(root: &Path, opts: &InitOpts) -> Result<InitOutcome, InitError> {
    let paths = Paths::with_home(root.to_owned());

    // ── Step 2: Detect SSH signing key ────────────────────────────────────────
    // Resolve HOME from env — independent of opts.root. SSH keys live in
    // $HOME/.ssh/, not in the nexum root (which may be overridden via --root).
    let ssh_home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(InitError::HomeNotFound)?;
    let key = detect_signing_key(&ssh_home, opts.ssh_key.as_deref())?;

    // ── Steps 3–4: mkdir tree ─────────────────────────────────────────────────
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
    let trust_dir = paths.notebook_git.join(".trust");
    let allowed_signers_path = trust_dir.join("allowed_signers");

    git_config_signing(
        &paths.notebook_git,
        &key.private_key_path,
        &allowed_signers_path,
        &user_name,
        &user_email,
    )?;

    // Steps 6–10 extracted into helpers to keep complexity bounded.
    write_trust_files(&trust_dir, &key)?;
    write_config_files(&paths, &key)?;
    let sha = write_bootstrap_commit(&paths.notebook_git, &trust_dir)?;

    Ok(InitOutcome {
        bootstrap_commit_sha: sha,
        fingerprint: key.fingerprint,
        root: root.to_owned(),
    })
}

/// Step 6: write `events.yml` seed and regenerate the three derived signer files.
fn write_trust_files(trust_dir: &Path, key: &DetectedKey) -> Result<(), InitError> {
    std::fs::create_dir_all(trust_dir).map_err(|e| InitError::Io {
        path: trust_dir.display().to_string(),
        source: e,
    })?;

    let events_path = trust_dir.join("events.yml");
    write_seed_yaml(&events_path, &key.fingerprint, &key.public_key_blob)?;
    regenerate_files(&events_path, trust_dir)?;
    Ok(())
}

/// Steps 7–8: write seed `config.toml` and `.bootstrap-fingerprint` pin.
fn write_config_files(paths: &Paths, key: &DetectedKey) -> Result<(), InitError> {
    // Step 7: seed config.toml with trust.bootstrap populated.
    let now = Utc::now().to_rfc3339();
    let mut cfg = Config::seed();
    cfg.trust.bootstrap = BootstrapConfig {
        fingerprint: key.fingerprint.clone(),
        key_type: key.key_type.clone(),
        public_key: key.public_key_blob.clone(),
        established_at: now,
        note: "Bootstrap key — do not delete or rotate without `nexum keys recover --reanchor`"
            .into(),
    };
    write_config(&paths.config, &cfg, false)?;

    // Step 8: .bootstrap-fingerprint sibling pin (fingerprint string only; no YAML wrapper).
    std::fs::write(&paths.bootstrap_pin, &key.fingerprint).map_err(|e| InitError::Io {
        path: paths.bootstrap_pin.display().to_string(),
        source: e,
    })?;

    Ok(())
}

/// Step 9: write `META.yml`, make signed bootstrap commit, verify on the spot.
fn write_bootstrap_commit(notebook_git: &Path, trust_dir: &Path) -> Result<String, InitError> {
    let now = Utc::now().to_rfc3339();
    let meta_path = notebook_git.join("META.yml");
    let meta_content = format!("schema_version: 1\ninit_at: {now}\n");
    std::fs::write(&meta_path, meta_content).map_err(|e| InitError::Io {
        path: meta_path.display().to_string(),
        source: e,
    })?;

    let commit_files: &[&Path] = &[
        Path::new("META.yml"),
        Path::new(".trust/events.yml"),
        Path::new(".trust/historical_signers"),
        Path::new(".trust/allowed_signers"),
        Path::new(".trust/revoked_signers"),
    ];

    let sha = git_commit_signed(
        notebook_git,
        commit_files,
        "bootstrap: initial signed commit",
    )?;

    // Verify on the spot via historical-signers redirect (§8 step 9a).
    // §8 step 9b (trust_events view row check) is deferred to Phase 3 because
    // index.db does not yet exist at Phase 2 init time.
    let historical_signers = trust_dir.join("historical_signers");
    git_verify_commit_with_signers(notebook_git, "HEAD", &historical_signers)?;

    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};
    use tempfile::tempdir;

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

    /// Run a full init into a fresh tempdir, returning `(root, result)`.
    ///
    /// Uses an ephemeral ed25519 key stored in a separate tempdir so it is
    /// never committed to the repository.
    fn run_init(root_parent: &Path) -> (PathBuf, Result<InitOutcome, InitError>) {
        let root = root_parent.join(".nexum");
        let key_dir = tempdir().unwrap();
        let priv_path = write_ephemeral_keypair(key_dir.path());
        let result = run(InitOpts {
            ssh_key: Some(priv_path),
            root: Some(root.clone()),
            force: false,
        });
        (root, result)
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

    #[test]
    fn successful_init_returns_sha_and_fingerprint() {
        let home = tempdir().unwrap();
        let (_root, result) = run_init(home.path());
        let outcome = result.expect("init must succeed");
        assert_eq!(outcome.bootstrap_commit_sha.len(), 40);
        assert!(outcome.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn successful_init_creates_all_expected_files() {
        let home = tempdir().unwrap();
        let (root, result) = run_init(home.path());
        result.expect("init must succeed");
        let nb = root.join("notebook.git");
        assert!(nb.join(".trust").join("events.yml").exists());
        assert!(nb.join(".trust").join("historical_signers").exists());
        assert!(nb.join(".trust").join("allowed_signers").exists());
        assert!(nb.join(".trust").join("revoked_signers").exists());
        assert!(nb.join("META.yml").exists());
        assert!(root.join("config.toml").exists());
        assert!(root.join(".bootstrap-fingerprint").exists());
    }

    #[test]
    fn bootstrap_fingerprint_pin_matches_config() {
        let home = tempdir().unwrap();
        let (root, result) = run_init(home.path());
        result.expect("init must succeed");
        let pin = std::fs::read_to_string(root.join(".bootstrap-fingerprint")).unwrap();
        let cfg_raw = std::fs::read_to_string(root.join("config.toml")).unwrap();
        let cfg: Config = toml::from_str(&cfg_raw).unwrap();
        assert_eq!(pin.trim(), cfg.trust.bootstrap.fingerprint);
    }

    #[test]
    fn force_flag_wipes_and_reinitializes() {
        let home = tempdir().unwrap();
        let root = home.path().join(".nexum");
        std::fs::create_dir_all(&root).unwrap();
        let key_dir = tempdir().unwrap();
        let priv_path = write_ephemeral_keypair(key_dir.path());
        let result = run(InitOpts {
            ssh_key: Some(priv_path),
            root: Some(root.clone()),
            force: true,
        });
        assert!(result.is_ok(), "force init must succeed");
    }

    #[test]
    fn failure_rolls_back_partial_tree() {
        // Simulate a bad SSH key path to trigger failure after step 1 mkdir.
        let home = tempdir().unwrap();
        let root = home.path().join(".nexum");
        let bad_key = home.path().join("nonexistent_key");
        // Write the private-key placeholder but NOT the .pub file.
        std::fs::write(&bad_key, "PLACEHOLDER").unwrap();
        let _err = run(InitOpts {
            ssh_key: Some(bad_key),
            root: Some(root.clone()),
            force: false,
        });
        assert!(
            !root.exists(),
            "rollback must remove partial tree on failure"
        );
    }
}
