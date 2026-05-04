//! Shell-out git helpers for `nexum init`.
//!
//! Production signing requires `git -c gpg.format=ssh …` because `git2` has
//! no SSH-signing path (confirmed by spike S6). All helpers use
//! `std::process::Command` and capture stdout/stderr for diagnostic errors.

use std::{
    path::Path,
    process::{Command, Output},
};

use super::options::InitError;

fn run_git(repo: &Path, args: &[&str]) -> Result<Output, InitError> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .map_err(|e| InitError::Io {
            path: repo.display().to_string(),
            source: e,
        })?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(InitError::Git {
            cmd: format!("git {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        })
    }
}

/// Run `git init` in `repo_path`.
///
/// # Errors
///
/// Returns `InitError::Git` if the command exits non-zero.
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_init(repo_path: &Path) -> Result<(), InitError> {
    run_git(repo_path, &["init"])?;
    Ok(())
}

/// Set the git config values required for SSH commit signing.
///
/// Configures `gpg.format`, `user.signingkey`, `user.email`, `user.name`,
/// `commit.gpgsign`, `tag.gpgsign`, and `gpg.ssh.allowedSignersFile`.
///
/// `private_key_path` must be an absolute path (§8 step 5 note — bare
/// fingerprints do not work with git's SSH backend).
///
/// # Errors
///
/// Returns `InitError::Git` on any failing git-config call.
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_config_signing(
    repo_path: &Path,
    private_key_path: &Path,
    allowed_signers_file: &Path,
    user_name: &str,
    user_email: &str,
) -> Result<(), InitError> {
    let key_path = private_key_path.display().to_string();
    let signers_path = allowed_signers_file.display().to_string();

    let settings: &[(&str, &str)] = &[
        ("gpg.format", "ssh"),
        ("user.signingkey", &key_path),
        ("user.email", user_email),
        ("user.name", user_name),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
        ("gpg.ssh.allowedSignersFile", &signers_path),
    ];

    for (key, value) in settings {
        run_git(repo_path, &["config", key, value])?;
    }
    Ok(())
}

/// Stage `files` and create a signed commit with `message`.
///
/// Requires that `git_config_signing` has already been called for `repo_path`
/// (i.e. `commit.gpgsign = true` and `gpg.format = ssh` are set).
///
/// # Errors
///
/// Returns `InitError::Git` on add or commit failure.
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_commit_signed(
    repo_path: &Path,
    files: &[&Path],
    message: &str,
) -> Result<String, InitError> {
    // Stage files.
    let file_strs: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    let mut add_args = vec!["add"];
    let strs: Vec<&str> = file_strs.iter().map(String::as_str).collect();
    add_args.extend_from_slice(&strs);
    run_git(repo_path, &add_args)?;

    // Commit (gpg.format=ssh and commit.gpgsign=true already set via git_config_signing).
    run_git(repo_path, &["commit", "-m", message])?;

    // Return HEAD sha.
    let out = run_git(repo_path, &["rev-parse", "HEAD"])?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Verify `commit` using `historical_signers` (the historical-verification redirect).
///
/// Invokes:
/// ```text
/// git -c gpg.format=ssh \
///     -c gpg.ssh.allowedSignersFile=<historical_signers> \
///     verify-commit <commit>
/// ```
///
/// Returns `Ok(())` on exit 0.
///
/// # Errors
///
/// Returns `InitError::BootstrapVerifyFailed` if verification fails (non-zero exit).
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_verify_commit_with_signers(
    repo_path: &Path,
    commit: &str,
    historical_signers: &Path,
) -> Result<(), InitError> {
    let signers_path = historical_signers.display().to_string();
    let out = Command::new("git")
        .current_dir(repo_path)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("gpg.ssh.allowedSignersFile={signers_path}"),
            "verify-commit",
            commit,
        ])
        .output()
        .map_err(|e| InitError::Io {
            path: repo_path.display().to_string(),
            source: e,
        })?;

    if out.status.success() {
        Ok(())
    } else {
        Err(InitError::BootstrapVerifyFailed {
            detail: format!(
                "git verify-commit exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}

/// Extra provenance captured alongside a successful verify-commit. Today
/// just the SSH signer fingerprint via `git log -1 --format=%GF`; future
/// fields (e.g., commit-time pin, key-rotation marker) can be added
/// without disrupting callers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyDetails {
    /// Signer fingerprint as reported by `git log --format=%GF`. `None`
    /// when git could not extract a fingerprint (e.g., legacy or
    /// unusually-formatted signature) — verification still succeeded if
    /// this struct is returned.
    pub signer_fingerprint: Option<String>,
}

/// Verify `commit` against `historical_signers` and capture the signer
/// fingerprint on success. Companion to [`git_verify_commit_with_signers`]
/// for callers that need the verifier provenance — leaves the simpler
/// boolean form intact for callers that only check the exit code.
///
/// On a successful verify, runs `git log -1 --format=%GF <commit>` to
/// surface the fingerprint git's SSH backend matched. The fingerprint is
/// optional in [`VerifyDetails`] because some signature shapes do not
/// produce one, and the verifier's "signature is valid" answer must not
/// hinge on whether git can also surface the fingerprint.
///
/// # Errors
///
/// Returns `InitError::BootstrapVerifyFailed` if verification fails.
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_verify_commit_with_signers_and_details(
    repo_path: &Path,
    commit: &str,
    historical_signers: &Path,
) -> Result<VerifyDetails, InitError> {
    git_verify_commit_with_signers(repo_path, commit, historical_signers)?;

    let log_out = Command::new("git")
        .current_dir(repo_path)
        .args(["log", "-1", "--format=%GF", commit])
        .output()
        .map_err(|e| InitError::Io {
            path: repo_path.display().to_string(),
            source: e,
        })?;

    let signer_fingerprint = if log_out.status.success() {
        let raw = String::from_utf8_lossy(&log_out.stdout).trim().to_owned();
        if raw.is_empty() { None } else { Some(raw) }
    } else {
        // verify-commit already passed, so a missing fingerprint here is
        // a soft signal — log nothing and return None rather than
        // promoting it to a failure.
        None
    };

    Ok(VerifyDetails { signer_fingerprint })
}

/// Read `user.name` and `user.email` from the global git config.
///
/// Returns `("", "")` if the values are not set (init will use empty strings
/// for the repository-local git config; user can fix later via `git config`).
///
/// # Errors
///
/// Returns `InitError::Io` if the git binary cannot be spawned.
pub fn git_global_identity() -> Result<(String, String), InitError> {
    fn read_global(key: &str) -> String {
        Command::new("git")
            .args(["config", "--global", key])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    }
    Ok((read_global("user.name"), read_global("user.email")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};
    use tempfile::tempdir;

    fn write_ephemeral_keypair(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use ssh_key::rand_core::OsRng;
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let pub_line = private.public_key().to_openssh().unwrap();
        let priv_path = dir.join("id_ed25519");
        let pub_path = dir.join("id_ed25519.pub");
        std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
        // Set mode 0600 (Unix) so git does not reject the private key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&pub_path, &pub_line).unwrap();
        (priv_path, pub_path)
    }

    /// Build an OpenSSH `allowed_signers` line from a public key blob.
    fn allowed_signers_content(pub_line: &str) -> String {
        format!("* {pub_line}\n")
    }

    #[test]
    fn git_init_creates_git_dir() {
        let dir = tempdir().unwrap();
        git_init(dir.path()).unwrap();
        assert!(dir.path().join(".git").exists());
    }

    #[test]
    fn git_config_signing_sets_gpg_format() {
        let dir = tempdir().unwrap();
        git_init(dir.path()).unwrap();
        let key_dir = tempdir().unwrap();
        let (priv_path, _) = write_ephemeral_keypair(key_dir.path());
        let signers = dir.path().join("allowed_signers");
        std::fs::write(&signers, "").unwrap();
        git_config_signing(
            dir.path(),
            &priv_path,
            &signers,
            "Test User",
            "test@example.invalid",
        )
        .unwrap();

        let out = Command::new("git")
            .current_dir(dir.path())
            .args(["config", "gpg.format"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ssh");
    }

    #[test]
    fn git_commit_signed_and_verify_roundtrip() {
        let repo = tempdir().unwrap();
        let key_dir = tempdir().unwrap();
        let (priv_path, pub_path) = write_ephemeral_keypair(key_dir.path());
        let pub_line = std::fs::read_to_string(&pub_path).unwrap();
        let pub_line = pub_line.trim();

        git_init(repo.path()).unwrap();

        // Write allowed_signers before config so git can verify.
        let trust_dir = repo.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).unwrap();
        let historical = trust_dir.join("historical_signers");
        std::fs::write(&historical, allowed_signers_content(pub_line)).unwrap();
        let allowed = trust_dir.join("allowed_signers");
        std::fs::write(&allowed, allowed_signers_content(pub_line)).unwrap();

        git_config_signing(
            repo.path(),
            &priv_path,
            &allowed,
            "Test User",
            "test@example.invalid",
        )
        .unwrap();

        // Create a file to commit.
        let test_file = repo.path().join("META.yml");
        std::fs::write(&test_file, "schema_version: 1\n").unwrap();

        let sha = git_commit_signed(
            repo.path(),
            &[Path::new("META.yml")],
            "bootstrap: initial signed commit",
        )
        .unwrap();
        assert_eq!(sha.len(), 40, "expected 40-char SHA-1 commit hash");

        // Verify via historical_signers redirect.
        git_verify_commit_with_signers(repo.path(), "HEAD", &historical).unwrap();
    }

    #[test]
    fn verify_fails_when_signer_not_in_signers_file() {
        let repo = tempdir().unwrap();
        let key_dir = tempdir().unwrap();
        let (priv_path, pub_path) = write_ephemeral_keypair(key_dir.path());
        let pub_line = std::fs::read_to_string(&pub_path).unwrap();
        let pub_line = pub_line.trim();

        git_init(repo.path()).unwrap();
        let trust_dir = repo.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).unwrap();
        let allowed = trust_dir.join("allowed_signers");
        std::fs::write(&allowed, allowed_signers_content(pub_line)).unwrap();

        git_config_signing(
            repo.path(),
            &priv_path,
            &allowed,
            "Test User",
            "test@example.invalid",
        )
        .unwrap();

        let test_file = repo.path().join("f.txt");
        std::fs::write(&test_file, "x").unwrap();
        git_commit_signed(repo.path(), &[Path::new("f.txt")], "test").unwrap();

        // Use an empty signers file — verification must fail.
        let empty_signers = trust_dir.join("empty_signers");
        std::fs::write(&empty_signers, "").unwrap();
        let result = git_verify_commit_with_signers(repo.path(), "HEAD", &empty_signers);
        assert!(
            matches!(result, Err(InitError::BootstrapVerifyFailed { .. })),
            "expected verification failure with empty signers file"
        );
    }
}
