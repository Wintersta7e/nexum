//! Fixture builder for synthesizing notebook.git histories with real
//! ssh-ed25519 signed commits. Tests use these to drive the trust
//! materializer through legitimate appends and forbidden mutations without
//! depending on `init::run`.
//!
//! The exposed surface is intentionally small: build keypairs with
//! [`new_keypair`], create a fresh notebook with [`init_notebook`], and
//! append a new `.trust/events.yml` revision with [`commit_events_yml`].
//! Tests own the YAML payload and therefore control the diff classifier's
//! input directly.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_key::PrivateKey;
use ssh_key::rand_core::OsRng;
use tempfile::TempDir;

/// Owned tempdir holding a `~/.nexum`-shaped layout for a single test. The
/// tempdir root is the home directory (`config.toml` and
/// `.bootstrap-fingerprint` live there); the notebook itself lives at
/// `<home>/notebook.git`. Keep the value alive for the duration of the
/// test; dropping it removes the on-disk tree.
pub struct NotebookFixture {
    pub dir: TempDir,
    pub keys: Vec<KeyPair>,
    notebook_path: PathBuf,
}

impl NotebookFixture {
    /// Path of the notebook.git working tree (also the cwd for git
    /// commands).
    pub fn path(&self) -> &Path {
        &self.notebook_path
    }

    /// Home directory containing `config.toml` and the bootstrap pin cache.
    /// Equivalent to `~/.nexum/` in production layout. The materializer
    /// derives this via `notebook_git.parent()`, so tests that exercise the
    /// reanchor verifier write the pin here.
    pub fn home(&self) -> &Path {
        self.dir.path()
    }

    /// Write `config.toml` (with a `[trust.bootstrap]` block pinning
    /// `fingerprint`) and the matching `.bootstrap-fingerprint` cache to the
    /// fixture's home. Tests that exercise the reanchor verifier call this
    /// after rotating the bootstrap so the pin reflects the post-recovery
    /// fingerprint.
    pub fn write_pin(&self, fingerprint: &str, public_openssh: &str) {
        let toml = format!(
            "[trust.bootstrap]\nfingerprint = \"{fp}\"\nkey_type = \"ssh-ed25519\"\npublic_key = \"{pk}\"\nestablished_at = \"2026-01-01T00:00:00Z\"\n",
            fp = fingerprint,
            pk = public_openssh.trim(),
        );
        std::fs::write(self.home().join("config.toml"), toml).expect("write config.toml");
        std::fs::write(
            self.home().join(".bootstrap-fingerprint"),
            format!("{fingerprint}\n"),
        )
        .expect("write .bootstrap-fingerprint");
    }

    /// Remove `config.toml` if present. Tests that exercise the
    /// pin-missing branch of the reanchor verifier call this between
    /// committing the reanchor revision and running `rebuild`.
    pub fn delete_pin(&self) {
        let _ = std::fs::remove_file(self.home().join("config.toml"));
        let _ = std::fs::remove_file(self.home().join(".bootstrap-fingerprint"));
    }
}

/// Generated SSH keypair plus its on-disk private-key path. The private
/// path is inside the fixture's tempdir so it disappears with the test.
#[derive(Clone)]
pub struct KeyPair {
    pub fingerprint: String,
    pub public_openssh: String,
    pub private_path: PathBuf,
}

/// Generate a fresh ed25519 keypair into `workdir/<name>_id`. Returns the
/// `KeyPair` (private path, fingerprint, OpenSSH public string).
pub fn new_keypair(workdir: &Path, name: &str) -> KeyPair {
    let key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
        .expect("ed25519 keygen should not fail");
    let priv_path = workdir.join(format!("{name}_id"));
    let pub_str = key
        .public_key()
        .to_openssh()
        .expect("public-key to_openssh should not fail");
    let priv_str = key
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("private-key to_openssh should not fail");
    std::fs::write(&priv_path, priv_str.as_str()).expect("write private key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 on private key");
    }
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    KeyPair {
        fingerprint,
        public_openssh: pub_str,
        private_path: priv_path,
    }
}

pub fn init_notebook(primary_key: &KeyPair) -> NotebookFixture {
    let dir = tempfile::Builder::new()
        .prefix("nexum-trust-fixture-")
        .tempdir()
        .expect("create notebook tempdir");
    // Nest the notebook under `<home>/notebook.git` so the materializer's
    // `home_for(notebook_git)` derivation (notebook_git.parent()) lands on a
    // directory where tests can write `config.toml` and the bootstrap pin
    // cache. Existing callers still receive a notebook-shaped path from
    // `fixture.path()` and don't need to change.
    let nb = dir.path().join("notebook.git");
    std::fs::create_dir_all(&nb).expect("create notebook subdir");
    run_git(&nb, &["init", "--initial-branch=main", "."]);
    run_git(&nb, &["config", "user.email", "test@example.invalid"]);
    run_git(&nb, &["config", "user.name", "Test"]);
    // SSH signing trio: the materializer reads `%GF` (signer fingerprint)
    // off the resulting commit, which only fires when ALL of these are set:
    // `gpg.format = ssh`, `user.signingkey` pointing at the private key,
    // and `gpg.ssh.allowedSignersFile` (configured below) at an absolute
    // path. Missing any one of them leaves `%GF` empty and the materializer
    // can't extract the signer.
    run_git(&nb, &["config", "gpg.format", "ssh"]);
    run_git(
        &nb,
        &[
            "config",
            "user.signingkey",
            primary_key
                .private_path
                .to_str()
                .expect("private path is valid utf-8"),
        ],
    );
    run_git(&nb, &["config", "commit.gpgsign", "true"]);

    std::fs::create_dir_all(nb.join(".trust")).expect("mkdir .trust");
    let allowed_signers_path = nb.join(".trust/allowed_signers");
    // The leading `*` is a principal wildcard: it accepts any commit author
    // identity, sidestepping the per-email principal that production init
    // would assign. Tests don't carry a stable email for each signer.
    std::fs::write(
        nb.join(".trust/historical_signers"),
        format!("* {}\n", primary_key.public_openssh),
    )
    .expect("write historical_signers");
    std::fs::write(
        &allowed_signers_path,
        format!("* {}\n", primary_key.public_openssh),
    )
    .expect("write allowed_signers");
    std::fs::write(nb.join(".trust/revoked_signers"), "").expect("write revoked_signers");
    run_git(
        &nb,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed_signers_path
                .to_str()
                .expect("allowed_signers path is valid utf-8"),
        ],
    );
    NotebookFixture {
        dir,
        keys: vec![primary_key.clone()],
        notebook_path: nb,
    }
}

/// Write `events_yml` to `.trust/events.yml`, stage it, and create a signed
/// commit using `signing_key`. Each call produces one commit; use `topo_pos
/// = 0` for the bootstrap commit and `1+` for subsequent appends.
pub fn commit_events_yml(nb: &Path, events_yml: &str, signing_key: &Path) {
    std::fs::write(nb.join(".trust/events.yml"), events_yml).expect("write events.yml");
    run_git(nb, &["add", ".trust/events.yml"]);
    run_git_signed(nb, signing_key, "trust: update events");
}

/// Run a plain `git` invocation in `nb`, panicking with the captured stderr
/// on non-zero exit.
pub fn run_git(nb: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(nb)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", nb)
        .env("XDG_CONFIG_HOME", nb.join(".config"))
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Create a signed commit with `key_path` as the SSH signing key. The
/// `-c user.signingkey=...` override means the commit is signed by
/// `key_path` regardless of the repo-level config (useful for forbidden-
/// signer tests).
pub fn run_git_signed(nb: &Path, key_path: &Path, message: &str) {
    let key_str = key_path.to_str().expect("signing key path is valid utf-8");
    let args = [
        "-c",
        &format!("user.signingkey={key_str}"),
        "commit",
        "-S",
        "-m",
        message,
    ];
    let out = Command::new("git")
        .args(args)
        .current_dir(nb)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", nb)
        .env("XDG_CONFIG_HOME", nb.join(".config"))
        .output()
        .unwrap_or_else(|e| panic!("git -S commit failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git -S commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
