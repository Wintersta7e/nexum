//! Shared test utilities for nexum-cli integration tests.
//! Each integration-test binary may import only the subset it needs;
//! `#[allow(dead_code)]` is applied to silence per-binary "unused" warnings.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

pub fn nexum_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nexum"))
}

/// Self-contained nexum home for `--json` error-envelope tests. Owns the
/// backing temp dir; dropping the value cleans up. The `path()` accessor
/// returns the value to set as `NEXUM_HOME` on a subprocess.
pub struct TestHome {
    _root: TempDir,
    nexum_home: PathBuf,
}

impl TestHome {
    /// Allocate a temp dir but skip `nexum init`. Useful for asserting
    /// `NOT_INITIALIZED` errors.
    pub fn uninitialized() -> Self {
        let root = TempDir::new().expect("tempdir for TestHome");
        let nexum_home = root.path().join(".nexum");
        Self {
            _root: root,
            nexum_home,
        }
    }

    /// Initialize a nexum home (notebook.git + config.toml + signed
    /// bootstrap) but do NOT run `nexum index`. Useful for asserting
    /// `NOT_INDEXED` errors with a fully-realized home directory.
    pub fn initialized_no_index() -> Self {
        let root = TempDir::new().expect("tempdir for TestHome");
        let nexum_home = root.path().join(".nexum");
        let ssh_home = root.path().join("ssh-home");
        std::fs::create_dir_all(ssh_home.join(".ssh")).expect("mkdir ssh-home/.ssh");
        let key_path = write_ephemeral_keypair(&ssh_home.join(".ssh"));
        let out = run_nexum(
            &nexum_home,
            &ssh_home,
            &["init", "--yes", "--ssh-key", key_path.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "TestHome init failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Self {
            _root: root,
            nexum_home,
        }
    }

    pub fn path(&self) -> &Path {
        &self.nexum_home
    }
}

/// Generate a fresh ed25519 keypair into `dir/id_ed25519{,.pub}`. Returns
/// the private key path. Mirrors the `nexum-core::tests::common` helper —
/// duplicated here because `tests/common/` cannot cross crate boundaries.
pub fn write_ephemeral_keypair(dir: &Path) -> PathBuf {
    use ssh_key::rand_core::OsRng;
    let private = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let pub_line = private.public_key().to_openssh().unwrap();
    let priv_path = dir.join("id_ed25519");
    std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(dir.join("id_ed25519.pub"), pub_line).unwrap();
    priv_path
}

/// Spawn the `nexum` binary with `NEXUM_HOME` and `HOME` redirected to
/// per-test temp dirs. The four `GIT_*` env vars override git's normal
/// `user.name`/`user.email` config lookup, which would otherwise return
/// empty strings under a fresh `HOME` and break any subcommand that
/// commits (e.g. `init`'s bootstrap commit). The existing `init_cli.rs`
/// test predates this hardening and relies on the developer's real
/// `~/.gitconfig`; this helper makes the binary CI-portable.
pub fn run_nexum(home: &Path, ssh_home: &Path, args: &[&str]) -> Output {
    Command::new(nexum_bin())
        .args(args)
        .env("NEXUM_HOME", home)
        .env("HOME", ssh_home)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("nexum binary exec failed")
}

/// Write a local-adapter-format YAML record at `home/notebook.git/<sub>/<id>.yml`.
/// Mirrors the equivalent helper in `nexum-core::tests::common`.
pub fn write_local_yaml(home: &Path, sub: &str, id: &str, body: &str) -> PathBuf {
    let notebook_git = home.join("notebook.git");
    let p = notebook_git.join(sub).join(format!("{id}.yml"));
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all for local yaml");
    }
    let kind = match sub {
        "decisions" => "decision",
        "recommendations" => "recommendation",
        "failures" => "failure",
        _ => "untyped",
    };
    std::fs::write(
        &p,
        format!(
            "schema_version: 1\nid: {id}\nrecord_type: {kind}\ntitle: {id}\nbody: |\n  {body}\nproject_id: example\ntags: []\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\nconfidence: high\noutcome: working\n"
        ),
    )
    .expect("write local yaml");
    p
}
