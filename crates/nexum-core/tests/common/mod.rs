// Shared test utilities for nexum-core integration tests. Each test gets its own
// `NexumTestHome` (isolated temp dir, auto-cleaned on drop). Build a Paths value
// from it with `home.paths()` and pass that into the code under test.

use nexum_core::paths::Paths;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Generate a fresh ed25519 keypair into `dir/id_ed25519{,.pub}`. Returns the
/// private key path. Tests use this to seed `init::run` with `--ssh-key`.
#[allow(dead_code)]
pub fn write_ephemeral_keypair(dir: &Path) -> PathBuf {
    use ssh_key::rand_core::OsRng;
    let private = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
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

pub struct NexumTestHome {
    tmp: TempDir,
}

impl NexumTestHome {
    pub fn new() -> std::io::Result<Self> {
        let tmp = tempfile::Builder::new()
            .prefix("nexum-test-home-")
            .tempdir()?;
        Ok(Self { tmp })
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    // Used by other integration test binaries (e.g. index_schema, paths_smoke).
    // Dead-code lint fires per-binary for test binaries that only use `path()`.
    #[allow(dead_code)]
    pub fn paths(&self) -> Paths {
        Paths::with_home(self.path().to_owned())
    }
}

impl Default for NexumTestHome {
    fn default() -> Self {
        Self::new().expect("failed to create temp dir for NexumTestHome")
    }
}
