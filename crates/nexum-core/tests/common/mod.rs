// Shared test utilities for nexum-core integration tests. Each test gets its own
// `NexumTestHome` (isolated temp dir, auto-cleaned on drop). Build a Paths value
// from it with `home.paths()` and pass that into the code under test.

use nexum_core::config::types::{AdapterCcConfig, AdapterCodexConfig, AdapterLocalConfig, Config};
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

/// Write a local-adapter-format YAML record at `notebook_git/<sub>/<id>.yml`.
/// `sub` is one of "decisions" | "recommendations" | "failures" (mapped to
/// the matching `record_type`) — anything else maps to "untyped". Returns
/// the path of the written file.
#[allow(dead_code)]
pub fn write_local_yaml(notebook_git: &Path, sub: &str, id: &str, body: &str) -> PathBuf {
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

/// `Config::seed()` with cc + codex disabled, local enabled.
#[allow(dead_code)]
pub fn test_cfg_local_only() -> Config {
    let mut cfg = Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = true;
    cfg
}

/// Path to the checked-in CC fixture corpus
/// (`tests/fixtures/cc/projects`).
#[allow(dead_code)]
pub fn fixture_cc_projects() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cc")
        .join("projects")
}

/// Path to the checked-in Codex fixture state `SQLite`.
#[allow(dead_code)]
pub fn fixture_codex_state_db() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("codex")
        .join("state_5.sqlite")
}

/// Count all rows in the `records` table of `db`. Opens read-only; panics on
/// any SQL or open failure (test helper only).
#[allow(dead_code)]
pub fn record_count(db: &Path) -> usize {
    let n: i64 = rusqlite::Connection::open(db)
        .unwrap()
        .query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
        .unwrap();
    usize::try_from(n).unwrap_or(0)
}

/// `Config::seed()` configured to ingest the checked-in CC + Codex fixture
/// corpora plus the local adapter. The codex memories dir is supplied by
/// the caller via `codex_memories_dir` — typically a per-test `TempDir`
/// path so we don't mutate the source tree.
#[allow(dead_code)]
pub fn test_cfg_with_fixtures(codex_memories_dir: &Path) -> Config {
    let mut cfg = Config::seed();
    cfg.adapters.cc = AdapterCcConfig {
        enabled: true,
        projects_dir: fixture_cc_projects().display().to_string(),
        max_age_years: 99,
    };
    cfg.adapters.codex = AdapterCodexConfig {
        enabled: true,
        memories_dir: codex_memories_dir.display().to_string(),
        state_db: fixture_codex_state_db().display().to_string(),
        read_raw_memories: false,
    };
    cfg.adapters.local = AdapterLocalConfig { enabled: true };
    cfg
}
