//! CLI subprocess test — full pipeline through the `nexum` binary.

use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

fn nexum_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nexum"))
}

fn write_ephemeral_keypair(dir: &std::path::Path) -> PathBuf {
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

fn run_nexum(home: &std::path::Path, ssh_home: &std::path::Path, args: &[&str]) -> Output {
    // Override git author/committer identity so the bootstrap commit succeeds
    // even when HOME is overridden away from the developer's global git config.
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

fn write_local_record(home: &std::path::Path, id: &str, body: &str) {
    let p = home
        .join("notebook.git")
        .join("decisions")
        .join(format!("{id}.yml"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(
        p,
        format!(
            "schema_version: 1\nid: {id}\nrecord_type: decision\ntitle: {id}\nbody: |\n  {body}\nproject_id: example\ntags: [auth]\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\nconfidence: high\noutcome: working\n"
        ),
    )
    .unwrap();
}

#[test]
fn nexum_init_then_index_then_search_pipeline() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(ssh_home.join(".ssh")).unwrap();
    let key_path = write_ephemeral_keypair(&ssh_home.join(".ssh"));

    let out = run_nexum(
        &nexum_home,
        &ssh_home,
        &["init", "--yes", "--ssh-key", key_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "init failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    write_local_record(&nexum_home, "alpha", "concurrency body alpha");

    let out = run_nexum(&nexum_home, &ssh_home, &["index", "--json"]);
    assert!(
        out.status.success(),
        "index failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("index --json must be valid JSON: {e}\nstdout={stdout_str}"));
    assert_eq!(parsed["upserts"], 1, "expected 1 upsert, got {parsed}");

    let out = run_nexum(&nexum_home, &ssh_home, &["search", "concurrency", "--json"]);
    assert!(out.status.success(), "search failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("search --json");
    let results = parsed["results"].as_array().unwrap();
    assert!(
        results.iter().any(|r| r["id"] == "alpha"),
        "expected `alpha` in search results, got {results:?}"
    );

    let out = run_nexum(&nexum_home, &ssh_home, &["get", "alpha", "--json"]);
    assert!(out.status.success(), "get failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("get --json");
    assert_eq!(parsed["id"], "alpha");

    let out = run_nexum(&nexum_home, &ssh_home, &["list", "--json"]);
    assert!(out.status.success(), "list failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("list --json");
    let results = parsed["results"].as_array().unwrap();
    assert!(!results.is_empty(), "list must include the record");
}

#[test]
fn nexum_index_without_init_returns_exit_3() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let out = run_nexum(&nexum_home, &ssh_home, &["index"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn nexum_index_with_force_and_incremental_returns_exit_2() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let out = run_nexum(
        &nexum_home,
        &ssh_home,
        &["index", "--force", "--incremental"],
    );
    assert_eq!(out.status.code(), Some(2));
}
