//! End-to-end CLI integration tests for `nexum init`.
//!
//! Invokes the compiled binary as a subprocess against a temp HOME.
//! Requires a `git` binary in PATH (standard on all dev machines).

use ssh_key::{Algorithm, PrivateKey};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

fn nexum_bin() -> PathBuf {
    // Built by `cargo test --package nexum-cli --locked`.
    // The test binary is at target/debug/deps/init_cli-<hash>,
    // so we walk up to target/debug/ and find nexum there.
    let mut p = std::env::current_exe().expect("current_exe");
    // Walk up: deps/ -> debug/
    while p.pop() {
        if p.file_name().is_some_and(|f| f == "debug") {
            return p.join("nexum");
        }
    }
    panic!("could not find target/debug from test binary")
}

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

fn run_init(home: &TempDir, extra_args: &[&str]) -> std::process::Output {
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let root = home.path().join(".nexum");
    Command::new(nexum_bin())
        .args(["init", "--ssh-key"])
        .arg(&priv_path)
        .args(["--root"])
        .arg(&root)
        .args(extra_args)
        .output()
        .expect("nexum binary must run")
}

#[test]
fn cli_init_exits_zero() {
    let home = tempfile::tempdir().unwrap();
    let out = run_init(&home, &[]);
    assert!(
        out.status.success(),
        "nexum init must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_init_stdout_contains_initialized() {
    let home = tempfile::tempdir().unwrap();
    let out = run_init(&home, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("nexum initialized successfully"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_init_already_exists_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();
    // First init.
    run_init(&home, &[]);

    // Second init without --force.
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let root = home.path().join(".nexum");
    let out = Command::new(nexum_bin())
        .args(["init", "--ssh-key"])
        .arg(&priv_path)
        .args(["--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "second init without --force must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--force"),
        "error message must mention --force; stderr: {stderr}"
    );
}

#[test]
fn cli_init_force_reinitializes() {
    let home = tempfile::tempdir().unwrap();
    run_init(&home, &[]);
    let out = run_init(&home, &["--force"]);
    assert!(
        out.status.success(),
        "force rerun must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
