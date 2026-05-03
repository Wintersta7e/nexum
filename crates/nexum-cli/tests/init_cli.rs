//! End-to-end CLI integration tests for `nexum init`.
//!
//! Invokes the compiled binary as a subprocess against a temp HOME.
//! Requires a `git` binary in PATH (standard on all dev machines).

mod common;

use std::process::Command;
use tempfile::TempDir;

fn run_init(home: &TempDir, extra_args: &[&str]) -> std::process::Output {
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = common::write_ephemeral_keypair(key_dir.path());
    let root = home.path().join(".nexum");
    Command::new(common::nexum_bin())
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
    let priv_path = common::write_ephemeral_keypair(key_dir.path());
    let root = home.path().join(".nexum");
    let out = Command::new(common::nexum_bin())
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
