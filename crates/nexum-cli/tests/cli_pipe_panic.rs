//! Regression: a downstream pipe closing before nexum finishes writing
//! must terminate the process cleanly (exit 0) instead of panicking with
//! exit 101 ("failed printing to stdout: Broken pipe").

use std::process::{Command, Stdio};

mod common;

#[test]
fn dropped_stdout_pipe_during_help_exits_zero() {
    // `--help` is the smallest, most-side-effect-free way to trigger
    // print-to-stdout under a parent that has closed its read end.
    // Dropping `child.stdout` (the read end the parent holds) leaves the
    // pipe with no readers; the next stdio write from nexum returns
    // EPIPE. Without the broken-pipe panic hook the default `print!`
    // behaviour panics and the process exits 101.
    let mut child = Command::new(common::nexum_bin())
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nexum --help");
    drop(child.stdout.take());
    let status = child.wait().expect("wait for nexum --help");
    assert!(
        status.success(),
        "broken pipe on stdout should exit 0 with the panic hook installed; got {:?}",
        status.code()
    );
}

#[test]
fn dropped_stdout_pipe_during_json_error_exits_zero() {
    // A `--json` verb against an uninitialized store emits a small
    // NOT_INITIALIZED envelope on stdout. Same path: with the pipe
    // dropped under it, the print should fail soundly (exit 0) not
    // panic. Uses an unused TMPDIR so it cannot find an init.
    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let nexum_home = tmp.path().join(".nexum");
    let ssh_home = tmp.path().join("ssh");
    std::fs::create_dir_all(&ssh_home).expect("mkdir ssh-home");

    let mut child = Command::new(common::nexum_bin())
        .args(["list", "--json"])
        .env("NEXUM_HOME", &nexum_home)
        .env("HOME", &ssh_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nexum list --json");
    drop(child.stdout.take());
    let status = child.wait().expect("wait for nexum list --json");
    assert!(
        status.success(),
        "broken pipe during JSON error envelope should exit 0; got {:?}",
        status.code()
    );
}
