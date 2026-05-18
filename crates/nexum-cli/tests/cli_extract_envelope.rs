//! End-to-end JSON-envelope checks for the EXTRACT_* error codes.
//!
//! Asserts that the three operator-fixable refusal paths surface a
//! wire-stable `ErrorEnvelope` on stdout under `--json`: missing API key,
//! missing consent ack, and `--backfill` without a manifest. The CLI must
//! emit the structured envelope (parseable JSON with a stable
//! `error_code`) rather than prose so agents can branch on the code.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod common;
use common::TestHome;

#[test]
fn missing_api_key_envelope() {
    let home = TestHome::initialized_no_index();
    home.write_extract_ack("anthropic", "claude-opus")
        .expect("write extract ack");

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_nexum"));
    let out = Command::new(&exe)
        .args([
            "extract",
            "--session",
            "00000000-0000-4000-8000-000000000000",
            "--quiet",
            "--json",
        ])
        .env("NEXUM_HOME", home.nexum_home())
        .env("HOME", home.ssh_home())
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .expect("spawn nexum");
    assert!(
        !out.status.success(),
        "missing api key should fail; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(env["error_code"], "EXTRACT_NO_API_KEY");
    assert!(
        env["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ANTHROPIC_API_KEY"),
        "message must name the env var; got {env}"
    );
}

#[test]
fn quiet_without_ack_envelope() {
    let home = TestHome::initialized_no_index();
    // Deliberately DO NOT call write_extract_ack — consent should be required.

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_nexum"));
    let out = Command::new(&exe)
        .args([
            "extract",
            "--session",
            "00000000-0000-4000-8000-000000000000",
            "--quiet",
            "--json",
        ])
        .env("NEXUM_HOME", home.nexum_home())
        .env("HOME", home.ssh_home())
        .env("ANTHROPIC_API_KEY", "test-key")
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("spawn nexum");
    assert!(
        !out.status.success(),
        "missing ack with --quiet should fail; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(env["error_code"], "EXTRACT_NOT_ACKNOWLEDGED");
}

#[test]
fn backfill_without_dry_run_envelope() {
    let home = TestHome::initialized_no_index();
    home.write_extract_ack("anthropic", "claude-opus")
        .expect("write extract ack");

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_nexum"));
    let out = Command::new(&exe)
        .args(["extract", "--backfill", "--quiet", "--json"])
        .env("NEXUM_HOME", home.nexum_home())
        .env("HOME", home.ssh_home())
        .env("ANTHROPIC_API_KEY", "test-key")
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("spawn nexum");
    assert!(
        !out.status.success(),
        "--backfill without a manifest should fail; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(env["error_code"], "EXTRACT_DRY_RUN_REQUIRED");
}
