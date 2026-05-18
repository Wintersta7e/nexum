//! End-to-end test for `nexum extract --backfill --dry-run --json`.
//!
//! Runs against an initialized `NEXUM_HOME` with no candidate sessions —
//! `cfg.adapters.cc.projects_dir` is unset relative to the harness, and
//! the codex adapter is disabled by default. The dry-run path therefore
//! sees zero candidates: the manifest is written with `candidate_count =
//! 0`, the `dry_run_id` is the canonical hash of an empty per-session
//! slice, and `count_tokens` is never called (so no wiremock is required).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod common;
use common::TestHome;

#[test]
fn dry_run_writes_manifest_zero_candidates() {
    let home = TestHome::initialized_no_index();
    home.write_extract_ack("anthropic", "claude-opus")
        .expect("write extract ack");

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_nexum"));
    let output = Command::new(&exe)
        .args(["extract", "--backfill", "--dry-run", "--json", "--quiet"])
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
        output.status.success(),
        "exit={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON: {e}\nstdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    let id = parsed["dry_run_id"]
        .as_str()
        .unwrap_or_else(|| panic!("manifest missing dry_run_id: {parsed}"));
    assert!(
        id.starts_with("sha256:"),
        "dry_run_id `{id}` must carry sha256 prefix"
    );
    assert_eq!(parsed["candidate_count"].as_u64(), Some(0));
    let total = parsed["total_estimated_cost_usd"].as_f64().expect("cost");
    assert!(total.abs() < f64::EPSILON, "zero-candidate cost must be 0");
}
