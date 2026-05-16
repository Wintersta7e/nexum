//! End-to-end: `nexum doctor` and `nexum doctor --resolve-pending-reanchor`
//! exercises the sentinel phases and the no-flags happy path.

use std::path::Path;

mod common;
use common::TestHome;

/// Write a `.reanchor_pending` sentinel with the given `phase_completed` value.
/// The `new_pin_fp` defaults to a placeholder; for the `pin_updated` cleanup
/// path the live config + cache file MUST match `new_pin_fp` or the resolver
/// refuses, so callers exercising that path use [`write_sentinel_with_pin`].
fn write_sentinel(home: &Path, phase: &str) {
    write_sentinel_with_pin(home, phase, "SHA256:new");
}

fn write_sentinel_with_pin(home: &Path, phase: &str, new_pin_fp: &str) {
    let path = home.join(".reanchor_pending");
    let body = format!(
        r#"{{
            "case": "A",
            "old_pin_fp": "SHA256:old",
            "new_pin_fp": "{new_pin_fp}",
            "new_pubkey": "ssh-ed25519 AAAA",
            "started_at": "2026-05-16T00:00:00Z",
            "pid": null,
            "phase_completed": "{phase}"
        }}"#,
    );
    std::fs::write(&path, body).unwrap();
}

/// Read the live bootstrap fingerprint from `config.toml` (set by `nexum init`).
/// Used by tests that need to write a sentinel whose `new_pin_fp` matches the
/// live state — what a real completed `pin_updated` phase looks like.
fn live_bootstrap_fingerprint(home: &Path) -> String {
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    for line in cfg.lines() {
        if let Some(rest) = line.trim().strip_prefix("fingerprint =") {
            return rest.trim().trim_matches('"').to_owned();
        }
    }
    panic!("no [trust.bootstrap].fingerprint in config.toml: {cfg}");
}

#[test]
fn doctor_no_flags_exits_zero_when_clean() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["doctor"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn doctor_refuses_to_resolve_init_phase_via_continue() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "init");
    let out = home.run(&["doctor", "--resolve-pending-reanchor", "--continue"]);
    assert!(
        !out.status.success(),
        "expected non-zero for init-phase --continue"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("keys-recover") || stderr.contains("not yet available"),
        "stderr should explain keys-recover is unavailable: {stderr}"
    );
}

#[test]
fn doctor_resolves_pin_updated_phase_idempotently() {
    let home = TestHome::initialized_no_index();
    // Stage a sentinel whose new_pin_fp matches the live bootstrap state —
    // i.e. a real reanchor that finished the pin update and only the
    // sentinel cleanup is left.
    let live = live_bootstrap_fingerprint(home.path());
    write_sentinel_with_pin(home.path(), "pin_updated", &live);
    let out = home.run(&["doctor", "--resolve-pending-reanchor"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !home.path().join(".reanchor_pending").exists(),
        "sentinel should be deleted after pin_updated cleanup"
    );
}

#[test]
fn doctor_refuses_pin_updated_cleanup_when_live_state_drifted() {
    let home = TestHome::initialized_no_index();
    // Sentinel claims pin was rotated to SHA256:new, but the live config
    // still carries the bootstrap fingerprint from init — drifted state.
    // The sentinel is the only audit signal; the resolver must refuse to
    // delete it.
    write_sentinel_with_pin(home.path(), "pin_updated", "SHA256:drifted");
    let out = home.run(&["doctor", "--resolve-pending-reanchor", "--json"]);
    assert!(
        !out.status.success(),
        "expected non-zero when sentinel disagrees with live state"
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["kind"], "doctor.reanchor.refused");
    let msg = payload["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("inconsistent") || msg.contains("drifted") || msg.contains("do not match"),
        "message should flag the drift: {msg}"
    );
    assert!(
        home.path().join(".reanchor_pending").exists(),
        "sentinel must NOT be deleted on drift refusal"
    );
}

#[test]
fn doctor_no_sentinel_reports_nothing_to_do() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["doctor", "--resolve-pending-reanchor"]);
    assert!(
        out.status.success(),
        "expected exit 0 when no sentinel present\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn doctor_init_revert_deletes_sentinel() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "init");
    let out = home.run(&["doctor", "--resolve-pending-reanchor", "--revert"]);
    assert!(
        out.status.success(),
        "expected exit 0 for init+--revert\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !home.path().join(".reanchor_pending").exists(),
        "sentinel should be deleted after init+--revert"
    );
}

#[test]
fn doctor_resolve_requires_mode_flag() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "init");
    // --resolve-pending-reanchor alone (no --continue or --revert) should
    // refuse and exit non-zero.
    let out = home.run(&["doctor", "--resolve-pending-reanchor"]);
    // With a sentinel present and no mode flag, `Refused` is returned.
    // No-sentinel path returns success; with sentinel it should refuse.
    // Verify the sentinel is still present (not deleted).
    assert!(
        home.path().join(".reanchor_pending").exists(),
        "sentinel should NOT be deleted when no mode flag is given"
    );
    assert!(
        !out.status.success(),
        "expected non-zero exit when sentinel present but no mode flag"
    );
}

#[test]
fn doctor_events_committed_revert_refused() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "events_committed");
    let out = home.run(&["doctor", "--resolve-pending-reanchor", "--revert"]);
    assert!(
        !out.status.success(),
        "expected non-zero for events_committed+--revert"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("events_committed") || stderr.contains("continue"),
        "stderr should explain why --revert is invalid here: {stderr}"
    );
}

#[test]
fn doctor_events_committed_continue_writes_pin_and_clears_sentinel() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "events_committed");
    let out = home.run(&[
        "doctor",
        "--resolve-pending-reanchor",
        "--continue",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "expected exit 0 for events_committed+--continue\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "doctor.reanchor.resolved");
    assert_eq!(payload["from_phase"], "events_committed");

    // Sentinel removed.
    assert!(
        !home.path().join(".reanchor_pending").exists(),
        "sentinel should be deleted after events_committed cleanup"
    );
    // Bootstrap pin in config.toml updated.
    let cfg_raw = std::fs::read_to_string(home.path().join("config.toml")).unwrap();
    assert!(
        cfg_raw.contains("SHA256:new"),
        "config.toml should carry the new pin fingerprint: {cfg_raw}"
    );
    // Cache file rewritten.
    let cached =
        std::fs::read_to_string(home.path().join(".bootstrap-fingerprint")).unwrap_or_default();
    assert!(
        cached.contains("SHA256:new"),
        ".bootstrap-fingerprint should mirror the new pin: {cached}"
    );
}

#[test]
fn doctor_no_flags_json_emits_ok_envelope() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["doctor", "--json"]);
    assert!(out.status.success(), "expected exit 0");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "doctor.ok");
}

#[test]
fn doctor_resolve_no_sentinel_json_emits_no_sentinel_envelope() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["doctor", "--resolve-pending-reanchor", "--json"]);
    assert!(out.status.success(), "expected exit 0 when no sentinel");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(true));
    assert_eq!(payload["kind"], "doctor.reanchor.no_sentinel");
}

#[test]
fn doctor_refused_emits_usage_exit_code() {
    let home = TestHome::initialized_no_index();
    write_sentinel(home.path(), "init");
    let out = home.run(&[
        "doctor",
        "--resolve-pending-reanchor",
        "--continue",
        "--json",
    ]);
    assert!(
        !out.status.success(),
        "expected non-zero for init+--continue"
    );
    // Refused is a usage error (exit code 2), not a store-integrity issue.
    assert_eq!(out.status.code(), Some(2));
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(payload["ok"], serde_json::Value::Bool(false));
    assert_eq!(payload["code"], "USAGE");
    assert_eq!(payload["kind"], "doctor.reanchor.refused");
}
