//! End-to-end: `nexum doctor` and `nexum doctor --resolve-pending-reanchor`
//! exercises the sentinel phases and the no-flags happy path.

use std::path::Path;

mod common;
use common::TestHome;

/// Write a `.reanchor_pending` sentinel with the given `phase_completed` value.
fn write_sentinel(home: &Path, phase: &str) {
    let path = home.join(".reanchor_pending");
    let body = format!(
        r#"{{
            "case": "A",
            "old_pin_fp": "SHA256:old",
            "new_pin_fp": "SHA256:new",
            "new_pubkey": "ssh-ed25519 AAAA",
            "started_at": "2026-05-16T00:00:00Z",
            "pid": null,
            "phase_completed": "{phase}"
        }}"#,
    );
    std::fs::write(&path, body).unwrap();
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
    write_sentinel(home.path(), "pin_updated");
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
