//! Integration tests for `nexum trust dismiss-pre-recovery-warning`.

mod common;
use common::TestHome;

#[test]
fn dismiss_default_codes_acks_both() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&["trust", "dismiss-pre-recovery-warning", "--json"]);
    assert!(
        out.status.success(),
        "dismiss-pre-recovery-warning should succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], true);
    assert_eq!(
        payload["kind"],
        "trust.dismiss_pre_recovery_warning.completed"
    );
    let added = payload["added"].as_array().unwrap();
    assert_eq!(added.len(), 2);
    assert!(added.iter().any(|v| v == "pre-recovery-record"));
    assert!(added.iter().any(|v| v == "chain-anchor-lost"));
}

#[test]
fn dismiss_single_code() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&[
        "trust",
        "dismiss-pre-recovery-warning",
        "--code",
        "pre-recovery-record",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "dismiss single code should succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["added"], serde_json::json!(["pre-recovery-record"]));
}

#[test]
fn dismiss_unknown_code_refuses_usage() {
    let home = TestHome::initialized_no_index();
    let out = home.run(&[
        "trust",
        "dismiss-pre-recovery-warning",
        "--code",
        "bogus-warning",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["error_code"], "USAGE");
}

#[test]
fn dismiss_is_idempotent() {
    let home = TestHome::initialized_no_index();
    let first = home.run(&["trust", "dismiss-pre-recovery-warning"]);
    assert!(
        first.status.success(),
        "first dismiss call must succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let out = home.run(&["trust", "dismiss-pre-recovery-warning", "--json"]);
    assert!(
        out.status.success(),
        "second dismiss call must succeed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let added = payload["added"].as_array().unwrap();
    assert!(added.is_empty(), "no new codes acked on second call");
    let already = payload["already_present"].as_array().unwrap();
    assert_eq!(already.len(), 2);
}
