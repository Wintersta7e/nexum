//! End-to-end tests for `nexum keys list`.

mod common;
use common::{TestHome, run_json};

#[test]
fn empty_bootstrap_one_active_row() {
    let home = TestHome::initialized_clean();
    let (env, code) = run_json(&home, &["keys", "list", "--json"]);
    assert_eq!(code, 0, "envelope: {env}");
    assert_eq!(env["ok"], serde_json::Value::Bool(true));
    assert_eq!(env["kind"], "keys.list.completed");
    let keys = env["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["role"], "active");
    // bootstrap signer is also the current signer (no rotation yet).
    assert!(env["bootstrap_fingerprint"].is_string());
    assert_eq!(
        env["current_signer_fingerprint"],
        env["bootstrap_fingerprint"]
    );
}

#[test]
fn json_envelope_shape_conforms() {
    let home = TestHome::initialized_clean();
    let (env, _code) = run_json(&home, &["keys", "list", "--json"]);
    assert_eq!(env["ok"], serde_json::Value::Bool(true));
    assert_eq!(env["kind"], "keys.list.completed");
    assert!(env["keys"].is_array());
    assert!(env["bootstrap_fingerprint"].is_string());
    // current_signer_fingerprint is either a string (set after init) or null.
    assert!(
        env["current_signer_fingerprint"].is_string()
            || env["current_signer_fingerprint"].is_null()
    );
}
