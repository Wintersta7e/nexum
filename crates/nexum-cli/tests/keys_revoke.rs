//! End-to-end tests for `nexum keys revoke`.

mod common;
use common::{TestHome, run_json};

#[test]
fn rotation_against_only_active_key_refuses_with_would_unsign_store() {
    let home = TestHome::initialized_clean();
    let k1_fp = home.bootstrap_pin_fingerprint();
    let (env, code) = run_json(&home, &["keys", "revoke", &k1_fp, "--rotation", "--json"]);
    assert_eq!(code, 4, "envelope: {env}");
    assert_eq!(env["error_code"], "KEYS_REVOKE_WOULD_UNSIGN_STORE");
}

#[test]
fn rotation_against_unknown_fingerprint_refuses() {
    let home = TestHome::initialized_clean();
    // A syntactically-valid-shape but never-introduced fingerprint —
    // would pass any future shape-validation but is not in events.yml.
    let bogus = "SHA256:0000000000000000000000000000000000000000000";
    let (env, code) = run_json(&home, &["keys", "revoke", bogus, "--rotation", "--json"]);
    assert_eq!(code, 2, "envelope: {env}");
    assert_eq!(env["error_code"], "TRUST_FINGERPRINT_NOT_KNOWN");
}

#[test]
fn strict_without_yes_in_json_refuses_usage() {
    let home = TestHome::initialized_clean();
    let k1_fp = home.bootstrap_pin_fingerprint();
    let (env, code) = run_json(&home, &["keys", "revoke", &k1_fp, "--strict", "--json"]);
    assert_eq!(code, 2, "envelope: {env}");
    assert_eq!(env["error_code"], "USAGE");
}

#[test]
fn reanchored_plus_stale_signingkey_target_equals_signer_refuses() {
    // Stale-signingkey + target == signer surfaces WouldSignOwnRevocation
    // because the resolved git signer (K1) equals the revoke target (K1).
    let (home, post) = TestHome::initialized_post_reanchor_case_a(true);
    let (env, code) = run_json(
        &home,
        &["keys", "revoke", &post.k1_fp, "--rotation", "--json"],
    );
    assert_eq!(code, 4, "envelope: {env}");
    assert_eq!(env["error_code"], "KEYS_REVOKE_WOULD_SIGN_OWN_REVOCATION");
}

#[test]
fn revoke_succeeds_for_reanchor_successor_with_distinct_signer() {
    // After post-reanchor (non-stale): K1 is Reanchored, K2 is Active and the
    // current signer. Revoking K1 succeeds because K2 stays Active and K2 is
    // not the target.
    let (home, post) = TestHome::initialized_post_reanchor_case_a(false);
    let (_env, code) = run_json(
        &home,
        &["keys", "revoke", &post.k1_fp, "--rotation", "--json"],
    );
    assert_eq!(code, 0);

    // After the revoke, the projection rule for `KeyRotatedOut` against an
    // already-Reanchored key updates the role to Rotated (retirements are
    // applied in event order, and KeyRotatedOut is the most recent retirement
    // event for K1).
    let (list_env, _list_code) = run_json(&home, &["keys", "list", "--json"]);
    let keys = list_env["keys"].as_array().expect("keys");
    let k1 = keys
        .iter()
        .find(|k| k["fingerprint"] == post.k1_fp)
        .expect("k1 row");
    assert_eq!(k1["role"], "rotated");
    assert!(k1["retired_event_id"].is_string());
}

// Coverage notes for the paths that are NOT directly exercised by an
// end-to-end test in this file:
//   - Resolver-failure path (user.signingkey points at an unreadable
//     filesystem path) is covered by the core unit test
//     `classify_path_with_unreadable_pubkey_refuses` in api::active_signer.
//   - The would-unsign-store path is covered by the rotation-against-only-
//     Active-key test above.
//   - Three-Active-key fixtures that exercise the signer-not-Active
//     preflight against a non-target Active signer require a rotate-in-
//     fixture helper that does not yet exist on TestHome; those tests are
//     tracked separately and not included here.

#[test]
fn round_trip_read_back_via_keys_list() {
    let (home, post) = TestHome::initialized_post_reanchor_case_a(false);
    // Revoke K1 (Reanchored). After the commit, `keys list` should show K1
    // as Rotated and carry the retirement event id + commit.
    let (_revoke_env, revoke_code) = run_json(
        &home,
        &["keys", "revoke", &post.k1_fp, "--rotation", "--json"],
    );
    assert_eq!(revoke_code, 0);

    let (list_env, list_code) = run_json(&home, &["keys", "list", "--json"]);
    assert_eq!(list_code, 0);
    let keys = list_env["keys"].as_array().unwrap();
    let k1 = keys
        .iter()
        .find(|k| k["fingerprint"] == post.k1_fp)
        .unwrap();
    assert_eq!(k1["role"], "rotated");
    assert!(k1["retired_event_id"].is_string());
    assert!(k1["retired_commit"].is_string());
}

#[test]
fn synthetic_post_reanchor_fixture_self_test() {
    let (home, post) = TestHome::initialized_post_reanchor_case_a(false);
    // events.yml has both events.
    let events_path = home.nexum_home().join("notebook.git/.trust/events.yml");
    let body = std::fs::read_to_string(&events_path).expect("read events.yml");
    assert!(body.contains("KeyAdded"));
    assert!(body.contains("BootstrapReanchor"));
    // config.toml has K2.
    let cfg: nexum_core::config::types::Config =
        nexum_core::config::io::load(&home.nexum_home().join("config.toml")).expect("load config");
    assert_eq!(cfg.trust.bootstrap.fingerprint, post.k2_fp);
    assert!(!cfg.trust.bootstrap.public_key.is_empty());
    // verify-commit on the reanchor commit succeeds.
    let nb_git = home.nexum_home().join("notebook.git");
    nexum_core::init::git_ops::git_verify_commit_with_signers(
        &nb_git,
        &post.reanchor_commit,
        &nb_git.join(".trust/historical_signers"),
    )
    .expect("verify reanchor commit");
    // The projection shows K1 Reanchored, K2 Active.
    let (list_env, _) = run_json(&home, &["keys", "list", "--json"]);
    let keys = list_env["keys"].as_array().unwrap();
    let k1 = keys
        .iter()
        .find(|k| k["fingerprint"] == post.k1_fp)
        .unwrap();
    let k2 = keys
        .iter()
        .find(|k| k["fingerprint"] == post.k2_fp)
        .unwrap();
    assert_eq!(k1["role"], "reanchored");
    assert_eq!(k2["role"], "active");
}
