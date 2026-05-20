//! Integration tests for `nexum doctor` default (no-flag) mode.

mod common;
use common::TestHome;

// ─── 1. Kind field and basic shape on clean bootstrap ────────────────────────

#[test]
fn doctor_on_clean_bootstrap_returns_doctor_report_kind() {
    // initialized_clean runs `nexum index` so index.db exists and keys_list
    // can read key state.
    let home = TestHome::initialized_clean();
    let out = home.run(&["doctor", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        payload["kind"], "doctor.report",
        "kind must be doctor.report"
    );
    assert_eq!(payload["ok"], true, "ok must be true on clean store");
    assert_eq!(
        payload["key_state"]["active"].as_u64().unwrap_or(0),
        1,
        "clean bootstrap has exactly 1 active key"
    );
}

// ─── 2. Prose output mentions key fields ─────────────────────────────────────

#[test]
fn doctor_default_emits_prose_summary() {
    let home = TestHome::initialized_clean();
    // Use --key-state and --check-trust-files to force all fields into prose.
    let out = home.run(&["doctor", "--key-state", "--check-trust-files"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("doctor:"),
        "prose must start with 'doctor:'"
    );
    assert!(
        stdout.contains("keys:"),
        "prose must include key-state line when --key-state is set"
    );
    assert!(
        stdout.contains("signer files:"),
        "prose must include signer-files line when --check-trust-files is set"
    );
}

// ─── 3. Signer-file mismatch → Critical, exit 4 ──────────────────────────────

#[test]
fn doctor_signer_file_mismatch_is_critical_exit_4() {
    // initialized_no_index is sufficient: key_state degrades to zeros but
    // signer_files check still runs and finds the mismatch.
    let home = TestHome::initialized_no_index();
    // Inject a spurious entry into historical_signers to trigger a mismatch.
    let hist = home.path().join("notebook.git/.trust/historical_signers");
    let mut content = std::fs::read_to_string(&hist).unwrap_or_default();
    content.push_str("\nssh-ed25519 AAAA injected-key\n");
    std::fs::write(&hist, &content).unwrap();

    let out = home.run(&["doctor", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected exit 4 (STORE_INTEGRITY)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert_eq!(
        payload["signer_files"]["severity"], "critical",
        "signer_files.severity must be critical"
    );
}

// ─── 4. Merge commit touching .trust/ → Critical, exit 4 ─────────────────────

#[test]
fn doctor_merge_commit_in_trust_is_critical_exit_4() {
    let home = TestHome::initialized_no_index();
    create_merge_commit_touching_trust(home.path(), home.ssh_home());

    let out = home.run(&["doctor", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected exit 4 (STORE_INTEGRITY)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert_eq!(
        payload["merge_commits"]["severity"], "critical",
        "merge_commits.severity must be critical"
    );
}

// ─── 5. Pending sentinel → Warn, exit 0 (bypass works) ───────────────────────

#[test]
fn doctor_pending_sentinel_emits_warn() {
    let home = TestHome::initialized_no_index();
    // Plant a sentinel that would block any command going through resolve_runtime.
    std::fs::write(
        home.path().join(".reanchor_pending"),
        r#"{"case":"A","old_pin_fp":"SHA256:x","new_pin_fp":"SHA256:y","new_pubkey":"ssh-ed25519 AAAA","started_at":"2026-05-20T12:00:00Z","phase_completed":"init"}"#,
    )
    .unwrap();

    let out = home.run(&["doctor", "--json"]);
    // Default mode must NOT exit 8; the sentinel surfaces as a Warn.
    assert_ne!(
        out.status.code(),
        Some(8),
        "doctor default mode must bypass the sentinel preflight (must not exit 8)"
    );
    assert!(
        out.status.success(),
        "expected exit 0 (Warn only, no Critical)\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        payload["reanchor_sentinel"]["severity"], "warn",
        "reanchor_sentinel must be warn when sentinel is present"
    );
}

// ─── 6. Post-reanchor fixture shows reanchored=1 active=1 ────────────────────

#[test]
fn doctor_after_recover_shows_reanchored_count() {
    // initialized_post_reanchor_case_a runs `nexum index` so index.db exists.
    let (home, _fixture) = TestHome::initialized_post_reanchor_case_a(false);

    let out = home.run(&["doctor", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], true);
    assert_eq!(
        payload["key_state"]["reanchored"].as_u64().unwrap_or(0),
        1,
        "post-reanchor fixture must show reanchored=1"
    );
    assert_eq!(
        payload["key_state"]["active"].as_u64().unwrap_or(0),
        1,
        "post-reanchor fixture must show active=1"
    );
}

// ─── 7. Acked warnings appear in acked_warnings array ────────────────────────

#[test]
fn doctor_with_pre_recovery_record_warning_acked_suppresses_it() {
    let (home, _fixture) = TestHome::initialized_post_reanchor_case_a(false);

    // Ack the pre-recovery-record warning.
    let dismiss = home.run(&[
        "trust",
        "dismiss-pre-recovery-warning",
        "--code",
        "pre-recovery-record",
        "--json",
    ]);
    assert!(
        dismiss.status.success(),
        "dismiss should succeed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&dismiss.stdout),
        String::from_utf8_lossy(&dismiss.stderr),
    );

    let out = home.run(&["doctor", "--json"]);
    assert!(out.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let acked = payload["acked_warnings"].as_array().unwrap();
    assert!(
        acked.iter().any(|v| v == "pre-recovery-record"),
        "acked_warnings must contain pre-recovery-record"
    );
}

// ─── 8. --key-state flag doesn't change JSON shape ───────────────────────────

#[test]
fn doctor_key_state_flag_forces_summary_on_clean_store() {
    let home = TestHome::initialized_clean();
    let out = home.run(&["doctor", "--key-state", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // JSON shape is unchanged; key_state is always present.
    assert!(
        payload["key_state"].is_object(),
        "key_state must be an object in JSON output"
    );
    assert_eq!(payload["kind"], "doctor.report");
}

// ─── 9. --check-trust-files flag doesn't change JSON shape ───────────────────

#[test]
fn doctor_check_trust_files_flag_emits_check_result_even_on_ok() {
    let home = TestHome::initialized_clean();
    let out = home.run(&["doctor", "--check-trust-files", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // signer_files is always present in JSON regardless of flag.
    assert!(
        payload["signer_files"].is_object(),
        "signer_files must be an object in JSON output"
    );
    assert_eq!(
        payload["signer_files"]["severity"], "ok",
        "clean store should have severity ok"
    );
}

// ─── 10. Both signer-file mismatch AND merge commit → both Critical, exit 4 ──

#[test]
fn doctor_multi_problem_report_combines_findings() {
    let home = TestHome::initialized_no_index();
    // Inject signer-file mismatch.
    let hist = home.path().join("notebook.git/.trust/historical_signers");
    let mut content = std::fs::read_to_string(&hist).unwrap_or_default();
    content.push_str("\nssh-ed25519 AAAA injected-key\n");
    std::fs::write(&hist, &content).unwrap();
    // Also create a merge commit.
    create_merge_commit_touching_trust(home.path(), home.ssh_home());

    let out = home.run(&["doctor", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "expected exit 4\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["signer_files"]["severity"], "critical");
    assert_eq!(payload["merge_commits"]["severity"], "critical");
}

// ─── 11. Sentinel at pin_updated phase → Warn (not Critical) ─────────────────

#[test]
fn doctor_pin_updated_only_sentinel_emits_warn_not_critical() {
    let home = TestHome::initialized_no_index();
    std::fs::write(
        home.path().join(".reanchor_pending"),
        r#"{"case":"A","old_pin_fp":"SHA256:x","new_pin_fp":"SHA256:y","new_pubkey":"ssh-ed25519 AAAA","started_at":"2026-05-20T12:00:00Z","phase_completed":"pin_updated"}"#,
    )
    .unwrap();

    let out = home.run(&["doctor", "--json"]);
    // Warn only → exit 0.
    assert!(
        out.status.success(),
        "expected exit 0 for warn-only\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        payload["reanchor_sentinel"]["severity"], "warn",
        "sentinel at pin_updated must be Warn, not Critical"
    );
    assert_eq!(payload["ok"], true);
}

// ─── 12. JSON is parseable and kind starts with "doctor." ────────────────────

#[test]
fn doctor_legacy_no_flag_json_kind_doctor_ok_when_truly_clean() {
    let home = TestHome::initialized_clean();
    let out = home.run(&["doctor", "--json"]);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be parseable JSON");
    let kind = payload["kind"].as_str().expect("kind must be a string");
    assert!(
        kind.starts_with("doctor."),
        "kind must start with 'doctor.', got '{kind}'"
    );
    assert_eq!(payload["ok"], true);
}

// ─── Shared test helper ───────────────────────────────────────────────────────

/// Create a merge commit that touches `.trust/events.yml` in the notebook repo.
/// Checks out a feature branch, makes a whitespace-only edit, commits it
/// unsigned (`--no-gpg-sign`), then merges back to the default branch with
/// `--no-ff` so a merge commit is recorded. Uses the same branch name as
/// `git init` produces (system default, typically `master`).
fn create_merge_commit_touching_trust(nexum_home: &std::path::Path, ssh_home: &std::path::Path) {
    let nb_git = nexum_home.join("notebook.git");
    let xdg = ssh_home.join(".config");
    let events_yml = nb_git.join(".trust/events.yml");

    // Pin local git identity (needed on CI runners without a global gitconfig).
    for (k, v) in [
        ("user.name", "nexum-test"),
        ("user.email", "nexum-test@example.invalid"),
    ] {
        run_git(&nb_git, ssh_home, &xdg, &["config", "--local", k, v]);
    }

    // Discover which branch HEAD currently points to so we can return to it.
    let default_branch = current_branch(&nb_git, ssh_home, &xdg);

    // Create a feature branch.
    run_git(
        &nb_git,
        ssh_home,
        &xdg,
        &["checkout", "-b", "feature-touching-trust"],
    );

    // Make a whitespace-only change so the file is modified but semantically
    // unchanged — the doctor merge-commit check looks at commit topology, not
    // content.
    let mut content = std::fs::read_to_string(&events_yml).unwrap_or_default();
    content.push('\n');
    std::fs::write(&events_yml, content).unwrap();

    run_git(&nb_git, ssh_home, &xdg, &["add", ".trust/events.yml"]);
    run_git(
        &nb_git,
        ssh_home,
        &xdg,
        &[
            "commit",
            "--no-gpg-sign",
            "-m",
            "test: whitespace touch on events.yml",
        ],
    );

    // Return to the default branch.
    run_git(
        &nb_git,
        ssh_home,
        &xdg,
        &["checkout", default_branch.as_str()],
    );

    // Merge with --no-ff to guarantee a merge commit in the history.
    run_git(
        &nb_git,
        ssh_home,
        &xdg,
        &[
            "merge",
            "--no-ff",
            "--no-gpg-sign",
            "--no-edit",
            "feature-touching-trust",
        ],
    );
}

/// Return the name of the branch HEAD currently points to.
fn current_branch(
    repo: &std::path::Path,
    home: &std::path::Path,
    xdg_config_home: &std::path::Path,
) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg_config_home)
        .output()
        .expect("git rev-parse HEAD");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn run_git(
    repo: &std::path::Path,
    home: &std::path::Path,
    xdg_config_home: &std::path::Path,
    args: &[&str],
) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg_config_home)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}
