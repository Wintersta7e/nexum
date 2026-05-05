//! CLI subprocess: any subcommand against a tree with `.reanchor_pending`
//! exits 8 (`REANCHOR_PENDING`) and emits guidance pointing at
//! `nexum doctor --resolve-pending-reanchor`.

use tempfile::TempDir;

mod common;

#[test]
fn search_against_tree_with_reanchor_pending_exits_8() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&nexum_home).unwrap();
    std::fs::create_dir_all(&ssh_home).unwrap();

    std::fs::write(
        nexum_home.join(".reanchor_pending"),
        r#"{
            "case": "A",
            "old_pin_fp": "SHA256:abc",
            "new_pin_fp": "SHA256:def",
            "started_at": "2026-05-04T12:00:00Z",
            "phase_completed": "init"
        }"#,
    )
    .unwrap();

    let out = common::run_nexum(&nexum_home, &ssh_home, &["search", "anything"]);
    assert_eq!(
        out.status.code(),
        Some(8),
        "expected exit 8, got {:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Pending reanchor detected"),
        "stderr missing guidance: {stderr}"
    );
    assert!(
        stderr.contains("nexum doctor --resolve-pending-reanchor"),
        "stderr missing recovery flow hint: {stderr}"
    );
}
