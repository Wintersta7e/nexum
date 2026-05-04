//! CLI subprocess test — full pipeline through the `nexum` binary.

mod common;

use tempfile::TempDir;

#[test]
fn nexum_init_then_index_then_search_pipeline() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(ssh_home.join(".ssh")).unwrap();
    let key_path = common::write_ephemeral_keypair(&ssh_home.join(".ssh"));

    let out = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &["init", "--yes", "--ssh-key", key_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "init failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    common::write_local_yaml(&nexum_home, "decisions", "alpha", "concurrency body alpha");

    let out = common::run_nexum(&nexum_home, &ssh_home, &["index", "--json"]);
    assert!(
        out.status.success(),
        "index failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("index --json must be valid JSON: {e}\nstdout={stdout_str}"));
    assert_eq!(parsed["upserts"], 1, "expected 1 upsert, got {parsed}");

    let out = common::run_nexum(&nexum_home, &ssh_home, &["search", "concurrency", "--json"]);
    assert!(out.status.success(), "search failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("search --json");
    let results = parsed["results"].as_array().unwrap();
    assert!(
        results.iter().any(|r| r["id"] == "alpha"),
        "expected `alpha` in search results, got {results:?}"
    );

    let out = common::run_nexum(&nexum_home, &ssh_home, &["get", "alpha", "--json"]);
    assert!(out.status.success(), "get failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("get --json");
    assert_eq!(parsed["id"], "alpha");

    let out = common::run_nexum(&nexum_home, &ssh_home, &["list", "--json"]);
    assert!(out.status.success(), "list failed: {out:?}");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_str).expect("list --json");
    let results = parsed["results"].as_array().unwrap();
    assert!(!results.is_empty(), "list must include the record");
}

#[test]
fn nexum_index_without_init_returns_exit_3() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let out = common::run_nexum(&nexum_home, &ssh_home, &["index"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn nexum_index_with_force_and_incremental_returns_exit_2() {
    let test_dir = TempDir::new().unwrap();
    let nexum_home = test_dir.path().join(".nexum");
    let ssh_home = test_dir.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).unwrap();
    let out = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &["index", "--force", "--incremental"],
    );
    assert_eq!(out.status.code(), Some(2));
}
