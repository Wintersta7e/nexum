//! Smoke test for `nexum project normalize-inbox` CLI subcommand.

#[test]
fn normalize_inbox_subcommand_help_succeeds() {
    let bin = env!("CARGO_BIN_EXE_nexum");
    let out = std::process::Command::new(bin)
        .args(["project", "normalize-inbox", "--help"])
        .output()
        .expect("spawn nexum");
    assert!(out.status.success(), "exit {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("state-db") || stdout.contains("--json") || stdout.contains("Backfill"),
        "{stdout}"
    );
}
