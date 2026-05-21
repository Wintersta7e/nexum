//! Integration test for `nexum project set-path`.

#[test]
fn set_path_subcommand_help_succeeds() {
    let bin = env!("CARGO_BIN_EXE_nexum");
    let out = std::process::Command::new(bin)
        .args(["project", "set-path", "--help"])
        .output()
        .expect("spawn nexum");
    assert!(out.status.success(), "exit {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("project_id") || stdout.contains("--help"),
        "{stdout}"
    );
}
