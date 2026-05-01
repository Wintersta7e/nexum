// crates/nexum-core/tests/paths_smoke.rs
//
// Smoke test: confirms the integration-test wiring (tests/common/mod.rs +
// NexumTestHome + Paths::with_home) all hangs together. Future phases add
// real adapter / verifier / index integration tests using this same pattern.

mod common;

use common::NexumTestHome;

#[test]
fn nexum_test_home_paths_are_under_temp() {
    let home = NexumTestHome::new().expect("create test home");
    let paths = home.paths();
    assert_eq!(paths.home, home.path());
    assert!(paths.notebook_git.starts_with(home.path()));
    assert_eq!(paths.notebook_git, home.path().join("notebook.git"));
    assert_eq!(paths.config, home.path().join("config.toml"));
    assert_eq!(paths.lock, home.path().join(".lock"));
}

#[test]
fn two_test_homes_are_isolated() {
    let a = NexumTestHome::new().expect("home a");
    let b = NexumTestHome::new().expect("home b");
    assert_ne!(a.path(), b.path(), "each home must be a unique temp dir");
    let pa = a.paths();
    let pb = b.paths();
    assert_ne!(pa.home, pb.home);
    assert_ne!(pa.notebook_git, pb.notebook_git);
}
