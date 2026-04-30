//! Integration tests for the env-based `Paths::resolve()` entry point.
//!
//! Live in their own integration-test binary because they mutate the process
//! environment (`NEXUM_HOME`, `HOME`, `USERPROFILE`) — which is process-global. Cargo
//! runs each integration-test binary in its own process, so isolation is preserved
//! here even if other integration tests grow to read env state.

use nexum_core::paths::{Paths, PathsError};
use std::path::PathBuf;

#[test]
fn resolve_uses_nexum_home_when_set() {
    // SAFETY: env mutation is process-global; this test binary has no other tests
    // that read NEXUM_HOME, and we reset the var before returning.
    let want = PathBuf::from("/tmp/nx-resolve-test-home");
    unsafe {
        std::env::set_var("NEXUM_HOME", &want);
    }
    let got = Paths::resolve().expect("resolve should succeed when NEXUM_HOME is set");
    unsafe {
        std::env::remove_var("NEXUM_HOME");
    }
    assert_eq!(got.home, want);
    assert_eq!(got.notebook_git, want.join("notebook.git"));
}

#[test]
fn resolve_errors_when_no_home_anywhere() {
    // SAFETY: env mutation is process-global; this test binary has no other tests
    // that read these vars. The other env-using test (`resolve_uses_nexum_home_when_set`)
    // sets and clears NEXUM_HOME but doesn't touch HOME / USERPROFILE.
    unsafe {
        std::env::remove_var("NEXUM_HOME");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");
    }
    let err = Paths::resolve().expect_err("must error when no home is available");
    assert!(matches!(err, PathsError::NoHome));
}
