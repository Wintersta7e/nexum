//! Integration tests for the env-based `Paths::resolve()` entry point.
//!
//! These tests mutate the process environment (`NEXUM_HOME`, `HOME`,
//! `USERPROFILE`), which is process-global. Cargo runs each integration-test
//! binary in its own process, so this binary is isolated from other test
//! binaries — but tests within a single binary run in parallel by default,
//! and `set_var` / `remove_var` from one would race the other. `ENV_MUTEX`
//! serializes them.

use nexum_core::paths::{Paths, PathsError};
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn resolve_uses_nexum_home_when_set() {
    let _guard = ENV_MUTEX.lock().expect("env mutex");
    let want = PathBuf::from("/tmp/nx-resolve-test-home");
    // SAFETY: serialized via ENV_MUTEX; reset before returning.
    unsafe {
        std::env::set_var("NEXUM_HOME", &want);
    }
    let got = Paths::resolve().expect("resolve should succeed when NEXUM_HOME is set");
    // SAFETY: serialized via ENV_MUTEX.
    unsafe {
        std::env::remove_var("NEXUM_HOME");
    }
    assert_eq!(got.home, want);
    assert_eq!(got.notebook_git, want.join("notebook.git"));
}

#[test]
fn resolve_errors_when_no_home_anywhere() {
    let _guard = ENV_MUTEX.lock().expect("env mutex");
    // SAFETY: serialized via ENV_MUTEX.
    unsafe {
        std::env::remove_var("NEXUM_HOME");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");
    }
    let err = Paths::resolve().expect_err("must error when no home is available");
    assert!(matches!(err, PathsError::NoHome));
}
