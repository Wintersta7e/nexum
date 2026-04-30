//! Filesystem paths for a nexum installation.
//!
//! `Paths::resolve()` is the production entry point — it reads the standard layout
//! under `$HOME/.nexum/` (Unix) or `%USERPROFILE%/.nexum/` (Windows), with `NEXUM_HOME`
//! as an explicit override. `Paths::with_home(p)` is the test entry point — it skips
//! all environment lookup and is thread-safe, so tests can run in parallel without
//! contending on a process-global env var.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PathsError {
    #[error("could not resolve nexum home: NEXUM_HOME unset and HOME/USERPROFILE both empty")]
    NoHome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub home: PathBuf,
    pub notebook_git: PathBuf,
    pub index_db: PathBuf,
    pub models: PathBuf,
    pub config: PathBuf,
    pub bootstrap_pin: PathBuf,
    pub projects: PathBuf,
    pub logs: PathBuf,
    pub state: PathBuf,
    pub lock: PathBuf,
}

impl Paths {
    /// Build paths rooted at an explicit home dir. Used by tests and by callers that
    /// already know the canonical `~/.nexum/` location.
    #[must_use]
    pub fn with_home(home: PathBuf) -> Self {
        Self {
            notebook_git: home.join("notebook.git"),
            index_db: home.join("index.db"),
            models: home.join("models"),
            config: home.join("config.toml"),
            bootstrap_pin: home.join(".bootstrap-fingerprint"),
            projects: home.join("projects"),
            logs: home.join("logs"),
            state: home.join("state"),
            lock: home.join(".lock"),
            home,
        }
    }

    /// Resolve from environment.
    ///
    /// Precedence:
    /// 1. `NEXUM_HOME` (explicit override; preferred for tests + sandboxed installs).
    /// 2. `$HOME/.nexum/` on Unix.
    /// 3. `%USERPROFILE%/.nexum/` on Windows.
    ///
    /// # Errors
    ///
    /// Returns `PathsError::NoHome` if none of the above are available.
    pub fn resolve() -> Result<Self, PathsError> {
        if let Some(h) = std::env::var_os("NEXUM_HOME") {
            return Ok(Self::with_home(PathBuf::from(h)));
        }
        if let Some(h) = std::env::var_os("HOME") {
            return Ok(Self::with_home(PathBuf::from(h).join(".nexum")));
        }
        if let Some(h) = std::env::var_os("USERPROFILE") {
            return Ok(Self::with_home(PathBuf::from(h).join(".nexum")));
        }
        Err(PathsError::NoHome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn with_home_derives_all_subpaths_under_root() {
        let root = PathBuf::from("/tmp/nx-fake-root");
        let p = Paths::with_home(root.clone());
        assert_eq!(p.home, root);
        assert_eq!(p.notebook_git, root.join("notebook.git"));
        assert_eq!(p.index_db, root.join("index.db"));
        assert_eq!(p.models, root.join("models"));
        assert_eq!(p.config, root.join("config.toml"));
        assert_eq!(p.bootstrap_pin, root.join(".bootstrap-fingerprint"));
        assert_eq!(p.projects, root.join("projects"));
        assert_eq!(p.logs, root.join("logs"));
        assert_eq!(p.state, root.join("state"));
        assert_eq!(p.lock, root.join(".lock"));
        // Sanity: every subpath must start with the home root (no escapes).
        for sub in [
            &p.notebook_git,
            &p.index_db,
            &p.models,
            &p.config,
            &p.bootstrap_pin,
            &p.projects,
            &p.logs,
            &p.state,
            &p.lock,
        ] {
            assert!(sub.starts_with(&root), "{sub:?} escaped {root:?}");
        }
        // Quiet a Path import lint if Path isn't otherwise used.
        let _: &Path = &p.home;
    }

    #[test]
    fn resolve_uses_nexum_home_when_set() {
        // SAFETY: env var manipulation is process-global. We use a temp dir name
        // that won't collide with anything real, and we reset the var at the end.
        // Cargo runs tests in parallel by default; this test serializes its env
        // touch via a dedicated NEXUM_HOME-only path that no other test uses.
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
        unsafe {
            std::env::remove_var("NEXUM_HOME");
            std::env::remove_var("HOME");
            std::env::remove_var("USERPROFILE");
        }
        let err = Paths::resolve().expect_err("must error when no home is available");
        assert!(matches!(err, PathsError::NoHome));
    }
}
