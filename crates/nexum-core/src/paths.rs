//! Filesystem paths for a nexum installation.
//!
//! `Paths::resolve()` is the production entry point — it reads the standard layout
//! under `$HOME/.nexum/` (Unix) or `%USERPROFILE%/.nexum/` (Windows), with `NEXUM_HOME`
//! as an explicit override. `Paths::with_home(p)` is the test entry point — it skips
//! all environment lookup and is thread-safe, so tests can run in parallel without
//! contending on a process-global env var.

use std::path::PathBuf;

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
}
