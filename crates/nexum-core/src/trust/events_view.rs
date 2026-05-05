//! Materialized view of `.trust/events.yml` walked through git history.
//!
//! This module ships the bootstrap-only branch: walks the history, parses
//! each revision, validates the first revision contains exactly one
//! `BootstrapKey` event, and populates `trust_events`. Future iterations
//! extend the loop with `KeyAdded` / `KeyRotatedOut` / `KeyCompromised`,
//! tampering detection, and the `BootstrapReanchor` exception.
//!
//! The materializer is idempotent: each `rebuild` call clears + repopulates
//! `trust_events` and `trust_chain_tampering` from scratch. A pair of cheap
//! sentinels in the `meta` table (the events.yml HEAD SHA + blob SHA) lets
//! callers skip the rebuild when the on-disk view is current.

use std::path::Path;

use chrono::Utc;
use rusqlite::{Connection, Transaction, params};

use crate::index::meta::{
    KEY_TRUST_EVENTS_BLOB_SHA, KEY_TRUST_EVENTS_HEAD_SHA, KEY_TRUST_EVENTS_MATERIALIZED_AT,
    read_str, write_str,
};
use crate::trust::events::{EventKind, EventLog, TrustError};
use crate::trust::git_history::{
    git_rev_parse, git_show_blob, has_merges_on_events_yml, topo_walk_events_yml,
};

/// Outcome of a materializer run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialization {
    /// Number of rows written to `trust_events`.
    pub events_count: u32,
    /// Number of rows written to `trust_chain_tampering` (always 0 in the
    /// bootstrap-only branch; populated by later iterations).
    pub tampering_count: u32,
}

/// Read-only access to materialized trust state. Constructed cheaply per
/// query verb invocation (read-side wiring lands in the api facade).
pub struct TrustEventsView<'a> {
    /// Borrowed connection used for read-only queries against the
    /// materialized rows. Private so the view's read API is the single
    /// surface callers depend on.
    conn: &'a Connection,
}

impl<'a> TrustEventsView<'a> {
    /// Wrap an existing connection for read-only trust-event queries.
    #[must_use]
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// True if any tampering row exists.
    ///
    /// In the bootstrap-only branch the materializer never writes tampering
    /// rows, so this only returns `true` if a future iteration's writer
    /// has populated `trust_chain_tampering`. The topo-position-aware
    /// variant (`has_tampering_at_or_before(commit)`) lands alongside the
    /// tampering-detection write path.
    ///
    /// # Errors
    ///
    /// Returns `TrustError::Sqlite` if the underlying `count(*)` query fails.
    pub fn has_any_tampering(&self) -> Result<bool, TrustError> {
        let count: i64 =
            self.conn
                .query_row("SELECT count(*) FROM trust_chain_tampering", [], |r| {
                    r.get(0)
                })?;
        Ok(count > 0)
    }
}

/// Rebuild `trust_events` and `trust_chain_tampering` from `notebook.git`.
///
/// Idempotent; safe to call repeatedly. Updates the meta sentinels
/// (`KEY_TRUST_EVENTS_HEAD_SHA`, `KEY_TRUST_EVENTS_BLOB_SHA`,
/// `KEY_TRUST_EVENTS_MATERIALIZED_AT`) post-rebuild so [`is_current`] can
/// short-circuit subsequent calls.
///
/// # Errors
///
/// Returns `TrustError::TrustHistoryNotLinear` if any merge commit has
/// touched `.trust/events.yml`. Returns `TrustError::TrustSchemaUnsupported`
/// if a revision declares a `schema_version` other than 1. Returns
/// `TrustError::MalformedBootstrap` if the first revision does not contain
/// exactly one `BootstrapKey` event. Propagates `TrustError::GitCommand`,
/// `TrustError::Io`, `TrustError::Parse`, and `TrustError::Sqlite` from the
/// underlying helpers.
pub fn rebuild(conn: &mut Connection, notebook_git: &Path) -> Result<Materialization, TrustError> {
    if has_merges_on_events_yml(notebook_git)? {
        return Err(TrustError::TrustHistoryNotLinear);
    }

    let commits = topo_walk_events_yml(notebook_git)?;
    if commits.is_empty() {
        // No events.yml history yet. Clear any stale rows; leave sentinels
        // alone so `is_current` continues to report false until a real
        // rebuild lands.
        let tx = conn.transaction()?;
        tx.execute_batch("DELETE FROM trust_events; DELETE FROM trust_chain_tampering;")?;
        tx.commit()?;
        return Ok(Materialization {
            events_count: 0,
            tampering_count: 0,
        });
    }

    let tx = conn.transaction()?;
    tx.execute_batch("DELETE FROM trust_events; DELETE FROM trust_chain_tampering;")?;

    let mut events_count = 0_u32;
    for (topo_pos, commit) in commits.iter().enumerate() {
        let blob = git_show_blob(notebook_git, &commit.sha)?;
        let log: EventLog = serde_yaml::from_str(&blob).map_err(|e| TrustError::Parse {
            path: format!("{}:.trust/events.yml", commit.sha),
            source: e,
        })?;
        if log.schema_version != 1 {
            return Err(TrustError::TrustSchemaUnsupported {
                found: log.schema_version,
            });
        }

        if topo_pos == 0 {
            insert_bootstrap_row(&tx, &log, &commit.sha, topo_pos, commit.signer.as_deref())?;
            events_count += 1;
        }
        // Subsequent revisions are handled by later iterations of the
        // materializer (KeyAdded / KeyRotatedOut / KeyCompromised /
        // BootstrapReanchor + tampering detection). The bootstrap-only
        // branch ignores them so multi-commit fixtures don't crash the
        // walker; production code paths only see single-commit histories.
    }

    let parsed = git_rev_parse(notebook_git, &["HEAD", "HEAD:.trust/events.yml"])?;
    let head_sha = parsed.first().map(String::as_str).unwrap_or_default();
    let blob_sha = parsed.get(1).map(String::as_str).unwrap_or_default();
    update_sentinels(&tx, head_sha, blob_sha)?;

    tx.commit()?;
    Ok(Materialization {
        events_count,
        tampering_count: 0,
    })
}

/// Insert the `BootstrapKey` row for the first revision. Validates that the
/// revision contains exactly one event of the expected kind.
fn insert_bootstrap_row(
    tx: &Transaction<'_>,
    log: &EventLog,
    commit_sha: &str,
    topo_pos: usize,
    signer: Option<&str>,
) -> Result<(), TrustError> {
    if log.events.len() != 1 {
        return Err(TrustError::MalformedBootstrap);
    }
    let kind = log.events[0].payload.as_db_str();
    let EventKind::BootstrapKey {
        fingerprint,
        public_key,
        reason,
    } = &log.events[0].payload
    else {
        return Err(TrustError::MalformedBootstrap);
    };

    // Bootstrap commits are introduced by their own signing key — fall back
    // to the bootstrap fingerprint if the commit was unsigned (defensive;
    // the production init path always signs).
    let introduced_by_signer = signer.unwrap_or(fingerprint.as_str());

    tx.execute(
        "INSERT INTO trust_events (
            event_id, kind, fingerprint, public_key,
            effective_commit, effective_commit_topo_pos,
            introduced_by_signer, chain_validated_by, reason, materialized_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9)",
        params![
            log.events[0].event_id.to_string(),
            kind,
            fingerprint,
            public_key,
            commit_sha,
            i64::try_from(topo_pos).unwrap_or(i64::MAX),
            introduced_by_signer,
            reason,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Persist the materializer sentinels (events.yml HEAD SHA, blob SHA, run
/// timestamp) inside the rebuild transaction.
fn update_sentinels(
    tx: &Transaction<'_>,
    head_sha: &str,
    blob_sha: &str,
) -> Result<(), TrustError> {
    write_str(tx, KEY_TRUST_EVENTS_HEAD_SHA, head_sha)?;
    write_str(tx, KEY_TRUST_EVENTS_BLOB_SHA, blob_sha)?;
    write_str(
        tx,
        KEY_TRUST_EVENTS_MATERIALIZED_AT,
        &Utc::now().to_rfc3339(),
    )?;
    Ok(())
}

/// Cheap sentinel check. Returns `true` if the on-disk view is current and
/// `rebuild` can be skipped, `false` otherwise. Sub-millisecond on
/// personal-scale notebooks: two `git rev-parse` invocations + two `meta`
/// reads.
///
/// # Errors
///
/// Returns `TrustError::Sqlite` if the meta lookups fail, or
/// `TrustError::GitCommand` / `TrustError::Io` if `git rev-parse` errors.
pub fn is_current(conn: &Connection, notebook_git: &Path) -> Result<bool, TrustError> {
    let stored_head = read_str(conn, KEY_TRUST_EVENTS_HEAD_SHA)?;
    let stored_blob = read_str(conn, KEY_TRUST_EVENTS_BLOB_SHA)?;
    if stored_head.is_none() || stored_blob.is_none() {
        return Ok(false);
    }
    let parsed = git_rev_parse(notebook_git, &["HEAD", "HEAD:.trust/events.yml"])?;
    let current_head = parsed.first().map(String::as_str).unwrap_or_default();
    let current_blob = parsed.get(1).map(String::as_str).unwrap_or_default();
    Ok(
        stored_head.as_deref() == Some(current_head)
            && stored_blob.as_deref() == Some(current_blob),
    )
}

/// Lazy-rebuild wrapper: callable once per query verb invocation. Cheap when
/// the view is already current; full rebuild otherwise.
///
/// # Errors
///
/// Returns any error surfaced by [`is_current`] or [`rebuild`].
pub fn ensure_current(conn: &mut Connection, notebook_git: &Path) -> Result<(), TrustError> {
    if !is_current(conn, notebook_git)? {
        rebuild(conn, notebook_git)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
        assert!(
            out.status.success(),
            "git {:?} exited non-zero: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_repo_with_events(notebook_git: &Path, events_yml: &str) {
        // Bare-bones fresh repo with an unsigned commit on .trust/events.yml.
        // Tests that require real signing live in the integration test crate.
        run_git(notebook_git, &["init", "."]);
        run_git(
            notebook_git,
            &["config", "user.email", "test@example.invalid"],
        );
        run_git(notebook_git, &["config", "user.name", "Test"]);
        run_git(notebook_git, &["config", "commit.gpgsign", "false"]);
        std::fs::create_dir_all(notebook_git.join(".trust")).unwrap();
        std::fs::write(notebook_git.join(".trust/events.yml"), events_yml).unwrap();
        run_git(notebook_git, &["add", ".trust/events.yml"]);
        run_git(notebook_git, &["commit", "-m", "init", "--no-gpg-sign"]);
    }

    fn open_test_db() -> Connection {
        crate::indexer::db::open_or_create_in_memory_for_tests()
    }

    fn bootstrap_yaml() -> &'static str {
        r#"schema_version: 1
events:
  - event_id: 019e0a14-7000-7c00-a000-000000000001
    kind: BootstrapKey
    fingerprint: "SHA256:abc"
    public_key: "ssh-ed25519 AAAA test"
    reason: "Initial bootstrap"
"#
    }

    #[test]
    fn rebuild_with_bootstrap_only_history_writes_one_row() {
        let dir = tempdir().unwrap();
        init_repo_with_events(dir.path(), bootstrap_yaml());
        let mut conn = open_test_db();
        let m = rebuild(&mut conn, dir.path()).unwrap();
        assert_eq!(m.events_count, 1);
        assert_eq!(m.tampering_count, 0);

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM trust_events WHERE kind = 'BootstrapKey'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rebuild_updates_sentinels() {
        let dir = tempdir().unwrap();
        init_repo_with_events(dir.path(), bootstrap_yaml());
        let mut conn = open_test_db();
        rebuild(&mut conn, dir.path()).unwrap();

        let head = read_str(&conn, KEY_TRUST_EVENTS_HEAD_SHA).unwrap();
        let blob = read_str(&conn, KEY_TRUST_EVENTS_BLOB_SHA).unwrap();
        let stamp = read_str(&conn, KEY_TRUST_EVENTS_MATERIALIZED_AT).unwrap();
        assert!(head.is_some(), "head sentinel should be set");
        assert!(blob.is_some(), "blob sentinel should be set");
        assert!(stamp.is_some(), "materialized-at sentinel should be set");
    }

    #[test]
    fn is_current_returns_true_after_fresh_rebuild() {
        let dir = tempdir().unwrap();
        init_repo_with_events(dir.path(), bootstrap_yaml());
        let mut conn = open_test_db();
        rebuild(&mut conn, dir.path()).unwrap();
        assert!(is_current(&conn, dir.path()).unwrap());
    }

    #[test]
    fn malformed_bootstrap_returns_error() {
        let dir = tempdir().unwrap();
        // Two BootstrapKey events in the first revision: forbidden.
        let bad = r#"schema_version: 1
events:
  - event_id: 019e0a14-7000-7c00-a000-000000000001
    kind: BootstrapKey
    fingerprint: "SHA256:abc"
    public_key: "ssh-ed25519 AAAA test"
    reason: "first"
  - event_id: 019e0a14-7000-7c00-a000-000000000002
    kind: BootstrapKey
    fingerprint: "SHA256:def"
    public_key: "ssh-ed25519 BBBB test2"
    reason: "second"
"#;
        init_repo_with_events(dir.path(), bad);
        let mut conn = open_test_db();
        let err = rebuild(&mut conn, dir.path()).unwrap_err();
        assert!(matches!(err, TrustError::MalformedBootstrap));
    }

    #[test]
    fn rebuild_no_history_writes_nothing() {
        let dir = tempdir().unwrap();
        // Init a repo with no .trust/events.yml history.
        run_git(dir.path(), &["init", "."]);
        run_git(
            dir.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git(dir.path(), &["config", "user.name", "Test"]);
        run_git(dir.path(), &["config", "commit.gpgsign", "false"]);
        run_git(
            dir.path(),
            &["commit", "--allow-empty", "-m", "empty", "--no-gpg-sign"],
        );

        let mut conn = open_test_db();
        let m = rebuild(&mut conn, dir.path()).unwrap();
        assert_eq!(m.events_count, 0);
        assert_eq!(m.tampering_count, 0);

        // No history → sentinels stay absent so the next ensure_current call
        // still triggers a real rebuild once events.yml lands.
        assert!(
            read_str(&conn, KEY_TRUST_EVENTS_HEAD_SHA)
                .unwrap()
                .is_none()
        );
        assert!(
            read_str(&conn, KEY_TRUST_EVENTS_BLOB_SHA)
                .unwrap()
                .is_none()
        );
    }
}
