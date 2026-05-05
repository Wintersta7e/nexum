//! Materialized view of `.trust/events.yml` walked through git history.
//!
//! Walks the history, parses each revision, validates the first revision
//! contains exactly one `BootstrapKey` event, classifies each subsequent
//! diff (`Append` / `Reanchor` / `NoOp` / `Forbidden`), authorizes the chain
//! extension, and populates `trust_events` and `trust_chain_tampering`. The
//! `BootstrapReanchor` exception is gated by a four-condition authorization
//! check; unauthorized reanchors freeze the chain via the
//! `chain_frozen_at_topo` meta sentinel rather than a tampering row.
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
use crate::trust::chain_state::{ChainState, ReanchorCase};
use crate::trust::diff::{Diff, TamperingKind, classify as classify_diff};
use crate::trust::events::{Event, EventKind, EventLog, TrustError};
use crate::trust::git_history::{
    git_rev_parse, git_show_blob, has_merges_on_events_yml, topo_walk_events_yml,
};
use crate::trust::pin::{BootstrapPin, read_pin};

/// Outcome of a materializer run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialization {
    /// Number of rows written to `trust_events`.
    pub events_count: u32,
    /// Number of rows written to `trust_chain_tampering`. Unauthorized
    /// reanchors do NOT contribute here — they're persisted via the
    /// `chain_frozen_at_topo` meta sentinel and surfaced as the
    /// `broken-trust-chain` warning at read time.
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

    /// True if any tampering row was recorded at or before `commit`'s
    /// topo position.
    ///
    /// `commit` is the SHA of an events.yml-touching revision in
    /// `trust_events`. Commits not present in `trust_events` (cc-native /
    /// codex-native records, or revisions after the chain was frozen and
    /// stopped accumulating new rows) return `Ok(false)` because the
    /// tampering precondition does not apply to them.
    ///
    /// # Errors
    ///
    /// Returns `TrustError::Sqlite` if the underlying `count(*)` query fails.
    pub fn has_tampering_at_or_before(&self, commit: &str) -> Result<bool, TrustError> {
        let topo: Option<i64> = self
            .conn
            .query_row(
                "SELECT effective_commit_topo_pos FROM trust_events WHERE effective_commit = ?1",
                [commit],
                |r| r.get(0),
            )
            .ok();
        let Some(topo) = topo else {
            return Ok(false);
        };
        let count: i64 = self.conn.query_row(
            "SELECT count(*) FROM trust_chain_tampering WHERE at_topo_pos <= ?1",
            [topo],
            |r| r.get(0),
        )?;
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

    let mut ctx = RebuildCtx {
        tx: &tx,
        chain: ChainState::new(),
        counters: Counters::default(),
        notebook_git,
    };
    let mut prev_log: Option<EventLog> = None;

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

        apply_revision(&mut ctx, &log, prev_log.as_ref(), commit, topo_pos)?;
        prev_log = Some(log);
    }

    let parsed = git_rev_parse(notebook_git, &["HEAD", "HEAD:.trust/events.yml"])?;
    let head_sha = parsed.first().map(String::as_str).unwrap_or_default();
    let blob_sha = parsed.get(1).map(String::as_str).unwrap_or_default();
    update_sentinels(&tx, head_sha, blob_sha)?;

    let counters = ctx.counters;
    tx.commit()?;
    Ok(Materialization {
        events_count: counters.events,
        tampering_count: counters.tampering,
    })
}

/// Mutable per-rebuild context threaded through the materializer loop. Bundles
/// the transaction handle, in-memory chain state, running counters, and the
/// notebook.git path the loop reads from. Keeps the per-revision dispatch
/// surface narrow without sharding state across many separate parameters.
struct RebuildCtx<'tx> {
    tx: &'tx Transaction<'tx>,
    chain: ChainState,
    counters: Counters,
    notebook_git: &'tx Path,
}

/// Running counts threaded through the materializer loop. Captures the
/// number of rows written to `trust_events` and `trust_chain_tampering` so
/// the surrounding [`rebuild`] can return them via [`Materialization`].
#[derive(Debug, Default)]
struct Counters {
    events: u32,
    tampering: u32,
}

/// Saturating-cast helper for the topological-position trio used across
/// the materializer's INSERT params and chain-state APIs. The `usize` →
/// `u64` direction can only saturate on platforms where `usize` is wider
/// than 64 bits (none currently supported), so the `unwrap_or` is purely
/// defensive.
fn topo_u64(pos: usize) -> u64 {
    u64::try_from(pos).unwrap_or(u64::MAX)
}

/// Saturating-cast helper for SQL `INTEGER` columns that hold the
/// topological position. `i64::try_from` saturates only beyond
/// `2^63 - 1` topological positions, which the spec doesn't approach.
fn topo_i64(pos: usize) -> i64 {
    i64::try_from(pos).unwrap_or(i64::MAX)
}

/// Apply a single events.yml revision: bootstrap on the first iteration,
/// otherwise classify the diff against `prev` and route the result through
/// the materializer's tampering/append handling.
fn apply_revision(
    ctx: &mut RebuildCtx<'_>,
    log: &EventLog,
    prev: Option<&EventLog>,
    commit: &crate::trust::git_history::TopoCommit,
    topo_pos: usize,
) -> Result<(), TrustError> {
    if topo_pos == 0 {
        insert_bootstrap_row(
            ctx.tx,
            log,
            &commit.sha,
            topo_pos,
            commit.signer.as_deref(),
            &mut ctx.chain,
        )?;
        ctx.counters.events += 1;
        return Ok(());
    }

    let prev = prev.expect("non-zero topo_pos implies prev_log set");
    // `topo_pos > 0` is guaranteed by the early-return guard above, so the
    // `topo_pos - 1` can't underflow.
    let parent_topo = topo_u64(topo_pos - 1);
    let here_topo = topo_u64(topo_pos);
    let here_topo_sql = topo_i64(topo_pos);

    match classify_diff(prev, log) {
        Diff::Append(new_event) => {
            let signer_fp = commit.signer.as_deref().unwrap_or("");
            if ctx
                .chain
                .is_authorized_to_extend_chain(signer_fp, parent_topo)
            {
                let chain_validated_by = ctx.chain.introducer_of(signer_fp);
                write_event_row(
                    ctx.tx,
                    &new_event,
                    &commit.sha,
                    here_topo,
                    signer_fp,
                    chain_validated_by.as_deref(),
                    None,
                )?;
                apply_event_to_chain(&mut ctx.chain, &new_event, here_topo);
                ctx.counters.events += 1;
            } else {
                write_tampering_row(
                    ctx.tx,
                    &commit.sha,
                    here_topo_sql,
                    &new_event.event_id.to_string(),
                    TamperingKind::ReorderedDeleted,
                )?;
                ctx.chain.freeze(here_topo);
                ctx.counters.tampering += 1;
            }
        }
        Diff::Reanchor(new_event) => {
            apply_reanchor_diff(ctx, &new_event, commit, here_topo, here_topo_sql)?;
        }
        Diff::NoOp => {
            // Whitespace / comment-only diff. Both revisions deserialize to
            // structurally-identical event lists; nothing to record.
        }
        Diff::Forbidden { kind, event_id } => {
            write_tampering_row(ctx.tx, &commit.sha, here_topo_sql, &event_id, kind)?;
            ctx.chain.freeze(here_topo);
            ctx.counters.tampering += 1;
        }
    }
    Ok(())
}

/// Apply a `Diff::Reanchor` revision: run the four-condition authorization
/// check, then either persist a `BootstrapReanchor` row + advance the chain
/// state (authorized) or freeze the chain via the `chain_frozen_at_topo`
/// meta sentinel (unauthorized). Extracted from `apply_revision` so the
/// dispatch loop stays under the per-function line budget.
fn apply_reanchor_diff(
    ctx: &mut RebuildCtx<'_>,
    new_event: &Event,
    commit: &crate::trust::git_history::TopoCommit,
    here_topo: u64,
    here_topo_sql: i64,
) -> Result<(), TrustError> {
    let pin = read_pin(&home_for(ctx.notebook_git)).ok();
    let signer_fp = commit.signer.as_deref();
    if !verify_reanchor_authorization(new_event, signer_fp, &ctx.chain, pin.as_ref()) {
        ctx.chain.freeze(here_topo);
        crate::index::meta::write_meta_min_topo(
            ctx.tx,
            crate::index::meta::KEY_CHAIN_FROZEN_AT_TOPO,
            here_topo_sql,
        )?;
        return Ok(());
    }
    let EventKind::BootstrapReanchor {
        old_fingerprint,
        new_fingerprint,
        acknowledge_chain_anchor_lost,
        ..
    } = &new_event.payload
    else {
        unreachable!("Diff::Reanchor implies BootstrapReanchor payload");
    };
    let case = if *acknowledge_chain_anchor_lost {
        ReanchorCase::B
    } else {
        ReanchorCase::A
    };
    // The reanchor commit's signing key is the new bootstrap by construction
    // (verified above). Persist the row and update the chain state so
    // post-reanchor records validate against the new root, while pre-reanchor
    // records carry their `case` marker.
    let signer_for_row = signer_fp.unwrap_or(new_fingerprint.as_str());
    write_event_row(
        ctx.tx,
        new_event,
        &commit.sha,
        here_topo,
        signer_for_row,
        None,
        Some(case),
    )?;
    ctx.chain.apply_reanchor(
        old_fingerprint,
        new_fingerprint,
        &new_event.event_id.to_string(),
        here_topo,
        case,
    );
    ctx.counters.events += 1;
    Ok(())
}

/// Derive the home directory (`~/.nexum/`) from the path of the notebook git
/// working tree. Production layout has `notebook.git` as a sibling of
/// `config.toml` and `.bootstrap-fingerprint` inside `~/.nexum/`, so the
/// home is just the parent. An empty path returns `PathBuf::new()`, which
/// the pin reader treats as missing (`read_pin` returns `Err`).
fn home_for(notebook_git: &Path) -> std::path::PathBuf {
    notebook_git
        .parent()
        .map_or_else(std::path::PathBuf::new, Path::to_path_buf)
}

/// Authorize a `BootstrapReanchor` event against the four conditions from
/// the design spec:
/// 1. The diff classifier surfaced the event as `Diff::Reanchor`, which
///    structurally guarantees the new revision adds exactly one event and
///    that event is `BootstrapReanchor`. Enforced before the call.
/// 2. The bootstrap pin in `config.toml` matches `new_fingerprint`. The pin
///    is the only piece of trust state outside `notebook.git`, so its match
///    is what authorizes a chain break. Missing pin → unauthorized.
/// 3. `old_fingerprint` matches the chain's most recent prior bootstrap.
///    `ChainState::current_bootstrap_fp` tracks this across reanchors so a
///    later reanchor's `old_fp` must equal the prior reanchor's `new_fp`.
/// 4. The commit is signed by `new_fingerprint`.
///
/// Case A vs. Case B (whether pre-reanchor records carry the
/// `chain-anchor-lost` warning) is a separate axis carried on the event
/// payload itself via `acknowledge_chain_anchor_lost`, not derived here.
fn verify_reanchor_authorization(
    new_event: &Event,
    signer_fp: Option<&str>,
    chain: &ChainState,
    pin: Option<&BootstrapPin>,
) -> bool {
    let EventKind::BootstrapReanchor {
        old_fingerprint,
        new_fingerprint,
        ..
    } = &new_event.payload
    else {
        return false;
    };
    let Some(pin) = pin else {
        return false;
    };
    let pin_match = pin.fingerprint == *new_fingerprint;
    let old_match = chain.current_bootstrap_fp() == Some(old_fingerprint.as_str());
    let signed_by_new = signer_fp == Some(new_fingerprint.as_str());
    pin_match && old_match && signed_by_new
}

/// Insert a row into `trust_chain_tampering` with the supplied classification.
fn write_tampering_row(
    tx: &Transaction<'_>,
    commit_sha: &str,
    topo_pos: i64,
    event_id: &str,
    kind: TamperingKind,
) -> Result<(), TrustError> {
    tx.execute(
        "INSERT INTO trust_chain_tampering \
         (at_commit, at_topo_pos, event_id, kind, detected_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            commit_sha,
            topo_pos,
            event_id,
            kind.as_db_str(),
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}

/// Insert the `BootstrapKey` row for the first revision and seed the
/// in-memory `ChainState` with the bootstrap signer. Validates that the
/// revision contains exactly one event of the expected kind. Routes the
/// SQL INSERT through [`write_event_row`] so the column projection stays
/// in one place; bootstrap-specific logic (length check, signer fallback,
/// `ChainState::set_bootstrap` seeding) stays here.
fn insert_bootstrap_row(
    tx: &Transaction<'_>,
    log: &EventLog,
    commit_sha: &str,
    topo_pos: usize,
    signer: Option<&str>,
    chain: &mut ChainState,
) -> Result<(), TrustError> {
    if log.events.len() != 1 {
        return Err(TrustError::MalformedBootstrap);
    }
    let event = &log.events[0];
    let EventKind::BootstrapKey { fingerprint, .. } = &event.payload else {
        return Err(TrustError::MalformedBootstrap);
    };

    // Bootstrap commits are introduced by their own signing key — fall back
    // to the bootstrap fingerprint if the commit was unsigned (defensive;
    // the production init path always signs).
    let introduced_by_signer = signer.unwrap_or(fingerprint.as_str());

    let here_topo = topo_u64(topo_pos);
    write_event_row(
        tx,
        event,
        commit_sha,
        here_topo,
        introduced_by_signer,
        None,
        None,
    )?;
    chain.set_bootstrap(fingerprint, &event.event_id.to_string(), here_topo);
    Ok(())
}

/// Insert any event row (bootstrap or otherwise). Uses one SQL INSERT
/// covering the full 13-column layout; columns the payload kind doesn't
/// populate stay NULL by binding `Option::None`. `reanchor_case` is `Some`
/// only on `BootstrapReanchor` rows and is persisted to `chain_anchor_lost`
/// (0 for Case A, 1 for Case B) so read-time projection can hydrate the
/// case without re-walking events.yml history.
fn write_event_row(
    tx: &Transaction<'_>,
    ev: &Event,
    commit_sha: &str,
    topo_pos: u64,
    signer_fp: &str,
    chain_validated_by: Option<&str>,
    reanchor_case: Option<ReanchorCase>,
) -> Result<(), TrustError> {
    let kind = ev.payload.as_db_str();
    let (fp, old_fp, new_fp, public_key, reason) = match &ev.payload {
        EventKind::BootstrapKey {
            fingerprint,
            public_key,
            reason,
        }
        | EventKind::KeyAdded {
            fingerprint,
            public_key,
            reason,
        } => (
            Some(fingerprint.as_str()),
            None,
            None,
            Some(public_key.as_str()),
            Some(reason.as_str()),
        ),
        EventKind::KeyRotatedOut {
            fingerprint,
            reason,
        }
        | EventKind::KeyCompromised {
            fingerprint,
            reason,
        } => (
            Some(fingerprint.as_str()),
            None,
            None,
            None,
            Some(reason.as_str()),
        ),
        EventKind::BootstrapReanchor {
            old_fingerprint,
            new_fingerprint,
            reason,
            ..
        } => (
            None,
            Some(old_fingerprint.as_str()),
            Some(new_fingerprint.as_str()),
            None,
            Some(reason.as_str()),
        ),
    };
    let chain_anchor_lost = reanchor_case.map(|c| match c {
        ReanchorCase::A => 0_i64,
        ReanchorCase::B => 1_i64,
    });
    tx.execute(
        "INSERT INTO trust_events (
            event_id, kind, fingerprint, old_fingerprint, new_fingerprint, public_key,
            effective_commit, effective_commit_topo_pos,
            introduced_by_signer, chain_validated_by, reason, chain_anchor_lost,
            materialized_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            ev.event_id.to_string(),
            kind,
            fp,
            old_fp,
            new_fp,
            public_key,
            commit_sha,
            i64::try_from(topo_pos).unwrap_or(i64::MAX),
            signer_fp,
            chain_validated_by,
            reason,
            chain_anchor_lost,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Mutate `chain` according to the event payload. Only invoked for
/// `Diff::Append` events: `BootstrapKey` seeding lives in
/// `insert_bootstrap_row`, and `BootstrapReanchor` is dispatched directly in
/// `apply_revision` (which calls `chain.apply_reanchor` itself, since the
/// reanchor path also persists chain freezes for the unauthorized branch).
/// The two unreachable arms exist so this function stays exhaustive against
/// `EventKind` without forcing callers to filter the input.
fn apply_event_to_chain(chain: &mut ChainState, ev: &Event, topo_pos: u64) {
    let event_id = ev.event_id.to_string();
    match &ev.payload {
        EventKind::BootstrapKey { .. } | EventKind::BootstrapReanchor { .. } => {}
        EventKind::KeyAdded { fingerprint, .. } => {
            chain.apply_key_added(fingerprint, &event_id, topo_pos);
        }
        EventKind::KeyRotatedOut { fingerprint, .. } => {
            chain.apply_key_rotated_out(fingerprint, topo_pos);
        }
        EventKind::KeyCompromised { fingerprint, .. } => {
            chain.apply_key_compromised(fingerprint, topo_pos);
        }
    }
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
