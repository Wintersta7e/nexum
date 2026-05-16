//! Thin facade both the CLI and (later) MCP surfaces call into. Verbs match
//! the agreed surface table; each opens its own `SQLite` connection — pooling
//! lands in a later milestone.

pub mod error;

use crate::{
    config::types::Config,
    indexer::{
        IndexerOpts, IndexerOutcome,
        db::{IndexerError, open_existing, open_existing_writable, open_or_create},
        run::{
            run as indexer_run, run_force as indexer_run_force,
            run_with_opts as indexer_run_with_opts,
        },
    },
    paths::Paths,
    query::{
        EmbedStatus, Filters, GetOpts, ResultSet, SearchOpts, SessionLookup,
        by_session::by_session as query_by_session, get::get as query_get,
        list::list as query_list, recent::recent as query_recent, search::search as query_search,
    },
    records::{GetOutcome, RecordKey},
};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    Indexer(#[from] crate::indexer::IndexerError),
    #[error(transparent)]
    Query(crate::query::QueryError),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("index schema v{v_disk} is older than this binary (v{v_code}); run `nexum migrate`")]
    MigrationRequired { v_disk: u32, v_code: u32 },
    #[error("trust regenerate refused: {reason}")]
    TrustRegenerateRefused { reason: String },
    #[error("trust regenerate failed: {stderr}")]
    TrustRegenerateFailed { stderr: String },
    // No #[from] — kept as a manual impl below to avoid coherence collision
    // with the existing From<QueryError> which also wraps TrustError.
    #[error(transparent)]
    Trust(crate::trust::events::TrustError),
}

impl From<crate::query::QueryError> for ApiError {
    fn from(err: crate::query::QueryError) -> Self {
        match err {
            crate::query::QueryError::MigrationRequired { v_disk } => ApiError::MigrationRequired {
                v_disk,
                v_code: crate::index::schema::INDEX_DB_LATEST_VERSION,
            },
            other => ApiError::Query(other),
        }
    }
}

// Trust errors raised directly (e.g. from admin verbs) surface as
// `ApiError::Trust`. The read pipeline's `ensure_current` path goes through
// `From<QueryError>` → `ApiError::Query(QueryError::Trust(_))`; that arm
// still exists and both variants map to the same `trust_envelope` in
// `api/error.rs`.
impl From<crate::trust::events::TrustError> for ApiError {
    fn from(e: crate::trust::events::TrustError) -> Self {
        ApiError::Trust(e)
    }
}

/// Acquire the exclusive writer lock at `~/.nexum/.lock`, run `body`, and
/// release the lock unconditionally on return (success, early-return, or
/// error inside the closure).
///
/// All four writer verbs (`index_reembed`, `migrate_index_db`,
/// `trust_regenerate_files`, `keys_rotate`) share the same acquire / release
/// shape; centralizing it removes ~50 lines of boilerplate and ensures the
/// release happens on every error path without needing a `lock_file.unlock()`
/// before every `return`.
///
/// The closure receives nothing — it just runs under the held lock and is
/// responsible for any rollback inside its own error-handling paths.
fn with_writer_lock<T>(
    paths: &Paths,
    body: impl FnOnce() -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    use fs2::FileExt as _;

    let lock_io_err = |e: std::io::Error| {
        ApiError::Indexer(IndexerError::Io {
            path: paths.lock.clone(),
            source: e,
        })
    };
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&paths.lock)
        .map_err(lock_io_err)?;
    lock_file.try_lock_exclusive().map_err(lock_io_err)?;

    let result = body();
    lock_file.unlock().ok();
    result
}

/// Run a reindex pass (default: incremental).
///
/// # Errors
///
/// Returns `ApiError::Indexer` on any indexer failure.
pub fn index_run(paths: &Paths, cfg: &Config) -> Result<IndexerOutcome, ApiError> {
    let mut conn = open_or_create(&paths.index_db)?;
    Ok(indexer_run(&mut conn, cfg, paths)?)
}

/// Run a `--force` reindex pass (immediate-delete on the current pass).
///
/// # Errors
///
/// Returns `ApiError::Indexer` on any indexer failure.
pub fn index_run_force(paths: &Paths, cfg: &Config) -> Result<IndexerOutcome, ApiError> {
    let mut conn = open_or_create(&paths.index_db)?;
    Ok(indexer_run_force(&mut conn, cfg, paths)?)
}

/// Run an indexer pass with the stale-row sweep threshold optionally lowered.
///
/// The mechanism is the regular pass plus a `threshold_override` threaded
/// through `apply_deletes`; nothing about the pass itself is "forced". When
/// `aggressive` is `true`, the threshold drops to 1 so the check fires
/// immediately on the first miss instead of waiting for `STALE_THRESHOLD`
/// (3) consecutive misses. Backing verb for `nexum index --sweep
/// [--aggressive]`.
///
/// Acquires `~/.nexum/.lock` via the same mechanism as the other admin verbs
/// (`index_reembed`, `migrate_index_db`, `trust_regenerate_files`,
/// `keys_rotate`).
///
/// # Errors
///
/// Returns `ApiError::Indexer` on any indexer failure.
pub fn index_sweep(
    paths: &Paths,
    cfg: &Config,
    aggressive: bool,
) -> Result<IndexerOutcome, ApiError> {
    with_writer_lock(paths, || {
        let mut conn = open_or_create(&paths.index_db)?;
        let opts = IndexerOpts {
            threshold_override: aggressive.then_some(1),
        };
        Ok(indexer_run_with_opts(&mut conn, cfg, paths, opts)?)
    })
}

/// Outcome of a `--reembed` pass.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReembedOutcome {
    /// Number of records that received a new embedding vector.
    pub embedded: u64,
    /// Number of records whose embedder call failed and were left
    /// unchanged (still logged at `warn` for the operator).
    pub failed: u64,
    /// Records already current (hash-stable skip — not yet implemented;
    /// placeholder always returns 0).
    pub skipped_current: u64,
    /// Resume cursor after a partial run. `None` after a clean completion.
    pub resume_rowid: Option<i64>,
}

/// Re-embed every record already in the index against the configured
/// embedder. Refuses if `cfg.embed.enabled = false`.
///
/// Acquires the writer lock so two concurrent `--reembed` invocations
/// cannot race the resume cursor. (The default `index_run` / `index_run_force`
/// paths do not take the writer lock today, so a long-running `--reembed`
/// against an actively-indexed store can still trail the head; the lock
/// here only protects against duplicate reembed jobs.) Released on every
/// return path.
///
/// # Errors
///
/// Returns `ApiError::Config(ConfigError::Invalid)` if embed is not enabled.
/// Returns `ApiError::Indexer` on any indexer or lock failure.
pub fn index_reembed(paths: &Paths, cfg: &Config) -> Result<ReembedOutcome, ApiError> {
    if !cfg.embed.enabled {
        return Err(ApiError::Config(crate::config::ConfigError::Invalid {
            field: "embed.enabled".into(),
            reason: "--reembed requires [embed].enabled = true".into(),
        }));
    }
    with_writer_lock(paths, || {
        let mut conn = open_existing_writable(&paths.index_db)?;
        Ok(crate::indexer::run::run_reembed_existing(
            &mut conn, cfg, paths,
        )?)
    })
}

/// Run the registered index-DB migrators under the writer lock.
///
/// Acquires `~/.nexum/.lock` exclusively before opening the database so no
/// concurrent indexer or reembed pass races the migration. Opens with raw
/// `rusqlite::Connection::open_with_flags(READ_WRITE)` rather than
/// `open_existing_writable` because that helper rejects an under-versioned
/// store with `MigrationRequired`, which is the exact case this verb exists
/// to resolve.
///
/// # Errors
///
/// Returns `ApiError::Indexer(IndexerError::Io)` if the lock file cannot be
/// opened or the exclusive lock cannot be acquired (store busy).
/// Returns `ApiError::Indexer(IndexerError::Rusqlite)` if the DB cannot be
/// opened. Returns `ApiError::Indexer(IndexerError::Migration)` on any
/// migration failure (step error, incompatible store, post-apply schema
/// verification failure).
pub fn migrate_index_db(paths: &Paths) -> Result<crate::migrate::MigrationOutcome, ApiError> {
    with_writer_lock(paths, || {
        // Register the sqlite-vec auto-extension before opening the raw
        // connection. The open_or_create / open_existing_* helpers do this
        // internally, but migrate_index_db bypasses them intentionally
        // (open_existing_writable rejects under-versioned stores with
        // MigrationRequired). Without this call, a DB that contains vec0
        // virtual tables would fail to open because the extension is not yet
        // loaded for this process.
        crate::indexer::db::register_sqlite_vec_once();

        // Open with raw rusqlite rather than open_existing_writable: the
        // open_existing_with_flags helper returns MigrationRequired when
        // v_disk < INDEX_DB_LATEST_VERSION, which is precisely the case we
        // are here to handle.
        let mut conn = rusqlite::Connection::open_with_flags(
            &paths.index_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|e| ApiError::Indexer(IndexerError::Rusqlite(e)))?;

        crate::migrate::index_db::migrate_to_latest(
            &mut conn,
            &paths.index_db,
            /* lock_held = */ true,
        )
        .map_err(|e| match e {
            // Unreachable in practice (lock_held = true silences the migrator's
            // own MigrationRequired arm), but defensive: route to the dedicated
            // ApiError::MigrationRequired so the wire keeps its exit-code-6
            // signal if the framework ever changes shape.
            crate::migrate::MigrationError::MigrationRequired { v_disk, v_code } => {
                ApiError::MigrationRequired { v_disk, v_code }
            }
            other => ApiError::Indexer(IndexerError::Migration(other)),
        })
    })
}

/// Outcome of `nexum trust regenerate-files`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrustRegenerateOutcome {
    /// The three derived signer files already match `events.yml`; no commit.
    NoChange,
    /// A signed commit landed with the listed files (relative to `notebook.git/`).
    Committed { commit: String, files: Vec<String> },
}

/// Re-derive the three OpenSSH-format signer files from
/// `notebook.git/.trust/events.yml` and stage them in a signed commit.
///
/// Acquires `~/.nexum/.lock`. Refuses if `notebook.git/.git/MERGE_HEAD`
/// exists or `~/.nexum/.reanchor_pending` is present. On either commit
/// or verify failure the worktree is reset so a partial regeneration
/// never lingers (per the no-dirty-worktree rule).
///
/// # Errors
///
/// `ApiError::TrustRegenerateRefused` on precondition failure (merge in
/// progress, pending reanchor).
/// `ApiError::TrustRegenerateFailed` on commit or verify failure (the
/// worktree is rolled back before this returns).
/// `ApiError::Trust` on trust-state read errors.
/// `ApiError::Indexer(IndexerError::Io)` on lock failures.
pub fn trust_regenerate_files(paths: &Paths) -> Result<TrustRegenerateOutcome, ApiError> {
    with_writer_lock(paths, || {
        let merge_head = paths.notebook_git.join(".git/MERGE_HEAD");
        if merge_head.exists() {
            return Err(ApiError::TrustRegenerateRefused {
                reason: "in-progress merge detected (notebook.git/.git/MERGE_HEAD exists); abort or complete it first".into(),
            });
        }
        crate::trust::reanchor_pending::check(&paths.home).map_err(ApiError::Trust)?;

        let events_yml = paths.notebook_git.join(".trust/events.yml");
        let trust_dir = paths.notebook_git.join(".trust");
        let outcome = crate::trust::regenerate::regenerate_files(&events_yml, &trust_dir)
            .map_err(ApiError::Trust)?;

        let touched: Vec<String> = match outcome {
            crate::trust::regenerate::RegenerateOutcome::NoChange => {
                return Ok(TrustRegenerateOutcome::NoChange);
            }
            crate::trust::regenerate::RegenerateOutcome::Updated { files } => {
                files.iter().map(|s| (*s).to_owned()).collect()
            }
        };

        let staged_pathbufs: Vec<std::path::PathBuf> = touched
            .iter()
            .map(|name| std::path::PathBuf::from(format!(".trust/{name}")))
            .collect();
        let staged_refs: Vec<&std::path::Path> = staged_pathbufs
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect();
        let message = "trust: regenerate signer projections from events.yml";

        // Regenerate may have rewritten worktree files to match HEAD (e.g. a
        // pure worktree tamper restored to canonical content). Stage the paths
        // and bail if nothing differs from HEAD — no empty commit.
        let _ = std::process::Command::new("git")
            .arg("add")
            .args(&staged_refs)
            .current_dir(&paths.notebook_git)
            .output();
        let diff_status = std::process::Command::new("git")
            .args(["diff", "--cached", "--quiet"])
            .current_dir(&paths.notebook_git)
            .status();
        if matches!(diff_status, Ok(s) if s.success()) {
            return Ok(TrustRegenerateOutcome::NoChange);
        }

        let commit = match crate::init::git_ops::git_commit_signed(
            &paths.notebook_git,
            &staged_refs,
            message,
        ) {
            Ok(sha) => sha,
            Err(commit_err) => {
                let _ = std::process::Command::new("git")
                    .args(["reset", "--hard", "HEAD"])
                    .current_dir(&paths.notebook_git)
                    .output();
                return Err(ApiError::TrustRegenerateFailed {
                    stderr: format!("git commit failed: {commit_err}"),
                });
            }
        };

        let historical = paths.notebook_git.join(".trust/historical_signers");
        if let Err(verify_err) = crate::init::git_ops::git_verify_commit_with_signers(
            &paths.notebook_git,
            "HEAD",
            &historical,
        ) {
            let _ = std::process::Command::new("git")
                .args(["reset", "--hard", "HEAD~1"])
                .current_dir(&paths.notebook_git)
                .output();
            return Err(ApiError::TrustRegenerateFailed {
                stderr: verify_err.to_string(),
            });
        }

        Ok(TrustRegenerateOutcome::Committed {
            commit,
            files: touched,
        })
    })
}

/// Outcome of `nexum keys rotate`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeysRotateOutcome {
    /// SSH fingerprint of the newly-added key.
    pub new_fingerprint: String,
    /// SHA of the signed rotation commit.
    pub commit: String,
    /// Bare file names that were staged and committed (events.yml + any
    /// regenerated signer files).
    pub regenerated_files: Vec<String>,
}

/// Append a `KeyAdded` event for the key at `new_key_path` to `events.yml`,
/// regenerate the derived signer files, sign the rotation commit with the
/// CURRENT (still-trusted) key, verify post-commit, and only then update
/// `notebook.git/.git/config user.signingkey` to the new key.
///
/// `new_key_path` is the **private**-key path. The function reads
/// `<path>.pub` to obtain the public-key blob and computes its fingerprint via
/// `crate::ssh_key::compute_fingerprint`.
///
/// # Errors
///
/// `ApiError::Trust(TrustError::DuplicateKey)` if the fingerprint already
/// appears in events.yml in any role.
/// `ApiError::TrustRegenerateRefused` on pre-flight failure (in-progress
/// merge, pending reanchor, or current bootstrap key already revoked).
/// `ApiError::TrustRegenerateFailed` on commit or verify failure; the
/// worktree is reset before this returns so no partial state lingers.
/// `ApiError::Indexer(IndexerError::Io)` on lock failures.
// The verb is a straight-line sequence of admin steps (preconds →
// duplicate-check → write events → regenerate → stage → diff → sign →
// verify → rollback-on-fail → update signingkey). Each step earns its own
// comment; splitting into sub-functions would hide the ordering that's
// load-bearing for the trust-chain invariant.
#[allow(clippy::too_many_lines)]
pub fn keys_rotate(
    paths: &Paths,
    cfg: &Config,
    new_key_path: &std::path::Path,
    reason: &str,
) -> Result<KeysRotateOutcome, ApiError> {
    with_writer_lock(paths, || {
        // Pre-flight: refuse if an in-progress merge is detected.
        let merge_head = paths.notebook_git.join(".git/MERGE_HEAD");
        if merge_head.exists() {
            return Err(ApiError::TrustRegenerateRefused {
                reason: "in-progress merge detected; abort or complete it first".into(),
            });
        }

        // Pre-flight: refuse if a reanchor sentinel is present.
        crate::trust::reanchor_pending::check(&paths.home).map_err(ApiError::Trust)?;

        // Pre-flight: the current bootstrap key must still be trusted. If it has a
        // KeyRotatedOut or KeyCompromised event the rotation commit would be signed
        // by an untrusted key and verify would fail. Surface a clean refusal rather
        // than committing then rolling back.
        let events_yml = paths.notebook_git.join(".trust/events.yml");
        let current_fp = &cfg.trust.bootstrap.fingerprint;
        let event_log =
            crate::trust::events::load_events_yml(&events_yml).map_err(ApiError::Trust)?;
        let current_trusted = event_log.events.iter().all(|e| match &e.payload {
            crate::trust::events::EventKind::KeyRotatedOut { fingerprint, .. }
            | crate::trust::events::EventKind::KeyCompromised { fingerprint, .. } => {
                fingerprint != current_fp
            }
            _ => true,
        });
        if !current_trusted {
            return Err(ApiError::TrustRegenerateRefused {
                reason: format!(
                    "current bootstrap key {current_fp} is no longer trusted; \
                     rotation requires a trusted signer (keys recover is the recovery path)"
                ),
            });
        }

        // Read the new key's public-key blob and compute its fingerprint.
        let pub_path = {
            let mut s = new_key_path.as_os_str().to_owned();
            s.push(".pub");
            std::path::PathBuf::from(s)
        };
        let public_key = std::fs::read_to_string(&pub_path)
            .map_err(|e| {
                ApiError::Indexer(IndexerError::Io {
                    path: pub_path.clone(),
                    source: e,
                })
            })?
            .trim()
            .to_owned();
        let fingerprint = crate::ssh_key::compute_fingerprint(&public_key).map_err(|e| {
            ApiError::TrustRegenerateRefused {
                reason: format!(
                    "could not compute SSH fingerprint of {}: {e}",
                    pub_path.display()
                ),
            }
        })?;

        let new_key = crate::trust::rotate::NewKey {
            fingerprint: fingerprint.clone(),
            public_key,
        };

        let trust_dir = paths.notebook_git.join(".trust");
        let touched =
            crate::trust::rotate::append_key_added(&events_yml, &trust_dir, &new_key, reason)
                .map_err(ApiError::Trust)?;

        // Stage paths with the `.trust/` prefix required by the notebook layout.
        let staged_pathbufs: Vec<std::path::PathBuf> = touched
            .iter()
            .map(|name| std::path::PathBuf::from(format!(".trust/{name}")))
            .collect();
        let staged_refs: Vec<&std::path::Path> = staged_pathbufs
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect();

        // Build a short fingerprint suffix for the commit message: the last 12
        // chars of the base64 body, with trailing `=` padding stripped. The
        // body is ASCII so byte-slicing is safe.
        let body = fingerprint
            .split(':')
            .next_back()
            .unwrap_or(&fingerprint)
            .trim_end_matches('=');
        let short = body.get(body.len().saturating_sub(12)..).unwrap_or(body);
        let commit_msg = format!("trust: add signing key {short}");

        // Sign with the CURRENT key (user.signingkey still points at the old key).
        let commit = match crate::init::git_ops::git_commit_signed(
            &paths.notebook_git,
            &staged_refs,
            &commit_msg,
        ) {
            Ok(sha) => sha,
            Err(commit_err) => {
                let _ = std::process::Command::new("git")
                    .args(["reset", "--hard", "HEAD"])
                    .current_dir(&paths.notebook_git)
                    .output();
                return Err(ApiError::TrustRegenerateFailed {
                    stderr: format!("git commit failed: {commit_err}"),
                });
            }
        };

        // Verify the rotation commit using historical_signers (which now includes
        // the new key but was signed by the old key — the old key must still be in
        // historical_signers for this to pass).
        let historical = paths.notebook_git.join(".trust/historical_signers");
        if let Err(verify_err) = crate::init::git_ops::git_verify_commit_with_signers(
            &paths.notebook_git,
            "HEAD",
            &historical,
        ) {
            let _ = std::process::Command::new("git")
                .args(["reset", "--hard", "HEAD~1"])
                .current_dir(&paths.notebook_git)
                .output();
            return Err(ApiError::TrustRegenerateFailed {
                stderr: verify_err.to_string(),
            });
        }

        // ONLY after verify succeeds: update user.signingkey to the new key path.
        // A failure here is non-fatal — the commit is already signed and verified;
        // the operator can update git config manually.
        let update_result = std::process::Command::new("git")
            .args(["config", "user.signingkey"])
            .arg(new_key_path)
            .current_dir(&paths.notebook_git)
            .output();
        if let Ok(out) = &update_result
            && !out.status.success()
        {
            tracing::warn!(
                target: "nexum::trust",
                "git config user.signingkey update failed after successful rotation commit; \
                 update it manually to {}",
                new_key_path.display(),
            );
        }

        Ok(KeysRotateOutcome {
            new_fingerprint: fingerprint,
            commit,
            regenerated_files: touched,
        })
    })
}

/// Open the index DB and prime the trust-events view for a read verb.
///
/// Read verbs share two preconditions: the DB must already exist
/// (`open_existing` errors if not — surfaced as `IndexMissing` so the CLI
/// can hint at running `nexum index`), and the materialized trust view
/// must be current with respect to `notebook.git` (`ensure_current` is a
/// no-op on a hot path / a full rebuild on a stale or missing one).
/// Centralizing both steps so a future read verb cannot land without
/// either.
fn open_for_query(paths: &Paths) -> Result<rusqlite::Connection, ApiError> {
    let mut conn = open_existing_writable(&paths.index_db)?;
    crate::trust::events_view::ensure_current(&mut conn, &paths.notebook_git)?;
    Ok(conn)
}

/// Hybrid search: FTS plus an optional vector branch when an embedder is
/// configured and the query embedding succeeds.
///
/// The `cfg.trust.ranking_penalty` value overrides any
/// `unsigned_ranking_penalty` set on `opts` so a single configured value
/// drives both ranking and presentation. `cfg.trust.strict_revocation`
/// likewise overrides `opts.filters.strict_revocation` so the projection
/// uses the runtime configuration.
///
/// When `cfg.embed.enabled` is true the facade attempts to load the
/// embedder and embed `opts.query`. Failure at either step degrades to
/// FTS-only and sets `meta.embed_pool_saturated` so callers see that the
/// requested semantic ranking was not applied.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite or filter encoding failure (and
/// on materializer rebuild failure, routed through `QueryError::Trust`).
pub fn search(paths: &Paths, cfg: &Config, opts: &SearchOpts) -> Result<ResultSet, ApiError> {
    let conn = open_for_query(paths)?;
    let (query_vector, embed_status) = build_query_vector(cfg, &opts.query);
    let mut effective_opts = opts.clone();
    effective_opts.unsigned_ranking_penalty = cfg.trust.ranking_penalty;
    // Stricter prevails: per-call flag wins if set, config default applies
    // otherwise. Same shape across every read verb.
    effective_opts.filters.strict_revocation =
        opts.filters.strict_revocation || cfg.trust.strict_revocation;
    effective_opts.query_vector = query_vector;
    effective_opts.top_k_semantic = cfg.embed.top_k_semantic;
    effective_opts.top_k_fts = cfg.embed.top_k_fts;
    effective_opts.embed_status = embed_status;
    // Wanted-but-didn't-get-it signal. The bool is kept for back-compat so
    // existing JSON consumers see the same shape; `embed_status` carries the
    // richer per-variant signal. The bool fires for every degraded variant
    // (Saturated / ModelMissing / EmbedFailed) — matching the pre-split
    // semantics — and stays false for Ok and Disabled. `or` so an explicit
    // caller flag still wins.
    let degraded = matches!(
        embed_status,
        EmbedStatus::Saturated | EmbedStatus::ModelMissing | EmbedStatus::EmbedFailed,
    );
    effective_opts.embed_pool_saturated = opts.embed_pool_saturated || degraded;
    Ok(query_search(&conn, &effective_opts)?)
}

/// Build the per-query embedding for the facade-side search verb.
///
/// Returns `(query_vector, embed_status)`. The status enum drives the
/// `_meta.embed_status` channel so agents can distinguish transient
/// saturation from an uninstalled model from a runtime embed failure
/// instead of branching on a single overloaded boolean.
///
/// - `cfg.embed.enabled == false` → `(None, Disabled)`: no embedder
///   constructed; the FTS-only path runs unchanged.
/// - `cfg.embed.enabled == true` but the cached load returned
///   `Ok(None)` (model not installed) → `(None, ModelMissing)`.
/// - Cached load errored → log warn, return `(None, EmbedFailed)`.
/// - Load succeeded but `Embedder::embed` errored → log warn, return
///   `(None, EmbedFailed)`.
/// - Load + embed both succeeded → `(Some(vec), Ok)`.
///
/// Logs go to stderr via `tracing` so MCP stdio framing stays clean.
/// The load path is cached process-wide; see
/// [`crate::embed::try_load_from_config_cached`] for the cache invariants.
fn build_query_vector(cfg: &Config, query: &str) -> (Option<Vec<f32>>, EmbedStatus) {
    if !cfg.embed.enabled {
        return (None, EmbedStatus::Disabled);
    }
    let embedder = match crate::embed::try_load_from_config_cached(cfg) {
        Ok(Some(e)) => e,
        Ok(None) => return (None, EmbedStatus::ModelMissing),
        Err(err) => {
            tracing::warn!(
                target: "nexum::embed",
                ?err,
                "failed to load embedder for query; degrading to FTS-only",
            );
            return (None, EmbedStatus::EmbedFailed);
        }
    };
    match embedder.embed(query) {
        Ok(v) => (Some(v), EmbedStatus::Ok),
        Err(err) => {
            tracing::warn!(
                target: "nexum::embed",
                ?err,
                "failed to embed query text; degrading to FTS-only",
            );
            (None, EmbedStatus::EmbedFailed)
        }
    }
}

/// Get one record by composite key; honors the `include_unsigned` escape
/// hatch under `trust_policy = Hide` (an unsigned record returns
/// `HiddenByPolicy` unless the caller opts in).
///
/// `key` may be exact, partial, or bare; partial / bare keys that match
/// more than one row produce `ApiError::Query(QueryError::Ambiguous)`.
///
/// `cfg.trust.strict_revocation` overrides `opts.strict_revocation` so the
/// projection uses the runtime configuration verbatim — same shape as
/// `search`'s opts override.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite / deserialization failure or
/// when the key matches multiple records (`QueryError::Ambiguous`).
pub fn get(
    paths: &Paths,
    cfg: &Config,
    key: &RecordKey,
    opts: &GetOpts,
) -> Result<GetOutcome, ApiError> {
    let conn = open_for_query(paths)?;
    let mut effective_opts = opts.clone();
    effective_opts.strict_revocation = opts.strict_revocation || cfg.trust.strict_revocation;
    Ok(query_get(&conn, key, &effective_opts)?)
}

/// List with filters + pagination.
///
/// `cfg.trust.unsigned_default` is forwarded into the query verb so the
/// response envelope's `_meta.trust_policy` reflects the runtime
/// configuration rather than a hardcoded default.
/// `cfg.trust.strict_revocation` overrides `filters.strict_revocation` so
/// every read verb consults the same configured value.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn list(
    paths: &Paths,
    cfg: &Config,
    filters: &Filters,
    limit: u32,
    cursor: Option<&str>,
) -> Result<ResultSet, ApiError> {
    let conn = open_for_query(paths)?;
    let mut effective_filters = filters.clone();
    effective_filters.strict_revocation = filters.strict_revocation || cfg.trust.strict_revocation;
    Ok(query_list(
        &conn,
        &effective_filters,
        cfg.trust.unsigned_default,
        limit,
        cursor,
    )?)
}

/// Recent records (filter on source optional).
///
/// `cfg.trust.unsigned_default` is forwarded into the query verb so the
/// response envelope's `_meta.trust_policy` reflects the runtime
/// configuration rather than a hardcoded default.
/// `cfg.trust.strict_revocation` flips the compromised-key projection
/// from Verified to Invalid.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure or unknown source name.
pub fn recent(
    paths: &Paths,
    cfg: &Config,
    filters: &Filters,
    limit: u32,
    source: Option<&str>,
) -> Result<ResultSet, ApiError> {
    let conn = open_for_query(paths)?;
    let mut effective_filters = filters.clone();
    effective_filters.strict_revocation = filters.strict_revocation || cfg.trust.strict_revocation;
    let filters = effective_filters;
    Ok(query_recent(
        &conn,
        &filters,
        cfg.trust.unsigned_default,
        limit,
        source,
    )?)
}

/// Records associated with a session ref.
///
/// `cfg.trust.unsigned_default` is forwarded into the query verb so the
/// response envelope's `_meta.trust_policy` reflects the runtime
/// configuration rather than a hardcoded default.
/// `cfg.trust.strict_revocation` flips the compromised-key projection
/// from Verified to Invalid.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn by_session(
    paths: &Paths,
    cfg: &Config,
    filters: &Filters,
    lookup: &SessionLookup,
) -> Result<ResultSet, ApiError> {
    let conn = open_for_query(paths)?;
    let mut effective_filters = filters.clone();
    effective_filters.strict_revocation = filters.strict_revocation || cfg.trust.strict_revocation;
    Ok(query_by_session(
        &conn,
        &effective_filters,
        cfg.trust.unsigned_default,
        lookup,
    )?)
}

/// Per-project record + signed-record counts. The `list_projects` MCP tool
/// reads this verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectSummary {
    pub project_id: String,
    pub identity_kind: String,
    pub record_count: u32,
    pub signed_record_count: u32,
    /// Filesystem path of the project root, recorded only for
    /// `name:`-identity (registered) projects via `nexum project register`.
    /// `None` for `git:` / `cc-slug:` / `codex-cwd:` / path identities — those
    /// carry no stored path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// `list_projects` response: the per-project summaries plus the shared
/// `_meta` envelope. The `_meta` block is part of the core contract — the
/// CLI and MCP layers serialize this struct rather than synthesizing the
/// envelope themselves.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProjectListing {
    pub results: Vec<ProjectSummary>,
    #[serde(rename = "_meta")]
    pub meta: crate::query::Meta,
}

/// Distinct project ids in the index with their record / signed-record
/// counts, plus the shared `_meta` envelope.
///
/// `identity_kind` is derived from the prefix of `project_id`
/// (`git:` / `name:` / `cc-slug:` / `codex-cwd:` / other). `path` is
/// resolved from `cfg.projects` (the `[projects.<name>]` table written by
/// `nexum project register`) for `name:`-identity ids and is `None`
/// otherwise — only registered projects carry a stored filesystem path.
///
/// `meta` is built via the shared `build_meta_listing` helper over the same
/// connection so `_meta.source_counts` aggregates the whole index and
/// `_meta.trust_policy` reflects `cfg.trust.unsigned_default`.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn list_projects(paths: &Paths, cfg: &Config) -> Result<ProjectListing, ApiError> {
    let conn = open_existing(&paths.index_db)?;
    let mut stmt = conn
        .prepare(
            "SELECT project_id, count(*), \
                sum(CASE WHEN crypto_result = 'good' THEN 1 ELSE 0 END) \
         FROM records \
         GROUP BY project_id \
         ORDER BY count(*) DESC",
        )
        .map_err(crate::query::QueryError::from)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        })
        .map_err(crate::query::QueryError::from)?;
    let results: Vec<ProjectSummary> = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::query::QueryError::from)?
        .into_iter()
        .map(|(pid, count, signed)| ProjectSummary {
            identity_kind: identity_kind_for(&pid).to_owned(),
            path: project_path_for(&pid, cfg),
            project_id: pid,
            record_count: u32::try_from(count).unwrap_or(u32::MAX),
            signed_record_count: u32::try_from(signed).unwrap_or(u32::MAX),
        })
        .collect();
    let meta = crate::query::meta::build_meta_listing(&conn, cfg.trust.unsigned_default)?;
    Ok(ProjectListing { results, meta })
}

/// Resolve the filesystem path for a `project_id` from `cfg.projects`.
///
/// Only `name:`-identity ids carry a registered path: the id `name:<name>`
/// maps to `cfg.projects["<name>"]["path"]`, the `[projects.<name>]` table
/// `nexum project register` writes. Every other identity kind (`git:`,
/// `cc-slug:`, `codex-cwd:`, path) returns `None` — the `records` table
/// has no path column and those identities are derived, not registered.
fn project_path_for(project_id: &str, cfg: &Config) -> Option<String> {
    let name = project_id.strip_prefix("name:")?;
    cfg.projects
        .get(name)?
        .as_table()?
        .get("path")?
        .as_str()
        .map(str::to_owned)
}

/// One row from the `trust_chain_tampering` table — a forbidden mutation of
/// `.trust/events.yml` that the materializer detected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TamperingRow {
    pub at_commit: String,
    pub at_topo_pos: u64,
    pub event_id: String,
    pub kind: String,
    pub detected_at: String,
}

/// Force a materializer rebuild and return any detected tampering rows.
///
/// Re-walks `.trust/events.yml` from scratch, ignoring the sentinel cache,
/// then reads `trust_chain_tampering`. Used by `nexum trust validate-events`
/// where the forced rebuild is the diagnostic's raison d'être.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure or
/// `ApiError::Query(QueryError::Trust)` on materializer error.
pub fn validate_events(paths: &Paths) -> Result<Vec<TamperingRow>, ApiError> {
    let mut conn = open_or_create(&paths.index_db)?;
    crate::trust::events_view::rebuild(&mut conn, &paths.notebook_git)?;
    read_tampering_rows(&conn)
}

/// Read tampering rows without forcing a rebuild. Used by
/// `nexum index --check` post-index, where the just-completed index pass
/// already called `ensure_current` and a second rebuild would duplicate
/// the same git walk.
///
/// # Errors
///
/// Same as [`validate_events`] minus the rebuild path.
pub fn validate_events_cached(paths: &Paths) -> Result<Vec<TamperingRow>, ApiError> {
    let mut conn = open_or_create(&paths.index_db)?;
    crate::trust::events_view::ensure_current(&mut conn, &paths.notebook_git)?;
    read_tampering_rows(&conn)
}

fn read_tampering_rows(conn: &rusqlite::Connection) -> Result<Vec<TamperingRow>, ApiError> {
    let mut stmt = conn
        .prepare(
            "SELECT at_commit, at_topo_pos, event_id, kind, detected_at \
             FROM trust_chain_tampering \
             ORDER BY at_topo_pos ASC",
        )
        .map_err(crate::query::QueryError::from)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(TamperingRow {
                at_commit: r.get(0)?,
                at_topo_pos: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                event_id: r.get(2)?,
                kind: r.get(3)?,
                detected_at: r.get(4)?,
            })
        })
        .map_err(crate::query::QueryError::from)?;
    Ok(rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::query::QueryError::from)?)
}

/// Resolution mode for `nexum doctor --resolve-pending-reanchor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorResolveMode {
    /// Re-attempt the next phase. Valid in `events_committed` (writes the new
    /// pin) and `pin_updated` (idempotent cleanup). Refused in `init` — the
    /// keys-recover entry path is not implemented in this release.
    Continue,
    /// Abandon the pending reanchor and remove the sentinel. Only valid in
    /// `init` (no signed commit exists yet). Refused in `events_committed`
    /// (a signed commit is already on HEAD; only `--continue` is valid).
    Revert,
}

/// Outcome of a sentinel-resolution attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReanchorResolveOutcome {
    /// No `.reanchor_pending` sentinel was found; nothing to do.
    NoSentinel,
    /// The sentinel was consumed and the indicated phase cleaned up.
    Resolved {
        /// Wire name of the phase that was resolved (`"init"`,
        /// `"events_committed"`, or `"pin_updated"`).
        from_phase: String,
    },
    /// The requested mode is not valid for the current phase.
    Refused {
        /// Wire name of the phase the sentinel reported.
        phase: String,
        /// Human-readable explanation of why the mode was refused.
        reason: String,
    },
}

/// Inspect `~/.nexum/.reanchor_pending` and apply the sentinel cleanup per the
/// documented phases.
///
/// - `init` + `Revert` → delete the sentinel (no events were committed).
/// - `init` + `Continue` → refuse (keys-recover path not yet available).
/// - `events_committed` + `Continue` → write the new bootstrap pin to
///   `paths.config` and `paths.bootstrap_pin`, then remove the sentinel.
/// - `events_committed` + `Revert` → refuse (a signed reanchor commit is
///   already on HEAD; only `--continue` is valid).
/// - `pin_updated` + any mode (or `None`) → idempotent cleanup: delete the
///   sentinel and report success.
/// - No sentinel → `NoSentinel` outcome.
/// - Sentinel present but `mode` is `None` → `Refused` (caller must specify
///   `--continue` or `--revert`).
///
/// # Errors
///
/// Returns `ApiError::Trust` on sentinel I/O failures.
/// Returns `ApiError::Config` when loading or saving `config.toml` fails
/// (only the `events_committed + Continue` branch).
/// Returns `ApiError::Indexer(IndexerError::Io)` when writing the bootstrap
/// pin cache file fails (same branch).
pub fn resolve_pending_reanchor(
    paths: &Paths,
    mode: Option<ReanchorResolveMode>,
) -> Result<ReanchorResolveOutcome, ApiError> {
    use crate::trust::reanchor_pending::{Phase, delete_sentinel, read_sentinel};

    let Some(sentinel) = read_sentinel(&paths.home)? else {
        return Ok(ReanchorResolveOutcome::NoSentinel);
    };
    let phase = sentinel.phase_completed();

    match (phase, mode) {
        (Phase::Init, Some(ReanchorResolveMode::Revert)) => {
            delete_sentinel(&paths.home)?;
            Ok(ReanchorResolveOutcome::Resolved {
                from_phase: "init".into(),
            })
        }
        (Phase::Init, Some(ReanchorResolveMode::Continue)) => {
            Ok(ReanchorResolveOutcome::Refused {
                phase: "init".into(),
                reason: "this release only supports cleanup of `pin_updated` and `--revert` of `init`; \
                         phase=init recovery requires the keys-recover command (not yet available)"
                    .into(),
            })
        }
        (Phase::EventsCommitted, Some(ReanchorResolveMode::Continue)) => {
            let mut cfg = crate::config::load(&paths.config).map_err(ApiError::Config)?;
            sentinel
                .new_pin_fp()
                .clone_into(&mut cfg.trust.bootstrap.fingerprint);
            sentinel
                .new_pubkey()
                .clone_into(&mut cfg.trust.bootstrap.public_key);
            crate::config::save(&paths.config, &cfg).map_err(ApiError::Config)?;
            std::fs::write(&paths.bootstrap_pin, sentinel.new_pin_fp().as_bytes()).map_err(
                |e| {
                    ApiError::Indexer(crate::indexer::db::IndexerError::Io {
                        path: paths.bootstrap_pin.clone(),
                        source: e,
                    })
                },
            )?;
            delete_sentinel(&paths.home)?;
            Ok(ReanchorResolveOutcome::Resolved {
                from_phase: "events_committed".into(),
            })
        }
        (Phase::EventsCommitted, Some(ReanchorResolveMode::Revert)) => {
            Ok(ReanchorResolveOutcome::Refused {
                phase: "events_committed".into(),
                reason: "phase=events_committed already has a signed reanchor commit on HEAD; \
                         --revert would require a manual `git revert`; only --continue is valid here"
                    .into(),
            })
        }
        (Phase::PinUpdated, _) => {
            delete_sentinel(&paths.home)?;
            Ok(ReanchorResolveOutcome::Resolved {
                from_phase: "pin_updated".into(),
            })
        }
        (_, None) => Ok(ReanchorResolveOutcome::Refused {
            phase: phase.as_str().into(),
            reason: "specify --continue or --revert".into(),
        }),
    }
}

fn identity_kind_for(project_id: &str) -> &'static str {
    let prefix = project_id.split(':').next().unwrap_or("");
    match prefix {
        "git" => "git",
        "name" => "registered",
        "cc-slug" => "cc-slug-fallback",
        "codex-cwd" => "codex-cwd-fallback",
        _ => "path",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::Config;
    use tempfile::TempDir;

    fn paths_with_temp_home() -> (TempDir, Paths) {
        let dir = TempDir::new().unwrap();
        let paths = Paths::with_home(dir.path().to_owned());
        (dir, paths)
    }

    #[test]
    fn index_run_with_no_enabled_adapters_is_no_op() {
        let (_dir, paths) = paths_with_temp_home();
        let mut cfg = Config::seed();
        cfg.adapters.cc.enabled = false;
        cfg.adapters.codex.enabled = false;
        cfg.adapters.local.enabled = false;
        let outcome = index_run(&paths, &cfg).unwrap();
        assert_eq!(outcome.upserts, 0);
    }

    #[test]
    fn list_projects_aggregates_distinct_ids() {
        let (_dir, paths) = paths_with_temp_home();
        let conn = open_or_create(&paths.index_db).unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('a','local','git:abc','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','good','2026-04-29T00:01:00Z'), \
             ('b','local','git:abc','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','no-signature','2026-04-29T00:01:00Z'), \
             ('c','local','name:projx','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','good','2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        drop(conn);
        let cfg = Config::seed();
        let listing = list_projects(&paths, &cfg).unwrap();
        assert_eq!(listing.results.len(), 2);
        let abc = listing
            .results
            .iter()
            .find(|s| s.project_id == "git:abc")
            .unwrap();
        assert_eq!(abc.record_count, 2);
        assert_eq!(abc.signed_record_count, 1);
        assert_eq!(abc.identity_kind, "git");
        // No registered path for a git: identity.
        assert_eq!(abc.path, None);
        let projx = listing
            .results
            .iter()
            .find(|s| s.project_id == "name:projx")
            .unwrap();
        assert_eq!(projx.record_count, 1);
        assert_eq!(projx.identity_kind, "registered");
        // projx is not registered in `cfg.projects`, so still None.
        assert_eq!(projx.path, None);
        // `_meta` is part of the core contract: source_counts aggregates the
        // whole index and trust_policy reflects the passed config.
        assert_eq!(listing.meta.source_counts.local, 3);
        assert_eq!(listing.meta.trust_policy, cfg.trust.unsigned_default);
    }

    #[test]
    fn list_projects_resolves_path_for_registered_name_identity() {
        let (_dir, paths) = paths_with_temp_home();
        let conn = open_or_create(&paths.index_db).unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('a','local','name:projx','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','good','2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        drop(conn);
        // Mirror what `nexum project register` writes: [projects.projx] path = "...".
        let mut cfg = Config::seed();
        let mut entry = toml::Table::new();
        entry.insert(
            "path".into(),
            toml::Value::String("/home/u/code/projx".into()),
        );
        cfg.projects
            .insert("projx".into(), toml::Value::Table(entry));
        let listing = list_projects(&paths, &cfg).unwrap();
        let projx = listing
            .results
            .iter()
            .find(|s| s.project_id == "name:projx")
            .unwrap();
        assert_eq!(projx.identity_kind, "registered");
        assert_eq!(projx.path.as_deref(), Some("/home/u/code/projx"));
    }

    #[test]
    fn list_projects_path_none_for_unregistered_and_non_name_identities() {
        let (_dir, paths) = paths_with_temp_home();
        let conn = open_or_create(&paths.index_db).unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('a','local','git:abc','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','good','2026-04-29T00:01:00Z'), \
             ('b','local','name:gone','decision','t','b','[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','good','2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        drop(conn);
        // `cfg.projects` registers a *different* name, so `name:gone` stays unresolved.
        let mut cfg = Config::seed();
        let mut entry = toml::Table::new();
        entry.insert("path".into(), toml::Value::String("/elsewhere".into()));
        cfg.projects
            .insert("other".into(), toml::Value::Table(entry));
        let listing = list_projects(&paths, &cfg).unwrap();
        for s in &listing.results {
            assert_eq!(s.path, None, "path must be None for {}", s.project_id);
        }
    }

    /// Seed one minimal row so the FTS path returns at least a candidate
    /// without requiring the indexer pipeline.
    fn seed_search_corpus(paths: &Paths) {
        let conn = open_or_create(&paths.index_db).unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('r1','local','git:abc','decision','concurrency notes','body with concurrency word', \
              '[]','','manual','[]','[]','[]','medium','working', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','ih','no-signature','2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn facade_search_skips_embed_when_disabled() {
        let (_dir, paths) = paths_with_temp_home();
        seed_search_corpus(&paths);
        let mut cfg = Config::seed();
        cfg.embed.enabled = false;
        let opts = SearchOpts::new("concurrency");
        let res = search(&paths, &cfg, &opts).expect("search");
        // FTS-only path runs unchanged: no embedder constructed, no
        // wanted-but-missing signal on the response envelope.
        assert!(!res.meta.embed_pool_saturated);
    }

    #[test]
    fn facade_search_sets_saturated_when_model_missing() {
        let (_dir, paths) = paths_with_temp_home();
        seed_search_corpus(&paths);
        let mut cfg = Config::seed();
        cfg.embed.enabled = true;
        // `model_path` defaults to the empty string under `Config::seed`; set
        // it to a path that definitely does not exist so `Embedder::load`
        // returns `ModelNotInstalled` and the facade degrades to FTS-only
        // while flipping the wanted-but-missing signal.
        cfg.embed.model_path = "/nonexistent/nexum-test/model.onnx".into();
        let opts = SearchOpts::new("concurrency");
        let res = search(&paths, &cfg, &opts).expect("search");
        assert!(
            res.meta.embed_pool_saturated,
            "embed.enabled=true with no installed model must surface as saturated"
        );
    }

    #[test]
    #[ignore = "requires bge-m3 model installed; gated by NEXUM_E2E_EMBED env"]
    fn facade_search_builds_query_vector_when_embed_enabled() {
        if std::env::var_os("NEXUM_E2E_EMBED").is_none() {
            return;
        }
        let (_dir, paths) = paths_with_temp_home();
        seed_search_corpus(&paths);
        let mut cfg = Config::seed();
        cfg.embed.enabled = true;
        // The gated env var implies a real install; the path comes from the
        // caller's local environment. Don't bake a fixture path into the test.
        if let Ok(p) = std::env::var("NEXUM_E2E_EMBED_MODEL_PATH") {
            cfg.embed.model_path = p;
        }
        let opts = SearchOpts::new("concurrency");
        let res = search(&paths, &cfg, &opts).expect("search");
        // Smoke: the hybrid path didn't crash; the envelope reports no
        // wanted-but-missing degradation since the model is installed.
        assert!(!res.meta.embed_pool_saturated);
        assert!(res.results.len() <= 5);
    }
}
