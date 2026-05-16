//! Thin facade both the CLI and (later) MCP surfaces call into. Verbs match
//! the agreed surface table; each opens its own `SQLite` connection — pooling
//! lands in a later milestone.

pub mod error;

use crate::{
    config::types::Config,
    indexer::{
        IndexerOutcome,
        db::{IndexerError, open_existing, open_existing_writable, open_or_create},
        run::{run as indexer_run, run_force as indexer_run_force},
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

// Trust-events materializer errors raised by the facade-level
// `ensure_current` call route through the same wire shape as verb-internal
// trust errors: `ApiError::Query(QueryError::Trust(_))`. Single canonical
// path so callers don't have to discriminate where in the read pipeline
// the error originated.
impl From<crate::trust::events::TrustError> for ApiError {
    fn from(e: crate::trust::events::TrustError) -> Self {
        ApiError::Query(crate::query::QueryError::Trust(e))
    }
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
    use fs2::FileExt as _;

    if !cfg.embed.enabled {
        return Err(ApiError::Config(crate::config::ConfigError::Invalid {
            field: "embed.enabled".into(),
            reason: "--reembed requires [embed].enabled = true".into(),
        }));
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&paths.lock)
        .map_err(|e| {
            ApiError::Indexer(IndexerError::Io {
                path: paths.lock.clone(),
                source: e,
            })
        })?;
    lock_file.try_lock_exclusive().map_err(|e| {
        ApiError::Indexer(IndexerError::Io {
            path: paths.lock.clone(),
            source: e,
        })
    })?;
    let mut conn = open_existing_writable(&paths.index_db)?;
    let outcome = crate::indexer::run::run_reembed_existing(&mut conn, cfg, paths)?;
    lock_file.unlock().ok();
    Ok(outcome)
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
