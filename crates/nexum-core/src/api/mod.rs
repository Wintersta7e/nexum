//! Thin facade both the CLI and (later) MCP surfaces call into. Verbs match
//! the agreed surface table; each opens its own `SQLite` connection — pooling
//! lands in a later milestone.

use crate::{
    config::types::Config,
    indexer::{
        IndexerOutcome,
        db::{open_existing, open_existing_writable, open_or_create},
        run::{run as indexer_run, run_force as indexer_run_force},
    },
    paths::Paths,
    query::{
        Filters, GetOpts, ResultSet, SearchOpts, SessionLookup,
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
    Query(#[from] crate::query::QueryError),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("index schema v{v_disk} is older than this binary (v{v_code}); run `nexum migrate`")]
    MigrationRequired { v_disk: u32, v_code: u32 },
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

/// FTS-only search (vector branch lands later).
///
/// The `cfg.trust.ranking_penalty` value overrides any
/// `unsigned_ranking_penalty` set on `opts` so a single configured value
/// drives both ranking and presentation. `cfg.trust.strict_revocation`
/// likewise overrides `opts.filters.strict_revocation` so the projection
/// uses the runtime configuration.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite or filter encoding failure (and
/// on materializer rebuild failure, routed through `QueryError::Trust`).
pub fn search(paths: &Paths, cfg: &Config, opts: &SearchOpts) -> Result<ResultSet, ApiError> {
    let conn = open_for_query(paths)?;
    let mut effective_opts = opts.clone();
    effective_opts.unsigned_ranking_penalty = cfg.trust.ranking_penalty;
    // Stricter prevails: per-call flag wins if set, config default applies
    // otherwise. Same shape across every read verb.
    effective_opts.filters.strict_revocation =
        opts.filters.strict_revocation || cfg.trust.strict_revocation;
    Ok(query_search(&conn, &effective_opts)?)
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
}

/// Distinct project ids in the index with their record / signed-record counts.
/// `identity_kind` is derived from the prefix of `project_id`
/// (`git:` / `name:` / `cc-slug:` / `codex-cwd:` / other).
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn list_projects(paths: &Paths) -> Result<Vec<ProjectSummary>, ApiError> {
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
    let summaries: Vec<ProjectSummary> = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::query::QueryError::from)?
        .into_iter()
        .map(|(pid, count, signed)| ProjectSummary {
            identity_kind: identity_kind_for(&pid).to_owned(),
            project_id: pid,
            record_count: u32::try_from(count).unwrap_or(u32::MAX),
            signed_record_count: u32::try_from(signed).unwrap_or(u32::MAX),
        })
        .collect();
    Ok(summaries)
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
/// and the orchestration in `nexum index --check`.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure or
/// `ApiError::Query(QueryError::Trust)` on materializer error.
pub fn validate_events(paths: &Paths) -> Result<Vec<TamperingRow>, ApiError> {
    let mut conn = open_or_create(&paths.index_db)?;
    crate::trust::events_view::rebuild(&mut conn, &paths.notebook_git)
        .map_err(crate::query::QueryError::Trust)?;
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
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::Query(crate::query::QueryError::from(e)))
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
        // Connection drops here; list_projects re-opens.
        drop(conn);
        let summaries = list_projects(&paths).unwrap();
        assert_eq!(summaries.len(), 2);
        let abc = summaries
            .iter()
            .find(|s| s.project_id == "git:abc")
            .unwrap();
        assert_eq!(abc.record_count, 2);
        assert_eq!(abc.signed_record_count, 1);
        assert_eq!(abc.identity_kind, "git");
        let projx = summaries
            .iter()
            .find(|s| s.project_id == "name:projx")
            .unwrap();
        assert_eq!(projx.record_count, 1);
        assert_eq!(projx.identity_kind, "registered");
    }
}
