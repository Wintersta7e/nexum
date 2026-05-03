//! Thin facade both the CLI and (later) MCP surfaces call into. Verbs match
//! the agreed surface table; each opens its own `SQLite` connection — pooling
//! lands in a later milestone.

use crate::{
    config::types::Config,
    indexer::{
        db::open_or_create,
        run::{run as indexer_run, run_force as indexer_run_force},
        IndexerOutcome,
    },
    paths::Paths,
    query::{
        by_session::by_session as query_by_session, get::get as query_get,
        list::list as query_list, recent::recent as query_recent, search::search as query_search,
        Filters, GetOpts, ResultSet, SearchOpts, SessionLookup,
    },
    records::UnifiedRecord,
};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    Indexer(#[from] crate::indexer::IndexerError),
    #[error(transparent)]
    Query(#[from] crate::query::QueryError),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
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

/// FTS-only search (vector branch lands later).
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite or filter encoding failure.
pub fn search(paths: &Paths, opts: &SearchOpts) -> Result<ResultSet, ApiError> {
    let conn = open_or_create(&paths.index_db)?;
    Ok(query_search(&conn, opts)?)
}

/// Get one record by id; honors the `include_unsigned` escape hatch under
/// `trust_policy = "hide"` (an unsigned record returns `None` unless the
/// caller opts in).
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite or deserialization failure.
pub fn get(paths: &Paths, id: &str, opts: &GetOpts) -> Result<Option<UnifiedRecord>, ApiError> {
    let conn = open_or_create(&paths.index_db)?;
    Ok(query_get(&conn, id, opts)?)
}

/// List with filters + pagination.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn list(
    paths: &Paths,
    filters: &Filters,
    limit: u32,
    cursor: Option<&str>,
) -> Result<ResultSet, ApiError> {
    let conn = open_or_create(&paths.index_db)?;
    Ok(query_list(&conn, filters, limit, cursor)?)
}

/// Recent records (filter on source optional).
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure or unknown source name.
pub fn recent(paths: &Paths, limit: u32, source: Option<&str>) -> Result<ResultSet, ApiError> {
    let conn = open_or_create(&paths.index_db)?;
    Ok(query_recent(&conn, limit, source)?)
}

/// Records associated with a session ref.
///
/// # Errors
///
/// Returns `ApiError::Query` on rusqlite failure.
pub fn by_session(paths: &Paths, lookup: &SessionLookup) -> Result<ResultSet, ApiError> {
    let conn = open_or_create(&paths.index_db)?;
    Ok(query_by_session(&conn, lookup)?)
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
    let conn = open_or_create(&paths.index_db)?;
    let mut stmt = conn
        .prepare(
            "SELECT project_id, count(*), \
                sum(CASE WHEN signature_status = 'verified' THEN 1 ELSE 0 END) \
         FROM records \
         WHERE project_id IS NOT NULL \
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
        .flatten()
        .map(|(pid, count, signed)| ProjectSummary {
            identity_kind: identity_kind_for(&pid).to_owned(),
            project_id: pid,
            record_count: u32::try_from(count).unwrap_or(u32::MAX),
            signed_record_count: u32::try_from(signed).unwrap_or(u32::MAX),
        })
        .collect();
    Ok(summaries)
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
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, signature_status, indexed_at) VALUES \
             ('a','local','git:abc','decision','t','b','[]','','manual','[]','[]','[]','medium', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','verified','2026-04-29T00:01:00Z'), \
             ('b','local','git:abc','decision','t','b','[]','','manual','[]','[]','[]','medium', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','unsigned','2026-04-29T00:01:00Z'), \
             ('c','local','name:projx','decision','t','b','[]','','manual','[]','[]','[]','medium', \
              '2026-04-29T00:00:00Z','2026-04-29T00:00:00Z','h','verified','2026-04-29T00:01:00Z')",
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
