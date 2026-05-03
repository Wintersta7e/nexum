//! Reindex pipeline — composes the three adapters into one pass against `index.db`.
//!
//! For each enabled adapter (cc / codex / local) the pipeline runs an isolated
//! per-source `SQLite` transaction. The completeness contract decides what to do
//! with the diff against the indexed state:
//!
//! * `Failed` → no upserts, no deletes, no counter mutation.
//! * `Authoritative` → apply upserts; bump miss counter on `gone` ids; delete
//!   only when the counter hits `STALE_THRESHOLD`.
//! * `Partial` → apply upserts; reset every miss counter for this source (we
//!   don't know which records were actually missing this pass).
//!
//! The vec0 ordering rule is honored on every UPDATE / DELETE path:
//! `record_embeddings` rows are removed before the `records` row they refer to.
//! vec0 INSERT is intentionally a no-op in this phase — semantic ranking lands
//! in a later milestone, and `record_embeddings` stays empty until then.

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    adapter::{
        Adapter, AdapterPass, PassCompleteness, cc::CcAdapter, codex::CodexAdapter,
        local::LocalAdapter,
    },
    config::types::Config,
    index::tag_normalization::normalize_tags_for_fts,
    indexer::{
        db::IndexerError,
        state::{
            IndexStateError, STALE_THRESHOLD, apply_index_state_ddl, bump_miss, drop_state,
            reset_miss_for_id, reset_misses_for_source,
        },
    },
    paths::Paths,
    records::{RecordId, Source, UnifiedRecord},
};

impl From<IndexStateError> for IndexerError {
    fn from(e: IndexStateError) -> Self {
        match e {
            IndexStateError::Rusqlite(r) => Self::Rusqlite(r),
        }
    }
}

/// Per-source slice of the reindex outcome. Surfaces what each adapter
/// contributed so the CLI can render a structured summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerSourceOutcome {
    pub source: Source,
    pub completeness: String,
    pub ingested: u32,
    pub upserts: u32,
    pub deletes: u32,
    pub deferred_deletes: u32,
}

/// Aggregate outcome of one reindex pass across all enabled adapters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerOutcome {
    pub upserts: u32,
    pub deletes: u32,
    pub deferred_deletes: u32,
    pub fts_rebuild_triggered: bool,
    pub per_source: Vec<PerSourceOutcome>,
}

/// Run a reindex pass over all enabled adapters.
///
/// Ensures the `index_state` table exists, then for each adapter (`cc`,
/// `codex`, `local`) — when enabled in `cfg.adapters` — fetches an
/// `AdapterPass`, computes the new/changed/gone sets, applies upserts
/// immediately, and gates deletes on the completeness rules described in the
/// module-level docs. Each per-source pass runs inside its own transaction so
/// a fault in one source can't corrupt the others.
///
/// # Errors
/// Returns `IndexerError::Rusqlite` on SQL failure or
/// `IndexerError::Adapter` when an adapter fatals.
pub fn run(
    conn: &mut Connection,
    cfg: &Config,
    paths: &Paths,
) -> Result<IndexerOutcome, IndexerError> {
    apply_index_state_ddl(conn)?;
    run_inner(conn, cfg, paths, false)
}

/// Force form — bypasses the staleness gate so deletes apply on the current
/// pass. Intended for the `nexum index --force` CLI flag; risky when an
/// upstream tool is mid-write because a transient empty list collapses to a
/// real deletion.
///
/// # Errors
/// Returns `IndexerError::Rusqlite` on SQL failure or
/// `IndexerError::Adapter` when an adapter fatals.
pub fn run_force(
    conn: &mut Connection,
    cfg: &Config,
    paths: &Paths,
) -> Result<IndexerOutcome, IndexerError> {
    apply_index_state_ddl(conn)?;
    run_inner(conn, cfg, paths, true)
}

fn run_inner(
    conn: &mut Connection,
    cfg: &Config,
    paths: &Paths,
    force: bool,
) -> Result<IndexerOutcome, IndexerError> {
    let mut outcome = IndexerOutcome::default();

    // Run adapters OUTSIDE any transaction — they perform their own I/O.
    let cc_pass = if cfg.adapters.cc.enabled {
        Some(build_cc_adapter(cfg).list()?)
    } else {
        None
    };
    let codex_pass = if cfg.adapters.codex.enabled {
        Some(build_codex_adapter(cfg).list()?)
    } else {
        None
    };
    let local_pass = if cfg.adapters.local.enabled {
        Some(LocalAdapter::new(paths.notebook_git.clone()).list()?)
    } else {
        None
    };

    if let Some(pass) = cc_pass {
        let cfg_for_read = cfg.clone();
        apply_pass(
            conn,
            Source::CcNative,
            &pass,
            |id| build_cc_adapter(&cfg_for_read).read(id).ok(),
            force,
            &mut outcome,
        )?;
    }
    if let Some(pass) = codex_pass {
        let cfg_for_read = cfg.clone();
        apply_pass(
            conn,
            Source::CodexNative,
            &pass,
            |id| build_codex_adapter(&cfg_for_read).read(id).ok(),
            force,
            &mut outcome,
        )?;
    }
    if let Some(pass) = local_pass {
        let notebook_for_read = paths.notebook_git.clone();
        apply_pass(
            conn,
            Source::Local,
            &pass,
            |id| LocalAdapter::new(notebook_for_read.clone()).read(id).ok(),
            force,
            &mut outcome,
        )?;
    }

    Ok(outcome)
}

fn build_cc_adapter(cfg: &Config) -> CcAdapter {
    CcAdapter::new(
        expand_home(&cfg.adapters.cc.projects_dir),
        cfg.adapters.cc.max_age_years,
    )
}

fn build_codex_adapter(cfg: &Config) -> CodexAdapter {
    CodexAdapter::new(
        expand_home(&cfg.adapters.codex.memories_dir),
        expand_home(&cfg.adapters.codex.state_db),
        cfg.adapters.codex.read_raw_memories,
    )
}

fn apply_pass<F>(
    conn: &mut Connection,
    source: Source,
    pass: &AdapterPass,
    read_full: F,
    force: bool,
    outcome: &mut IndexerOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    let completeness_label = match &pass.completeness {
        PassCompleteness::Authoritative => "authoritative",
        PassCompleteness::Partial { .. } => "partial",
        PassCompleteness::Failed { .. } => "failed",
    }
    .to_owned();
    let mut per_source = PerSourceOutcome {
        source,
        completeness: completeness_label,
        ingested: u32::try_from(pass.records.len()).unwrap_or(u32::MAX),
        upserts: 0,
        deletes: 0,
        deferred_deletes: 0,
    };

    if let PassCompleteness::Failed { reason } = &pass.completeness {
        warn!(
            ?source,
            ?reason,
            "adapter pass failed; no upserts, no deletes"
        );
        outcome.per_source.push(per_source);
        return Ok(());
    }

    let tx = conn.transaction()?;
    apply_pass_inside_tx(
        &tx,
        source,
        pass,
        &read_full,
        force,
        outcome,
        &mut per_source,
    )?;
    tx.commit()?;
    outcome.per_source.push(per_source);
    Ok(())
}

fn apply_pass_inside_tx<F>(
    tx: &Transaction<'_>,
    source: Source,
    pass: &AdapterPass,
    read_full: &F,
    force: bool,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    let indexed = load_indexed_for_source(tx, source)?;

    let candidates: std::collections::HashMap<String, String> = pass
        .records
        .iter()
        .map(|r| (r.id.clone(), r.content_hash.clone()))
        .collect();

    apply_upserts(
        tx,
        source,
        &candidates,
        &indexed,
        read_full,
        outcome,
        per_source,
    )?;

    let gone: Vec<String> = indexed
        .keys()
        .filter(|k| !candidates.contains_key(*k))
        .cloned()
        .collect();

    apply_deletes(
        tx,
        source,
        &pass.completeness,
        &gone,
        force,
        outcome,
        per_source,
    )
}

fn load_indexed_for_source(
    tx: &Transaction<'_>,
    source: Source,
) -> Result<std::collections::HashMap<String, String>, IndexerError> {
    let mut indexed: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut stmt = tx.prepare("SELECT id, content_hash FROM records WHERE source = ?1")?;
    let src_str = source.as_db_str();
    let rows = stmt.query_map(params![src_str], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, hash) = row?;
        indexed.insert(id, hash);
    }
    Ok(indexed)
}

fn apply_upserts<F>(
    tx: &Transaction<'_>,
    source: Source,
    candidates: &std::collections::HashMap<String, String>,
    indexed: &std::collections::HashMap<String, String>,
    read_full: &F,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    for (id, hash) in candidates {
        let cached_matches = indexed.get(id) == Some(hash);
        if cached_matches {
            // Present + unchanged: refresh the miss counter — it may have been
            // bumped on a prior pass that observed this id as gone.
            reset_miss_for_id(tx, source, id)?;
            continue;
        }
        let Some(record) = read_full(id) else {
            warn!(
                ?source,
                ?id,
                "adapter list named id but read returned None; skipping"
            );
            continue;
        };
        upsert(tx, source, &record)?;
        per_source.upserts += 1;
        outcome.upserts += 1;
        reset_miss_for_id(tx, source, id)?;
    }
    Ok(())
}

fn apply_deletes(
    tx: &Transaction<'_>,
    source: Source,
    completeness: &PassCompleteness,
    gone: &[String],
    force: bool,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError> {
    if force {
        for id in gone {
            hard_delete(tx, source, id)?;
            per_source.deletes += 1;
            outcome.deletes += 1;
        }
        return Ok(());
    }
    match completeness {
        PassCompleteness::Authoritative => {
            for id in gone {
                let counter = bump_miss(tx, source, id)?;
                if counter >= STALE_THRESHOLD {
                    hard_delete(tx, source, id)?;
                    per_source.deletes += 1;
                    outcome.deletes += 1;
                } else {
                    per_source.deferred_deletes += 1;
                    outcome.deferred_deletes += 1;
                }
            }
        }
        PassCompleteness::Partial { .. } => {
            // Partial pass: any "gone" id may simply have been skipped this
            // round, so resetting all miss counters for this source is the
            // safe move. The deferred-delete tally records the size of the
            // diff that the next Authoritative pass will reconsider.
            reset_misses_for_source(tx, source)?;
            let n = u32::try_from(gone.len()).unwrap_or(u32::MAX);
            per_source.deferred_deletes = per_source.deferred_deletes.saturating_add(n);
            outcome.deferred_deletes = outcome.deferred_deletes.saturating_add(n);
        }
        PassCompleteness::Failed { .. } => {
            unreachable!("Failed pass returns early before apply_deletes is called");
        }
    }
    Ok(())
}

fn upsert(tx: &Transaction<'_>, source: Source, r: &UnifiedRecord) -> Result<(), IndexerError> {
    let tags_json = serde_json::to_string(&r.tags).expect("serializable record fields");
    let tags_fts = normalize_tags_for_fts(&tags_json);
    let session_refs_json =
        serde_json::to_string(&r.session_refs).expect("serializable record fields");
    let files_json = serde_json::to_string(&r.files).expect("serializable record fields");
    let commits_json = serde_json::to_string(&r.commits).expect("serializable record fields");
    let extras_json = serde_json::to_string(&r.extras).expect("serializable record fields");
    let now = Utc::now().to_rfc3339();
    let signature_status = r.provenance.signature_status.as_db_str();
    let body_origin_path = r.body_origin_path.as_ref().map(|p| p.display().to_string());

    // Look up rowid; if a row exists we mirror the vec0-before-records ordering
    // rule on the UPDATE path (DELETE the embedding row first, then UPDATE the
    // record). vec0 INSERT is skipped — `record_embeddings` is empty in this
    // phase. The records UPDATE / INSERT statements fire the FTS triggers.
    let existing_rowid: Option<i64> = tx
        .query_row(
            "SELECT rowid FROM records WHERE id = ?1",
            params![r.id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(rid) = existing_rowid {
        tx.execute(
            "DELETE FROM record_embeddings WHERE record_rowid = ?1",
            params![rid],
        )?;
        tx.execute(
            "UPDATE records SET source = ?1, project_id = ?2, record_type = ?3, title = ?4, \
             summary = ?5, body = ?6, body_origin_path = ?7, tags = ?8, tags_fts = ?9, \
             confidence = ?10, outcome = ?11, agent = ?12, session_refs = ?13, files = ?14, \
             commits = ?15, created = ?16, updated = ?17, content_hash = ?18, \
             signature_status = ?19, extras = ?20, indexed_at = ?21 \
             WHERE id = ?22",
            params![
                source.as_db_str(),
                r.project_id,
                r.record_type.as_db_str(),
                r.title,
                r.summary,
                r.body,
                body_origin_path,
                tags_json,
                tags_fts,
                r.confidence.as_db_str(),
                r.outcome.as_db_str(),
                r.agent.as_db_str(),
                session_refs_json,
                files_json,
                commits_json,
                r.created.to_rfc3339(),
                r.updated.to_rfc3339(),
                r.content_hash,
                signature_status,
                extras_json,
                now,
                r.id,
            ],
        )?;
    } else {
        tx.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, summary, body, \
             body_origin_path, tags, tags_fts, confidence, outcome, agent, session_refs, \
             files, commits, created, updated, content_hash, signature_status, extras, \
             indexed_at) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
              ?19, ?20, ?21, ?22)",
            params![
                r.id,
                source.as_db_str(),
                r.project_id,
                r.record_type.as_db_str(),
                r.title,
                r.summary,
                r.body,
                body_origin_path,
                tags_json,
                tags_fts,
                r.confidence.as_db_str(),
                r.outcome.as_db_str(),
                r.agent.as_db_str(),
                session_refs_json,
                files_json,
                commits_json,
                r.created.to_rfc3339(),
                r.updated.to_rfc3339(),
                r.content_hash,
                signature_status,
                extras_json,
                now,
            ],
        )?;
    }
    Ok(())
}

fn hard_delete(tx: &Transaction<'_>, source: Source, id: &str) -> Result<(), IndexerError> {
    let id_owned = id.to_owned();
    let rowid: Option<i64> = tx
        .query_row(
            "SELECT rowid FROM records WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(rid) = rowid {
        // Ordering rule: vec0 DELETE before records DELETE. The FTS trigger
        // fires on the records DELETE.
        tx.execute(
            "DELETE FROM record_embeddings WHERE record_rowid = ?1",
            params![rid],
        )?;
        tx.execute("DELETE FROM records WHERE id = ?1", params![id])?;
    }
    drop_state(tx, source, &id_owned)?;
    Ok(())
}

fn expand_home(p: &str) -> std::path::PathBuf {
    // Minimal `~/...` expansion for adapter config paths. The seed config
    // writes paths like `~/.claude/projects` — we resolve `~` to $HOME (or
    // %USERPROFILE% on Windows) at runtime so tests can override via env
    // without a config rewrite.
    if let Some(stripped) = p.strip_prefix("~/") {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from);
        home.join(stripped)
    } else {
        std::path::PathBuf::from(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::db::open_or_create;
    use tempfile::TempDir;

    fn cfg_with_adapters_off() -> Config {
        let mut cfg = Config::seed();
        cfg.adapters.cc.enabled = false;
        cfg.adapters.codex.enabled = false;
        cfg.adapters.local.enabled = false;
        cfg
    }

    fn write_record_yaml(notebook_git: &std::path::Path, id: &str, content_hash: &str) {
        let dir = notebook_git.join("decisions");
        std::fs::create_dir_all(&dir).unwrap();
        let yaml = format!(
            "schema_version: 1\n\
             id: {id}\n\
             record_type: decision\n\
             project_id: example\n\
             title: {id} title\n\
             body: {id} body\n\
             tags: [auth]\n\
             agent: manual\n\
             created: 2026-04-29T00:00:00Z\n\
             updated: 2026-04-29T00:00:00Z\n\
             content_hash: {content_hash}\n",
        );
        std::fs::write(dir.join(format!("{id}.yml")), yaml).unwrap();
    }

    #[test]
    fn run_with_no_enabled_adapters_is_no_op() {
        let dir = TempDir::new().unwrap();
        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let cfg = cfg_with_adapters_off();
        let paths = Paths::with_home(dir.path().to_owned());
        let outcome = run(&mut conn, &cfg, &paths).unwrap();
        assert_eq!(outcome.upserts, 0);
        assert_eq!(outcome.deletes, 0);
        assert!(outcome.per_source.is_empty());
    }

    #[test]
    fn local_adapter_pass_inserts_record_into_index() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_record_yaml(&nb, "alpha", "deadbeef");

        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let mut cfg = cfg_with_adapters_off();
        cfg.adapters.local.enabled = true;
        let paths = Paths::with_home(dir.path().to_owned());

        let outcome = run(&mut conn, &cfg, &paths).unwrap();
        assert_eq!(outcome.upserts, 1);
        assert_eq!(outcome.deletes, 0);

        let count: i64 = conn
            .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
        let body: String = conn
            .query_row("SELECT body FROM records WHERE id = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(body, "alpha body");
    }

    #[test]
    fn second_pass_with_unchanged_record_is_noop() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_record_yaml(&nb, "alpha", "hashc");

        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let mut cfg = cfg_with_adapters_off();
        cfg.adapters.local.enabled = true;
        let paths = Paths::with_home(dir.path().to_owned());

        let _ = run(&mut conn, &cfg, &paths).unwrap();
        let outcome2 = run(&mut conn, &cfg, &paths).unwrap();
        assert_eq!(outcome2.upserts, 0, "unchanged content_hash skips upsert");
    }

    #[test]
    fn deferred_delete_under_threshold_keeps_row() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_record_yaml(&nb, "alpha", "h");
        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let mut cfg = cfg_with_adapters_off();
        cfg.adapters.local.enabled = true;
        let paths = Paths::with_home(dir.path().to_owned());
        let _ = run(&mut conn, &cfg, &paths).unwrap();

        std::fs::remove_file(nb.join("decisions").join("alpha.yml")).unwrap();
        let _ = run(&mut conn, &cfg, &paths).unwrap();
        let _ = run(&mut conn, &cfg, &paths).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "row must persist below stale threshold");
    }

    #[test]
    fn three_authoritative_misses_delete_row() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_record_yaml(&nb, "alpha", "h");
        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let mut cfg = cfg_with_adapters_off();
        cfg.adapters.local.enabled = true;
        let paths = Paths::with_home(dir.path().to_owned());
        let _ = run(&mut conn, &cfg, &paths).unwrap();

        std::fs::remove_file(nb.join("decisions").join("alpha.yml")).unwrap();
        for _ in 0..3 {
            let _ = run(&mut conn, &cfg, &paths).unwrap();
        }
        let count: i64 = conn
            .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "row must be deleted after 3 Authoritative misses");
    }

    #[test]
    fn force_path_deletes_immediately() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_record_yaml(&nb, "alpha", "h");
        let mut conn = open_or_create(&dir.path().join("index.db")).unwrap();
        let mut cfg = cfg_with_adapters_off();
        cfg.adapters.local.enabled = true;
        let paths = Paths::with_home(dir.path().to_owned());
        let _ = run(&mut conn, &cfg, &paths).unwrap();

        std::fs::remove_file(nb.join("decisions").join("alpha.yml")).unwrap();
        let _ = run_force(&mut conn, &cfg, &paths).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "force path bypasses the stale-threshold gate");
    }
}
