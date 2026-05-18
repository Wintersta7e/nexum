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
//! Indexer — open / create `index.db`, run a reindex pass over all enabled
//! adapters, write results into `records` + `records_fts` + (when
//! `embed.enabled` and the bge-m3 model is installed) `record_embeddings`.
//! Vec0 writes respect the documented ordering rule (records first on
//! insert; embedding first on delete; DELETE+INSERT inside one transaction
//! on update).

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    adapter::{
        Adapter, AdapterPass, PassCompleteness, SkipKind, SkipReason, cc::CcAdapter,
        codex::CodexAdapter, local::LocalAdapter,
    },
    config::types::Config,
    embed::{Embedder, f32_slice_to_le_bytes},
    index::tag_normalization::normalize_tags_for_fts,
    indexer::{
        db::IndexerError,
        state::{
            IndexStateError, STALE_THRESHOLD, apply_index_state_ddl, bump_miss, drop_state,
            reset_miss_for_id, reset_misses_for_source,
        },
    },
    paths::Paths,
    records::{RecordId, Source, UnifiedRecord, hash::compute_index_hash},
};

impl From<IndexStateError> for IndexerError {
    fn from(e: IndexStateError) -> Self {
        match e {
            IndexStateError::Rusqlite(r) => Self::Rusqlite(r),
        }
    }
}

impl From<crate::index::meta::MetaError> for IndexerError {
    fn from(e: crate::index::meta::MetaError) -> Self {
        match e {
            crate::index::meta::MetaError::Sqlite(r) => Self::Rusqlite(r),
        }
    }
}

/// Completeness label for a single per-source pass. Mirrors the variants of
/// the internal `PassCompleteness` enum but is scoped to the per-source
/// boundary so the JSON wire format stays flat (`snake_case` strings rather than
/// adjacently-tagged objects).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerSourceCompleteness {
    Authoritative,
    Partial,
    Failed,
    MissingRoot,
    Unreadable,
}

impl std::fmt::Display for PerSourceCompleteness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Authoritative => "authoritative",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::MissingRoot => "missing_root",
            Self::Unreadable => "unreadable",
        };
        f.write_str(s)
    }
}

/// One bucket in `PerSourceOutcome.partial_reasons` — a `SkipKind` with its
/// running count from a `PassCompleteness::Partial` adapter pass. JSON-form:
/// `{"kind": "file-malformed", "count": 3}`. The kind is the same kebab
/// string `SkipKind` serializes as, so agents can match on a stable
/// enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialReasonSummary {
    pub kind: SkipKind,
    pub count: u32,
}

/// Bucket `skipped` reasons by `SkipKind` and emit one summary per kind,
/// ordered by `SkipKind` declaration order so the JSON output is stable.
fn summarize_skip_reasons(skipped: &[SkipReason]) -> Vec<PartialReasonSummary> {
    let mut counts: std::collections::BTreeMap<SkipKind, u32> = std::collections::BTreeMap::new();
    for r in skipped {
        *counts.entry(r.kind).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(kind, count)| PartialReasonSummary { kind, count })
        .collect()
}

/// Per-source slice of the reindex outcome. Surfaces what each adapter
/// contributed so the CLI can render a structured summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerSourceOutcome {
    pub source: Source,
    pub completeness: PerSourceCompleteness,
    pub ingested: u32,
    pub upserts: u32,
    pub deletes: u32,
    pub deferred_deletes: u32,
    /// Count of warn-level embedder failures during this pass. The indexer
    /// logs each failure as a warning and continues with an FTS-only insert;
    /// this field surfaces the running count so operators can detect a
    /// degrading embedder from the reindex summary.
    #[serde(default)]
    pub embed_failures: u32,
    /// Count of duplicate record ids the adapter pass surfaced — two records
    /// with the same `id` (typically across CC project slugs when two
    /// projects share a memory filename). The indexer keeps the last
    /// observed copy and counts the rest here; operators see the running
    /// total in the summary and a `tracing::warn` per pass with the
    /// colliding ids.
    #[serde(default)]
    pub duplicate_ids_skipped: u32,
    /// When `completeness` is `partial`, an ordered breakdown of the
    /// `SkipReason` kinds the adapter surfaced — e.g. how many files were
    /// `file-malformed` vs `file-transient` vs `lock-contention`. Empty for
    /// every other completeness state. Agents read this to decide whether
    /// a partial pass is worth retrying (transient) or escalating
    /// (malformed).
    #[serde(default)]
    pub partial_reasons: Vec<PartialReasonSummary>,
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

/// Options threaded through an indexer pass.
///
/// Callers that need only the default behaviour construct with
/// `IndexerOpts::default()`, which preserves the existing semantics
/// exactly (`threshold_override: None` → use `STALE_THRESHOLD`).
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexerOpts {
    /// Override the stale-row miss threshold for this pass only. `None`
    /// means use `STALE_THRESHOLD` (3). `Some(1)` makes every gone row
    /// eligible for deletion on the current pass — the `--aggressive` sweep
    /// mode.
    pub threshold_override: Option<u32>,
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
    run_with_opts(conn, cfg, paths, IndexerOpts::default())
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
    run_inner(conn, cfg, paths, true, IndexerOpts::default())
}

/// Full-control entry point. Accepts `IndexerOpts` so callers can adjust
/// per-pass behaviour (e.g. `api::index_sweep` lowers the stale-row
/// threshold). `run` is a thin shim over it.
///
/// # Errors
/// Returns `IndexerError::Rusqlite` on SQL failure or
/// `IndexerError::Adapter` when an adapter fatals.
pub fn run_with_opts(
    conn: &mut Connection,
    cfg: &Config,
    paths: &Paths,
    opts: IndexerOpts,
) -> Result<IndexerOutcome, IndexerError> {
    apply_index_state_ddl(conn)?;
    run_inner(conn, cfg, paths, false, opts)
}

fn run_inner(
    conn: &mut Connection,
    cfg: &Config,
    paths: &Paths,
    force: bool,
    opts: IndexerOpts,
) -> Result<IndexerOutcome, IndexerError> {
    let mut outcome = IndexerOutcome::default();

    // Build the embedder once per pass. Returns `None` when embed.enabled is
    // false, or when the configured model isn't installed (logged at warn so
    // indexing degrades gracefully — records still land in FTS).
    let embedder: Option<Embedder> = build_embedder_for_pass(cfg)?;

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
            opts,
            embedder.as_ref(),
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
            opts,
            embedder.as_ref(),
            &mut outcome,
        )?;
    }
    if let Some(pass) = local_pass {
        let notebook_for_read = paths.notebook_git.clone();
        // Materialize the trust-events view before the upsert pass so the
        // crypto batch's per-commit `relevant_trust_events_commit` lookups
        // see a fresh view. Skipped when `notebook_git` isn't a real git
        // repo — test fixtures use fake paths and there's no trust state
        // to materialize anyway.
        if paths.notebook_git.join(".git").exists() {
            crate::trust::events_view::ensure_current(conn, &paths.notebook_git)?;
        }
        // Per-commit verify cache. The `read_full` callback below
        // populates it lazily — one verify shell-out per unique record
        // commit. Wrapped in `RefCell` so the `Fn` closure required by
        // `apply_pass` can mutate it. Verify failures fall back to a
        // conservative `BadSignature` outcome (the spec routes
        // unrecognized verifier results through the invalid bucket so the
        // warning fires; a silent drop to `NoSignature` would underclaim).
        let crypto_cache: std::cell::RefCell<
            std::collections::HashMap<String, crate::indexer::crypto_batch::CryptoOutcome>,
        > = std::cell::RefCell::new(std::collections::HashMap::new());
        // Hoist the adapter out of the closure: each `read` already
        // re-walks the local subdirs internally, so constructing a
        // fresh adapter per id added an O(N) churn that the cache
        // could not amortize.
        let local_adapter = LocalAdapter::new(notebook_for_read.clone());
        apply_pass(
            conn,
            Source::Local,
            &pass,
            |id| {
                let mut record = local_adapter.read(id).ok()?;
                let Some(sha) = record.provenance.record_commit_sha.clone() else {
                    // Record's path is not in git history — leave the
                    // adapter's placeholder Provenance and proceed.
                    return Some(record);
                };
                let outcome = {
                    let mut cache = crypto_cache.borrow_mut();
                    if let Some(hit) = cache.get(&sha) {
                        hit.clone()
                    } else {
                        let resolved = match crate::indexer::crypto_batch::verify_and_resolve(
                            &notebook_for_read,
                            &sha,
                        ) {
                            Ok(o) => o,
                            Err(e) => {
                                tracing::warn!(
                                    error = ?e,
                                    sha = %sha,
                                    "verify shell-out failed; persisting record as BadSignature",
                                );
                                crate::indexer::crypto_batch::CryptoOutcome::bad_signature_fallback(
                                )
                            }
                        };
                        cache.insert(sha.clone(), resolved.clone());
                        resolved
                    }
                };
                record.provenance.crypto_result = outcome.crypto_result;
                record.provenance.signer_fingerprint = outcome.signer_fingerprint;
                record.provenance.relevant_trust_events_commit =
                    outcome.relevant_trust_events_commit;
                Some(record)
            },
            force,
            opts,
            embedder.as_ref(),
            &mut outcome,
        )?;
    }

    Ok(outcome)
}

/// Construct the per-pass `Embedder`. Returns `Ok(None)` when embeddings are
/// disabled in config, or when the configured model isn't installed yet — the
/// indexer logs a warning and proceeds without writing to `record_embeddings`.
/// Any other load failure surfaces as `IndexerError::Embed` via the `#[from]`
/// conversion on `IndexerError`.
fn build_embedder_for_pass(cfg: &Config) -> Result<Option<Embedder>, IndexerError> {
    Ok(crate::embed::try_load_from_config(cfg)?)
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

// 8 args after the IndexerOpts thread-through; an args-struct would add
// an indirection layer at every call site without simplifying any of the
// inner logic.
#[allow(clippy::too_many_arguments)]
fn apply_pass<F>(
    conn: &mut Connection,
    source: Source,
    pass: &AdapterPass,
    read_full: F,
    force: bool,
    opts: IndexerOpts,
    embedder: Option<&Embedder>,
    outcome: &mut IndexerOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    let completeness = match &pass.completeness {
        PassCompleteness::Authoritative => PerSourceCompleteness::Authoritative,
        PassCompleteness::Partial { .. } => PerSourceCompleteness::Partial,
        PassCompleteness::Failed { .. } => PerSourceCompleteness::Failed,
        PassCompleteness::MissingRoot { .. } => PerSourceCompleteness::MissingRoot,
        PassCompleteness::Unreadable { .. } => PerSourceCompleteness::Unreadable,
    };
    let partial_reasons = match &pass.completeness {
        PassCompleteness::Partial { skipped } => summarize_skip_reasons(skipped),
        _ => Vec::new(),
    };
    let mut per_source = PerSourceOutcome {
        source,
        completeness,
        ingested: u32::try_from(pass.records.len()).unwrap_or(u32::MAX),
        upserts: 0,
        deletes: 0,
        deferred_deletes: 0,
        embed_failures: 0,
        duplicate_ids_skipped: 0,
        partial_reasons,
    };

    if let PassCompleteness::Failed { reason } = &pass.completeness {
        warn!(
            target: "nexum::indexer",
            ?source,
            ?reason,
            "adapter pass failed; no upserts, no deletes"
        );
        outcome.per_source.push(per_source);
        return Ok(());
    }

    if let PassCompleteness::MissingRoot { path } = &pass.completeness {
        // Suppress upserts AND deletes — a temporarily absent configured root
        // (mount drop, workspace move) must not prune prior records. Emit at
        // warn level when prior records exist (something to protect) and at
        // info level when none do (fresh-setup common case).
        if any_records_from_source(conn, source)? {
            warn!(
                target: "nexum::indexer",
                ?source,
                ?path,
                "configured root is missing; preserving prior records"
            );
        } else {
            info!(
                target: "nexum::indexer",
                ?source,
                ?path,
                "configured root is missing; no prior records to preserve"
            );
        }
        outcome.per_source.push(per_source);
        return Ok(());
    }

    if let PassCompleteness::Unreadable { path, reason } = &pass.completeness {
        warn!(
            target: "nexum::indexer",
            ?source,
            ?path,
            ?reason,
            "configured root is unreadable; no upserts, no deletes"
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
        opts,
        embedder,
        outcome,
        &mut per_source,
    )?;
    tx.commit()?;
    outcome.per_source.push(per_source);
    Ok(())
}

/// True iff at least one row exists in `records` for `source`. Used by the
/// `MissingRoot` early-return branch to decide between info-level (fresh
/// install) and warn-level (something to protect) logging. Takes
/// `&Connection` rather than `&Transaction` because it is invoked before
/// `apply_pass` opens its per-source transaction.
fn any_records_from_source(conn: &Connection, source: Source) -> Result<bool, IndexerError> {
    let mut stmt = conn.prepare("SELECT 1 FROM records WHERE source = ?1 LIMIT 1")?;
    let exists = stmt
        .query_row(params![source.as_db_str()], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

// The per-pass plumbing carries the tx, source, candidates view, indexed
// view, adapter read callback, optional embedder, and the two outcome
// accumulators. Bundling them into a context struct would mostly move the
// noise to the call site without simplifying any of the inner logic.
#[allow(clippy::too_many_arguments)]
fn apply_pass_inside_tx<F>(
    tx: &Transaction<'_>,
    source: Source,
    pass: &AdapterPass,
    read_full: &F,
    force: bool,
    opts: IndexerOpts,
    embedder: Option<&Embedder>,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    let indexed = load_indexed_for_source(tx, source)?;

    // The candidate key is just `id` because adapters cannot universally
    // resolve `project_id` at list time without doing the read-full work
    // (e.g., Codex derives it from the threads index inside
    // `build_record`). The composite UNIQUE on the records table prevents
    // silent overwrite at upsert time, but within a single pass two list
    // entries that share an id collapse here. The two records compete on
    // the same `read_full(id)` call: the adapter's first-match-wins
    // behaviour returns one and silently drops the other.
    //
    // Surface the collision via a warn + a `SkipReason` so operators
    // notice that one of their records is being shadowed. Renaming one
    // of the colliding files is the documented workaround until the
    // adapter / indexer plumb a composite `(project_id, id)` key end to
    // end.
    let mut candidates: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(pass.records.len());
    let mut duplicate_ids: Vec<String> = Vec::new();
    for r in &pass.records {
        if candidates
            .insert(r.id.clone(), r.content_hash.clone())
            .is_some()
        {
            duplicate_ids.push(r.id.clone());
        }
    }
    if !duplicate_ids.is_empty() {
        warn!(
            target: "nexum::indexer",
            ?source,
            ?duplicate_ids,
            "adapter pass contained duplicate record ids across projects; the indexer keeps the last \
             observed copy for each id and skips the others. Rename one of the colliding files to \
             avoid silent shadowing."
        );
        per_source.duplicate_ids_skipped += u32::try_from(duplicate_ids.len()).unwrap_or(u32::MAX);
    }

    apply_upserts(
        tx,
        source,
        &candidates,
        &indexed,
        read_full,
        embedder,
        outcome,
        per_source,
    )?;

    // `indexed` is keyed by (project_id, id); a candidate id absent from
    // the candidate set is "gone" REGARDLESS of project_id.
    let gone: Vec<(String, String)> = indexed
        .keys()
        .filter(|(_pid, id)| !candidates.contains_key(id))
        .cloned()
        .collect();

    apply_deletes(
        tx,
        source,
        &pass.completeness,
        &gone,
        force,
        opts,
        outcome,
        per_source,
    )
}

/// Map of `(project_id, id)` -> `(content_hash, index_hash)` for the indexed
/// rows under one source. Both hashes are needed for the upsert skip check.
type IndexedHashes = std::collections::HashMap<(String, String), (String, String)>;

fn load_indexed_for_source(
    tx: &Transaction<'_>,
    source: Source,
) -> Result<IndexedHashes, IndexerError> {
    let mut indexed: IndexedHashes = std::collections::HashMap::new();
    let mut stmt = tx.prepare(
        "SELECT project_id, id, content_hash, index_hash FROM records WHERE source = ?1",
    )?;
    let src_str = source.as_db_str();
    let rows = stmt.query_map(params![src_str], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (project_id, id, content_hash, index_hash) = row?;
        indexed.insert((project_id, id), (content_hash, index_hash));
    }
    Ok(indexed)
}

// Same plumbing rationale as `apply_pass_inside_tx`: the per-candidate
// loop needs the read callback, the optional embedder, and the two outcome
// accumulators alongside the SQL handle.
#[allow(clippy::too_many_arguments)]
fn apply_upserts<F>(
    tx: &Transaction<'_>,
    source: Source,
    candidates: &std::collections::HashMap<String, String>,
    indexed: &IndexedHashes,
    read_full: &F,
    embedder: Option<&Embedder>,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError>
where
    F: Fn(&RecordId) -> Option<UnifiedRecord>,
{
    // Build a secondary index keyed by bare `id` so the per-candidate lookup
    // is O(1) rather than O(N). Cross-project same-id collisions within a
    // source are not modeled here — last-write-wins on collision, matching the
    // existing TODO on `candidates` in `apply_pass_inside_tx`.
    let indexed_by_id: std::collections::HashMap<&str, &(String, String)> = indexed
        .iter()
        .map(|((_pid, id), v)| (id.as_str(), v))
        .collect();

    for (id, candidate_content_hash) in candidates {
        // Look up cached hashes for any indexed row under this source with
        // this id.
        let cached_hashes = indexed_by_id.get(id.as_str()).copied();
        // TODO: every candidate now pays a `read_full` + `compute_index_hash`
        // because the dual-hash skip requires the full record. For corpora that
        // are mostly unchanged between passes this is the dominant per-pass cost.
        // Caching `index_hash` alongside `content_hash` on `AdapterPass.records`
        // would restore the cheap pre-`read_full` skip path; needs adapters to
        // surface enough state to compute the hash without the full read.
        let Some(record) = read_full(id) else {
            warn!(
                ?source,
                ?id,
                "adapter list named id but read returned None; skipping"
            );
            continue;
        };
        // The "skip upsert" shortcut requires BOTH hashes to match: the
        // user-visible content_hash (title/summary/body) AND the index_hash
        // (every other load-bearing field — tags, signature_status, etc.).
        // content_hash alone misses tag-only / status-only edits.
        let new_index_hash = compute_index_hash(&record);
        if let Some((cached_content, cached_index)) = cached_hashes
            && cached_content == candidate_content_hash
            && cached_index == &new_index_hash
        {
            // Present + unchanged: refresh the miss counter — it may have been
            // bumped on a prior pass that observed this id as gone.
            reset_miss_for_id(tx, source, id)?;
            continue;
        }
        // Compute the dense embedding before opening the upsert SQL block —
        // but only when `content_hash` (title + summary + body) actually
        // changed. A tag- or status-only edit bumps `index_hash` without
        // touching the embed input, so the previously-stored vector is
        // byte-identical to what we'd recompute; recomputing wastes CPU/GPU
        // inference. Embedding failure is non-fatal: log at warn and persist
        // the record without a vec0 row — FTS still indexes it, and a later
        // re-embedding pass can fill in the gap.
        let content_changed = cached_hashes
            .is_none_or(|(cached_content, _)| cached_content != candidate_content_hash);
        let embedding: Option<Vec<f32>> = if content_changed {
            embedder.and_then(|e| {
                let input = record.embed_input();
                match e.embed(&input) {
                    Ok(v) => Some(v),
                    Err(err) => {
                        warn!(
                            target: "nexum::indexer",
                            ?err,
                            ?id,
                            "embed failed; persisting record without vector",
                        );
                        per_source.embed_failures += 1;
                        None
                    }
                }
            })
        } else {
            None
        };
        upsert(tx, source, &record, &new_index_hash, embedding.as_deref())?;
        per_source.upserts += 1;
        outcome.upserts += 1;
        reset_miss_for_id(tx, source, id)?;
    }
    Ok(())
}

// 8 args after the IndexerOpts thread-through; mirrors apply_pass's shape
// and stays a single-purpose helper rather than a pack-and-unpack args
// struct.
#[allow(clippy::too_many_arguments)]
fn apply_deletes(
    tx: &Transaction<'_>,
    source: Source,
    completeness: &PassCompleteness,
    gone: &[(String, String)],
    force: bool,
    opts: IndexerOpts,
    outcome: &mut IndexerOutcome,
    per_source: &mut PerSourceOutcome,
) -> Result<(), IndexerError> {
    if force {
        for (project_id, id) in gone {
            hard_delete(tx, source, project_id, id)?;
            per_source.deletes += 1;
            outcome.deletes += 1;
        }
        return Ok(());
    }
    match completeness {
        PassCompleteness::Authoritative => {
            let threshold = opts.threshold_override.unwrap_or(STALE_THRESHOLD);
            for (project_id, id) in gone {
                // `index_state` is keyed by (source, id) only; cross-project
                // same-id collisions in miss-tracking are deferred to a
                // follow-up. The composite delete still scopes correctly
                // because hard_delete uses (source, project_id, id).
                let counter = bump_miss(tx, source, id)?;
                if counter >= threshold {
                    hard_delete(tx, source, project_id, id)?;
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
        PassCompleteness::Failed { .. }
        | PassCompleteness::MissingRoot { .. }
        | PassCompleteness::Unreadable { .. } => {
            unreachable!(
                "Failed/MissingRoot/Unreadable passes return early before apply_deletes is called"
            );
        }
    }
    Ok(())
}

/// Flattened, JSON-serialized form of a `UnifiedRecord` ready for binding
/// against the records table. Centralizes the per-row prep so `upsert` can
/// hand the same row off to either the INSERT or the UPDATE path without
/// duplicating the column ordering.
struct UpsertRow<'a> {
    tags_json: String,
    tags_fts: String,
    session_refs_json: String,
    files_json: String,
    commits_json: String,
    extras_json: String,
    body_origin_path: Option<String>,
    now: String,
    /// Encoded for the `records.crypto_result` SQL column (one of
    /// `good` / `bad-signature` / `unknown-signer` / `no-signature`).
    crypto_result: &'a str,
    record_commit_sha: Option<&'a str>,
    signer_fingerprint: Option<&'a str>,
}

impl<'a> UpsertRow<'a> {
    fn from_record(r: &'a UnifiedRecord) -> Self {
        let tags_json = serde_json::to_string(&r.tags).expect("serializable record fields");
        let tags_fts = normalize_tags_for_fts(&tags_json);
        Self {
            tags_json,
            tags_fts,
            session_refs_json: serde_json::to_string(&r.session_refs)
                .expect("serializable record fields"),
            files_json: serde_json::to_string(&r.files).expect("serializable record fields"),
            commits_json: serde_json::to_string(&r.commits).expect("serializable record fields"),
            extras_json: serde_json::to_string(&r.extras).expect("serializable record fields"),
            body_origin_path: r.body_origin_path.as_ref().map(|p| p.display().to_string()),
            now: Utc::now().to_rfc3339(),
            crypto_result: r.provenance.crypto_result.as_db_str(),
            record_commit_sha: r.provenance.record_commit_sha.as_deref(),
            signer_fingerprint: r.provenance.signer_fingerprint.as_deref(),
        }
    }
}

fn upsert(
    tx: &Transaction<'_>,
    source: Source,
    r: &UnifiedRecord,
    index_hash: &str,
    embedding: Option<&[f32]>,
) -> Result<(), IndexerError> {
    let row = UpsertRow::from_record(r);

    // Look up rowid by composite (source, project_id, id) — the natural
    // identity. If a row exists we mirror the documented ordering on the
    // UPDATE path (DELETE the embedding row first, then UPDATE the record,
    // then re-INSERT the embedding when present). The records UPDATE /
    // INSERT statements fire the FTS triggers.
    //
    // Embedding replacement is gated on `embedding.is_some()`. The cases:
    //   1. `content_changed = false` → caller skipped the recompute and the
    //      existing vec0 row is already correct; leave it in place.
    //   2. `content_changed = true && embedding = None` → either embeddings
    //      are disabled (embedder was None) or the live embed call returned
    //      Err. In the disabled case there is nothing to replace anyway. In
    //      the failed-embed case we keep the prior (now-stale-but-present)
    //      vector rather than stripping it; a re-index after the transient
    //      failure clears will refresh it. Stale > missing — the row still
    //      answers k-NN; a missing row drops the record from the semantic
    //      branch entirely until another content edit re-triggers embed.
    //   3. `content_changed = true && embedding = Some(_)` → DELETE the old
    //      row before re-INSERT, per the vec0 ordering rule.
    let existing_rowid: Option<i64> = tx
        .query_row(
            "SELECT rowid FROM records WHERE source = ?1 AND project_id = ?2 AND id = ?3",
            params![source.as_db_str(), r.project_id, r.id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(rid) = existing_rowid {
        if let Some(vec) = embedding {
            tx.execute(
                "DELETE FROM record_embeddings WHERE record_rowid = ?1",
                params![rid],
            )?;
            update_record(tx, r, index_hash, &row, rid)?;
            insert_embedding(tx, rid, vec)?;
        } else {
            update_record(tx, r, index_hash, &row, rid)?;
        }
    } else {
        insert_record(tx, source, r, index_hash, &row)?;
        if let Some(vec) = embedding {
            let rid = tx.last_insert_rowid();
            insert_embedding(tx, rid, vec)?;
        }
    }
    Ok(())
}

/// Insert one row into the `record_embeddings` vec0 virtual table. The
/// caller is responsible for the ordering: on INSERT, records must be
/// written first so `last_insert_rowid()` is valid; on UPDATE, the prior
/// embedding row must be deleted before the new one is written.
///
/// `sqlite-vec` 0.1 accepts a binary blob (raw little-endian f32 bytes)
/// wrapped by the `vec_f32` SQL function. Byte length must equal
/// `EMBED_DIM * 4`; the schema enforces dimension via the `FLOAT[1024]`
/// column declaration.
pub(crate) fn insert_embedding(
    tx: &Transaction<'_>,
    record_rowid: i64,
    embedding: &[f32],
) -> Result<(), IndexerError> {
    let bytes = f32_slice_to_le_bytes(embedding);
    tx.execute(
        "INSERT INTO record_embeddings (record_rowid, embedding) VALUES (?1, vec_f32(?2))",
        params![record_rowid, bytes.as_slice()],
    )?;
    Ok(())
}

/// Re-embed every record already in `records` against the configured embedder.
///
/// Iterates by `rowid` in 50-row batches and persists the resume cursor to
/// `index.db.meta` per batch so a killed run picks up where it left off.
/// Embedder failures on a single row are logged at `warn`, counted in the
/// returned outcome's `failed` field, and skipped; the row keeps its existing
/// embedding (or none).
///
/// # Errors
///
/// Returns `IndexerError::Config` when no embedder can be built from `cfg`
/// (model not installed or configuration invalid).
/// Returns `IndexerError::Rusqlite` on any SQL failure.
pub fn run_reembed_existing(
    conn: &mut Connection,
    cfg: &Config,
    _paths: &Paths,
) -> Result<crate::api::ReembedOutcome, IndexerError> {
    use crate::index::meta::{read_str, write_str};

    const BATCH: i64 = 50;
    const RESUME_KEY: &str = "reembed_resume_rowid";

    let model = build_embedder_for_pass(cfg)?.ok_or_else(|| {
        IndexerError::Config(
            "embedder unavailable: model not installed or config invalid".to_owned(),
        )
    })?;

    // Discriminate the three meta-read outcomes so a transient SQL error
    // doesn't get silently collapsed into "start from scratch" — that would
    // re-embed every row on a large index and rack up hours of work.
    //
    // - SQL error: propagate (the caller's retry decides).
    // - No row yet (first run): start from 0.
    // - Row with unparseable value (manual edit, corruption): warn-log and
    //   start from 0 — staying in lockstep with the previous behavior for
    //   the only failure mode that was actually self-healing.
    let mut resume_rowid: i64 = match read_str(conn, RESUME_KEY)? {
        None => 0,
        Some(raw) => raw.parse::<i64>().unwrap_or_else(|e| {
            tracing::warn!(
                target: "nexum::reembed",
                raw = %raw,
                error = %e,
                "reembed resume cursor unparseable; restarting from rowid 0"
            );
            0
        }),
    };
    let mut embedded: u64 = 0;
    let mut failed: u64 = 0;

    loop {
        let tx = conn.transaction()?;
        let rows: Vec<(i64, String, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT rowid, title, COALESCE(summary, ''), COALESCE(body, '') \
                 FROM records WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
            )?;
            stmt.query_map(params![resume_rowid, BATCH], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let Some(last) = rows.last() else {
            tx.commit()?;
            break;
        };
        let last_rowid_in_batch = last.0;

        for (rowid, title, summary, body) in &rows {
            let text = crate::records::types::embed_input_for(title, summary, body);
            match model.embed(&text) {
                Ok(vec) => {
                    tx.execute(
                        "DELETE FROM record_embeddings WHERE record_rowid = ?1",
                        params![rowid],
                    )?;
                    insert_embedding(&tx, *rowid, &vec)?;
                    embedded += 1;
                }
                Err(e) => {
                    tracing::warn!(rowid = *rowid, error = %e, "reembed: embedding failed; skipping");
                    failed += 1;
                }
            }
        }
        write_str(&tx, RESUME_KEY, &last_rowid_in_batch.to_string())?;
        tx.commit()?;
        resume_rowid = last_rowid_in_batch;
    }

    write_str(conn, RESUME_KEY, "")?;

    Ok(crate::api::ReembedOutcome {
        embedded,
        failed,
        skipped_current: 0,
        resume_rowid: None,
    })
}

fn update_record(
    tx: &Transaction<'_>,
    r: &UnifiedRecord,
    index_hash: &str,
    row: &UpsertRow<'_>,
    rid: i64,
) -> Result<(), IndexerError> {
    tx.execute(
        "UPDATE records SET record_type = ?1, title = ?2, \
         summary = ?3, body = ?4, body_origin_path = ?5, tags = ?6, tags_fts = ?7, \
         confidence = ?8, outcome = ?9, agent = ?10, session_refs = ?11, files = ?12, \
         commits = ?13, created = ?14, updated = ?15, content_hash = ?16, \
         index_hash = ?17, crypto_result = ?18, extras = ?19, indexed_at = ?20, \
         record_commit_sha = ?22, signer_fingerprint = ?23 \
         WHERE rowid = ?21",
        params![
            r.record_type.as_db_str(),
            r.title,
            r.summary,
            r.body,
            row.body_origin_path,
            row.tags_json,
            row.tags_fts,
            r.confidence.as_db_str(),
            r.outcome.as_db_str(),
            r.agent.as_db_str(),
            row.session_refs_json,
            row.files_json,
            row.commits_json,
            r.created.to_rfc3339(),
            r.updated.to_rfc3339(),
            r.content_hash,
            index_hash,
            row.crypto_result,
            row.extras_json,
            row.now,
            rid,
            row.record_commit_sha,
            row.signer_fingerprint,
        ],
    )?;
    Ok(())
}

fn insert_record(
    tx: &Transaction<'_>,
    source: Source,
    r: &UnifiedRecord,
    index_hash: &str,
    row: &UpsertRow<'_>,
) -> Result<(), IndexerError> {
    tx.execute(
        "INSERT INTO records (id, source, project_id, record_type, title, summary, body, \
         body_origin_path, tags, tags_fts, confidence, outcome, agent, session_refs, \
         files, commits, created, updated, content_hash, index_hash, crypto_result, \
         extras, indexed_at, record_commit_sha, signer_fingerprint) VALUES \
         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
          ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
        params![
            r.id,
            source.as_db_str(),
            r.project_id,
            r.record_type.as_db_str(),
            r.title,
            r.summary,
            r.body,
            row.body_origin_path,
            row.tags_json,
            row.tags_fts,
            r.confidence.as_db_str(),
            r.outcome.as_db_str(),
            r.agent.as_db_str(),
            row.session_refs_json,
            row.files_json,
            row.commits_json,
            r.created.to_rfc3339(),
            r.updated.to_rfc3339(),
            r.content_hash,
            index_hash,
            row.crypto_result,
            row.extras_json,
            row.now,
            row.record_commit_sha,
            row.signer_fingerprint,
        ],
    )?;
    Ok(())
}

fn hard_delete(
    tx: &Transaction<'_>,
    source: Source,
    project_id: &str,
    id: &str,
) -> Result<(), IndexerError> {
    let id_owned = id.to_owned();
    let rowid: Option<i64> = tx
        .query_row(
            "SELECT rowid FROM records WHERE source = ?1 AND project_id = ?2 AND id = ?3",
            params![source.as_db_str(), project_id, id],
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
        tx.execute("DELETE FROM records WHERE rowid = ?1", params![rid])?;
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

    #[test]
    fn per_source_outcome_carries_embed_failures() {
        let outcome = PerSourceOutcome {
            source: Source::CcNative,
            completeness: PerSourceCompleteness::Authoritative,
            ingested: 0,
            upserts: 0,
            deletes: 0,
            deferred_deletes: 0,
            embed_failures: 0,
            duplicate_ids_skipped: 0,
            partial_reasons: Vec::new(),
        };
        assert_eq!(outcome.embed_failures, 0);
    }

    #[test]
    fn per_source_outcome_carries_duplicate_ids_skipped() {
        let outcome = PerSourceOutcome {
            source: Source::CcNative,
            completeness: PerSourceCompleteness::Authoritative,
            ingested: 2,
            upserts: 1,
            deletes: 0,
            deferred_deletes: 0,
            embed_failures: 0,
            duplicate_ids_skipped: 1,
            partial_reasons: Vec::new(),
        };
        assert_eq!(outcome.duplicate_ids_skipped, 1);
    }

    #[test]
    fn summarize_skip_reasons_buckets_by_kind() {
        // Two `file-malformed` and one `file-transient` collapse into two
        // summary rows. Order follows `SkipKind`'s declaration order, which
        // is the stable ABI we hand agents.
        use std::path::PathBuf;
        let skipped = vec![
            SkipReason {
                path: PathBuf::from("a.yml"),
                kind: SkipKind::FileMalformed,
                at: chrono::Utc::now(),
            },
            SkipReason {
                path: PathBuf::from("b.yml"),
                kind: SkipKind::FileMalformed,
                at: chrono::Utc::now(),
            },
            SkipReason {
                path: PathBuf::from("c.yml"),
                kind: SkipKind::FileTransient,
                at: chrono::Utc::now(),
            },
        ];
        let summary = summarize_skip_reasons(&skipped);
        assert_eq!(summary.len(), 2);
        // BTreeMap iteration follows `SkipKind`'s declared order:
        // FileTransient, FileMalformed, LockContention.
        assert_eq!(summary[0].kind, SkipKind::FileTransient);
        assert_eq!(summary[0].count, 1);
        assert_eq!(summary[1].kind, SkipKind::FileMalformed);
        assert_eq!(summary[1].count, 2);
    }

    #[test]
    fn per_source_outcome_carries_partial_reasons_field() {
        // The field defaults to empty for non-partial completeness states
        // and round-trips through serde so existing JSON consumers see no
        // change unless `partial_reasons` is populated.
        let outcome = PerSourceOutcome {
            source: Source::Local,
            completeness: PerSourceCompleteness::Partial,
            ingested: 3,
            upserts: 2,
            deletes: 0,
            deferred_deletes: 0,
            embed_failures: 0,
            duplicate_ids_skipped: 0,
            partial_reasons: vec![PartialReasonSummary {
                kind: SkipKind::FileMalformed,
                count: 1,
            }],
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains(r#""partial_reasons":[{"kind":"file-malformed","count":1}]"#));
        let parsed: PerSourceOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.partial_reasons.len(), 1);
        assert_eq!(parsed.partial_reasons[0].count, 1);
    }
}
