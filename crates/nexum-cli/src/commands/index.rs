//! `nexum index [--force | --incremental | --reembed]` — build / update the index.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api;

// Clap-derived CLI flag struct: each bool is an independent --flag toggle, so
// the state-machine refactor clippy suggests would obscure the surface.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct IndexArgs {
    /// Force a full pass: bypass the stale-row gate and apply the entire
    /// `gone` set immediately. Useful after manually confirming that the
    /// upstream tool is not actively writing.
    #[arg(long, default_value_t = false, conflicts_with = "incremental")]
    pub force: bool,
    /// Incremental pass (default; equivalent to passing no flag).
    #[arg(long, default_value_t = false)]
    pub incremental: bool,
    /// Run a forced index pass and validate `.trust/events.yml` for
    /// tampering. Exits 4 if any tampering is detected.
    #[arg(long, default_value_t = false, conflicts_with = "incremental")]
    pub check: bool,
    /// Re-embed every record already in the index against the configured
    /// embedder. Refuses if `[embed].enabled = false`. Idempotent — a kill
    /// mid-run resumes from where it stopped.
    #[arg(long, default_value_t = false, conflicts_with_all = ["force", "check"])]
    pub reembed: bool,
    /// Run a stale-row sweep pass over all enabled sources. Functions like
    /// an Authoritative pass so the `STALE_THRESHOLD` deferred-delete loop
    /// can fire; pair with `--aggressive` to lower the threshold to 1 for
    /// this pass. Mutually exclusive with --force, --check, and --reembed.
    #[arg(
        long,
        default_value_t = false,
        conflicts_with_all = ["force", "check", "reembed"]
    )]
    pub sweep: bool,
    /// Lower the sweep threshold to 1 so the current pass's gone set is
    /// deleted immediately (one Authoritative pass is enough). Requires
    /// --sweep.
    #[arg(long, default_value_t = false, requires = "sweep")]
    pub aggressive: bool,
    /// Print the per-source summary as JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run `nexum index`.
pub fn run(args: &IndexArgs) -> ExitCode {
    if args.sweep {
        return run_sweep(args.json, args.aggressive);
    }
    if args.reembed {
        return run_reembed(args.json);
    }
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    // --check forces a full crypto + materializer rebuild, then surfaces any
    // detected tampering. When the index pass succeeds, the post-pass
    // tampering check decides the final exit code; an index error short-
    // circuits to STORE_INTEGRITY before the check ever runs.
    let outcome = if args.force || args.check {
        api::index_run_force(&paths, &cfg)
    } else {
        api::index_run(&paths, &cfg)
    };
    // `--check` keeps the legacy stderr-prose channel for pre-tampering
    // errors; the dedicated tampering envelope and the pre-tampering envelope
    // route ship in their own follow-up tasks. Default mode routes
    // serialize-failure and indexer errors through the envelope under
    // `--json`.
    match outcome {
        Ok(o) => {
            if args.json {
                match serde_json::to_string_pretty(&o) {
                    Ok(s) => println!("{s}"),
                    Err(e) => return super::json_emit::emit_serialize_failure(&e),
                }
            } else {
                println!(
                    "Index built. Upserts: {}, deletes: {}, deferred: {}",
                    o.upserts, o.deletes, o.deferred_deletes
                );
                for src in &o.per_source {
                    let embed_col = if src.embed_failures > 0 {
                        format!(" embed_fail={}", src.embed_failures)
                    } else {
                        String::new()
                    };
                    println!(
                        "  [{}] completeness={} ingested={} upserts={} deletes={} deferred={}{}",
                        src.source,
                        src.completeness,
                        src.ingested,
                        src.upserts,
                        src.deletes,
                        src.deferred_deletes,
                        embed_col,
                    );
                }
            }
            if args.check {
                check_tampering(&paths, args.json)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => super::json_emit::route_api_error(&e, args.json && !args.check),
    }
}

/// Run `nexum index --reembed`: re-embed all records in the existing index.
fn run_reembed(emit_json: bool) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(emit_json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    match api::index_reembed(&paths, &cfg) {
        Ok(outcome) => {
            if emit_json {
                let env = serde_json::json!({
                    "ok": true,
                    "kind": "index.reembed.completed",
                    "embedded": outcome.embedded,
                    "failed": outcome.failed,
                });
                println!("{env:#}");
            } else if outcome.failed == 0 {
                println!("re-embedded {} records", outcome.embedded);
            } else {
                println!(
                    "re-embedded {} records; {} failed (see warn logs)",
                    outcome.embedded, outcome.failed,
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => super::json_emit::route_api_error(&e, emit_json),
    }
}

/// Run `nexum index --sweep [--aggressive]`.
///
/// Executes one indexer pass under the writer lock with the stale-row
/// threshold optionally overridden. When `aggressive` is true the threshold
/// drops to 1 so every gone record is deleted on this pass; otherwise the
/// default `STALE_THRESHOLD` (3) applies and the gone set defers until 3
/// consecutive misses confirm the deletion.
fn run_sweep(emit_json: bool, aggressive: bool) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(emit_json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    match api::index_sweep(&paths, &cfg, aggressive) {
        Ok(outcome) => {
            if emit_json {
                let env = serde_json::json!({
                    "ok": true,
                    "kind": "index.sweep.completed",
                    "deletes": outcome.deletes,
                    "deferred_deletes": outcome.deferred_deletes,
                    "aggressive": aggressive,
                });
                println!("{env:#}");
            } else {
                println!(
                    "sweep complete: deleted={}, deferred={}",
                    outcome.deletes, outcome.deferred_deletes,
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => super::json_emit::route_api_error(&e, emit_json),
    }
}

/// Run the cached tampering check after a successful `--check` index pass.
/// The index pass already called `ensure_current` so the materialized view
/// is fresh; `validate_events_cached` reads `trust_chain_tampering` without
/// duplicating the rebuild walk.
///
/// Under `--json`, the underlying-error arm (when `validate_events_cached`
/// itself fails before any rows can be returned) routes through the
/// envelope emitter instead of the prose-on-stderr fallback so agents see
/// a structured `STORE_INTEGRITY` payload on stdout. Default mode keeps the
/// stderr prose for parity with the rest of `index --check`.
fn check_tampering(paths: &nexum_core::paths::Paths, json: bool) -> ExitCode {
    let rows = match api::validate_events_cached(paths) {
        Ok(r) => r,
        Err(e) => return super::json_emit::route_api_error(&e, json),
    };
    super::trust::render_tampering(&rows, json)
}
