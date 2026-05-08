//! `nexum index [--force | --incremental]` — build / update the index.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, api::error::ErrorEnvelope};

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
    /// Print the per-source summary as JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run `nexum index`.
pub fn run(args: &IndexArgs) -> ExitCode {
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
                    println!(
                        "  [{}] completeness={} ingested={} upserts={} deletes={} deferred={}",
                        src.source,
                        src.completeness,
                        src.ingested,
                        src.upserts,
                        src.deletes,
                        src.deferred_deletes,
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
        Err(e) => {
            if json {
                let env: ErrorEnvelope = (&e).into();
                return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
            }
            return super::common::handle_read_verb_error(&e);
        }
    };
    super::trust::render_tampering(&rows, json)
}
