//! `nexum index [--force | --incremental]` — build / update the index.

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
    #[arg(long, default_value_t = false)]
    pub check: bool,
    /// Print the per-source summary as JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run `nexum index`.
pub fn run(args: &IndexArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
    };
    // --check forces a full crypto + materializer rebuild, then surfaces any
    // detected tampering. If tampering is present, exit 4 even if the index
    // pass itself succeeded — the integrity signal wins over the upsert count.
    let outcome = if args.force || args.check {
        api::index_run_force(&paths, &cfg)
    } else {
        api::index_run(&paths, &cfg)
    };
    match outcome {
        Ok(o) => {
            if args.json {
                match serde_json::to_string_pretty(&o) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: failed to serialize outcome: {e}");
                        return ExitCode::FAILURE;
                    }
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
        Err(e) => super::common::handle_read_verb_error(&e),
    }
}

/// Run `validate_events` after a successful `--check` index pass and surface
/// any detected tampering. Splits out so the orchestration is testable
/// independently of the index pass.
fn check_tampering(paths: &nexum_core::paths::Paths, json: bool) -> ExitCode {
    let rows = match api::validate_events(paths) {
        Ok(r) => r,
        Err(e) => return super::common::handle_read_verb_error(&e),
    };
    if json {
        if let Err(e) = serde_json::to_string_pretty(&rows).map(|s| println!("{s}")) {
            eprintln!("error: serialize: {e}");
            return ExitCode::FAILURE;
        }
    } else if rows.is_empty() {
        println!("trust events: clean (no tampering detected)");
    } else {
        eprintln!("trust events: {} tampering event(s) detected:", rows.len());
        for r in &rows {
            eprintln!(
                "  - commit {} (topo {}): {} on event {}",
                r.at_commit, r.at_topo_pos, r.kind, r.event_id
            );
        }
    }
    if rows.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(super::exit_codes::STORE_INTEGRITY)
    }
}
