//! `nexum index [--force | --incremental]` — build / update the index.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, config::load as load_config, paths::Paths};

#[derive(Args, Debug)]
pub struct IndexArgs {
    /// Force a full pass: bypass the stale-row gate and apply the entire
    /// `gone` set immediately. Useful after manually confirming that the
    /// upstream tool is not actively writing.
    #[arg(long, default_value_t = false)]
    pub force: bool,
    /// Incremental pass (default; equivalent to passing no flag).
    #[arg(long, default_value_t = false)]
    pub incremental: bool,
    /// Print the per-source summary as JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run `nexum index`.
pub fn run(args: &IndexArgs) -> ExitCode {
    if args.force && args.incremental {
        eprintln!("error: --force and --incremental are mutually exclusive");
        return ExitCode::from(2);
    }
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}\nDid you run `nexum init`?");
            return ExitCode::from(3);
        }
    };
    let cfg = match load_config(&paths.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to read config: {e}\nDid you run `nexum init`?");
            return ExitCode::from(3);
        }
    };
    let outcome = if args.force {
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
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(4)
        }
    }
}
