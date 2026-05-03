//! `nexum recent [--limit=N] [--source=...]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, config::io::load as load_config, paths::Paths};

#[derive(Args, Debug)]
pub struct RecentArgs {
    #[arg(long, default_value_t = 10_u32)]
    pub limit: u32,
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &RecentArgs) -> ExitCode {
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    let cfg = match load_config(&paths.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    match api::recent(&paths, &cfg, args.limit, args.source.as_deref()) {
        Ok(rs) => {
            if args.json {
                match serde_json::to_string_pretty(&rs) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: serialize: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                for r in &rs.results {
                    println!("  {}  {}  {}", r.updated, r.id, r.title);
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
