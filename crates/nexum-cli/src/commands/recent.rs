//! `nexum recent [--limit=N] [--source=...]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, query::QueryError};

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
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
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
        Err(api::ApiError::Query(QueryError::IndexMissing { path })) => {
            super::common::handle_index_missing(&path)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(super::exit_codes::STORE_INTEGRITY)
        }
    }
}
