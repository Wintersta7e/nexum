//! `nexum recent [--limit=N] [--source=...]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, query::Filters};

#[derive(Args, Debug)]
pub struct RecentArgs {
    #[arg(long, default_value_t = 10_u32)]
    pub limit: u32,
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long, default_value_t = false)]
    pub require_signed: bool,
    #[arg(long, default_value_t = false)]
    pub strict_revocation: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &RecentArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let filters = Filters {
        require_signed: args.require_signed,
        strict_revocation: args.strict_revocation,
        ..Filters::default()
    };
    let rs = match api::recent(&paths, &cfg, &filters, args.limit, args.source.as_deref()) {
        Ok(r) => r,
        Err(e) => return super::json_emit::route_api_error(&e, args.json),
    };
    if args.json {
        match serde_json::to_string_pretty(&rs) {
            Ok(s) => println!("{s}"),
            Err(e) => return super::json_emit::emit_serialize_failure(&e),
        }
    } else {
        for r in &rs.results {
            println!("  {}  {}  {}", r.updated, r.id, r.title);
        }
    }
    ExitCode::SUCCESS
}
