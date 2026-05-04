//! `nexum list [filters] [--json]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
    query::{Filters, QueryError},
    records::{RecordType, Source},
};

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    pub r#type: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long)]
    pub tag: Vec<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long, default_value_t = 50_u32)]
    pub limit: u32,
    #[arg(long)]
    pub cursor: Option<String>,
    #[arg(long, default_value_t = false)]
    pub require_signed: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &ListArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
    };

    let filters = Filters {
        record_type: args
            .r#type
            .as_deref()
            .and_then(RecordType::try_from_user_str),
        project_id: args.project.clone(),
        source: args.source.as_deref().and_then(Source::try_from_user_str),
        tags: args.tag.clone(),
        since_iso: args.since.clone(),
        min_confidence: None,
        require_signed: args.require_signed,
        strict_revocation: false,
        no_unsigned_penalty: false,
    };

    match api::list(&paths, &cfg, &filters, args.limit, args.cursor.as_deref()) {
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
                    println!("  {}  {}  ({})", r.id, r.title, r.updated);
                }
                if let Some(c) = rs.next_cursor {
                    println!("Next cursor: {c}");
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
