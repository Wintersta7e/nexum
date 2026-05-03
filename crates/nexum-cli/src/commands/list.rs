//! `nexum list [filters] [--json]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
    config::io::load as load_config,
    paths::Paths,
    query::Filters,
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

    let filters = Filters {
        record_type: args.r#type.as_deref().and_then(|s| match s {
            "decision" => Some(RecordType::Decision),
            "recommendation" => Some(RecordType::Recommendation),
            "failure" => Some(RecordType::Failure),
            "untyped" => Some(RecordType::Untyped),
            _ => None,
        }),
        project_id: args.project.clone(),
        source: args.source.as_deref().and_then(|s| match s {
            "local" => Some(Source::Local),
            "cc-native" => Some(Source::CcNative),
            "codex-native" => Some(Source::CodexNative),
            _ => None,
        }),
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
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(4)
        }
    }
}
