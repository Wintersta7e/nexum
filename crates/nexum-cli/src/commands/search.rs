//! `nexum search <query> [filters] [--json] [--full]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
    config::io::load as load_config,
    paths::Paths,
    query::{Filters, SearchOpts},
    records::{Confidence, RecordType, Source},
};

#[derive(Args, Debug)]
// `clap` derive struct mirrors the CLI flag surface 1:1, which legitimately
// includes five booleans (`require_signed`, `strict_revocation`,
// `no_unsigned_penalty`, `json`, `full`). Each is independent and user-
// visible; collapsing them into an enum or struct would distort the help
// output and the underlying API shape.
#[allow(clippy::struct_excessive_bools)]
pub struct SearchArgs {
    pub query: String,
    #[arg(long, default_value_t = 5_u32)]
    pub top_k: u32,
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
    #[arg(long)]
    pub min_confidence: Option<String>,
    #[arg(long, default_value_t = false)]
    pub require_signed: bool,
    #[arg(long, default_value_t = false)]
    pub strict_revocation: bool,
    #[arg(long, default_value_t = false)]
    pub no_unsigned_penalty: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

pub fn run(args: &SearchArgs) -> ExitCode {
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
            eprintln!("error: {e}");
            return ExitCode::from(3);
        }
    };
    let mut opts = SearchOpts::new(args.query.clone());
    opts.top_k = args.top_k;
    opts.trust_policy.clone_from(&cfg.trust.unsigned_default);
    opts.filters = build_filters(args);
    let res = match api::search(&paths, &cfg, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(4);
        }
    };
    if args.json {
        match serde_json::to_string_pretty(&res) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for r in &res.results {
            println!(
                "{:>6.4}  {}  {} ({}) — {}",
                r.score, r.id, r.title, r.signature_status, r.source
            );
            if args.full
                && let Some(b) = &r.body
            {
                println!("    {}", indent_lines(b));
            }
        }
    }
    ExitCode::SUCCESS
}

fn build_filters(args: &SearchArgs) -> Filters {
    Filters {
        record_type: args.r#type.as_deref().and_then(parse_record_type),
        project_id: args.project.clone(),
        source: args.source.as_deref().and_then(parse_source),
        tags: args.tag.clone(),
        since_iso: args.since.clone(),
        min_confidence: args.min_confidence.as_deref().and_then(parse_confidence),
        require_signed: args.require_signed,
        strict_revocation: args.strict_revocation,
        no_unsigned_penalty: args.no_unsigned_penalty,
    }
}

fn parse_record_type(s: &str) -> Option<RecordType> {
    Some(match s {
        "decision" => RecordType::Decision,
        "recommendation" => RecordType::Recommendation,
        "failure" => RecordType::Failure,
        "untyped" => RecordType::Untyped,
        _ => return None,
    })
}

fn parse_source(s: &str) -> Option<Source> {
    Some(match s {
        "local" => Source::Local,
        "cc-native" => Source::CcNative,
        "codex-native" => Source::CodexNative,
        _ => return None,
    })
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    Some(match s {
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        _ => return None,
    })
}

fn indent_lines(s: &str) -> String {
    s.lines().collect::<Vec<_>>().join("\n    ")
}
