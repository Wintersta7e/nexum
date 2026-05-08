//! `nexum search <query> [filters] [--json] [--full]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
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
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut opts = SearchOpts::new(args.query.clone());
    opts.top_k = args.top_k;
    opts.trust_policy = cfg.trust.unsigned_default;
    opts.filters = build_filters(args);
    let res = match api::search(&paths, &cfg, &opts) {
        Ok(r) => r,
        Err(e) => {
            if args.json {
                let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
                let code = super::exit_codes::for_envelope(&env);
                return super::json_emit::emit_error(&env, code);
            }
            return super::common::handle_read_verb_error(&e);
        }
    };
    if args.json {
        match serde_json::to_string_pretty(&res) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                let env = nexum_core::api::error::ErrorEnvelope {
                    error_code: nexum_core::api::error::error_codes::SERIALIZE_FAILED,
                    message: format!("serialize: {e}"),
                    remediation: None,
                    context: serde_json::json!({ "kind": "json", "message": format!("{e}") }),
                };
                return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
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
                println!("{}", indent_lines(b));
            }
        }
    }
    ExitCode::SUCCESS
}

fn build_filters(args: &SearchArgs) -> Filters {
    Filters {
        record_type: args
            .r#type
            .as_deref()
            .and_then(RecordType::try_from_user_str),
        project_id: args.project.clone(),
        source: args.source.as_deref().and_then(Source::try_from_user_str),
        tags: args.tag.clone(),
        since_iso: args.since.clone(),
        min_confidence: args
            .min_confidence
            .as_deref()
            .and_then(Confidence::try_from_user_str),
        require_signed: args.require_signed,
        strict_revocation: args.strict_revocation,
        no_unsigned_penalty: args.no_unsigned_penalty,
    }
}

const BODY_INDENT: &str = "    ";

fn indent_lines(s: &str) -> String {
    s.lines()
        .map(|l| format!("{BODY_INDENT}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}
