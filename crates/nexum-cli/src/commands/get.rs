//! `nexum get <id-or-key> [--json] [--include-unsigned]`.
//!
//! The positional argument accepts either a bare id (`my-record`) or a
//! fully-qualified key (`<source>:<project_id>:<id>`, e.g.
//! `local:git:abc123:my-record`). Bare ids that match more than one row
//! produce an `AMBIGUOUS` exit with the candidate list printed to stderr
//! so the user can re-invoke with the qualified form.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
    query::{GetOpts, QueryError},
    records::{GetOutcome, RecordKey},
};

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Record id (bare) or fully-qualified key `<source>:<project_id>:<id>`.
    pub id: String,
    #[arg(long, default_value_t = false)]
    pub json: bool,
    #[arg(long, default_value_t = false)]
    pub include_unsigned: bool,
}

pub fn run(args: &GetArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let opts = GetOpts {
        include_unsigned: args.include_unsigned,
        trust_policy: cfg.trust.unsigned_default,
        // `strict_revocation` is populated from cfg by the api facade so the
        // CLI does not have to re-thread it. Default keeps the construction
        // exhaustive without leaning on `#[derive(Default)]`'s field defaults.
        strict_revocation: false,
    };
    let key = match parse_key(&args.id) {
        Ok(k) => k,
        Err(c) => return c,
    };
    match api::get(&paths, &cfg, &key, &opts) {
        Ok(GetOutcome::Found(r)) => {
            if args.json {
                match serde_json::to_string_pretty(&r) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: serialize: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!("{}", r.title);
                if let Some(s) = &r.summary {
                    println!("  {s}");
                }
                println!();
                println!("{}", r.body);
            }
            ExitCode::SUCCESS
        }
        Ok(GetOutcome::NotFound) => {
            eprintln!("error: no record matches `{}`", args.id);
            ExitCode::from(super::exit_codes::NOT_FOUND)
        }
        Ok(GetOutcome::HiddenByPolicy { signature_status }) => {
            eprintln!(
                "error: record exists but hidden by trust policy (status: {signature_status}); \
                 retry with --include-unsigned"
            );
            ExitCode::from(super::exit_codes::HIDDEN_BY_POLICY)
        }
        Err(api::ApiError::Query(QueryError::Ambiguous { matches })) => {
            eprintln!(
                "error: ambiguous record id `{}`; {} candidates match. Re-run with the \
                 fully-qualified key `<source>:<project_id>:<id>`:",
                args.id,
                matches.len()
            );
            for m in &matches {
                eprintln!("  {m}");
            }
            ExitCode::from(super::exit_codes::AMBIGUOUS)
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

/// Parse the positional arg into a `RecordKey`. A bare id (no `:`) becomes
/// a bare key; otherwise the qualified form is required and the parse must
/// succeed — a colon-bearing string that fails to parse is a usage error
/// (we won't silently fall back to bare in case the user typoed `local:foo`
/// expecting it to qualify).
fn parse_key(arg: &str) -> Result<RecordKey, ExitCode> {
    if arg.contains(':') {
        RecordKey::parse_qualified(arg).ok_or_else(|| {
            eprintln!(
                "error: `{arg}` looks like a qualified key but isn't valid \
                 `<source>:<project_id>:<id>`"
            );
            ExitCode::from(super::exit_codes::USAGE)
        })
    } else {
        Ok(RecordKey::bare(arg))
    }
}
