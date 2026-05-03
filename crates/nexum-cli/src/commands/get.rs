//! `nexum get <id> [--json] [--include-unsigned]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, query::GetOpts, records::GetOutcome};

#[derive(Args, Debug)]
pub struct GetArgs {
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
    };
    match api::get(&paths, &args.id, &opts) {
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
            eprintln!("error: no record matches id `{}`", args.id);
            ExitCode::from(super::exit_codes::NOT_FOUND)
        }
        Ok(GetOutcome::HiddenByPolicy { signature_status }) => {
            eprintln!(
                "error: record exists but hidden by trust policy (status: {signature_status}); \
                 retry with --include-unsigned"
            );
            ExitCode::from(super::exit_codes::HIDDEN_BY_POLICY)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(super::exit_codes::RUNTIME)
        }
    }
}
