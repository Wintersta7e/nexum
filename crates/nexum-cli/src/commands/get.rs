//! `nexum get <id> [--json] [--include-unsigned]`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{api, config::io::load as load_config, paths::Paths, query::GetOpts};

#[derive(Args, Debug)]
pub struct GetArgs {
    pub id: String,
    #[arg(long, default_value_t = false)]
    pub json: bool,
    #[arg(long, default_value_t = false)]
    pub include_unsigned: bool,
}

pub fn run(args: &GetArgs) -> ExitCode {
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
    let opts = GetOpts {
        include_unsigned: args.include_unsigned,
        trust_policy: cfg.trust.unsigned_default.clone(),
    };
    match api::get(&paths, &args.id, &opts) {
        Ok(Some(r)) => {
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
        Ok(None) => {
            eprintln!(
                "error: record `{}` not found OR hidden by trust policy `{}` (try --include-unsigned)",
                args.id, opts.trust_policy
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(4)
        }
    }
}
