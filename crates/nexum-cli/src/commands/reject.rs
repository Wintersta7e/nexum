//! `nexum reject` — reject a local recommendation.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api;

#[derive(Args, Debug)]
pub struct RejectArgs {
    /// Recommendation id (bare) or `source/project_id/id` triple.
    pub rec: String,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &RejectArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    match api::reject(&paths, &cfg, &args.rec) {
        Ok(out) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "reject.completed",
                        "notebook_commit": out.notebook_commit,
                        "index_warning": out.index_warning,
                    })
                );
            } else {
                println!("rejected {} (commit {})", args.rec, out.notebook_commit);
                if out.index_warning.is_some() {
                    eprintln!("warning: index refresh failed; run `nexum index`");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => render_error(&e, args.json),
    }
}

fn render_error(e: &api::ApiError, json: bool) -> ExitCode {
    let env: nexum_core::api::error::ErrorEnvelope = e.into();
    let code = super::exit_codes::for_envelope(&env);
    if json {
        super::json_emit::emit_error(&env, code)
    } else {
        eprintln!("error: {}", env.message);
        ExitCode::from(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Cmd {
        #[command(flatten)]
        args: RejectArgs,
    }

    fn parse(args: &[&str]) -> Result<RejectArgs, clap::Error> {
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full).map(|c| c.args)
    }

    #[test]
    fn minimal_required_args_parse() {
        let a = parse(&["abc123"]).unwrap();
        assert_eq!(a.rec, "abc123");
        assert!(!a.json);
    }

    #[test]
    fn json_flag_parses() {
        let a = parse(&["abc123", "--json"]).unwrap();
        assert_eq!(a.rec, "abc123");
        assert!(a.json);
    }

    #[test]
    fn missing_rec_fails_parse() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn qualified_id_parses() {
        let a = parse(&["local/proj/rec42"]).unwrap();
        assert_eq!(a.rec, "local/proj/rec42");
    }
}
