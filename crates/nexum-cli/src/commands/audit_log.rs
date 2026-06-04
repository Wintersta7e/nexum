//! `nexum audit-log` — walk the notebook history newest-first, classifying
//! each commit by its lifecycle kind.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api;

#[derive(Args, Debug)]
pub struct AuditLogArgs {
    /// Cap the number of entries returned (newest-first).
    #[arg(long)]
    pub limit: Option<usize>,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &AuditLogArgs) -> ExitCode {
    let (paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    match api::audit_log(&paths, args.limit) {
        Ok(entries) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "audit_log.completed",
                        "entries": entries.iter().map(|e| serde_json::json!({
                            "commit_sha": e.commit_sha,
                            "kind": e.kind,
                            "subject": e.subject,
                            "signer_fingerprint": e.signer_fingerprint,
                            "committed_at": e.committed_at,
                        })).collect::<Vec<_>>(),
                    })
                );
            } else {
                for e in &entries {
                    let short = &e.commit_sha[..e.commit_sha.len().min(8)];
                    println!("{short}  {:9}  {}", e.kind, e.subject);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => super::common::render_error(&e, args.json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Cmd {
        #[command(flatten)]
        args: AuditLogArgs,
    }

    fn parse(args: &[&str]) -> Result<AuditLogArgs, clap::Error> {
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full).map(|c| c.args)
    }

    #[test]
    fn no_args_parse_to_defaults() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.limit, None);
        assert!(!a.json);
    }

    #[test]
    fn limit_and_json_parse() {
        let a = parse(&["--limit", "10", "--json"]).unwrap();
        assert_eq!(a.limit, Some(10));
        assert!(a.json);
    }

    #[test]
    fn non_numeric_limit_fails_parse() {
        assert!(parse(&["--limit", "abc"]).is_err());
    }
}
