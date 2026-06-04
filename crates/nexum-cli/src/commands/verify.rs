//! `nexum verify` — fresh cryptographic verification of a single record.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Record id (bare) or `source/project_id/id` triple.
    pub id: String,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &VerifyArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    match api::verify_record(&paths, &cfg, &args.id) {
        Ok(out) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "verify.completed",
                        "id": out.id,
                        "signature_status": out.signature_status,
                        "trust_basis": out.trust_basis,
                        "warnings": out.warnings,
                        "signer_fingerprint": out.signer_fingerprint,
                        "record_commit_sha": out.record_commit_sha,
                        "commit_evidence": out.commit_evidence_status,
                    })
                );
            } else {
                println!("{}: {}", out.id, out.signature_status);
                if let Some(basis) = &out.trust_basis {
                    println!("  trust basis: {basis}");
                }
                if let Some(fp) = &out.signer_fingerprint {
                    println!("  signer: {fp}");
                }
                if let Some(ce) = &out.commit_evidence_status {
                    println!("  commit evidence: {ce}");
                }
                for w in &out.warnings {
                    eprintln!("  warning: {w}");
                }
            }
            ExitCode::from(verdict_code(&out.signature_status))
        }
        Err(e) => super::common::render_error(&e, args.json),
    }
}

/// Map the live signature verdict to an exit code: `verified` → `0`;
/// `invalid` → the tampering exit code (mirrors `trust validate-events`);
/// `unsigned` / `unknown` / anything else → a soft non-zero failure.
fn verdict_code(status: &str) -> u8 {
    match status {
        "verified" => 0,
        "invalid" => super::exit_codes::STORE_INTEGRITY,
        _ => super::exit_codes::FAILURE,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Cmd {
        #[command(flatten)]
        args: VerifyArgs,
    }

    fn parse(args: &[&str]) -> Result<VerifyArgs, clap::Error> {
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full).map(|c| c.args)
    }

    #[test]
    fn id_required_and_parses() {
        let a = parse(&["abc123"]).unwrap();
        assert_eq!(a.id, "abc123");
        assert!(!a.json);
    }

    #[test]
    fn qualified_id_and_json_parse() {
        let a = parse(&["local/proj/rec42", "--json"]).unwrap();
        assert_eq!(a.id, "local/proj/rec42");
        assert!(a.json);
    }

    #[test]
    fn missing_id_fails_parse() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn verdict_code_maps_each_verdict() {
        assert_eq!(verdict_code("verified"), 0);
        assert_eq!(
            verdict_code("invalid"),
            super::super::exit_codes::STORE_INTEGRITY
        );
        assert_eq!(verdict_code("unsigned"), super::super::exit_codes::FAILURE);
        assert_eq!(verdict_code("unknown"), super::super::exit_codes::FAILURE);
    }
}
