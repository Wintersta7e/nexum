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
    api::error::{ErrorEnvelope, Remediation, error_codes},
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
    #[arg(long, default_value_t = false)]
    pub strict_revocation: bool,
}

pub fn run(args: &GetArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let opts = GetOpts {
        include_unsigned: args.include_unsigned,
        trust_policy: cfg.trust.unsigned_default,
        strict_revocation: args.strict_revocation,
    };
    let key = match parse_key(&args.id) {
        Ok(k) => k,
        Err(c) => return c,
    };
    match api::get(&paths, &cfg, &key, &opts) {
        Ok(GetOutcome::Found { record: r, meta }) => {
            if args.json {
                // `get --json` success emits `{ record, _meta }` — the
                // record nested under `record`, the shared envelope under
                // `_meta`. The CLI names the field `_meta` explicitly here
                // because an enum variant's fields cannot carry a
                // struct-level serde rename.
                let payload = serde_json::json!({ "record": &r, "_meta": &meta });
                match serde_json::to_string_pretty(&payload) {
                    Ok(s) => println!("{s}"),
                    Err(e) => return super::json_emit::emit_serialize_failure(&e),
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
            let env = ErrorEnvelope {
                error_code: error_codes::NOT_FOUND,
                message: format!("no record matches `{}`", args.id),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Verify the id is correct, or run `nexum search` \
                                to find candidate records."
                        .into(),
                }),
                context: serde_json::json!({ "requested_id": args.id }),
            };
            if args.json {
                super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(super::exit_codes::NOT_FOUND)
            }
        }
        Ok(GetOutcome::HiddenByPolicy { signature_status }) => {
            let env = ErrorEnvelope {
                error_code: error_codes::HIDDEN_BY_POLICY,
                message: format!(
                    "record exists but hidden by trust policy (status: {signature_status})"
                ),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Retry with `--include-unsigned` to inspect the record \
                                deliberately."
                        .into(),
                }),
                context: serde_json::json!({
                    "signature_status": signature_status.to_string(),
                }),
            };
            if args.json {
                super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {}; retry with --include-unsigned", env.message);
                ExitCode::from(super::exit_codes::HIDDEN_BY_POLICY)
            }
        }
        Err(e) => {
            if args.json {
                let env: ErrorEnvelope = (&e).into();
                super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env))
            } else if let api::ApiError::Query(QueryError::Ambiguous { matches }) = &e {
                // Default mode: keep the legacy ambiguous-with-list rendering.
                eprintln!(
                    "error: ambiguous record id `{}`; {} candidates match. Re-run with the \
                     fully-qualified key `<source>:<project_id>:<id>`:",
                    args.id,
                    matches.len()
                );
                for m in matches {
                    eprintln!("  {m}");
                }
                ExitCode::from(super::exit_codes::AMBIGUOUS)
            } else {
                super::common::handle_read_verb_error(&e)
            }
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
