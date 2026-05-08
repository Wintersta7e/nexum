//! `nexum by-session <session-or-rollout-path>`.

use std::process::ExitCode;

use clap::Args;
use nexum_core::{
    api,
    api::error::ErrorEnvelope,
    query::{Filters, SessionLookup},
};

#[derive(Args, Debug)]
pub struct BySessionArgs {
    /// CC session UUID, Codex rollout path (`.jsonl`), or Codex thread id.
    pub needle: String,
    #[arg(long, default_value_t = false)]
    pub require_signed: bool,
    #[arg(long, default_value_t = false)]
    pub strict_revocation: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &BySessionArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let lookup = if let Ok(uuid) = uuid::Uuid::parse_str(&args.needle) {
        SessionLookup::CcSession { uuid }
    } else if has_jsonl_ext(&args.needle) {
        SessionLookup::CodexRollout {
            path: args.needle.clone().into(),
        }
    } else {
        SessionLookup::CodexThread {
            thread_id: args.needle.clone(),
        }
    };
    let filters = Filters {
        require_signed: args.require_signed,
        strict_revocation: args.strict_revocation,
        ..Filters::default()
    };
    let rs = match api::by_session(&paths, &cfg, &filters, &lookup) {
        Ok(r) => r,
        Err(e) => {
            if args.json {
                let env: ErrorEnvelope = (&e).into();
                return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
            }
            return super::common::handle_read_verb_error(&e);
        }
    };
    if args.json {
        match serde_json::to_string_pretty(&rs) {
            Ok(s) => println!("{s}"),
            Err(e) => return super::json_emit::emit_serialize_failure(&e),
        }
    } else {
        for r in &rs.results {
            println!("  {}  {}", r.id, r.title);
        }
    }
    ExitCode::SUCCESS
}

/// Case-insensitive `.jsonl` suffix check. Treats Windows-style mixed-case
/// extensions (`.JSONL`, `.Jsonl`) the same as `.jsonl` so the rollout
/// detection is platform-friendly.
fn has_jsonl_ext(needle: &str) -> bool {
    std::path::Path::new(needle)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
}
