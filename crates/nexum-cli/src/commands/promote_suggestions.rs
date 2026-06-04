//! `nexum promote-suggestions` — sweep stale recommendations, then scan
//! proposed recommendations for candidate commits and (interactively) promote.

use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use clap::Args;
use nexum_core::api::{self, Suggestion};
use nexum_core::config::types::Config;
use nexum_core::paths::Paths;

#[derive(Args, Debug)]
pub struct PromoteSuggestionsArgs {
    /// Print candidates without prompting (agent-friendly; pairs with --json).
    #[arg(long, default_value_t = false)]
    pub non_interactive: bool,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// Cap the number of candidates printed / prompted.
    #[arg(long)]
    pub limit: Option<usize>,
}

pub fn run(args: &PromoteSuggestionsArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut out = match api::promote_suggestions(&paths, &cfg) {
        Ok(o) => o,
        Err(e) => return super::common::render_error(&e, args.json),
    };
    if let Some(limit) = args.limit {
        out.suggestions.truncate(limit);
    }

    if args.json || args.non_interactive {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "kind": "promote_suggestions.completed",
                "marked_stale": out.marked_stale,
                "suggestions": out.suggestions.iter().map(|s| serde_json::json!({
                    "rec_id": s.rec_id,
                    "project_id": s.project_id,
                    "commit_sha": s.commit_sha,
                    "file_overlap": s.file_overlap,
                    "message_reference": s.message_reference,
                })).collect::<Vec<_>>(),
                "index_warning": out.index_warning,
            })
        );
        return ExitCode::SUCCESS;
    }

    // Human path. Surface the stale sweep first (a visible auto-mutation).
    if out.marked_stale > 0 {
        println!(
            "Marked {} recommendation(s) as stale (>{}d, no candidate commit)",
            out.marked_stale, cfg.promote.correlation_window_days
        );
    }
    if out.index_warning.is_some() {
        eprintln!("warning: index refresh failed after the stale sweep; run `nexum index`");
    }
    if out.suggestions.is_empty() {
        println!("No promotion candidates.");
        return ExitCode::SUCCESS;
    }
    interactive_walk(&paths, &cfg, &out.suggestions)
}

/// Walk each candidate, prompting `[y/n/skip-rec/skip-rest]`. `y` promotes the
/// (rec, commit) pair; `n` moves on; `skip-rec` drops remaining candidates for
/// that rec; `skip-rest` (and EOF) stops the walk. Unrecognized input is
/// treated as `n`.
fn interactive_walk(paths: &Paths, cfg: &Config, suggestions: &[Suggestion]) -> ExitCode {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut skipped_recs: HashSet<&str> = HashSet::new();
    for s in suggestions {
        if skipped_recs.contains(s.rec_id.as_str()) {
            continue;
        }
        let short = &s.commit_sha[..s.commit_sha.len().min(8)];
        print!(
            "promote {} via {} (overlap {:.2}, msg-ref {})? [y/n/skip-rec/skip-rest] ",
            s.rec_id, short, s.file_overlap, s.message_reference
        );
        let _ = io::stdout().flush();
        let Some(Ok(line)) = lines.next() else {
            break; // EOF or read error → skip-rest
        };
        match line.trim() {
            "y" => promote_one(paths, cfg, s),
            "skip-rec" => {
                skipped_recs.insert(s.rec_id.as_str());
            }
            "skip-rest" => break,
            // "n" and anything unrecognized fall through to the next candidate.
            _ => {}
        }
    }
    ExitCode::SUCCESS
}

/// Promote a single suggestion, printing the outcome. Errors are surfaced on
/// stderr without aborting the walk.
fn promote_one(paths: &Paths, cfg: &Config, s: &Suggestion) {
    let params = api::PromoteParams {
        rec: &s.rec_id,
        commit: &s.commit_sha,
        repo: None,
        branch: None,
        skip_fingerprint: false,
        force_untrusted: false,
    };
    match api::promote(paths, cfg, &params) {
        Ok(o) => {
            println!(
                "  promoted -> {} ({})",
                o.decision_id, o.commit_evidence_status
            );
            if o.index_warning.is_some() {
                eprintln!("  warning: index refresh failed; run `nexum index`");
            }
        }
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            eprintln!("  error: {}", env.message);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Cmd {
        #[command(flatten)]
        args: PromoteSuggestionsArgs,
    }

    fn parse(args: &[&str]) -> Result<PromoteSuggestionsArgs, clap::Error> {
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full).map(|c| c.args)
    }

    #[test]
    fn no_args_parse_to_defaults() {
        let a = parse(&[]).unwrap();
        assert!(!a.non_interactive);
        assert!(!a.json);
        assert_eq!(a.limit, None);
    }

    #[test]
    fn all_flags_parse() {
        let a = parse(&["--non-interactive", "--json", "--limit", "5"]).unwrap();
        assert!(a.non_interactive);
        assert!(a.json);
        assert_eq!(a.limit, Some(5));
    }

    #[test]
    fn non_numeric_limit_fails_parse() {
        assert!(parse(&["--limit", "abc"]).is_err());
    }
}
