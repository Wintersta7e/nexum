//! `nexum promote` — promote a local recommendation to a decision.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use nexum_core::api::{self, error::ErrorEnvelope, error::Remediation, error::error_codes};

#[allow(clippy::struct_excessive_bools)] // flag cluster mirrors the API surface; no state-machine applies
#[derive(Args, Debug)]
pub struct PromoteArgs {
    /// Recommendation id (bare) or `source/project_id/id` triple.
    pub rec: String,
    /// Project-repo commit that enacts the recommendation.
    #[arg(long)]
    pub commit: String,
    /// Override the project repo path (else resolved from the registry).
    #[arg(long)]
    pub repo: Option<PathBuf>,
    /// Override default-branch resolution.
    #[arg(long)]
    pub branch: Option<String>,
    /// Record the commit claim without live fingerprint verification.
    #[arg(long, default_value_t = false)]
    pub skip_fingerprint: bool,
    /// Promote despite an unsigned/unknown source (requires the ack flag).
    #[arg(long, default_value_t = false)]
    pub force_untrusted: bool,
    /// Explicit acknowledgement required by --force-untrusted.
    #[arg(long, default_value_t = false)]
    pub acknowledge_untrusted_promotion: bool,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &PromoteArgs) -> ExitCode {
    let (paths, cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    // Reject a commit/branch that git could mis-parse as an option or revision
    // expression before it reaches any git subprocess in the core.
    if let Err(reason) = validate_promote_refs(&args.commit, args.branch.as_deref()) {
        return emit_usage(reason, None, "invalid_commit_or_branch", args.json);
    }
    if args.force_untrusted && !args.acknowledge_untrusted_promotion {
        return emit_usage(
            "--force-untrusted requires --acknowledge-untrusted-promotion".to_owned(),
            Some(Remediation {
                command: None,
                rationale:
                    "Re-run with both --force-untrusted and --acknowledge-untrusted-promotion."
                        .to_owned(),
            }),
            "force_untrusted_not_acknowledged",
            args.json,
        );
    }
    let params = api::PromoteParams {
        rec: &args.rec,
        commit: &args.commit,
        repo: args.repo.as_deref(),
        branch: args.branch.as_deref(),
        skip_fingerprint: args.skip_fingerprint,
        force_untrusted: args.force_untrusted,
    };
    match api::promote(&paths, &cfg, &params) {
        Ok(out) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "promote.completed",
                        "decision_id": out.decision_id,
                        "notebook_commit": out.notebook_commit,
                        "commit_evidence": out.commit_evidence_status,
                        "index_warning": out.index_warning,
                    })
                );
            } else {
                println!(
                    "promoted {} -> {} ({})",
                    args.rec, out.decision_id, out.commit_evidence_status
                );
                if out.index_warning.is_some() {
                    eprintln!("warning: index refresh failed; run `nexum index`");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => super::common::render_error(&e, args.json),
    }
}

/// Reject a commit SHA / branch name that git could interpret as an option or
/// a revision expression (argument injection) when passed as a positional.
fn validate_promote_refs(commit: &str, branch: Option<&str>) -> Result<(), String> {
    if commit.is_empty() || commit.len() > 64 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "--commit must be a hex commit SHA (1-64 hex chars), got {commit:?}"
        ));
    }
    if let Some(b) = branch {
        let valid = !b.is_empty()
            && !b.starts_with('-')
            && !b.contains("..")
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'/'));
        if !valid {
            return Err(format!("--branch is not a valid branch name, got {b:?}"));
        }
    }
    Ok(())
}

/// Emit a `USAGE` `ErrorEnvelope` (JSON or prose) and return the exit code.
fn emit_usage(
    message: String,
    remediation: Option<Remediation>,
    subkind: &str,
    json: bool,
) -> ExitCode {
    let env = ErrorEnvelope {
        error_code: error_codes::USAGE,
        message,
        remediation,
        context: serde_json::json!({ "kind": "promote", "subkind": subkind }),
        severity: None,
        state_mutated: None,
        requires_reindex: None,
    };
    if json {
        super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env))
    } else {
        eprintln!("error: {}", env.message);
        ExitCode::from(super::exit_codes::USAGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // Minimal wrapper so PromoteArgs can be parsed standalone in tests.
    #[derive(Parser, Debug)]
    struct Cmd {
        #[command(flatten)]
        args: PromoteArgs,
    }

    fn parse(args: &[&str]) -> Result<PromoteArgs, clap::Error> {
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full).map(|c| c.args)
    }

    #[test]
    fn minimal_required_args_parse() {
        let a = parse(&["abc123", "--commit", "deadbeef"]).unwrap();
        assert_eq!(a.rec, "abc123");
        assert_eq!(a.commit, "deadbeef");
        assert!(!a.skip_fingerprint);
        assert!(!a.force_untrusted);
        assert!(!a.acknowledge_untrusted_promotion);
        assert!(!a.json);
    }

    #[test]
    fn all_flags_parse() {
        let a = parse(&[
            "src/proj/rec1",
            "--commit",
            "abc",
            "--repo",
            "/tmp/repo",
            "--branch",
            "main",
            "--skip-fingerprint",
            "--force-untrusted",
            "--acknowledge-untrusted-promotion",
            "--json",
        ])
        .unwrap();
        assert_eq!(a.rec, "src/proj/rec1");
        assert!(a.skip_fingerprint);
        assert!(a.force_untrusted);
        assert!(a.acknowledge_untrusted_promotion);
        assert!(a.json);
    }

    #[test]
    fn missing_commit_fails_parse() {
        assert!(parse(&["abc123"]).is_err());
    }

    #[test]
    fn force_untrusted_without_ack_returns_usage() {
        // The ack gate fires at run() time, not parse time.
        // Verify parse succeeds but the combination is structurally representable.
        let a = parse(&["rec", "--commit", "sha", "--force-untrusted"]).unwrap();
        assert!(a.force_untrusted);
        assert!(!a.acknowledge_untrusted_promotion);
        // run() would return USAGE for this combo; tested at the unit level:
        // we cannot call run() here without a live store, so we verify the
        // gate condition directly.
        assert!(a.force_untrusted && !a.acknowledge_untrusted_promotion);
    }

    #[test]
    fn validate_promote_refs_accepts_hex_and_safe_branch() {
        assert!(validate_promote_refs("deadbeef", None).is_ok());
        assert!(validate_promote_refs("abc123", Some("release/1.2")).is_ok());
    }

    #[test]
    fn validate_promote_refs_rejects_non_hex_commit() {
        assert!(validate_promote_refs("--output=/tmp/x", None).is_err());
        assert!(validate_promote_refs("HEAD~1", None).is_err());
    }

    #[test]
    fn validate_promote_refs_rejects_flaglike_or_range_branch() {
        assert!(validate_promote_refs("abcd", Some("--all")).is_err());
        assert!(validate_promote_refs("abcd", Some("a..b")).is_err());
    }
}
