//! `nexum keys` parent + subcommands.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::api;
use nexum_core::api::RevokeMode;

use super::common::resolve_runtime;
use super::exit_codes;
use super::json_emit;

#[derive(Subcommand, Debug)]
pub enum KeysCommand {
    /// Add a new signing key without retiring the old one. The CURRENT key
    /// signs the rotation commit and stays trusted; a future revocation
    /// command retires it.
    Rotate(RotateArgs),
    /// List every known signing key with its current trust role.
    List(ListArgs),
    /// Revoke a signing key. Requires exactly one of --rotation
    /// (routine retirement) or --strict (suspected compromise).
    Revoke(RevokeArgs),
}

#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Path to the new SSH **private** key. The wrapper reads `<path>.pub`
    /// to derive the public-key blob and fingerprint.
    #[arg(long)]
    pub new_key: PathBuf,
    /// Human-readable reason recorded on the `KeyAdded` event.
    #[arg(long, default_value = "operator-initiated rotation")]
    pub reason: String,
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
#[command(group(
    clap::ArgGroup::new("mode")
        .required(true)
        .args(["rotation", "strict"]),
))]
// The four bool flags are the natural surface for the revoke verb
// (mode picker + confirmation skip + JSON output). Splitting them into
// sub-structs would invert the clap derive ergonomics for no payoff.
#[allow(clippy::struct_excessive_bools)]
pub struct RevokeArgs {
    /// SSH fingerprint to revoke (the SHA256:... form from `keys list`).
    pub fingerprint: String,

    /// Routine retirement. Records signed by this key before now remain
    /// valid as verified-at-signing.
    #[arg(long, default_value_t = false)]
    pub rotation: bool,

    /// Suspected compromise. Records signed by this key before now stay
    /// readable but flagged; under --strict-revocation they're excluded.
    #[arg(long, default_value_t = false)]
    pub strict: bool,

    /// Human-readable reason recorded on the trust event.
    #[arg(long)]
    pub reason: Option<String>,

    /// Skip the --strict prompt-confirm (no effect for --rotation).
    /// Required when invoking with --json + --strict.
    #[arg(long, default_value_t = false)]
    pub yes: bool,

    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(cmd: &KeysCommand) -> ExitCode {
    match cmd {
        KeysCommand::Rotate(args) => run_rotate(args),
        KeysCommand::List(args) => run_list(args),
        KeysCommand::Revoke(args) => run_revoke(args),
    }
}

/// First 12 chars (or the whole string if shorter) for human-readable commit display.
fn short_commit(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

fn run_list(args: &ListArgs) -> ExitCode {
    let (paths, cfg) = match resolve_runtime(args.json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    match api::keys_list(&paths, &cfg) {
        Ok(outcome) => {
            if args.json {
                let envelope = serde_json::json!({
                    "ok": true,
                    "kind": "keys.list.completed",
                    "keys": outcome.keys,
                    "current_signer_fingerprint": outcome.current_signer_fingerprint,
                    "bootstrap_fingerprint": outcome.bootstrap_fingerprint,
                });
                println!("{envelope}");
            } else {
                println!("bootstrap pin: {}", outcome.bootstrap_fingerprint);
                match outcome.current_signer_fingerprint.as_deref() {
                    Some(fp) => println!("current signer: {fp}"),
                    None => println!("current signer: (none configured)"),
                }
                println!();
                for key in &outcome.keys {
                    println!(
                        "  {fp}  {role:?}  introduced {commit}",
                        fp = key.fingerprint,
                        role = key.role,
                        commit = short_commit(&key.introduced_commit),
                    );
                    if let Some(ret_commit) = &key.retired_commit {
                        println!("       retired in {}", short_commit(ret_commit));
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => render_error(&e, args.json),
    }
}

fn run_rotate(args: &RotateArgs) -> ExitCode {
    let (paths, cfg) = match resolve_runtime(args.json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    match api::keys_rotate(&paths, &cfg, &args.new_key, &args.reason) {
        Ok(outcome) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "keys.rotate.completed",
                        "new_fingerprint": outcome.new_fingerprint,
                        "commit": outcome.commit,
                        "regenerated_files": outcome.regenerated_files,
                        "signingkey_updated": outcome.signingkey_updated,
                    })
                );
            } else if outcome.signingkey_updated {
                println!(
                    "rotated in {} (commit {})",
                    outcome.new_fingerprint, outcome.commit
                );
            } else {
                println!(
                    "rotated in {} (commit {}); user.signingkey update failed — \
                     next commit will sign with the OLD key until you run \
                     `git -C notebook.git config user.signingkey <new-key-path>`",
                    outcome.new_fingerprint, outcome.commit
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => render_error(&e, args.json),
    }
}

// Single linear flow: resolve runtime, classify the mode, run the pre-mutation
// count, prompt-confirm, render the resulting outcome. Splitting it would
// scatter the JSON / TTY rendering across helpers without making the
// behaviour easier to follow.
#[allow(clippy::too_many_lines)]
fn run_revoke(args: &RevokeArgs) -> ExitCode {
    let (paths, cfg) = match resolve_runtime(args.json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    let mode = if args.rotation {
        RevokeMode::Rotation
    } else {
        RevokeMode::Compromise
    };

    // CLI-layer USAGE refusal: --json + --strict requires --yes.
    // Single guarded branch; nesting an inner `if args.json` here would
    // produce a dead `else` arm (the outer guard already requires it),
    // which `clippy -D warnings` rejects. Routed through the wire-stable
    // ErrorEnvelope shape (NOT a hand-rolled JSON object) so agents see
    // the same envelope discriminator they get from every other USAGE
    // failure.
    if args.json && matches!(mode, RevokeMode::Compromise) && !args.yes {
        let env = nexum_core::api::error::ErrorEnvelope {
            error_code: nexum_core::api::error::error_codes::USAGE,
            message: "--strict + --json requires --yes (no interactive prompt available)"
                .to_owned(),
            remediation: Some(nexum_core::api::error::Remediation {
                command: None,
                rationale: "Pass --yes to acknowledge the compromise prompt non-interactively."
                    .to_owned(),
            }),
            context: serde_json::json!({ "phase": "strict_yes_required" }),
        };
        return json_emit::emit_error(&env, 2);
    }

    // Pre-mutation count for the prompt display. Rotation mode skips the
    // count entirely; only compromise gates the user with an estimate.
    let affected_count_predicted: u64 = match mode {
        RevokeMode::Rotation => 0,
        RevokeMode::Compromise => {
            match api::count_strict_revocation_affected(&paths, &args.fingerprint) {
                Ok(n) => n,
                Err(e) => return render_error(&e, args.json),
            }
        }
    };

    // Prompt-confirm for --strict (skipped under --json or --yes).
    if matches!(mode, RevokeMode::Compromise) && !args.yes && !args.json {
        let n = affected_count_predicted;
        let fp = &args.fingerprint;
        eprintln!("About to mark this signing key COMPROMISED:");
        eprintln!("  fingerprint   {fp}");
        eprintln!();
        eprintln!("This is irreversible. Under default policy, ~{n} record(s) signed by this");
        eprintln!(
            "key will remain readable but flagged with warnings: \
             [\"signed-by-compromised-key\"]."
        );
        eprintln!("Under --strict-revocation, those {n} record(s) will be excluded entirely.");
        eprintln!();
        eprint!("Continue? [y/N] ");
        let _ = io::stderr().flush();
        let mut buf = String::new();
        if io::stdin().lock().read_line(&mut buf).is_err() {
            eprintln!("aborted: could not read confirmation");
            return ExitCode::from(2);
        }
        let trimmed = buf.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            eprintln!("aborted by operator");
            return ExitCode::from(2);
        }
    }

    let reason = args.reason.clone().unwrap_or_else(|| match mode {
        RevokeMode::Rotation => "operator-initiated rotation".to_owned(),
        RevokeMode::Compromise => "operator-initiated revocation (suspected compromise)".to_owned(),
    });

    match api::keys_revoke(
        &paths,
        &cfg,
        &args.fingerprint,
        mode,
        &reason,
        affected_count_predicted,
    ) {
        Ok(outcome) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": true,
                    "kind": "keys.revoke.completed",
                    "fingerprint": outcome.fingerprint,
                    "mode": match outcome.mode {
                        RevokeMode::Rotation => "rotation",
                        RevokeMode::Compromise => "compromise",
                    },
                    "commit": outcome.commit,
                    "regenerated_files": outcome.regenerated_files,
                    "affected_records_estimated": outcome.affected_records_estimated,
                });
                println!("{env}");
            } else {
                let mode_str = match outcome.mode {
                    RevokeMode::Rotation => "rotation",
                    RevokeMode::Compromise => "compromise",
                };
                println!(
                    "revoked {fp} as {mode_str} (commit {commit})",
                    fp = outcome.fingerprint,
                    commit = short_commit(&outcome.commit),
                );
                if let Some(n) = outcome.affected_records_estimated {
                    println!("  ~{n} record(s) estimated as affected by --strict-revocation");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => render_error(&e, args.json),
    }
}

/// Render an `ApiError` either as a JSON envelope on stdout or as prose on
/// stderr. Shared by `run_rotate`, `run_list`, and `run_revoke` so the three
/// keys verbs route failures the same way.
fn render_error(e: &api::ApiError, json: bool) -> ExitCode {
    let env: nexum_core::api::error::ErrorEnvelope = e.into();
    let code = exit_codes::for_envelope(&env);
    if json {
        json_emit::emit_error(&env, code)
    } else {
        eprintln!("error: {}", env.message);
        ExitCode::from(code)
    }
}
