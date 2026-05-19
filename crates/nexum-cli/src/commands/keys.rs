//! `nexum keys` parent + subcommands.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::api;

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

pub fn run(cmd: &KeysCommand) -> ExitCode {
    match cmd {
        KeysCommand::Rotate(args) => run_rotate(args),
        KeysCommand::List(args) => run_list(args),
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
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            let code = exit_codes::for_envelope(&env);
            if args.json {
                json_emit::emit_error(&env, code)
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(code)
            }
        }
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
        Err(e) => {
            // Inline error rendering — not route_api_error which is shaped for
            // read verbs (hints "rerun nexum index" etc.).
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            let code = exit_codes::for_envelope(&env);
            if args.json {
                json_emit::emit_error(&env, code)
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(code)
            }
        }
    }
}
