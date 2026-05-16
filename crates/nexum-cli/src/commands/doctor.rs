//! `nexum doctor` — store health check and reanchor-sentinel cleanup.
//!
//! With no flags, exits 0 and prints "doctor: OK" (or a JSON envelope).
//! With `--resolve-pending-reanchor`, inspects `~/.nexum/.reanchor_pending`
//! and dispatches the cleanup per the three documented phases.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api::{self, ReanchorResolveMode, ReanchorResolveOutcome};
use nexum_core::paths::Paths;

use super::exit_codes;

// Four `bool` flags are inherent to clap's `Args` derive; a state machine
// would conflict with the `default_value_t` / `conflicts_with` machinery.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Inspect `.reanchor_pending` and apply the phase-based cleanup.
    /// Requires exactly one of `--continue` or `--revert`.
    #[arg(long, default_value_t = false)]
    pub resolve_pending_reanchor: bool,

    /// Re-attempt the next reanchor phase. Valid in phases `pin_updated` or
    /// `events_committed`. Refused in phase `init` (keys-recover not yet
    /// available).
    #[arg(
        long,
        default_value_t = false,
        conflicts_with = "revert",
        requires = "resolve_pending_reanchor"
    )]
    pub r#continue: bool,

    /// Abandon a pending reanchor and remove the sentinel. Only valid in
    /// phase `init` (no signed commit exists yet).
    #[arg(
        long,
        default_value_t = false,
        conflicts_with = "continue",
        requires = "resolve_pending_reanchor"
    )]
    pub revert: bool,

    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &DoctorArgs) -> ExitCode {
    if args.resolve_pending_reanchor {
        return run_resolve_pending(args);
    }

    // No flags: plain health check. Uses the normal runtime path so the same
    // NOT_INITIALIZED / REANCHOR_PENDING guards apply.
    let (_paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    if args.json {
        println!(r#"{{"ok": true, "kind": "doctor.ok"}}"#);
    } else {
        println!("doctor: OK");
    }
    ExitCode::SUCCESS
}

/// Handle `--resolve-pending-reanchor`. Deliberately bypasses the normal
/// `resolve_runtime` pre-check so that a command whose entire purpose is to
/// clear a reanchor sentinel is not itself blocked by that sentinel.
fn run_resolve_pending(args: &DoctorArgs) -> ExitCode {
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            if args.json {
                println!(r#"{{"ok": false, "code": "NOT_INITIALIZED", "message": "{e}"}}"#);
            } else {
                eprintln!("error: {e}");
            }
            return ExitCode::from(exit_codes::NOT_INITIALIZED);
        }
    };

    let mode = match (args.r#continue, args.revert) {
        (true, false) => Some(ReanchorResolveMode::Continue),
        (false, true) => Some(ReanchorResolveMode::Revert),
        _ => None,
    };

    match api::resolve_pending_reanchor(&paths, mode) {
        Ok(ReanchorResolveOutcome::NoSentinel) => {
            if args.json {
                println!(r#"{{"ok": true, "kind": "doctor.reanchor.no_sentinel"}}"#);
            } else {
                println!("no pending reanchor; nothing to do");
            }
            ExitCode::SUCCESS
        }
        Ok(ReanchorResolveOutcome::Resolved { from_phase }) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": true,
                    "kind": "doctor.reanchor.resolved",
                    "from_phase": from_phase,
                });
                println!("{env:#}");
            } else {
                println!("resolved pending reanchor (was phase={from_phase})");
            }
            ExitCode::SUCCESS
        }
        Ok(ReanchorResolveOutcome::Refused { phase, reason }) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": false,
                    "code": "STORE_INTEGRITY",
                    "kind": "doctor.reanchor.refused",
                    "phase": phase,
                    "message": reason,
                });
                println!("{env:#}");
            } else {
                eprintln!("refused: {reason}");
            }
            ExitCode::from(exit_codes::STORE_INTEGRITY)
        }
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            if args.json {
                super::json_emit::emit_error(&env, exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(exit_codes::for_envelope(&env))
            }
        }
    }
}
