//! `nexum trust` parent + subcommands.

use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::api::{self, TamperingRow};

const RECOGNIZED_CODES: &[&str] = &["pre-recovery-record", "chain-anchor-lost"];

#[derive(Subcommand, Debug)]
pub enum TrustCommand {
    /// Force a materializer rebuild and surface any detected tampering of
    /// `.trust/events.yml`. Exits 0 if clean, 4 (`STORE_INTEGRITY`) on
    /// detection.
    ValidateEvents(ValidateEventsArgs),

    /// Re-derive the OpenSSH-format signer files from `events.yml` and
    /// stage them in a signed commit. No-op when already consistent.
    /// Refuses on in-progress merge or pending reanchor.
    RegenerateFiles(RegenerateFilesArgs),

    /// Suppress `pre-recovery-record` / `chain-anchor-lost` warnings
    /// from subsequent doctor runs.
    DismissPreRecoveryWarning(DismissArgs),
}

#[derive(Args, Debug)]
pub struct ValidateEventsArgs {
    /// Print the detected tampering rows as JSON. Without this flag the
    /// output is human-readable.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RegenerateFilesArgs {
    /// Emit a structured JSON envelope to stdout (success or failure).
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DismissArgs {
    /// Warning code to acknowledge. Repeatable. Accepts
    /// `pre-recovery-record` and `chain-anchor-lost`. When unspecified,
    /// both codes are acked.
    #[arg(long, action = clap::ArgAction::Append)]
    pub code: Vec<String>,

    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(cmd: &TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::ValidateEvents(args) => run_validate_events(args),
        TrustCommand::RegenerateFiles(args) => run_regenerate_files(args),
        TrustCommand::DismissPreRecoveryWarning(args) => run_dismiss(args),
    }
}

fn run_validate_events(args: &ValidateEventsArgs) -> ExitCode {
    let (paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let rows = match api::validate_events(&paths) {
        Ok(r) => r,
        Err(e) => return super::json_emit::route_api_error(&e, args.json),
    };
    render_tampering(&rows, args.json)
}

fn run_regenerate_files(args: &RegenerateFilesArgs) -> ExitCode {
    let (paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    match api::trust_regenerate_files(&paths) {
        Ok(api::TrustRegenerateOutcome::NoChange) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "trust.regenerate.noop",
                        "message": "trust files already match events.yml",
                    })
                );
            } else {
                println!("trust files already match events.yml; nothing to do");
            }
            ExitCode::SUCCESS
        }
        Ok(api::TrustRegenerateOutcome::Committed { commit, files }) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "trust.regenerate.committed",
                        "commit": commit,
                        "files": files,
                    })
                );
            } else {
                println!("regenerated trust files; signed commit {commit} updated {files:?}");
            }
            ExitCode::SUCCESS
        }
        // Route via render_error rather than super::json_emit::route_api_error:
        // that helper's prose path is read-verb-shaped (it hints "rerun nexum
        // index" on MigrationRequired etc.), which would mislead operators of
        // this admin write verb.
        Err(e) => render_error(&e, args.json),
    }
}

fn run_dismiss(args: &DismissArgs) -> ExitCode {
    let (paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };

    // Validate supplied codes against the recognized set. Default to both
    // codes when none supplied.
    let codes: Vec<String> = if args.code.is_empty() {
        RECOGNIZED_CODES.iter().map(|s| (*s).to_owned()).collect()
    } else {
        let unknown: Vec<&String> = args
            .code
            .iter()
            .filter(|c| !RECOGNIZED_CODES.contains(&c.as_str()))
            .collect();
        if !unknown.is_empty() {
            let env = nexum_core::api::error::ErrorEnvelope {
                error_code: nexum_core::api::error::error_codes::USAGE,
                message: format!(
                    "unknown warning code(s): {}; recognized: {}",
                    unknown
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    RECOGNIZED_CODES.join(", ")
                ),
                remediation: Some(nexum_core::api::error::Remediation {
                    command: None,
                    rationale: format!(
                        "Accepted codes are: {}. Re-run with one of those.",
                        RECOGNIZED_CODES.join(", ")
                    ),
                }),
                context: serde_json::json!({
                    "kind": "trust",
                    "subkind": "dismiss",
                    "unknown_codes": unknown,
                }),
                severity: None,
                state_mutated: None,
                requires_reindex: None,
            };
            if args.json {
                return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
            }
            eprintln!("error: {}", env.message);
            return ExitCode::from(super::exit_codes::USAGE);
        }
        args.code.clone()
    };

    match api::dismiss_pre_recovery_warning(&paths, &codes) {
        Ok(outcome) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "kind": "trust.dismiss_pre_recovery_warning.completed",
                        "added": outcome.added,
                        "already_present": outcome.already_present,
                        "total": outcome.total,
                    })
                );
            } else {
                if outcome.added.is_empty() {
                    println!("no new codes acked (all already present)");
                } else {
                    println!("acked: {}", outcome.added.join(", "));
                }
                if !outcome.already_present.is_empty() {
                    println!("already present: {}", outcome.already_present.join(", "));
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => render_error(&e, args.json),
    }
}

fn render_error(e: &nexum_core::api::ApiError, json: bool) -> ExitCode {
    let env: nexum_core::api::error::ErrorEnvelope = e.into();
    let code = super::exit_codes::for_envelope(&env);
    if json {
        super::json_emit::emit_error(&env, code)
    } else {
        eprintln!("error: {}", env.message);
        ExitCode::from(code)
    }
}

/// Print tampering rows (human or JSON) and translate to an exit code.
/// Shared between `nexum trust validate-events` and the post-index step
/// in `nexum index --check`.
///
/// `--json` shape:
/// - clean (`rows.is_empty()`): emits `[]` on stdout + exit 0. Preserves the
///   pre-envelope success shape so agents already keyed on
///   `exit 0 + [] = clean` stay green.
/// - tampering detected: emits a `TAMPERING_DETECTED` `ErrorEnvelope` with
///   the rows in `context.events`, exit 4.
pub(crate) fn render_tampering(rows: &[TamperingRow], json: bool) -> ExitCode {
    if rows.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("trust events: clean (no tampering detected)");
        }
        return ExitCode::SUCCESS;
    }

    if json {
        let events = rows
            .iter()
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
            .collect::<Vec<_>>();
        let env = nexum_core::api::error::ErrorEnvelope {
            error_code: nexum_core::api::error::error_codes::TAMPERING_DETECTED,
            message: format!("trust events: {} tampering event(s) detected", rows.len()),
            remediation: Some(nexum_core::api::error::Remediation {
                command: None,
                rationale: "events.yml history has been mutated. Recovery requires the \
                            admin trust commands shipping in a later phase."
                    .into(),
            }),
            context: serde_json::json!({ "events": events }),
            severity: None,
            state_mutated: None,
            requires_reindex: None,
        };
        return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
    }

    eprintln!("trust events: {} tampering event(s) detected:", rows.len());
    for r in rows {
        eprintln!(
            "  - commit {} (topo {}): {} on event {}",
            r.at_commit, r.at_topo_pos, r.kind, r.event_id
        );
    }
    ExitCode::from(super::exit_codes::STORE_INTEGRITY)
}
