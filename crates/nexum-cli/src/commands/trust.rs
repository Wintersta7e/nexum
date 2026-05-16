//! `nexum trust` parent + subcommands.

use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::api::{self, TamperingRow};

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

pub fn run(cmd: &TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::ValidateEvents(args) => run_validate_events(args),
        TrustCommand::RegenerateFiles(args) => run_regenerate_files(args),
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
        Err(e) => {
            // Inline routing rather than super::json_emit::route_api_error:
            // that helper's prose path is read-verb-shaped (it hints "rerun
            // nexum index" on MigrationRequired etc.), which would mislead
            // operators of this admin write verb. JSON mode is identical;
            // prose mode just prints the envelope message and maps the code.
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            let code = super::exit_codes::for_envelope(&env);
            if args.json {
                super::json_emit::emit_error(&env, code)
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(code)
            }
        }
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
