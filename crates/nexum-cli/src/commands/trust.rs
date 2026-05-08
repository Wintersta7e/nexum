//! `nexum trust` parent + `validate-events` subcommand.

use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::api::{self, TamperingRow};

#[derive(Subcommand, Debug)]
pub enum TrustCommand {
    /// Force a materializer rebuild and surface any detected tampering of
    /// `.trust/events.yml`. Exits 0 if clean, 4 (`STORE_INTEGRITY`) on
    /// detection.
    ValidateEvents(ValidateEventsArgs),
}

#[derive(Args, Debug)]
pub struct ValidateEventsArgs {
    /// Print the detected tampering rows as JSON. Without this flag the
    /// output is human-readable.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(cmd: &TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::ValidateEvents(args) => run_validate_events(args),
    }
}

fn run_validate_events(args: &ValidateEventsArgs) -> ExitCode {
    let (paths, _cfg) = match super::common::resolve_runtime(args.json) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let rows = match api::validate_events(&paths) {
        Ok(r) => r,
        Err(e) => return super::common::handle_read_verb_error(&e),
    };
    render_tampering(&rows, args.json)
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
