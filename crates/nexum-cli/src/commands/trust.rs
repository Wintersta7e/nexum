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
pub(crate) fn render_tampering(rows: &[TamperingRow], json: bool) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(rows) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if rows.is_empty() {
        println!("trust events: clean (no tampering detected)");
    } else {
        eprintln!("trust events: {} tampering event(s) detected:", rows.len());
        for r in rows {
            eprintln!(
                "  - commit {} (topo {}): {} on event {}",
                r.at_commit, r.at_topo_pos, r.kind, r.event_id
            );
        }
    }
    if rows.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(super::exit_codes::STORE_INTEGRITY)
    }
}
