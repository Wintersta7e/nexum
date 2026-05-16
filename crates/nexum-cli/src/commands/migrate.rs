use std::process::ExitCode;

use clap::Args;
use nexum_core::api;
use nexum_core::migrate::MigrationOutcome;
use serde_json::json;

use super::common::resolve_runtime;
use super::exit_codes;
use super::json_emit;

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Emit a structured JSON envelope to stdout (success or failure)
    /// instead of the default human-readable output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: &MigrateArgs) -> ExitCode {
    let (paths, _cfg) = match resolve_runtime(args.json) {
        Ok(rt) => rt,
        Err(code) => return code,
    };

    match api::migrate_index_db(&paths) {
        Ok(MigrationOutcome::NoOp) => {
            if args.json {
                let env = json!({
                    "ok": true,
                    "kind": "migration.noop",
                    "message": "index.db is already at the latest version",
                });
                println!("{env:#}");
            } else {
                println!("index.db is already at the latest version");
            }
            ExitCode::SUCCESS
        }
        Ok(MigrationOutcome::Migrated {
            from,
            to,
            backup_path,
        }) => {
            if args.json {
                let env = json!({
                    "ok": true,
                    "kind": "migration.completed",
                    "from": from,
                    "to": to,
                    "backup_path": backup_path.to_string_lossy(),
                });
                println!("{env:#}");
            } else {
                println!(
                    "migrated index.db from v{from} to v{to} (backup at {})",
                    backup_path.display(),
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            if args.json {
                json_emit::emit_error(&env, exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(exit_codes::for_envelope(&env))
            }
        }
    }
}
