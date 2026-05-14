//! `nexum project register <name> <path>` / `list` / `resolve <path>`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::{
    api,
    api::error::{ErrorEnvelope, Remediation, error_codes},
    config::io::save as save_config,
    paths::Paths,
    project::{ProjectInput, ProjectResolution, resolve::resolve as resolve_project},
};

#[derive(Args, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectSub,
}

#[derive(Subcommand, Debug)]
pub enum ProjectSub {
    /// Register a non-git project under a stable name.
    Register {
        /// Stable project name (used in `[projects.<name>]`).
        name: String,
        /// Absolute path to the project root.
        path: PathBuf,
    },
    /// List known projects + their record / signed-record counts.
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show how a path resolves through the project-identity precedence.
    Resolve {
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

pub fn run(args: &ProjectArgs) -> ExitCode {
    match &args.command {
        ProjectSub::Register { name, path } => register(name, path),
        ProjectSub::List { json } => {
            let (paths, cfg) = match super::common::resolve_runtime(*json) {
                Ok(v) => v,
                Err(c) => return c,
            };
            list(&paths, &cfg, *json)
        }
        ProjectSub::Resolve { path, json } => resolve_path(path, *json),
    }
}

fn register(name: &str, path: &Path) -> ExitCode {
    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(super::exit_codes::USAGE);
    }
    if !path.is_dir() {
        eprintln!("error: not a directory: {}", path.display());
        return ExitCode::from(super::exit_codes::USAGE);
    }
    let (paths, mut cfg) = match super::common::resolve_runtime(false) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut entry = toml::Table::new();
    entry.insert(
        "path".into(),
        toml::Value::String(path.display().to_string()),
    );
    cfg.projects
        .insert(name.to_owned(), toml::Value::Table(entry));
    if let Err(e) = save_config(&paths.config, &cfg) {
        eprintln!("error: save config: {e}");
        return ExitCode::from(super::exit_codes::NOT_INITIALIZED);
    }
    println!("Registered project `{name}` -> {}", path.display());
    ExitCode::SUCCESS
}

fn list(paths: &Paths, cfg: &nexum_core::config::types::Config, json: bool) -> ExitCode {
    match api::list_projects(paths, cfg) {
        Ok(listing) => {
            if json {
                // `ProjectListing` serializes as `{ results, _meta }` — the
                // `_meta` envelope is part of the core contract, not
                // synthesized here.
                match serde_json::to_string_pretty(&listing) {
                    Ok(s) => println!("{s}"),
                    Err(e) => return super::json_emit::emit_serialize_failure(&e),
                }
            } else {
                println!(
                    "{:<24}  {:<18}  {:>10}  {:>10}  PATH",
                    "PROJECT_ID", "IDENTITY_KIND", "RECORDS", "SIGNED"
                );
                for p in &listing.results {
                    println!(
                        "{:<24}  {:<18}  {:>10}  {:>10}  {}",
                        p.project_id,
                        p.identity_kind,
                        p.record_count,
                        p.signed_record_count,
                        p.path.as_deref().unwrap_or("-"),
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if json {
                let env: ErrorEnvelope = (&e).into();
                super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {e}");
                ExitCode::from(super::exit_codes::STORE_INTEGRITY)
            }
        }
    }
}

fn resolve_path(path: &Path, json: bool) -> ExitCode {
    if !path.exists() {
        if json {
            let env = ErrorEnvelope {
                error_code: error_codes::USAGE,
                message: format!("path does not exist: {}", path.display()),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Pass an existing directory path.".into(),
                }),
                context: serde_json::json!({ "path": path.to_string_lossy() }),
            };
            return super::json_emit::emit_error(&env, super::exit_codes::for_envelope(&env));
        }
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(super::exit_codes::USAGE);
    }
    let input = ProjectInput {
        cc_slug: None,
        codex_cwd: Some(path.to_owned()),
        git_origin_url: None,
        registered_name: None,
    };
    let resolution = resolve_project(&input);
    if json {
        let value = match &resolution {
            ProjectResolution::Resolved { project_id, reason } => serde_json::json!({
                "kind": "resolved",
                "project_id": project_id,
                "reason": reason,
            }),
            ProjectResolution::Ambiguous { candidates, reason } => serde_json::json!({
                "kind": "ambiguous",
                "candidates": candidates.iter().map(|c| serde_json::json!({
                    "project_id": c.project_id,
                    "path": c.path.display().to_string(),
                })).collect::<Vec<_>>(),
                "reason": reason,
            }),
            ProjectResolution::Unresolved => serde_json::json!({"kind": "unresolved"}),
        };
        match serde_json::to_string_pretty(&value) {
            Ok(s) => println!("{s}"),
            Err(e) => return super::json_emit::emit_serialize_failure(&e),
        }
    } else {
        match resolution {
            ProjectResolution::Resolved { project_id, reason } => {
                println!("Resolved: {project_id}  ({reason:?})");
            }
            ProjectResolution::Ambiguous { candidates, reason } => {
                println!("Ambiguous ({reason:?}):");
                for c in candidates {
                    println!("  {} -> {}", c.project_id, c.path.display());
                }
            }
            ProjectResolution::Unresolved => {
                println!("Unresolved (no signal -- register the project explicitly)");
            }
        }
    }
    ExitCode::SUCCESS
}
