//! `nexum project register <name> <path>` / `list` / `resolve <path>`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::{
    api,
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
            let paths = match Paths::resolve() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}\nDid you run `nexum init`?");
                    return ExitCode::from(super::exit_codes::NOT_INITIALIZED);
                }
            };
            list(&paths, *json)
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
    let (paths, mut cfg) = match super::common::resolve_runtime() {
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

fn list(paths: &Paths, json: bool) -> ExitCode {
    match api::list_projects(paths) {
        Ok(summaries) => {
            if json {
                match serde_json::to_string_pretty(&summaries) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: serialize: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "{:<24}  {:<18}  {:>10}  {:>10}",
                    "PROJECT_ID", "IDENTITY_KIND", "RECORDS", "SIGNED"
                );
                for p in &summaries {
                    println!(
                        "{:<24}  {:<18}  {:>10}  {:>10}",
                        p.project_id, p.identity_kind, p.record_count, p.signed_record_count,
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(super::exit_codes::RUNTIME)
        }
    }
}

fn resolve_path(path: &Path, json: bool) -> ExitCode {
    if !path.exists() {
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
                "reason": format!("{reason:?}"),
            }),
            ProjectResolution::Ambiguous { candidates, reason } => serde_json::json!({
                "kind": "ambiguous",
                "candidates": candidates.iter().map(|c| serde_json::json!({
                    "project_id": c.project_id,
                    "path": c.path.display().to_string(),
                })).collect::<Vec<_>>(),
                "reason": format!("{reason:?}"),
            }),
            ProjectResolution::Unresolved => serde_json::json!({"kind": "unresolved"}),
        };
        match serde_json::to_string_pretty(&value) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serialize: {e}");
                return ExitCode::FAILURE;
            }
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
