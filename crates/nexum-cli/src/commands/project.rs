//! `nexum project register <name> <path>` / `list` / `resolve <path>`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use nexum_core::{
    api,
    api::error::{ErrorEnvelope, Remediation, error_codes},
    config::io::save as save_config,
    config::types::Config,
    paths::Paths,
    project::normalize_inbox::normalize_inbox,
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
    /// Bind a local filesystem path to a non-`name:` `project_id`.
    ///
    /// Lets `git:` / `cc-slug:` / `codex-cwd:` identities — which carry
    /// no path by default — get a registered local checkout so M3 can
    /// scan their git history during promotion. Writes
    /// `[projects."<project_id>"] path = "<path>"` to `~/.nexum/config.toml`.
    SetPath {
        /// Full `project_id` including identity prefix (e.g.
        /// `git:abc123def4567890`).
        project_id: String,
        /// Absolute path to the local checkout.
        path: PathBuf,
    },
    /// Backfill `project_id` on extracted records that landed in `_inbox/`.
    NormalizeInbox {
        /// Path to a Codex `state_5.sqlite` consulted for `git_origin_url`
        /// resolution. Defaults to the `[adapters.codex] state_db` value.
        #[arg(long)]
        state_db: Option<PathBuf>,
        /// Emit a JSON envelope on stdout.
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
        ProjectSub::SetPath { project_id, path } => set_path(project_id, path),
        ProjectSub::NormalizeInbox { state_db, json } => {
            let (paths, cfg) = match super::common::resolve_runtime(*json) {
                Ok(v) => v,
                Err(c) => return c,
            };
            normalize_inbox_dispatch(&paths, &cfg, state_db.as_deref(), *json)
        }
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

fn list(paths: &Paths, cfg: &Config, json: bool) -> ExitCode {
    match api::list_projects(paths, cfg) {
        Ok(listing) => {
            if json {
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

fn set_path(project_id: &str, path: &Path) -> ExitCode {
    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(super::exit_codes::USAGE);
    }
    if !path.is_dir() {
        eprintln!("error: not a directory: {}", path.display());
        return ExitCode::from(super::exit_codes::USAGE);
    }

    // Identity check: for `git:` ids, verify the repo's origin URL
    // canonicalizes to the same project_id. Skip for non-git identities.
    if project_id.starts_with("git:") {
        match check_git_identity(path, project_id) {
            Ok(()) => {}
            Err(envelope) => {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&envelope).unwrap_or_default()
                );
                return ExitCode::from(super::exit_codes::USAGE);
            }
        }
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
        .insert(project_id.to_owned(), toml::Value::Table(entry));
    if let Err(e) = save_config(&paths.config, &cfg) {
        eprintln!("error: save config: {e}");
        return ExitCode::from(super::exit_codes::NOT_INITIALIZED);
    }
    println!("set-path: {project_id} -> {}", path.display());
    ExitCode::SUCCESS
}

fn check_git_identity(path: &Path, project_id: &str) -> Result<(), ErrorEnvelope> {
    let url_output = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["remote", "get-url", "origin"])
        .output();
    let url = match url_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        _ => {
            return Err(ErrorEnvelope {
                error_code: error_codes::REPO_IDENTITY_MISMATCH,
                message: format!(
                    "no `origin` remote at {} — register via `nexum project register` instead, or set the remote first",
                    path.display()
                ),
                remediation: Some(Remediation {
                    command: None,
                    rationale: "Set a git origin remote or use `nexum project register` for non-git projects.".into(),
                }),
                context: serde_json::json!({"path": path.display().to_string()}),
            });
        }
    };
    // `git_url_hint` returns the full `git:<hex>` form already.
    let canonical = nexum_core::project::canon::canonicalize_git_url(&url);
    let derived = nexum_core::project::canon::git_url_hint(&canonical);
    if derived == project_id {
        Ok(())
    } else {
        Err(ErrorEnvelope {
            error_code: error_codes::REPO_IDENTITY_MISMATCH,
            message: format!("origin url {url} canonicalizes to {derived}, not {project_id}"),
            remediation: Some(Remediation {
                command: None,
                rationale: format!(
                    "Supply the correct project_id `{derived}` or update the repo's origin remote."
                ),
            }),
            context: serde_json::json!({
                "expected": project_id,
                "observed": derived,
                "url": url,
            }),
        })
    }
}

fn normalize_inbox_dispatch(
    paths: &Paths,
    cfg: &Config,
    state_db_override: Option<&Path>,
    json: bool,
) -> ExitCode {
    let state_db_path = state_db_override.map(Path::to_path_buf).or_else(|| {
        let raw = &cfg.adapters.codex.state_db;
        if raw.is_empty() {
            None
        } else {
            Some(PathBuf::from(raw))
        }
    });

    let outcome = match normalize_inbox(paths, state_db_path.as_deref()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(super::exit_codes::STORE_INTEGRITY);
        }
    };

    if json {
        let body = serde_json::json!({
            "moved": outcome.moved_ids.len(),
            "moved_ids": outcome.moved_ids,
            "ambiguous": outcome.ambiguous,
            "ambiguous_ids": outcome.ambiguous_ids,
            "unresolved": outcome.unresolved,
            "unresolved_ids": outcome.unresolved_ids,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&body).unwrap_or_default()
        );
    } else {
        println!(
            "Normalized {} records. {} ambiguous, {} unresolved (left in _inbox).",
            outcome.moved_ids.len(),
            outcome.ambiguous,
            outcome.unresolved,
        );
    }
    ExitCode::SUCCESS
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
