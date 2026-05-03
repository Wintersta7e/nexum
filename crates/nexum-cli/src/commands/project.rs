//! `nexum project` — placeholder; the real handler lands in a later task.

use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectSub,
}

#[derive(Subcommand, Debug)]
pub enum ProjectSub {
    /// Register a project root under a name.
    Register { name: String, path: PathBuf },
    /// List registered projects.
    List,
    /// Resolve a project path to its `identity_kind` / `project_id`.
    Resolve { path: PathBuf },
}

pub fn run(_args: ProjectArgs) -> ExitCode {
    eprintln!("error: `nexum project` is not yet available in this build");
    ExitCode::FAILURE
}
