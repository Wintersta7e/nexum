//! `nexum` CLI binary entry point.
//!
//! Dispatches to subcommand handlers in `commands::*`. The CLI is purely
//! synchronous; `nexum_core::init::run` and the indexer entry points are sync.
//! No async runtime is pulled in.

#![forbid(unsafe_code)]

mod commands;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "nexum", version, about = "Hybrid native-store memory layer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a nexum installation at `~/.nexum/`.
    Init(commands::init::InitArgs),
    /// Build or update the index from CC + Codex + Local sources.
    Index(commands::index::IndexArgs),
    /// Search the index.
    Search(commands::search::SearchArgs),
    /// Get one record by id.
    Get(commands::get::GetArgs),
    /// List records matching filters.
    List(commands::list::ListArgs),
    /// Recently-updated records.
    Recent(commands::recent::RecentArgs),
    /// Records associated with a session.
    BySession(commands::by_session::BySessionArgs),
    /// Manage the projects registry.
    Project(commands::project::ProjectArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init(a) => commands::init::run(a),
        Commands::Index(a) => commands::index::run(&a),
        Commands::Search(a) => commands::search::run(&a),
        Commands::Get(a) => commands::get::run(&a),
        Commands::List(a) => commands::list::run(&a),
        Commands::Recent(a) => commands::recent::run(&a),
        Commands::BySession(a) => commands::by_session::run(&a),
        Commands::Project(a) => commands::project::run(a),
    }
}
