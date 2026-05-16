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
    /// Manage embedding models. The bge-m3 install is the only supported model in this release.
    Models {
        #[command(subcommand)]
        cmd: commands::models::ModelsCmd,
    },
    /// Manage the projects registry.
    Project(commands::project::ProjectArgs),
    /// Trust-events admin (`validate-events` exits 4 on tampering).
    Trust {
        #[command(subcommand)]
        cmd: commands::trust::TrustCommand,
    },
    /// Run pending index-DB schema migrations.
    Migrate(commands::migrate::MigrateArgs),
    /// Diagnose store health and (with `--resolve-pending-reanchor`) clean
    /// up a partial-reanchor sentinel.
    Doctor(commands::doctor::DoctorArgs),
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Commands::Init(a) => commands::init::run(&a),
        Commands::Index(a) => commands::index::run(&a),
        Commands::Search(a) => commands::search::run(&a),
        Commands::Get(a) => commands::get::run(&a),
        Commands::List(a) => commands::list::run(&a),
        Commands::Recent(a) => commands::recent::run(&a),
        Commands::BySession(a) => commands::by_session::run(&a),
        Commands::Models { cmd } => commands::models::run(&cmd),
        Commands::Project(a) => commands::project::run(&a),
        Commands::Trust { cmd } => commands::trust::run(&cmd),
        Commands::Migrate(args) => commands::migrate::run(&args),
        Commands::Doctor(args) => commands::doctor::run(&args),
    }
}

/// Initialize the tracing subscriber so warns from the core library
/// (graceful semantic-search degradation, indexer warnings, etc.) reach
/// the operator on stderr. Default level is `warn` to surface the
/// degradation path without dragging in rustls / reqwest INFO noise.
///
/// Override via `NEXUM_LOG=...` (precedence) or the standard `RUST_LOG=...`
/// envelope. Writer is stderr so JSON output on stdout (every read verb
/// under `--json`) stays clean for downstream parsers.
fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("NEXUM_LOG")
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init();
}
