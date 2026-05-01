//! `nexum` CLI binary entry point.
//!
//! Dispatches to subcommand handlers in `commands::*`. See §6 for the full
//! command surface; this file wires only the M1 subcommands.
//!
//! The CLI is purely synchronous — `nexum_core::init::run` is sync.
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init(args) => commands::init::run(args),
    }
}
