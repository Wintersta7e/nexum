//! `nexum search` — placeholder; the real handler lands in a later task.

use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct SearchArgs {
    pub query: String,
}

pub fn run(_args: SearchArgs) -> ExitCode {
    eprintln!("error: `nexum search` is not implemented yet");
    ExitCode::FAILURE
}
