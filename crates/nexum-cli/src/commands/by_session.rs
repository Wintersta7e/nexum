//! `nexum by-session` — placeholder; the real handler lands in a later task.

use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct BySessionArgs {
    pub session: String,
}

pub fn run(_args: BySessionArgs) -> ExitCode {
    eprintln!("error: `nexum by-session` is not yet available in this build");
    ExitCode::FAILURE
}
