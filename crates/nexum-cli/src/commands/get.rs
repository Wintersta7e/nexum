//! `nexum get` — placeholder; the real handler lands in a later task.

use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct GetArgs {
    pub id: String,
}

pub fn run(_args: GetArgs) -> ExitCode {
    eprintln!("error: `nexum get` is not yet available in this build");
    ExitCode::FAILURE
}
