//! `nexum recent` — placeholder; the real handler lands in a later task.

use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct RecentArgs {}

pub fn run(_args: RecentArgs) -> ExitCode {
    eprintln!("error: `nexum recent` is not yet available in this build");
    ExitCode::FAILURE
}
