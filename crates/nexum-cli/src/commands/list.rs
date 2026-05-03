//! `nexum list` — placeholder; the real handler lands in a later task.

use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug)]
pub struct ListArgs {}

pub fn run(_args: ListArgs) -> ExitCode {
    eprintln!("error: `nexum list` is not implemented yet");
    ExitCode::FAILURE
}
