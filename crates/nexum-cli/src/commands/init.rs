//! `nexum init` CLI handler.
//!
//! Parses flags, presents a confirm-key prompt when `--ssh-key` is not given
//! (§8 step 3), then delegates to `nexum_core::init::run`.
//! `nexum_core::init::run` stays non-interactive for testability; the prompt
//! lives here in the CLI layer.

use std::{
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use clap::Args;
use nexum_core::{
    init::{InitError, InitOpts, InitOutcome},
    ssh_key::detect::detect_signing_key,
};

/// Arguments for `nexum init`.
#[derive(Args, Debug)]
pub struct InitArgs {
    /// Path to the SSH private key to use for signing.
    /// Defaults to `~/.ssh/id_ed25519`, `id_rsa`, or `id_ecdsa` (first found).
    #[arg(long, value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,

    /// Override the nexum root directory (default: `~/.nexum/`).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Wipe and reinitialize if `~/.nexum/` already exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Skip the confirm-key prompt (for scripted / test invocations).
    #[arg(long, short = 'y', default_value_t = false)]
    pub yes: bool,
}

/// Run the `nexum init` subcommand.
///
/// Returns `ExitCode::SUCCESS` on success, `ExitCode::FAILURE` on any error
/// (error message is printed to stderr before returning).
pub fn run(args: &InitArgs) -> ExitCode {
    // Resolve SSH HOME for key detection. Independent of --root.
    // SSH keys always live in $HOME/.ssh/, not in the nexum root.
    let ssh_home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    // §8 step 3: if --ssh-key not given, detect candidate and ask user to confirm.
    let resolved_ssh_key: Option<PathBuf> = if let Some(explicit) = &args.ssh_key {
        Some(explicit.clone())
    } else if args.yes {
        // --yes without --ssh-key: detect silently (core will detect again using
        // $HOME lookup, but omitting the path here lets the core handle it).
        None
    } else {
        // Interactive confirm-key prompt.
        let Some(home) = ssh_home.as_deref() else {
            eprintln!("error: cannot determine $HOME for SSH key detection");
            return ExitCode::FAILURE;
        };
        match detect_signing_key(home, None) {
            Ok(detected) => {
                println!(
                    "Detected SSH signing key: {}\n  fingerprint: {}",
                    detected.private_key_path.display(),
                    detected.fingerprint
                );
                print!("Use this key? [y/N]: ");
                io::stdout().flush().ok();
                let mut buf = String::new();
                if io::stdin().read_line(&mut buf).is_err() {
                    eprintln!("error: could not read from stdin");
                    return ExitCode::FAILURE;
                }
                if buf.trim().eq_ignore_ascii_case("y") {
                    Some(detected.private_key_path)
                } else {
                    println!("Aborted.");
                    return ExitCode::FAILURE;
                }
            }
            Err(e) => {
                eprintln!(
                    "error: SSH key detection failed: {e}\n\
                     Pass --ssh-key <path> to specify a key explicitly."
                );
                return ExitCode::FAILURE;
            }
        }
    };

    let opts = InitOpts {
        ssh_key: resolved_ssh_key,
        root: args.root.clone(),
        force: args.force,
    };

    match nexum_core::init::run(opts) {
        Ok(InitOutcome {
            root,
            bootstrap_commit_sha,
            fingerprint,
        }) => {
            println!("nexum initialized successfully.");
            println!("  Root:             {}", root.display());
            println!("  Bootstrap commit: {bootstrap_commit_sha}");
            println!("  Signing key:      {fingerprint}");
            println!();
            println!(
                "Run `nexum models install bge-m3` to enable semantic search,\n\
                 or skip and use FTS-only. Then run `nexum index` to build the initial index."
            );
            ExitCode::SUCCESS
        }
        Err(InitError::AlreadyInitialized { path }) => {
            eprintln!(
                "error: nexum is already initialized at {path}.\n\
                 Pass --force to wipe and reinitialize."
            );
            ExitCode::FAILURE
        }
        Err(InitError::SshKey(e)) => {
            eprintln!("error: SSH key error: {e}");
            ExitCode::FAILURE
        }
        Err(InitError::BootstrapVerifyFailed { detail }) => {
            eprintln!(
                "error: bootstrap commit verification failed: {detail}\n\
                 This indicates a git SSH signing configuration issue.\n\
                 Check that `git` >= 2.34 is installed and your SSH key is readable."
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
