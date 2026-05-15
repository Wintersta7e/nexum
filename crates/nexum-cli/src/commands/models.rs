//! `nexum models install bge-m3` — download + verify + smoke the bge-m3
//! ONNX export, then flip `[embed].enabled = true` in config.toml.

use std::io::{Write, stderr};
use std::process::ExitCode;

use clap::Subcommand;

use nexum_core::config;
use nexum_core::embed::install::{install_bge_m3, install_bge_m3_with};
use nexum_core::embed::{InstallReport, ManifestEntry, Reporter};
use nexum_core::session::resolve_runtime;

use super::exit_codes;

/// `nexum models …` subcommands. Reserved for future model-management
/// verbs; in this release only `install bge-m3` is supported.
#[derive(Debug, Subcommand)]
pub enum ModelsCmd {
    /// Install an embedding model. Only `bge-m3` is supported in this release.
    Install {
        /// Model name. Only `bge-m3` is supported.
        model: String,
    },
}

/// Entry point dispatched from `main.rs`.
#[must_use]
pub fn run(cmd: &ModelsCmd) -> ExitCode {
    match cmd {
        ModelsCmd::Install { model } => run_install(model),
    }
}

fn run_install(model: &str) -> ExitCode {
    if model != "bge-m3" {
        let _ = writeln!(
            stderr(),
            "error: unsupported model '{model}' — only 'bge-m3' is supported in this release.",
        );
        return ExitCode::from(exit_codes::USAGE);
    }

    let (paths, cfg) = match resolve_runtime() {
        Ok(rt) => rt,
        Err(envelope) => {
            let _ = writeln!(stderr(), "error: {}", envelope.message);
            return ExitCode::from(exit_codes::for_envelope(&envelope));
        }
    };

    let mut reporter = StderrReporter::new();
    let install_result = match test_manifest_from_env() {
        Some(fixture) => install_bge_m3_with(
            &paths.models,
            &cfg,
            &mut reporter,
            &fixture.entries,
            /* skip_smoke = */ true,
        ),
        None => install_bge_m3(&paths.models, &cfg, &mut reporter),
    };

    let (report, next_cfg): (InstallReport, _) = match install_result {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(stderr(), "error: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = config::save(&paths.config, &next_cfg) {
        let _ = writeln!(stderr(), "error: failed to update config.toml: {err}");
        return ExitCode::FAILURE;
    }

    let _ = writeln!(
        stderr(),
        "install complete: downloaded {} bytes; smoke-test {} ms; embed.enabled=true",
        report.downloaded,
        report.smoke_test_ms,
    );
    ExitCode::SUCCESS
}

/// Test-only manifest override loaded from the
/// `NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST` env var (JSON array of
/// `{name, size, sha256}` entries). Returning `Some` switches the install
/// pipeline to `install_bge_m3_with` with the parsed manifest and a
/// skipped smoke test — the integration test exercises the download +
/// verify + config-write-back path against a stub HTTP server.
struct TestFixture {
    entries: Vec<ManifestEntry>,
}

fn test_manifest_from_env() -> Option<TestFixture> {
    let raw = std::env::var("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST").ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let array = parsed.as_array()?;
    let mut entries = Vec::with_capacity(array.len());
    for v in array {
        let name = v.get("name")?.as_str()?.to_owned();
        let size = v.get("size")?.as_u64()?;
        let sha256 = v.get("sha256")?.as_str()?.to_owned();
        entries.push(ManifestEntry {
            // The install pipeline reads `name` and `sha256` as `&'static
            // str` — for the test path we leak the owned strings so the
            // `ManifestEntry` borrow remains satisfied for the lifetime of
            // the process. Acceptable in a one-shot CLI invocation gated
            // behind a test env var.
            name: Box::leak(name.into_boxed_str()),
            size,
            sha256: Box::leak(sha256.into_boxed_str()),
        });
    }
    Some(TestFixture { entries })
}

/// Reporter that writes coalesced progress to stderr. Debounces byte
/// updates to one line per ~5% of the file or every ~50 MiB, whichever
/// comes first.
struct StderrReporter {
    last_byte_pct: u8,
    last_file_bytes: u64,
}

impl StderrReporter {
    fn new() -> Self {
        Self {
            last_byte_pct: 0,
            last_file_bytes: 0,
        }
    }
}

impl Reporter for StderrReporter {
    fn progress(&mut self, msg: &str) {
        let _ = writeln!(stderr(), "{msg}");
        self.last_byte_pct = 0;
        self.last_file_bytes = 0;
    }

    fn bytes(&mut self, done: u64, total: u64) {
        if total == 0 {
            return;
        }
        // `pct` is bounded to [0, 100] by `min(100)`; the cast is lossless.
        let pct = u8::try_from((done.saturating_mul(100) / total).min(100)).unwrap_or(100);
        let pct_jump = pct >= self.last_byte_pct.saturating_add(5);
        let byte_jump = done >= self.last_file_bytes + 50 * 1024 * 1024;
        if pct_jump || byte_jump {
            let _ = writeln!(stderr(), "  {pct}% ({done} / {total} bytes)");
            self.last_byte_pct = pct;
            self.last_file_bytes = done;
        }
    }
}
