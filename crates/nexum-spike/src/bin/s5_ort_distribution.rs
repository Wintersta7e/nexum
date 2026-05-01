//! Spike S5 — ort distribution
//!
//! Pass criteria (per design §3.6 S5):
//!   - The spike binary, built with the chosen `ort` feature flags, must run on a clean
//!     machine without ONNX Runtime preinstalled.
//!   - If it doesn't (e.g., DLL not found on Windows; .so not found on Linux), §15's
//!     distribution strategy needs revision.
//!
//! Build configuration (declared in `crates/nexum-spike/Cargo.toml`):
//!   `ort = { workspace = true, features = ["download-binaries"] }`
//!
//! With `download-binaries`, the `ort-sys` build script fetches matching ONNX Runtime
//! libraries at compile time and links them so the resulting binary doesn't need a
//! system-installed ORT to run.
//!
//! What this binary does at runtime:
//!   1. Calls `ort::init()` and checks the result. If init fails, ORT libs weren't found
//!      → §15 distribution claim is wrong.
//!   2. Builds an empty `Session::builder()` to confirm the API surface is reachable.
//!   3. Reports its own binary path so the user can copy it to a clean machine for the
//!      true cross-platform verification (this dev machine is not "clean" by definition).
//!
//! Skip behavior: none. The build either produces a self-contained binary or it doesn't.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::too_many_lines
)]

use anyhow::{Result, bail};
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;

fn main() -> Result<()> {
    init_tracing();
    let mut report = Report::new();

    // Self-binary path — useful for the user to copy to a clean machine.
    let self_path = std::env::current_exe().ok();

    // Step 1: ort::init().
    let init_ok = ort::init().with_telemetry(false).commit();
    if init_ok {
        report.pass(
            "ort-init",
            "ort::init() returned true — ONNX Runtime libraries are available without \
             external preinstallation. The `download-binaries` feature delivered the libs \
             at build time as designed.",
        );
    } else {
        report.fail(
            "ort-init",
            "ort::init().commit() returned false — ORT was already initialized with a \
             different config, or libraries are unavailable. §15 distribution strategy \
             needs revision OR the build feature flags need adjustment.",
        );
    }

    // Step 2: Session::builder() — confirm API surface is reachable post-init.
    match Session::builder() {
        Ok(b) => match b.with_optimization_level(GraphOptimizationLevel::Level3) {
            Ok(_) => report.pass(
                "session-builder",
                "Session::builder().with_optimization_level() succeeded — full API surface \
                 is callable; an actual model would load via .commit_from_file(...)",
            ),
            Err(e) => {
                report.fail(
                    "session-builder",
                    &format!("Session builder accepted but configuring it failed: {e}"),
                );
            }
        },
        Err(e) => {
            report.fail(
                "session-builder",
                &format!(
                    "Session::builder() failed: {e}. ORT libraries appear initialized but \
                     the Session API is not reachable — the build is broken."
                ),
            );
        }
    }

    // Step 3: hand-off NOTE for the cross-platform verification (which can only happen on
    // a separate clean machine).
    let path_str = self_path
        .as_ref()
        .map_or_else(|| "<unknown>".to_owned(), |p| p.display().to_string());
    report.note(
        "clean-machine-handoff",
        &format!(
            "Per §3.6 S5, the true pass criterion is \"runs on a clean machine\". This dev \
             machine had the build environment (and possibly ORT) installed, so it can't \
             prove the negative. To complete S5 verification:\n\
             1. Copy this binary ({path_str}) to a fresh Windows install (no ORT preinstalled).\n\
             2. Run it. Expect: same PASS rows for ort-init + session-builder.\n\
             3. If it fails to start (\"DLL not found\" / \"library not loaded\"), §15 needs \
                a different distribution mode (static linking / bundled libs alongside binary)."
        ),
    );

    report.print();
    if report.all_pass() {
        Ok(())
    } else {
        bail!("S5 failed on dev machine — revisit ort feature flags before clean-machine run");
    }
}

// ============================================================================
// reporting (same shape as S1/S2/S3/S4/S6)
// ============================================================================

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

#[derive(Debug)]
struct Report {
    rows: Vec<ReportRow>,
}

#[derive(Debug)]
enum ReportRow {
    Pass { name: String, detail: String },
    Fail { name: String, detail: String },
    Note { name: String, detail: String },
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn pass(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Pass {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn fail(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Fail {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn note(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Note {
            name: name.into(),
            detail: detail.into(),
        });
    }
    #[allow(dead_code)]
    fn assert(&mut self, name: &str, condition: bool, detail: &str) {
        if condition {
            self.pass(name, detail);
        } else {
            self.fail(name, detail);
        }
    }
    fn all_pass(&self) -> bool {
        !self
            .rows
            .iter()
            .any(|r| matches!(r, ReportRow::Fail { .. }))
    }
    fn print(&self) {
        println!("\n=== nexum spike S5 — ort distribution ===\n");
        for row in &self.rows {
            match row {
                ReportRow::Pass { name, detail } => println!("  PASS  [{name}] {detail}"),
                ReportRow::Fail { name, detail } => println!("  FAIL  [{name}] {detail}"),
                ReportRow::Note { name, detail } => println!("  NOTE  [{name}] {detail}"),
            }
        }
        let passes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Pass { .. }))
            .count();
        let fails = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Fail { .. }))
            .count();
        let notes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Note { .. }))
            .count();
        println!("\n  --- {passes} pass / {fails} fail / {notes} note(s) ---\n");
    }
}
