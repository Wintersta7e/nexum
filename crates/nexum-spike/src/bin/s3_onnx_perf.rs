//! Spike S3 — ONNX cold-start + steady-state inference timing
//!
//! Pass criteria (per design §3.6 S3):
//!   - bge-m3 cold-start <8 s (session build + first inference combined).
//!   - Steady-state <300 ms per inference (CPU), measured as average of 100 runs.
//!   - Peak RAM <2 GB during inference.
//!
//! Hardware: user's actual laptop (per global CLAUDE.md hardware notes:
//! i7-11800H + RTX 3060 Laptop, CPU-only path here since WSL2 has no GPU passthrough).
//!
//! Skip behavior: if `~/.nexum/models/bge-m3/{model.onnx, tokenizer.json}` is not present,
//! the spike prints clear download instructions and exits 2 (skipped, distinct from 1=fail).
//! Once the model is downloaded, re-run `cargo run -p nexum-spike --bin spike-s3-onnx-perf`.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::too_many_lines
)]

use anyhow::{anyhow, bail, Context, Result};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::TensorRef;
use std::path::PathBuf;
use std::time::Instant;
use tokenizers::Tokenizer;

const COLD_START_TARGET_MS: u128 = 8_000;
const STEADY_STATE_TARGET_MS: u128 = 300;
const PEAK_RAM_TARGET_KB: u64 = 2 * 1024 * 1024;
const STEADY_RUNS: usize = 100;

const SAMPLE_TEXT: &str = "Spike S3 sample text for embedding inference timing measurement.";

fn main() -> Result<()> {
    init_tracing();
    let mut report = Report::new();

    let model_dir = resolve_model_dir().context("resolve $HOME/.nexum/models/bge-m3")?;
    let model_path = model_dir.join("model.onnx");
    let tokenizer_path = model_dir.join("tokenizer.json");

    if !model_path.exists() || !tokenizer_path.exists() {
        report.note(
            "model-missing",
            &format!(
                "Skipping S3 timing measurement. bge-m3 ONNX model not found at {}.\n\
                 \n\
                 To enable S3:\n\
                 1. Export bge-m3 to ONNX (recommended path):\n\
                    pip install --upgrade optimum[exporters,onnxruntime]\n\
                    optimum-cli export onnx --model BAAI/bge-m3 --task feature-extraction \\\n\
                        {}\n\
                 2. Or use a community ONNX upload (e.g., search HF Hub for \"bge-m3 onnx\").\n\
                 \n\
                 Required files (single-line OpenSSH; tokenizer.json from same export):\n\
                   {}\n\
                   {}\n\
                 \n\
                 Then re-run: cargo run -p nexum-spike --bin spike-s3-onnx-perf",
                model_dir.display(),
                model_dir.display(),
                model_path.display(),
                tokenizer_path.display(),
            ),
        );
        report.print();
        std::process::exit(2);
    }

    let init_ok = ort::init().with_telemetry(false).commit();
    if !init_ok {
        bail!("ort::init().commit() returned false — ORT was already initialized with a different config");
    }
    report.pass("ort-init", "ONNX Runtime initialized");

    let tokenizer =
        Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow!("tokenizer load: {e}"))?;
    report.pass("tokenizer-load", "tokenizer.json loaded");

    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);

    // Cold-start = session build + first inference (after the model file has been touched).
    let cold_start = Instant::now();
    let mut session = Session::builder()
        .map_err(|e| anyhow!("Session::builder: {e}"))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| anyhow!("set optimization level: {e}"))?
        .with_intra_threads(threads)
        .map_err(|e| anyhow!("set intra-threads: {e}"))?
        .commit_from_file(&model_path)
        .map_err(|e| anyhow!("commit_from_file: {e}"))?;
    let session_build_ms = cold_start.elapsed().as_millis();

    let encoding = tokenizer
        .encode(SAMPLE_TEXT, true)
        .map_err(|e| anyhow!("tokenize sample: {e}"))?;
    let ids: Vec<i64> = encoding.get_ids().iter().map(|&x| i64::from(x)).collect();
    let mask: Vec<i64> = encoding
        .get_attention_mask()
        .iter()
        .map(|&x| i64::from(x))
        .collect();
    let seq_len = ids.len();

    let first_inf_start = Instant::now();
    run_one_inference(&mut session, &ids, &mask, seq_len)?;
    let first_inf_ms = first_inf_start.elapsed().as_millis();

    let total_cold_ms = session_build_ms + first_inf_ms;
    report.assert(
        "cold-start",
        total_cold_ms < COLD_START_TARGET_MS,
        &format!(
            "session build {session_build_ms}ms + first inference {first_inf_ms}ms = \
             {total_cold_ms}ms (target <{COLD_START_TARGET_MS}ms); seq_len={seq_len}, \
             intra_threads={threads}"
        ),
    );

    // Steady-state — average over STEADY_RUNS subsequent inferences.
    let steady_start = Instant::now();
    for _ in 0..STEADY_RUNS {
        run_one_inference(&mut session, &ids, &mask, seq_len)?;
    }
    let steady_total = steady_start.elapsed();
    let avg_ms = steady_total.as_millis() / STEADY_RUNS as u128;
    report.assert(
        "steady-state",
        avg_ms < STEADY_STATE_TARGET_MS,
        &format!(
            "{STEADY_RUNS} inferences total {steady_total:?}; avg {avg_ms}ms \
             (target <{STEADY_STATE_TARGET_MS}ms)"
        ),
    );

    // Peak RAM via /proc/self/status (Linux). On Windows this read fails — skip the assertion
    // gracefully so the spike's other measurements still land.
    match read_peak_rss_kb() {
        Ok(peak_kb) => {
            let peak_mb = peak_kb / 1024;
            report.assert(
                "peak-ram",
                peak_kb < PEAK_RAM_TARGET_KB,
                &format!(
                    "peak RSS {peak_mb} MB (target <{} MB) — measured via VmHWM",
                    PEAK_RAM_TARGET_KB / 1024
                ),
            );
        }
        Err(e) => {
            report.note(
                "peak-ram-skipped",
                &format!(
                    "Could not read /proc/self/status: {e}. Re-run on Linux to measure peak RAM, \
                     or instrument via a platform-appropriate API on Windows."
                ),
            );
        }
    }

    report.print();
    if report.all_pass() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

// ============================================================================
// inference + measurement helpers
// ============================================================================

fn run_one_inference(
    session: &mut Session,
    ids: &[i64],
    mask: &[i64],
    seq_len: usize,
) -> Result<()> {
    let input_ids_tensor = TensorRef::from_array_view(([1_usize, seq_len], ids))
        .map_err(|e| anyhow!("build input_ids tensor: {e}"))?;
    let mask_tensor = TensorRef::from_array_view(([1_usize, seq_len], mask))
        .map_err(|e| anyhow!("build mask tensor: {e}"))?;
    let _outputs = session
        .run(ort::inputs![
            "input_ids" => input_ids_tensor,
            "attention_mask" => mask_tensor,
        ])
        .map_err(|e| anyhow!("session.run: {e}"))?;
    Ok(())
}

fn resolve_model_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
    Ok(PathBuf::from(home)
        .join(".nexum")
        .join("models")
        .join("bge-m3"))
}

fn read_peak_rss_kb() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("VmHWM missing value"))?
                .parse()?;
            return Ok(kb);
        }
    }
    bail!("VmHWM not found in /proc/self/status")
}

// ============================================================================
// reporting
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
    #[allow(dead_code)]
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
        println!("\n=== nexum spike S3 — ONNX cold-start + steady-state inference timing ===\n");
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
