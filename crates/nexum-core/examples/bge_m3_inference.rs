//! Inference-latency measurement bench for the bge-m3 ONNX export.
//!
//! Loads the installed bge-m3 model, runs a single warm-up inference,
//! then times 100 inferences over a short input. Prints p50/p95/p99 in
//! microseconds. When `BGE_M3_INPUT_LONG=1`, additionally runs the same
//! 100-iteration loop over a built-in ~500-token paragraph so callers
//! can compare best-case latency against a realistic record shape.
//!
//! Run with:
//!
//! ```text
//! BGE_M3_DIR=$HOME/.nexum/models/bge-m3 \
//!   cargo run --release --example bge_m3_inference
//! ```
//!
//! Optional overrides:
//! - `BGE_M3_INPUT`        — replace the default short sentence.
//! - `BGE_M3_INPUT_LONG=1` — also run the realistic long-input variant.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use nexum_core::embed::Embedder;

const DEFAULT_SHORT_INPUT: &str = "The quick brown fox jumps over the lazy dog.";

/// Realistic ~500-token paragraph: concatenated title + summary + body
/// shaped material. Length is what matters here; the exact wording is
/// generic prose so the bench stays portable.
const LONG_INPUT: &str = "\
A distributed memory layer indexes a flowing stream of notes, decisions, \
and observations gathered across many sessions. Each record carries a \
title, an optional summary, a body, a set of tags, and a project anchor; \
the indexer normalizes those fields, computes a content hash, derives a \
content-addressed identifier, and writes the record into a SQLite store. \
Alongside the row, a dense vector embedding of the concatenated text is \
written into a sqlite-vec virtual table; a full-text mirror is written \
into an FTS5 table; a trust event referencing the row's content hash is \
appended to an append-only event log signed by the active local key. \
Reads fan out across the dense and lexical branches in parallel and \
fuse the two ranked lists with reciprocal rank fusion before a final \
cryptographic check verifies that every returned row's content hash \
still matches the trust event log. Misses on the verifier downgrade the \
result to a recommendation rather than a decision, with the reason \
embedded in the response envelope so the calling agent can branch. \
Configuration lives in a per-home toml file and is loaded lazily; the \
session-resolution helper threads a runtime handle through every entry \
point so the cli, the mcp server, and the embedded test fixtures all \
share the same store and trust state without leaking globals. The store \
is portable across linux, macos, and windows targets, and the bundled \
sqlite build avoids the system library mismatch problems that an \
otherwise-shared linkage would create on each of those platforms.";

const SAMPLES: usize = 100;

fn percentiles(samples: &[u64]) -> (u64, u64, u64) {
    debug_assert!(samples.len() >= SAMPLES);
    // For SAMPLES = 100, the 50th-percentile index is 49 (the 50th element,
    // 0-indexed). p95 and p99 already apply the -1 correction; the median
    // calculation was the outlier.
    let p50 = samples[(SAMPLES / 2).saturating_sub(1)];
    let p95 = samples[(SAMPLES * 95) / 100 - 1];
    let p99 = samples[(SAMPLES * 99) / 100 - 1];
    (p50, p95, p99)
}

fn measure(embedder: &Embedder, label: &str, text: &str) -> Result<(), String> {
    // Warm-up: one inference outside the timed loop.
    let _ = embedder
        .embed(text)
        .map_err(|e| format!("warm-up failed: {e}"))?;

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        let _ = embedder
            .embed(text)
            .map_err(|e| format!("inference failed: {e}"))?;
        let elapsed_u128 = t0.elapsed().as_micros();
        // Saturating cast: a single inference exceeding ~580 years would
        // saturate to u64::MAX. Practically unreachable; keeps the cast
        // pedantic-clippy-clean.
        let elapsed = u64::try_from(elapsed_u128).unwrap_or(u64::MAX);
        samples.push(elapsed);
    }
    samples.sort_unstable();
    let (p50, p95, p99) = percentiles(&samples);
    println!(
        "bge-m3 inference [{label}] (chars={chars}): p50 = {p50} µs, p95 = {p95} µs, p99 = {p99} µs",
        chars = text.chars().count(),
    );
    Ok(())
}

fn main() -> ExitCode {
    let model_dir = std::env::var_os("BGE_M3_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                let mut p = PathBuf::from(home);
                p.push(".nexum");
                p.push("models");
                p.push("bge-m3");
                p
            })
        });
    let Some(model_dir) = model_dir else {
        eprintln!(
            "no BGE_M3_DIR set and HOME is unavailable; export BGE_M3_DIR=$HOME/.nexum/models/bge-m3"
        );
        return ExitCode::FAILURE;
    };

    println!("loading bge-m3 from {}", model_dir.display());
    let embedder = match Embedder::load(&model_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("failed to load bge-m3 from {}: {e}", model_dir.display());
            return ExitCode::FAILURE;
        }
    };

    let short_input = std::env::var("BGE_M3_INPUT").unwrap_or_else(|_| DEFAULT_SHORT_INPUT.into());
    if let Err(e) = measure(&embedder, "short", &short_input) {
        eprintln!("short-input bench failed: {e}");
        return ExitCode::FAILURE;
    }

    let run_long = std::env::var_os("BGE_M3_INPUT_LONG").is_some_and(|v| v == "1");
    if run_long {
        if let Err(e) = measure(&embedder, "long", LONG_INPUT) {
            eprintln!("long-input bench failed: {e}");
            return ExitCode::FAILURE;
        }
    } else {
        println!("(set BGE_M3_INPUT_LONG=1 to also run the ~500-token variant)");
    }

    ExitCode::SUCCESS
}
