//! Spike S5 — ort distribution
//!
//! Pass criteria (per design §3.6):
//!   - Build the spike with `ort` and chosen feature flags (download-binaries vs system).
//!   - Run on a clean machine without ONNX Runtime preinstalled.
//!   - If failure: §15 distribution strategy needs revision.
//!
//! TODO(next-session): implement.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s5-ort-distribution: not implemented yet — populate per design §3.6 S5");
    std::process::exit(2);
}
