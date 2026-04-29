//! Spike S3 — ONNX cold-start + steady-state inference timing
//!
//! Pass criteria (per design §3.6):
//!   - bge-m3 cold-start under 8s, steady-state under 300ms per inference (CPU), peak RAM under 2GB.
//!   - Hardware: user's actual laptop (per global CLAUDE.md hardware notes).
//!
//! TODO(next-session): implement after `ort` + `tokenizers` deps are wired in.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s3-onnx-perf: not implemented yet — populate per design §3.6 S3");
    std::process::exit(2);
}
