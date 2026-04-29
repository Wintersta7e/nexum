//! Spike S4 — rmcp + executor split + semaphore saturation
//!
//! Pass criteria (per design §3.6):
//!   - Phase (i): under-cap concurrent slow_op + fast_op; fast_op median <50ms.
//!   - Phase (ii): over-cap async slow_op; permit acquisition awaits; timeout fires Error::Busy.
//!   - Phase (iii): sync embed_blocking → Error::Busy { retry_after_ms: 0 } via try_acquire.
//!
//! TODO(next-session): implement after `rmcp` + `tokio` + `rayon` are wired.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s4-rmcp-executor: not implemented yet — populate per design §3.6 S4");
    std::process::exit(2);
}
