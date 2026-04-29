//! Spike S1 — sqlite-vec DDL + tag-heavy query
//!
//! Pass criteria (per design §3.6):
//!   - DDL accepted on Linux x86_64 + Windows native.
//!   - Vector query, FTS query, hybrid (RRF) query, and a tag-heavy query all return correct results
//!     against a 100-record fake corpus.
//!   - Results inform whether §7's DDL needs adjustment before M1.
//!
//! TODO(next-session): implement the spike body. See `docs/spec/2026-04-29-nexum-design.md` §3.6 (S1).

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s1-sqlite-vec-ddl: not implemented yet — populate per design §3.6 S1");
    std::process::exit(2);
}
