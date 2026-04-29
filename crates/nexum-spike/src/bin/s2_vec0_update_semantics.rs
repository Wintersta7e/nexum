//! Spike S2 — vec0 update semantics
//!
//! Pass criteria (per design §3.6):
//!   - Insert → update → delete a record. FTS5 external-content triggers fire correctly.
//!   - Vec0 delete-before-records-delete and vec0-insert-after-records-insert ordering produces
//!     no orphaned rows.
//!
//! TODO(next-session): implement.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s2-vec0-update-semantics: not implemented yet — populate per design §3.6 S2");
    std::process::exit(2);
}
