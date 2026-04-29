//! Spike S6 — full trust state-machine roundtrip with REAL records
//!
//! Pass criteria (per design §3.6, expanded in v1.7 from 6 → 7 phases):
//!   1. Bootstrap key A; events.yml + 3 derived signer files; signed bootstrap commit; trust_events row.
//!   2. Real record signed by A under decisions/test-rec-A.yml; verify_record → verified, current.
//!   3. KeyAdded(B); events.yml + regen; commit signed by A; two trust_events rows.
//!   4. KeyRotatedOut(A); events.yml + regen; commit signed by B. verify_record(test-rec-A) →
//!      verified, rotated-historical, ["signer-key-rotated"]. Plain `git verify-commit` (no redirect)
//!      against default config → expect FAILURE.
//!   5. NEGATIVE — payload tampering: edit existing event's public_key in commit C4. Re-materialize.
//!      Expect trust_chain_tampering row. verify_record → invalid, ["broken-trust-chain", "event-tampered"].
//!   6. NEGATIVE — reanchor without pin update: D signs BootstrapReanchor(A,D) but pin not updated.
//!      verify_record → invalid, ["broken-trust-chain"].
//!   7. POSITIVE reanchor: pin updated first, then BootstrapReanchor commit + Cr2 signed by D.
//!      verify_record(test-rec-A) (pre-reanchor) → verified, pre-reanchor, ["pre-recovery-record"].
//!      verify_record(test-rec-D) (post-reanchor) → verified, current.
//!
//! Run on Linux + Windows (via Windows OpenSSH) to validate cross-platform.
//!
//! TODO(next-session): implement after `git2` + `ssh-key` + `uuid` + `serde_yaml` + `rusqlite` are wired.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("spike-s6-trust-state-machine: not implemented yet — populate per design §3.6 S6 (7 phases, see header comment)");
    std::process::exit(2);
}
