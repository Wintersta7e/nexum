//! Trust event log types and signer-file projection.
//!
//! `events::EventLog` is the canonical structured event log (§9).
//! `regenerate::regenerate_files` projects it into the three derived
//! OpenSSH-format signer files (`historical_signers`, `allowed_signers`,
//! `revoked_signers`).

pub mod events;
pub mod regenerate;

pub use events::{Event, EventKind, EventLog, TrustError, write_seed_yaml};
pub use regenerate::{RegenerateOutcome, regenerate_files};
