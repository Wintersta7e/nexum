//! Trust event log types and signer-file projection.
//!
//! `events::EventLog` is the canonical structured event log.
//! `regenerate::regenerate_files` projects it into the three derived
//! OpenSSH-format signer files (`historical_signers`, `allowed_signers`,
//! `revoked_signers`).

pub mod events;
pub mod pin;
pub mod reanchor_pending;
pub mod regenerate;

pub use events::{Event, EventKind, EventLog, TrustError, load_events_yml, write_seed_yaml};
pub use pin::{BootstrapPin, read_pin};
pub use reanchor_pending::{ReanchorPending, check as check_reanchor_pending};
pub use regenerate::{RegenerateOutcome, regenerate_files};
