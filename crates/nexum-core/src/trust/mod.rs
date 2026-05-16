//! Trust event log types and signer-file projection.
//!
//! `events::EventLog` is the canonical structured event log.
//! `regenerate::regenerate_files` projects it into the three derived
//! OpenSSH-format signer files (`historical_signers`, `allowed_signers`,
//! `revoked_signers`).

pub mod chain_state;
pub mod diff;
pub mod events;
pub mod events_view;
pub mod git_history;
pub mod pin;
pub mod reanchor_pending;
pub mod regenerate;
pub mod rotate;

pub use events::{Event, EventKind, EventLog, TrustError, load_events_yml, write_seed_yaml};
pub use pin::{BootstrapPin, read_pin};
pub use regenerate::{RegenerateOutcome, regenerate_files};
