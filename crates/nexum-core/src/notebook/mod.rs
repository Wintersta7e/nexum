// Audit-log walker — reads notebook.git history and classifies by prefix.
pub(crate) mod audit;
// Fresh cryptographic record verification (re-runs git verify-commit live).
pub(crate) mod verify;
// Lifecycle-event types and commit-message renderers.
pub mod lifecycle;
// Decision-record YAML emitter and recommendation-stamping helpers.
pub mod emit;
// Pre-flight guard, eligibility check, and the lifecycle-mutation writer.
pub mod writer;
