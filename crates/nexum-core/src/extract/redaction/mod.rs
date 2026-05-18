//! Secret-shaped substring redaction. Best-effort defence in depth — not a
//! privacy guarantee. The default pattern set covers public-form keys; users
//! extend it via `~/.nexum/redaction/custom_patterns.toml`.

mod custom;
mod log;
mod patterns;
mod types;

pub use custom::load_custom_patterns;
pub use log::append_redaction_log;
pub use patterns::default_patterns;
pub use types::{RedactedText, RedactionEngine, RedactionError, RedactionEvent, RedactionPattern};

/// Convenience: a `RedactionEngine` preloaded with `default_patterns()`.
#[must_use]
pub fn default_engine() -> RedactionEngine {
    RedactionEngine::new(default_patterns())
}
