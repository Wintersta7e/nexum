//! Typed extraction pipeline. Reads CC transcripts and Codex rollouts, scrubs
//! common secret-shaped substrings, sends a session digest to a `ModelClient`,
//! parses the YAML response into typed records, and commits them via the
//! existing trust-chain signed-commit path.

pub mod digest;
pub mod model;
pub mod pricing;
pub mod prompts;
pub mod redaction;
