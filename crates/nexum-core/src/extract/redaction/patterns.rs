//! The frozen default pattern set. Order matters when patterns can match
//! overlapping substrings — `env_secret_assignment` runs after the typed
//! key patterns so a typed key embedded in `API_KEY=...` keeps its named
//! redaction label rather than being subsumed.

use regex::Regex;

use super::types::RedactionPattern;

/// Build the default pattern set used by `default_engine()`.
///
/// # Panics
///
/// Panics if a compiled-in regex literal fails to compile. The set is
/// internal-only and exercised by unit tests; a compile failure is a
/// programmer bug, not a runtime condition.
#[must_use]
pub fn default_patterns() -> Vec<RedactionPattern> {
    let raw: &[(&str, &str)] = &[
        ("aws_access_key", r"\bAKIA[A-Z0-9]{16}\b"),
        ("github_pat", r"\bgh[poas]_[a-zA-Z0-9]{36,255}\b"),
        (
            "jwt",
            r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
        ),
        (
            "slack_token",
            r"\bxox[abprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+-[a-f0-9]+\b",
        ),
        ("anthropic_key", r"\bsk-ant-[a-zA-Z0-9\-_]{20,}\b"),
        (
            "openai_key",
            r"\bsk-(?:proj-|live_|None_)?[a-zA-Z0-9\-_]{20,}\b",
        ),
        (
            "ssh_private_key_block",
            r"-----BEGIN[^\n]+PRIVATE KEY-----[\s\S]*?-----END[^\n]+PRIVATE KEY-----",
        ),
        ("url_basic_auth", r"\b[a-zA-Z]+://[^:\s/]+:[^@\s]+@\S+"),
        (
            "env_secret_assignment",
            r"(?i)\b(?:PASSWORD|SECRET|TOKEN|API_?KEY)\s*=\s*\S+",
        ),
    ];
    raw.iter()
        .map(|(name, pattern)| {
            let regex = Regex::new(pattern).expect("default pattern compiles");
            RedactionPattern {
                name: (*name).to_owned(),
                regex,
                replacement: format!("[REDACTED:{name}]"),
            }
        })
        .collect()
}
