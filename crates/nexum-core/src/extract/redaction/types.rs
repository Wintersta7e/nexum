//! Types for the secret redaction layer.

use std::io;

use regex::Regex;
use serde::Serialize;

pub struct RedactionEngine {
    patterns: Vec<RedactionPattern>,
}

impl RedactionEngine {
    #[must_use]
    pub fn new(patterns: Vec<RedactionPattern>) -> Self {
        Self { patterns }
    }

    /// Append additional patterns (custom-pattern set). Order: built-ins run
    /// first, custom patterns run on the already-redacted text. This makes
    /// `[REDACTED:<name>]` markers semi-stable across re-runs.
    pub fn extend(&mut self, more: impl IntoIterator<Item = RedactionPattern>) {
        self.patterns.extend(more);
    }

    /// Apply every pattern in registration order. Each pattern's regex
    /// scans the current (possibly partially-redacted) text and replaces
    /// every match with the pattern's `replacement`. Events carry the
    /// sha256 of the pre-replacement match for later auditing.
    #[must_use]
    pub fn redact(&self, input: &str) -> RedactedText {
        let mut text = input.to_owned();
        let mut events: Vec<RedactionEvent> = Vec::new();
        for pattern in &self.patterns {
            // Collect spans before mutating; regex-find iterator borrows the haystack.
            let spans: Vec<(usize, usize)> = pattern
                .regex
                .find_iter(&text)
                .map(|m| (m.start(), m.end()))
                .collect();
            if spans.is_empty() {
                continue;
            }
            for &(start, end) in &spans {
                let matched = &text[start..end];
                let context_start = start.saturating_sub(8);
                let context_end = (end + 8).min(text.len());
                events.push(RedactionEvent {
                    pattern_name: pattern.name.clone(),
                    before_hash: sha256_hex(matched.as_bytes()),
                    context_window_hash: sha256_hex(&text.as_bytes()[context_start..context_end]),
                });
            }
            text = pattern
                .regex
                .replace_all(&text, pattern.replacement.as_str())
                .into_owned();
        }
        RedactedText { text, events }
    }
}

#[derive(Debug)]
pub struct RedactionPattern {
    pub name: String,
    pub regex: Regex,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedText {
    pub text: String,
    pub events: Vec<RedactionEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionEvent {
    pub pattern_name: String,
    /// `sha256:` prefix + 64 hex chars over the matched substring AS SEEN
    /// by the firing pattern. For patterns that fire on already-redacted
    /// text in overlap cases (e.g. `env_secret_assignment` running after
    /// `aws_access_key`), this hash is over the partially-redacted
    /// intermediate, not the original input. Acceptable forensic signal
    /// for first-pass events; not authoritative for subsequent passes.
    pub before_hash: String,
    pub context_window_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RedactionError {
    #[error("I/O reading custom patterns: {0}")]
    Io(#[from] io::Error),
    #[error("invalid pattern {name}: {reason}")]
    Invalid { name: String, reason: String },
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble_to_hex(b >> 4));
        s.push(nibble_to_hex(b & 0x0f));
    }
    s
}

#[inline]
fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}
