//! `~/.nexum/redaction/custom_patterns.toml` loader.

use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use super::types::{RedactionError, RedactionPattern};

/// Load user-supplied redaction patterns from a TOML file.
///
/// # Errors
///
/// Returns `RedactionError::Io` if the file cannot be read,
/// `RedactionError::Toml` if the TOML is malformed, and
/// `RedactionError::Invalid` if any entry's `regex` field fails to compile.
pub fn load_custom_patterns(path: &Path) -> Result<Vec<RedactionPattern>, RedactionError> {
    let text = std::fs::read_to_string(path)?;
    let file: CustomFile = toml::from_str(&text)?;
    file.pattern
        .into_iter()
        .map(|entry| {
            let regex = Regex::new(&entry.regex).map_err(|e| RedactionError::Invalid {
                name: entry.name.clone(),
                reason: e.to_string(),
            })?;
            Ok(RedactionPattern {
                name: entry.name,
                regex,
                replacement: entry.replacement,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct CustomFile {
    #[serde(default)]
    pattern: Vec<CustomEntry>,
}

#[derive(Deserialize)]
struct CustomEntry {
    name: String,
    regex: String,
    replacement: String,
}
