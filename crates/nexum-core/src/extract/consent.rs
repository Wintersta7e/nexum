//! First-run consent gate.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AckedRecord {
    pub acked_at: DateTime<Utc>,
    pub acked_provider: String,
    pub acked_model_family: String,
}

/// Strip the trailing numeric suffix (`-N-M-...`) from a model id to get
/// the family.
#[must_use]
pub fn model_family(model: &str) -> String {
    let mut parts: Vec<&str> = model.split('-').collect();
    while let Some(last) = parts.last() {
        if last.chars().all(|c| c.is_ascii_digit()) {
            parts.pop();
        } else {
            break;
        }
    }
    parts.join("-")
}

/// Return true iff the supplied `ack` does NOT satisfy the consent contract
/// for the configured (provider, model).
#[must_use]
pub fn consent_required(ack: Option<&AckedRecord>, provider: &str, model: &str) -> bool {
    let Some(ack) = ack else {
        return true;
    };
    if ack.acked_provider != provider {
        return true;
    }
    let family = model_family(model);
    ack.acked_model_family != family
}

/// Load the ack from `path`. `Ok(None)` when absent.
///
/// # Errors
/// I/O or parse error.
pub fn read_ack(path: &Path) -> std::io::Result<Option<AckedRecord>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the ack to `path` atomically. Creates parent dirs.
///
/// # Errors
/// Filesystem errors only.
pub fn write_ack(path: &Path, ack: &AckedRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(ack)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Render the data-leaves-the-machine warning text. Centralised so CLI + (future)
/// hook paths share the wording.
#[must_use]
pub fn warning_text(provider: &str) -> String {
    format!(
        "\u{26a0} Extraction sends a digest of session content (user prompts, assistant prose,\n  tool-call summaries) to {provider} for analysis. Best-effort redaction is\n  applied first (see ~/.nexum/logs/redaction.jsonl for what was scrubbed) but\n  is not comprehensive \u{2014} review the redaction log if your session may have\n  contained sensitive content."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 5, 17, 12, 0, 0).unwrap()
    }

    #[test]
    fn model_family_strips_numeric_suffix() {
        assert_eq!(model_family("claude-opus-4-7"), "claude-opus");
        assert_eq!(model_family("claude-sonnet-4-6"), "claude-sonnet");
        assert_eq!(model_family("gpt-4o-2024-08-06"), "gpt-4o");
    }

    #[test]
    fn consent_required_when_no_ack() {
        assert!(consent_required(None, "anthropic", "claude-opus-4-7"));
    }

    #[test]
    fn consent_not_required_when_ack_matches_provider_and_family() {
        let ack = AckedRecord {
            acked_at: ts(),
            acked_provider: "anthropic".into(),
            acked_model_family: "claude-opus".into(),
        };
        assert!(!consent_required(
            Some(&ack),
            "anthropic",
            "claude-opus-4-7"
        ));
    }

    #[test]
    fn consent_required_when_provider_changes() {
        let ack = AckedRecord {
            acked_at: ts(),
            acked_provider: "anthropic".into(),
            acked_model_family: "claude-opus".into(),
        };
        assert!(consent_required(Some(&ack), "openai", "gpt-4o"));
    }

    #[test]
    fn consent_required_when_family_changes() {
        let ack = AckedRecord {
            acked_at: ts(),
            acked_provider: "anthropic".into(),
            acked_model_family: "claude-opus".into(),
        };
        assert!(consent_required(
            Some(&ack),
            "anthropic",
            "claude-haiku-4-5"
        ));
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("extract_acked.json");
        let ack = AckedRecord {
            acked_at: ts(),
            acked_provider: "anthropic".into(),
            acked_model_family: "claude-opus".into(),
        };
        write_ack(&path, &ack).unwrap();
        let back = read_ack(&path).unwrap().expect("present");
        assert_eq!(back, ack);
    }

    #[test]
    fn read_ack_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        assert!(read_ack(&path).unwrap().is_none());
    }
}
