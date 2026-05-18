//! Batch state + dry-run manifest types.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchState {
    pub started_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub completed_session_ids: Vec<String>,
    pub failed_session_ids: Vec<FailedSession>,
}

impl BatchState {
    #[must_use]
    pub fn contains_completed(&self, id: &str) -> bool {
        self.completed_session_ids.iter().any(|s| s == id)
    }

    /// Write the state to `path` atomically (write-then-rename).
    ///
    /// # Errors
    /// Returns the underlying filesystem or serialization error if the parent
    /// directory cannot be created, the temporary file cannot be written, or
    /// the rename fails.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }

    /// Load the state from `path`. Returns `Ok(None)` if the file does not
    /// exist; `Err` for any other I/O or parse failure.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the file cannot be read for a
    /// reason other than "not found", or a JSON parse error wrapped in
    /// `std::io::Error` if the payload is malformed.
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedSession {
    pub session_id: String,
    pub error_code: String,
    pub message: String,
    pub retry_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub dry_run_id: String,
    pub provider: String,
    pub model: String,
    pub pricing_snapshot_at: DateTime<Utc>,
    pub candidate_count: u32,
    pub total_estimated_cost_usd: f64,
    pub p95_per_session_cost_usd: f64,
    pub per_source: PerSourceManifest,
    pub candidate_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PerSourceManifest {
    pub codex: SourceBreakdown,
    pub cc: SourceBreakdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SourceBreakdown {
    pub candidate_count: u32,
    pub estimated_cost_usd: f64,
}

/// Compute the dry-run id. Inputs are sorted into a canonical form before
/// hashing so identical-meaning calls produce identical ids. Including the
/// per-session content digest hash means a same-token-count content change
/// flips the id, preventing silent re-use of a stale manifest.
///
/// # Panics
/// Panics only if `serde_json` fails to serialize the canonical payload,
/// which is unreachable for the fixed shape this function constructs.
#[must_use]
pub fn compute_dry_run_id(
    provider: &str,
    model: &str,
    pricing_snapshot_at: DateTime<Utc>,
    per_session: &[(impl AsRef<str>, u32, impl AsRef<str>)],
) -> String {
    let mut sorted: BTreeMap<&str, (u32, &str)> = BTreeMap::new();
    for (id, tokens, digest_hash) in per_session {
        sorted.insert(id.as_ref(), (*tokens, digest_hash.as_ref()));
    }
    let per_session_payload: Vec<_> = sorted
        .iter()
        .map(|(id, (tokens, digest_hash))| {
            serde_json::json!({
                "id": id,
                "tokens": tokens,
                "digest_hash": digest_hash,
            })
        })
        .collect();
    let payload = serde_json::json!({
        "provider": provider,
        "model": model,
        "pricing_snapshot_at": pricing_snapshot_at.to_rfc3339(),
        "per_session": per_session_payload,
    });
    let bytes = serde_json::to_vec(&payload).expect("payload serializes");
    let digest = Sha256::digest(&bytes);
    format!("sha256:{}", to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchState, Manifest, PerSourceManifest, compute_dry_run_id};
    use chrono::TimeZone;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 5, 17, 12, 0, 0).unwrap()
    }

    #[test]
    fn empty_state_round_trips_json() {
        let state = BatchState {
            started_at: fixed_now(),
            provider: "anthropic".into(),
            model: "claude-opus-4-7".into(),
            completed_session_ids: vec![],
            failed_session_ids: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: BatchState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn manifest_serializes_dry_run_id_first_field() {
        let manifest = Manifest {
            dry_run_id: "sha256:abc".into(),
            provider: "anthropic".into(),
            model: "claude-opus-4-7".into(),
            pricing_snapshot_at: fixed_now(),
            candidate_count: 2,
            total_estimated_cost_usd: 0.16,
            p95_per_session_cost_usd: 0.10,
            per_source: PerSourceManifest::default(),
            candidate_ids: vec!["a".into(), "b".into()],
        };
        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["dry_run_id"], "sha256:abc");
    }

    #[test]
    fn compute_dry_run_id_is_deterministic_on_canonical_inputs() {
        let id1 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            fixed_now(),
            &[("s1", 100, "hashA"), ("s2", 200, "hashB")],
        );
        let id2 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            fixed_now(),
            &[("s2", 200, "hashB"), ("s1", 100, "hashA")],
        );
        assert_eq!(id1, id2);
        assert!(id1.starts_with("sha256:"));
    }

    #[test]
    fn compute_dry_run_id_flips_on_pricing_change() {
        let id1 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            fixed_now(),
            &[("s1", 100, "hashA")],
        );
        let later = fixed_now() + chrono::Duration::days(1);
        let id2 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            later,
            &[("s1", 100, "hashA")],
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_dry_run_id_flips_on_digest_hash_change() {
        let id1 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            fixed_now(),
            &[("s1", 100, "hashA")],
        );
        let id2 = compute_dry_run_id(
            "anthropic",
            "claude-opus-4-7",
            fixed_now(),
            &[("s1", 100, "hashB")],
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn batch_state_contains_session_is_short_circuit() {
        let state = BatchState {
            started_at: fixed_now(),
            provider: "anthropic".into(),
            model: "claude-opus-4-7".into(),
            completed_session_ids: vec!["s1".into(), "s2".into()],
            failed_session_ids: vec![],
        };
        assert!(state.contains_completed("s1"));
        assert!(!state.contains_completed("s3"));
    }
}
