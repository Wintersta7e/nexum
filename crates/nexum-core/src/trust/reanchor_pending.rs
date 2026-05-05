//! `~/.nexum/.reanchor_pending` sentinel detection.
//!
//! When this file exists, every nexum command refuses with
//! `TrustError::ReanchorPending` (exit 8). Detection ships now to surface a
//! clear error if the sentinel is encountered (e.g., importing a
//! `notebook.git` from another machine mid-recovery); the resolution flow
//! itself lives in `nexum doctor --resolve-pending-reanchor`.

use std::path::Path;

use serde::Deserialize;

use crate::trust::events::TrustError;

/// Parsed contents of the `.reanchor_pending` sentinel file.
///
/// `case` is `"A"` (existing pin known) or `"B"` (pin lost / Case B). When
/// `case == "B"` the previous pin is unknown and `old_pin_fp` is `None`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReanchorPending {
    /// `"A"` (pin known) or `"B"` (pin lost).
    pub case: String,
    /// Previous bootstrap fingerprint, `None` for case B.
    pub old_pin_fp: Option<String>,
    /// New bootstrap fingerprint being installed.
    pub new_pin_fp: String,
    /// New bootstrap public key (SSH `authorized_keys` line).
    #[serde(default)]
    pub new_pubkey: String,
    /// RFC3339 timestamp when the reanchor was started.
    pub started_at: String,
    /// Optional PID of the process that wrote the sentinel.
    #[serde(default)]
    pub pid: Option<u64>,
    /// `"init"` | `"events_committed"` | `"pin_updated"`.
    pub phase_completed: String,
}

/// Returns `Ok(())` when no `.reanchor_pending` sentinel is present.
///
/// # Errors
///
/// - `TrustError::Io` when the sentinel exists but cannot be read.
/// - `TrustError::ReanchorPending` when the sentinel exists, including the
///   case where it is malformed (callers must refuse to proceed either way).
pub fn check(home: &Path) -> Result<(), TrustError> {
    let path = home.join(".reanchor_pending");
    if !path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| TrustError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let parsed: ReanchorPending =
        serde_json::from_str(&raw).map_err(|e| TrustError::ReanchorPending {
            message: format!(
                ".reanchor_pending exists but is malformed: {e}. \
                 Resolution requires the recovery flow \
                 (`nexum doctor --resolve-pending-reanchor`). \
                 If you know the reanchor was abandoned, delete .reanchor_pending."
            ),
        })?;

    Err(TrustError::ReanchorPending {
        message: format!(
            "Pending reanchor detected (case {}, phase {}). \
             Resolution requires the recovery flow \
             (`nexum doctor --resolve-pending-reanchor`). \
             Either upgrade the binary, or delete .reanchor_pending if the reanchor was abandoned.",
            parsed.case, parsed.phase_completed,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::{TrustError, check};
    use std::path::Path;
    use tempfile::tempdir;

    fn write(home: &Path, name: &str, body: &str) {
        std::fs::write(home.join(name), body).unwrap();
    }

    #[test]
    fn check_returns_ok_when_sentinel_absent() {
        let dir = tempdir().unwrap();
        assert!(check(dir.path()).is_ok());
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_present_phase_init() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "new_pubkey": "ssh-ed25519 BBBB",
                "started_at": "2026-05-04T12:00:00Z",
                "pid": 12345,
                "phase_completed": "init"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("case A"));
                assert!(message.contains("phase init"));
                assert!(message.contains("nexum doctor --resolve-pending-reanchor"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_malformed() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".reanchor_pending", "{ bad json");
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_case_b() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "B",
                "old_pin_fp": null,
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "events_committed"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("case B"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }
}
