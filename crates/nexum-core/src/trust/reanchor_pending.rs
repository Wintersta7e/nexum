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

/// Reanchor case: the previous bootstrap state when the sentinel was written.
///
/// Wire form is the bare letter (`"A"` / `"B"`); deserialization rejects
/// every other value, routing through the malformed-sentinel branch.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(crate) enum Case {
    /// Existing pin known; reanchor is rotating from a known-good fingerprint.
    A,
    /// Pin lost or unverifiable; reanchor proceeds without an old fingerprint.
    B,
}

impl Case {
    fn as_str(self) -> &'static str {
        match self {
            Case::A => "A",
            Case::B => "B",
        }
    }
}

/// Reanchor phase reached at the moment the sentinel was last written.
///
/// Wire form is `snake_case` (`"init"` / `"events_committed"` / `"pin_updated"`);
/// deserialization rejects every other value.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    /// Sentinel created; no events committed yet.
    Init,
    /// Trust events for the new pin have been committed; pin file not yet rotated.
    EventsCommitted,
    /// New pin file in place; sentinel awaiting cleanup.
    PinUpdated,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Init => "init",
            Phase::EventsCommitted => "events_committed",
            Phase::PinUpdated => "pin_updated",
        }
    }
}

/// Parsed contents of the `.reanchor_pending` sentinel file.
///
/// `case == Case::B` indicates the previous pin was lost; `old_pin_fp` is
/// `None` in that case. Unknown values for `case` or `phase_completed` fail
/// deserialization, which routes through the malformed-sentinel branch in
/// [`check`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct ReanchorPending {
    pub case: Case,
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
    pub phase_completed: Phase,
}

/// Returns `Ok(())` when no `.reanchor_pending` sentinel is present.
///
/// # Errors
///
/// - `TrustError::Io` when the sentinel exists but cannot be read.
/// - `TrustError::ReanchorPending` when the sentinel exists, including the
///   case where it is malformed (callers must refuse to proceed either way).
pub(crate) fn check(home: &Path) -> Result<(), TrustError> {
    let path = home.join(".reanchor_pending");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(TrustError::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
    };
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
            parsed.case.as_str(),
            parsed.phase_completed.as_str(),
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
                assert!(message.contains("phase events_committed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_empty() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".reanchor_pending", "");
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_unknown_case() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "C",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "init"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_unknown_phase() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "rolled_back"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }
}
