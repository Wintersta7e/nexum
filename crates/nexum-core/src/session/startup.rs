//! `pre_check` runs before every nexum command (CLI + MCP). Detects global
//! refusal conditions (currently: pending reanchor sentinel) and returns the
//! appropriate top-level error so callers can map to the dedicated exit
//! code.

use std::path::Path;

use crate::trust::events::TrustError;
use crate::trust::reanchor_pending;

/// Error type returned by [`pre_check`]. Currently a thin wrapper around
/// `TrustError`; carries its own enum so future preconditions can extend the
/// surface without breaking existing match arms in callers.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// A trust-layer precondition failed (e.g., pending reanchor sentinel).
    #[error("{0}")]
    Trust(#[from] TrustError),
}

/// Returns `Ok(())` if the session can proceed; `Err` otherwise.
///
/// Callers map `StartupError::Trust(TrustError::ReanchorPending { .. })` to
/// exit code 8 and the rest to a generic store-integrity exit.
///
/// # Errors
///
/// Propagates any error from the underlying trust-layer pre-checks (today,
/// only [`reanchor_pending::check`]).
pub fn pre_check(home: &Path) -> Result<(), StartupError> {
    reanchor_pending::check(home)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::pre_check;
    use tempfile::tempdir;

    #[test]
    fn pre_check_clean_home_succeeds() {
        let dir = tempdir().unwrap();
        assert!(pre_check(dir.path()).is_ok());
    }

    #[test]
    fn pre_check_with_reanchor_pending_fails() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".reanchor_pending"),
            r#"{
                "case": "A",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "init"
            }"#,
        )
        .unwrap();
        assert!(pre_check(dir.path()).is_err());
    }
}
