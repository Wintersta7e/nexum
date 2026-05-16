//! Shared, serialized handle to an ORT inference session.
//!
//! M1 runs a single `ort::Session` shared across query and indexer threads.
//! `ort = "=2.0.0-rc.12"` exposes `Session: Send + Sync`, but `run()` takes
//! `&mut self`, so a mutex is required to serialize callers. This newtype
//! makes the contention model explicit: any `run(...)` call holds the mutex
//! for the duration of one inference. There is no worker pool in M1; if M2
//! introduces one, swap this type for an `InferencePool` newtype with the
//! same `run(...)` surface — call sites will not move.

use std::sync::{Arc, Mutex};

use ort::session::Session;

use super::types::EmbedError;

/// Owned handle to a shared ORT inference session. `Clone` is cheap (only
/// the `Arc` is duplicated); the underlying session is single-instance per
/// process.
#[derive(Clone)]
pub(crate) struct InferenceCell {
    session: Arc<Mutex<Session>>,
}

impl InferenceCell {
    /// Wrap an owned session for shared, serialized inference.
    pub(crate) fn new(session: Session) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
        }
    }

    /// Run a closure with exclusive access to the inner session. Any panic
    /// inside the closure poisons the mutex; subsequent callers see
    /// `EmbedError::OrtRun` with the poison message.
    pub(crate) fn run<F, T>(&self, f: F) -> Result<T, EmbedError>
    where
        F: FnOnce(&mut Session) -> Result<T, EmbedError>,
    {
        let mut guard = self.session.lock().map_err(|e| {
            let message = format!("inference session mutex poisoned: {e}");
            EmbedError::OrtRun {
                source: Box::<dyn std::error::Error + Send + Sync>::from(message.clone()),
                message,
            }
        })?;
        f(&mut guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_cell_is_send_sync_clone() {
        // No real ort::Session is buildable in a unit test, so the shape
        // check here is that the type compiles with Send + Sync + Clone.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_clone<T: Clone>() {}
        assert_send::<InferenceCell>();
        assert_sync::<InferenceCell>();
        assert_clone::<InferenceCell>();
    }
}
