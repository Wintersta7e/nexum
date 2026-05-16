//! Progress reporting for the install pipeline. Decouples the core
//! download/verify logic from the CLI's stderr surface.

/// Reports install progress. The CLI passes an stderr-printing impl;
/// tests pass a buffer; the indexer doesn't invoke install at all.
pub trait Reporter: Send {
    /// Coarse-grained progress: a short message (e.g.,
    /// "downloading `model.onnx_data` (2.1 GB)…"). Implementations may
    /// debounce or coalesce.
    fn progress(&mut self, msg: &str);

    /// Byte-level progress for the active file. `done` and `total` are
    /// per-file, not cumulative. Implementations should debounce; this
    /// fires once per ~64 KiB of read body.
    fn bytes(&mut self, done: u64, total: u64);
}

/// No-op reporter, useful as a default and for tests that don't care
/// about progress messages.
pub struct NullReporter;

impl Reporter for NullReporter {
    fn progress(&mut self, _msg: &str) {}
    fn bytes(&mut self, _done: u64, _total: u64) {}
}
