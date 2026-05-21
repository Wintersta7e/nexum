//! Backfill `project_id` on extracted records that landed in `_inbox/`.
//!
//! M2's extraction pipeline sets every record's `project_id` to `_inbox`
//! (see `extract/pipeline.rs` and `extract/record_io.rs`). This module
//! walks the inbox, re-resolves the project identity from each record's
//! `session_refs`, and re-commits the record under
//! `<project_id>/<type>/<id>.yml`.
//!
//! YAML body is updated via a line-level regex substitution (only the
//! `project_id:` line changes) so the rest of the file is byte-identical;
//! the record's `content_hash` drifts by exactly one line's worth, which is
//! a clean diff in the trust audit log.

/// Outcome of a single `normalize_inbox` invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizeOutcome {
    /// IDs of records moved out of `_inbox/`, in commit order.
    pub moved_ids: Vec<String>,
    /// Count of records that resolved ambiguously. Left in `_inbox/`.
    pub ambiguous: u32,
    /// IDs of records whose resolution was ambiguous.
    pub ambiguous_ids: Vec<String>,
    /// Count of records that produced no identifying signal. Left in `_inbox/`.
    pub unresolved: u32,
    /// IDs of records that were unresolved.
    pub unresolved_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::project::resolve::resolve;
    use crate::project::{ProjectInput, ProjectResolution};

    #[test]
    fn resolve_with_git_url_succeeds() {
        let input = ProjectInput {
            cc_slug: None,
            codex_cwd: None,
            git_origin_url: Some("https://github.com/example/foo.git".into()),
            registered_name: None,
        };
        let res = resolve(&input);
        assert!(matches!(res, ProjectResolution::Resolved { .. }));
    }
}
