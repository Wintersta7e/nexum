//! Project identity resolution per §13 of the design spec.
//!
//! `resolve(input) -> ProjectResolution` composes the §13 resolution order:
//!   1. `git_origin_url` (canonicalized) — the strongest signal.
//!   2. Registered project name from the user's `nexum` config, when supplied.
//!   3. Path-based identity from canonicalized cwd (or, for CC, from one of the
//!      slug-decoded path candidates).
//!
//! CC slug decoding is best-effort: the `/` → `-` substitution doesn't
//! roundtrip when path components contain hyphens. When the slug is ambiguous
//! and no higher-priority signal applies, `resolve()` returns
//! `ProjectResolution::Ambiguous` rather than auto-picking a candidate.

pub mod canon;
pub mod cc_slug;
pub mod resolve;

use std::path::PathBuf;

/// Input to `project::resolve`. Captures everything an adapter knows about a
/// candidate project before the resolver runs the §13 precedence.
#[derive(Debug, Clone)]
pub struct ProjectInput {
    /// The cwd-encoded slug from a CC project dir, if known. Caller already
    /// stripped the leading `~/.claude/projects/` prefix.
    pub cc_slug: Option<String>,
    /// The Codex `threads.cwd` value (or any direct cwd path), if known.
    pub codex_cwd: Option<PathBuf>,
    /// `git_origin_url` from `state_5.sqlite.threads.git_origin_url`, if known.
    /// May be raw (will be canonicalized by `resolve`).
    pub git_origin_url: Option<String>,
    /// The user-registered project name (from the user `nexum` config), if the
    /// caller has already looked it up. None means "resolver doesn't have access
    /// to the registry" — registered-name-precedence is skipped if so.
    pub registered_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectResolution {
    /// Resolved to a single `project_id` with a recorded reason for the choice.
    Resolved {
        project_id: String,
        reason: ResolutionReason,
    },
    /// Multiple plausible candidates with no higher-priority signal to pick
    /// among them. Caller should surface as a `nexum doctor` warning and let
    /// the user disambiguate via `nexum project register <name> <path>`.
    Ambiguous {
        candidates: Vec<AmbiguityCandidate>,
        reason: AmbiguityReason,
    },
    /// No identifying signal at all (no slug, no cwd, no git remote, no name).
    /// Caller likely wants to skip the record.
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ResolutionReason {
    GitOriginUrl,
    RegisteredName,
    /// Path-based identity. The `PathBuf` is the canonical form that produced the
    /// `project_id_path_hint`; useful for diagnostics.
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguityCandidate {
    pub project_id: String,
    /// Canonical path that produced this candidate's `project_id_path_hint`.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum AmbiguityReason {
    /// The CC slug had multiple plausible decodings.
    SlugDecodeMultipleCandidates,
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("path canonicalization failed: {0}")]
    Canon(#[from] canon::CanonError),
    #[error("slug decoding failed: {0}")]
    Slug(#[from] cc_slug::SlugError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolution_reason_serializes_as_tagged_json() {
        // Unit variant — no `value` field emitted.
        let r = ResolutionReason::GitOriginUrl;
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"git-origin-url\""),
            "expected kebab-cased kind, got {json}"
        );

        // Tuple variant — emitted as `{"kind": "path", "value": "<path>"}`.
        let r = ResolutionReason::Path(PathBuf::from("/tmp/project"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"path\""), "expected kind=path, got {json}");
        assert!(
            json.contains("/tmp/project"),
            "expected path value, got {json}"
        );
    }

    #[test]
    fn ambiguity_reason_serializes_as_tagged_json() {
        let r = AmbiguityReason::SlugDecodeMultipleCandidates;
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("\"slug-decode-multiple-candidates\""),
            "expected kebab-cased variant, got {json}"
        );
    }
}
