//! §13 project-identity resolution composer.
//!
//! Walks the §13 precedence: `git_origin_url` → `registered_name` → `cwd`-based
//! path identity → `CC` slug-decoded path candidates. Returns `Resolved` (one
//! identity) or `Ambiguous` (multiple plausible identities, no higher-priority
//! signal to pick) or `Unresolved` (no signal at all).
//!
//! The patch4 rule: ambiguous slugs must NOT auto-resolve. The resolver returns
//! `ProjectResolution::Ambiguous` and lets the caller decide (typically: surface
//! as a `nexum doctor` warning; ask the user to register the project explicitly).

use crate::project::{
    AmbiguityCandidate, AmbiguityReason, ProjectInput, ProjectResolution, ResolutionReason,
    canon::{canonicalize_git_url, canonicalize_path, git_url_hint, path_hint},
    cc_slug::decode_cc_slug,
};
use std::path::PathBuf;

/// Resolve a `ProjectInput` to a `ProjectResolution` per the §13 precedence.
#[must_use]
pub fn resolve(input: &ProjectInput) -> ProjectResolution {
    // Precedence 1: git_origin_url. Strongest signal — even if other inputs
    // disagree, the URL identifies the project unambiguously (modulo
    // canonicalization).
    if let Some(raw) = &input.git_origin_url {
        let canonical = canonicalize_git_url(raw);
        let project_id = git_url_hint(&canonical);
        return ProjectResolution::Resolved {
            project_id,
            reason: ResolutionReason::GitOriginUrl,
        };
    }

    // Precedence 2: user-registered project name (caller looked it up).
    if let Some(name) = &input.registered_name {
        return ProjectResolution::Resolved {
            project_id: format!("name:{name}"),
            reason: ResolutionReason::RegisteredName,
        };
    }

    // Precedence 3: Codex direct `cwd`. Exists when the Codex adapter has a
    // `threads.cwd` value.
    if let Some(cwd) = &input.codex_cwd
        && let Ok(canon) = canonicalize_path(cwd)
    {
        let project_id = path_hint(&canon);
        return ProjectResolution::Resolved {
            project_id,
            reason: ResolutionReason::Path(canon),
        };
    }

    // Precedence 4: `CC` slug-decoded candidates.
    if let Some(slug) = &input.cc_slug
        && let Some(resolution) = resolve_cc_slug(slug)
    {
        return resolution;
    }

    ProjectResolution::Unresolved
}

/// Attempt to resolve a `CC` slug to a `ProjectResolution`.
///
/// Returns `Some(resolution)` if the slug yields at least one on-disk candidate,
/// or `None` if no candidates exist (caller falls through to `Unresolved`).
fn resolve_cc_slug(slug: &str) -> Option<ProjectResolution> {
    if let Ok(candidates) = decode_cc_slug(slug) {
        let mut resolved: Vec<AmbiguityCandidate> = candidates
            .into_iter()
            .filter_map(|cand| {
                canonicalize_path(&cand)
                    .ok()
                    .map(|canon| AmbiguityCandidate {
                        project_id: path_hint(&canon),
                        path: canon,
                    })
            })
            .collect();
        resolved.dedup_by(|a, b| a.project_id == b.project_id);
        match resolved.len() {
            0 => None,
            1 => {
                let Some(only) = resolved.into_iter().next() else {
                    unreachable!("len == 1 was just matched");
                };
                Some(ProjectResolution::Resolved {
                    project_id: only.project_id,
                    reason: ResolutionReason::Path(only.path),
                })
            }
            _ => Some(ProjectResolution::Ambiguous {
                candidates: resolved,
                reason: AmbiguityReason::SlugDecodeMultipleCandidates,
            }),
        }
    } else {
        // Slug decoding errored (too many hyphens). Fall back to using the
        // slug as a literal path component.
        let literal = PathBuf::from(format!("/{}", slug.trim_start_matches('-')));
        canonicalize_path(&literal)
            .ok()
            .map(|canon| ProjectResolution::Resolved {
                project_id: path_hint(&canon),
                reason: ResolutionReason::Path(canon),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> ProjectInput {
        ProjectInput {
            cc_slug: None,
            codex_cwd: None,
            git_origin_url: None,
            registered_name: None,
        }
    }

    #[test]
    fn empty_input_is_unresolved() {
        assert_eq!(resolve(&empty_input()), ProjectResolution::Unresolved);
    }

    #[test]
    fn git_origin_url_wins_over_everything() {
        let input = ProjectInput {
            git_origin_url: Some("https://github.com/o/r.git".to_owned()),
            registered_name: Some("ignored".to_owned()),
            codex_cwd: Some(PathBuf::from("/ignored")),
            cc_slug: Some("-ignored".to_owned()),
        };
        let r = resolve(&input);
        match r {
            ProjectResolution::Resolved { project_id, reason } => {
                assert!(project_id.starts_with("git:"));
                assert_eq!(reason, ResolutionReason::GitOriginUrl);
            }
            other => panic!("expected Resolved(git_origin_url), got {other:?}"),
        }
    }

    #[test]
    fn registered_name_wins_when_no_git_url() {
        let mut input = empty_input();
        input.registered_name = Some("project-a".to_owned());
        input.codex_cwd = Some(PathBuf::from("/ignored"));
        match resolve(&input) {
            ProjectResolution::Resolved { project_id, reason } => {
                assert_eq!(project_id, "name:project-a");
                assert_eq!(reason, ResolutionReason::RegisteredName);
            }
            other => panic!("expected Resolved(name), got {other:?}"),
        }
    }
}
