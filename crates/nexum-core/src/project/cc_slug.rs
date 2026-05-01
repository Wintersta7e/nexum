//! CC cwd-slug decoding per §5 (best-effort).
//!
//! Real CC stores encode the original cwd as `<dir>` where `<dir>` is the cwd's
//! absolute path with `/` substituted to `-`. The leading `/` becomes the
//! leading `-`. Example:
//!
//!     cwd `/home/user/projects/foo` → slug `-home-user-projects-foo`
//!
//! Decoding is **lossy**: every `/` in the original path becomes `-` in the
//! slug, but `-` characters that exist in path components also become `-` in
//! the slug. Two paths with the same character sequence after substitution are
//! indistinguishable from the slug.
//!
//!     slug `-home-user-my-project` could mean:
//!         /home/user/my-project       (1 inner hyphenated component)
//!         /home/user/my/project       (3 single-word components)
//!         /home/user/my-project/      (trailing sep — equivalent after canon)
//!         /home-user-my/project       (etc.)
//!
//! `decode_cc_slug(slug)` returns ALL plausible decodings as a `Vec<PathBuf>`
//! (sorted fewest-components-first by component count). The caller (`project::resolve`)
//! treats the candidates as ranked guesses, NOT as authoritative.
//!
//! For slugs with many internal hyphens, the candidate count is `2^n` where
//! `n` = number of internal hyphens. To prevent exponential blowup, slugs
//! with more than `MAX_HYPHEN_PERMUTATIONS` (currently 6) internal hyphens
//! return `Err(SlugError::TooManyHyphens)`. The caller falls back to the slug-
//! as-literal form (treat the whole slug as one long component).

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SlugError {
    #[error("slug too long to enumerate decodings: {hyphen_count} internal hyphens")]
    TooManyHyphens { hyphen_count: usize },
}

pub const MAX_HYPHEN_PERMUTATIONS: usize = 6;

/// Decode a CC cwd-slug into all plausible cwd `PathBuf`s.
///
/// # Errors
/// Returns `SlugError::TooManyHyphens` when the slug has more than
/// `MAX_HYPHEN_PERMUTATIONS` internal hyphens — `2^n` candidates would
/// exceed a sensible enumeration budget.
pub fn decode_cc_slug(slug: &str) -> Result<Vec<PathBuf>, SlugError> {
    // Strip leading `-` (corresponds to the leading `/` of the original path).
    let body = slug.strip_prefix('-').unwrap_or(slug);
    if body.is_empty() {
        return Ok(vec![PathBuf::from("/")]);
    }

    // Count internal hyphens. Each can be either a `/` (split here) or a literal
    // `-` (don't split). 2^n permutations.
    let hyphen_positions: Vec<usize> = body
        .char_indices()
        .filter_map(|(i, c)| if c == '-' { Some(i) } else { None })
        .collect();
    let n = hyphen_positions.len();
    if n > MAX_HYPHEN_PERMUTATIONS {
        return Err(SlugError::TooManyHyphens { hyphen_count: n });
    }

    let mut candidates: Vec<PathBuf> = Vec::with_capacity(1 << n);
    for mask in 0_u32..(1_u32 << n) {
        let mut path = String::with_capacity(body.len() + 1);
        path.push('/');
        let mut last = 0;
        for (idx, &pos) in hyphen_positions.iter().enumerate() {
            path.push_str(&body[last..pos]);
            if (mask >> idx) & 1 == 1 {
                path.push('/'); // split here
            } else {
                path.push('-'); // keep literal
            }
            last = pos + 1;
        }
        path.push_str(&body[last..]);
        candidates.push(PathBuf::from(path));
    }

    // Sort: prefer candidates with FEWER components (more literal hyphens).
    // Rationale: hyphens in directory names are common; long deeply-nested
    // paths from a slug full of hyphens are less likely. Adapter resolves
    // ambiguity later; this just orders the guesses.
    candidates.sort_by_key(|p| p.components().count());
    candidates.dedup();
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slug_after_leading_dash_returns_root() {
        assert_eq!(decode_cc_slug("-").unwrap(), vec![PathBuf::from("/")]);
    }

    #[test]
    fn slug_with_no_internal_hyphens_returns_single_candidate() {
        assert_eq!(
            decode_cc_slug("-projalpha").unwrap(),
            vec![PathBuf::from("/projalpha")]
        );
    }

    #[test]
    fn slug_with_one_internal_hyphen_returns_two_candidates() {
        // `-a-b` could be `/a-b` or `/a/b`. Returned in order of fewer-components-first.
        let got = decode_cc_slug("-a-b").unwrap();
        assert_eq!(got, vec![PathBuf::from("/a-b"), PathBuf::from("/a/b")]);
    }

    #[test]
    fn slug_with_two_internal_hyphens_returns_four_candidates() {
        // `-a-b-c` has 2^2 = 4 splits.
        let got = decode_cc_slug("-a-b-c").unwrap();
        assert_eq!(got.len(), 4);
        // The all-literal candidate is fewest-components (1 component).
        assert_eq!(got[0], PathBuf::from("/a-b-c"));
        // The all-split candidate is most-components (3 components).
        assert_eq!(got.last().unwrap(), &PathBuf::from("/a/b/c"));
    }

    #[test]
    fn realistic_slug_decodes_to_first_hint_of_real_path() {
        // -tmp-fixture-projalpha → primary candidate /tmp-fixture-projalpha
        // (the all-literal form), with /tmp/fixture/projalpha later in the list.
        let got = decode_cc_slug("-tmp-fixture-projalpha").unwrap();
        assert!(got.contains(&PathBuf::from("/tmp-fixture-projalpha")));
        assert!(got.contains(&PathBuf::from("/tmp/fixture/projalpha")));
    }

    #[test]
    fn too_many_hyphens_errors() {
        // 7 internal hyphens > MAX_HYPHEN_PERMUTATIONS (6).
        let err = decode_cc_slug("-a-b-c-d-e-f-g-h").unwrap_err();
        assert!(matches!(err, SlugError::TooManyHyphens { hyphen_count: 7 }));
    }

    #[test]
    fn ambiguous_hyphenated_app_slug_yields_multiple_candidates() {
        // -tmp-fixture-my-hyphenated-app — the fixture's edge case.
        // 4 internal hyphens → 16 candidates. Verify both the "intended"
        // and the "ambiguous-split" forms appear.
        let got = decode_cc_slug("-tmp-fixture-my-hyphenated-app").unwrap();
        assert!(got.contains(&PathBuf::from("/tmp/fixture/my-hyphenated-app")));
        assert!(got.contains(&PathBuf::from("/tmp/fixture/my/hyphenated/app")));
        assert!(got.contains(&PathBuf::from("/tmp-fixture-my-hyphenated-app")));
        assert_eq!(got.len(), 1 << 4);
    }

    #[test]
    fn missing_leading_dash_treated_as_body() {
        // Defensive: the spec says slugs always start with `-`, but if the caller
        // hands us a stripped form, decode it as the body.
        let got = decode_cc_slug("a-b").unwrap();
        assert_eq!(got, vec![PathBuf::from("/a-b"), PathBuf::from("/a/b")]);
    }
}
