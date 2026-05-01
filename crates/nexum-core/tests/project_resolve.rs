//! Integration tests for `project::resolve` using `NexumTestHome`.

mod common;

use common::NexumTestHome;
use nexum_core::project::{ProjectInput, ProjectResolution, ResolutionReason, resolve::resolve};

fn empty_input() -> ProjectInput {
    ProjectInput {
        cc_slug: None,
        codex_cwd: None,
        git_origin_url: None,
        registered_name: None,
    }
}

#[test]
fn codex_cwd_path_resolves_via_path_hint_against_test_home() {
    let home = NexumTestHome::new().expect("create test home");
    let mut input = empty_input();
    input.codex_cwd = Some(home.path().to_owned());
    match resolve(&input) {
        ProjectResolution::Resolved { project_id, reason } => {
            // `path_hint` is 16 hex chars (no `git:` prefix).
            assert_eq!(project_id.len(), 16);
            assert!(project_id.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(matches!(reason, ResolutionReason::Path(_)));
        }
        other => panic!("expected Resolved(Path), got {other:?}"),
    }
}

#[test]
fn cc_slug_with_no_existing_paths_is_unresolved() {
    // Slug points at paths that don't exist in the test environment.
    let mut input = empty_input();
    input.cc_slug = Some("-tmp-fixture-projalpha".to_owned());
    // `/tmp/fixture/projalpha` doesn't exist in this test environment;
    // `/tmp-fixture-projalpha` doesn't either. Resolution falls through.
    let r = resolve(&input);
    assert!(
        matches!(
            r,
            ProjectResolution::Unresolved | ProjectResolution::Ambiguous { .. }
        ),
        "got {r:?} (Unresolved acceptable; Ambiguous acceptable if some candidate happens to exist)"
    );
}
