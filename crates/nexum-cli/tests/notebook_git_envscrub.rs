//! Regression guard for the notebook trust-store env-scrub policy.
//!
//! Every git invocation against the notebook routes through the env-scrubbed
//! builder (`GIT_CONFIG_GLOBAL=/dev/null`), so a user's global gitconfig can't
//! run a `core.hooksPath` hook or redirect the signer during a trust operation.
//!
//! This plants a hostile global gitconfig whose `core.hooksPath` points at a
//! `pre-commit` hook that writes a sentinel and fails. `nexum init` makes a
//! signed seed commit; if any notebook git op leaked the global config, the
//! hook would fire — the sentinel would appear and the commit (hence init)
//! would abort. With the scrub in place the hook is never seen. If a future
//! change reintroduced a raw, unscrubbed notebook commit, this test fails.

mod common;

#[cfg(unix)]
#[test]
fn hostile_global_hookspath_is_ignored_during_init() {
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    let root = TempDir::new().expect("tempdir");
    let nexum_home = root.path().join(".nexum");
    let ssh_home = root.path().join("home");
    std::fs::create_dir_all(ssh_home.join(".ssh")).expect("mkdir .ssh");
    let key_path = common::write_ephemeral_keypair(&ssh_home.join(".ssh"));

    // A hostile hooks dir: pre-commit writes a sentinel, then fails. If git
    // ever honors the global config below, this runs on init's signed commit —
    // the sentinel appears and the commit aborts.
    let hooks_dir = root.path().join("evil-hooks");
    std::fs::create_dir_all(&hooks_dir).expect("mkdir hooks");
    let sentinel = root.path().join("HOOK_RAN");
    let pre_commit = hooks_dir.join("pre-commit");
    std::fs::write(
        &pre_commit,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", sentinel.display()),
    )
    .expect("write hook");
    std::fs::set_permissions(&pre_commit, std::fs::Permissions::from_mode(0o755))
        .expect("chmod hook");

    // Plant it as the user's GLOBAL git config — run_nexum sets HOME=ssh_home,
    // so `$HOME/.gitconfig` is git's global config for the child process.
    std::fs::write(
        ssh_home.join(".gitconfig"),
        format!("[core]\n\thooksPath = {}\n", hooks_dir.display()),
    )
    .expect("write .gitconfig");

    let out = common::run_nexum(
        &nexum_home,
        &ssh_home,
        &[
            "init",
            "--yes",
            "--ssh-key",
            key_path.to_str().expect("ssh key path utf-8"),
        ],
    );

    assert!(
        out.status.success(),
        "init failed — a hostile global `core.hooksPath` was honored during the \
         signed notebook commit.\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !sentinel.exists(),
        "the global gitconfig's pre-commit hook ran during init — notebook git \
         ops are not env-scrubbed",
    );
}
