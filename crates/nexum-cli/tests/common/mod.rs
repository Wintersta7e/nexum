//! Shared test utilities for nexum-cli integration tests.
//! Each integration-test binary may import only the subset it needs;
//! `#[allow(dead_code)]` is applied to silence per-binary "unused" warnings.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

pub fn nexum_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nexum"))
}

/// Self-contained nexum home for `--json` error-envelope tests. Owns the
/// backing temp dir; dropping the value cleans up. Tracks both `nexum_home`
/// (the value to set as `NEXUM_HOME`) and `ssh_home` (used as `HOME` so the
/// SSH-key probe and git config lookups land inside the temp dir).
pub struct TestHome {
    _root: TempDir,
    nexum_home: PathBuf,
    ssh_home: PathBuf,
}

/// Companion struct returned alongside `TestHome` from
/// `initialized_post_reanchor_case_a`. Carries the fingerprints and commit
/// SHA the test asserts on so callers do not have to re-derive them from
/// disk after the fixture finishes setup.
pub struct PostReanchorFixture {
    pub k1_fp: String,
    pub k2_fp: String,
    pub reanchor_commit: String,
}

impl TestHome {
    /// Allocate a temp dir but skip `nexum init`. Useful for asserting
    /// `NOT_INITIALIZED` errors.
    pub fn uninitialized() -> Self {
        let root = TempDir::new().expect("tempdir for TestHome");
        let nexum_home = root.path().join(".nexum");
        let ssh_home = root.path().join("ssh-home");
        Self {
            _root: root,
            nexum_home,
            ssh_home,
        }
    }

    /// Initialize a nexum home (notebook.git + config.toml + signed
    /// bootstrap) but do NOT run `nexum index`. Useful for asserting
    /// `NOT_INDEXED` errors with a fully-realized home directory.
    pub fn initialized_no_index() -> Self {
        let root = TempDir::new().expect("tempdir for TestHome");
        let nexum_home = root.path().join(".nexum");
        let ssh_home = root.path().join("ssh-home");
        std::fs::create_dir_all(ssh_home.join(".ssh")).expect("mkdir ssh-home/.ssh");
        let key_path = write_ephemeral_keypair(&ssh_home.join(".ssh"));
        let out = run_nexum(
            &nexum_home,
            &ssh_home,
            &["init", "--yes", "--ssh-key", key_path.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "TestHome init failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Self {
            _root: root,
            nexum_home,
            ssh_home,
        }
    }

    /// Initialize a nexum home, seed at least one local YAML record, and
    /// run `nexum index` so the index database exists. Useful for asserting
    /// per-record verb errors that require a populated index (e.g. `NOT_FOUND`).
    pub fn initialized_with_seeded_index() -> Self {
        let home = Self::initialized_no_index();
        write_local_yaml(home.path(), "decisions", "seed", "seed body");
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome seed-index failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        home
    }

    /// Initialize a nexum home (signed bootstrap commit) and run `nexum
    /// index` once so the index database and trust-events view both exist.
    /// Used by tests that exercise the post-index tampering check on a
    /// known-clean chain.
    pub fn initialized_clean() -> Self {
        let home = Self::initialized_no_index();
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome initialized_clean index failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        home
    }

    /// Initialize a nexum home (signed bootstrap commit), then append a
    /// second signed revision of `.trust/events.yml` that mutates the
    /// bootstrap event's `fingerprint` payload while keeping the same
    /// `event_id`. The materializer classifies that diff as `MutatedPayload`
    /// and writes a row to `trust_chain_tampering`. Used for asserting the
    /// `TAMPERING_DETECTED` envelope shape.
    ///
    /// Re-uses the SSH key planted by `initialized_no_index` and the git
    /// signing config that `nexum init` already wrote to the notebook repo.
    pub fn initialized_with_tampered_events_yml() -> Self {
        Self::initialized_with_mutated_events_yml(|events_path| {
            let original = std::fs::read_to_string(events_path).expect("read events.yml");
            // Mutate the fingerprint line to a synthetic value while leaving
            // the event_id intact. Same event_id + different payload trips
            // the `MutatedPayload` classifier.
            let mutated = mutate_first_fingerprint(&original);
            assert_ne!(mutated, original, "fingerprint mutation must change file");
            std::fs::write(events_path, mutated).expect("write tampered events.yml");
        })
    }

    /// Initialize a nexum home (signed bootstrap commit), then append a
    /// second signed revision of `.trust/events.yml` whose contents are
    /// invalid YAML. The materializer's `serde_yaml::from_str` call against
    /// that revision raises `TrustError::Parse`, which routes through
    /// `From<&ApiError> for ErrorEnvelope` to a `STORE_INTEGRITY` envelope
    /// with `context.kind = "trust"` and `context.path` populated.
    ///
    /// Used to exercise the underlying-error arm of `trust validate-events`,
    /// distinct from `initialized_with_tampered_events_yml` which produces a
    /// well-formed-but-mutated payload that yields a tampering row instead.
    pub fn initialized_with_corrupt_events_yml() -> Self {
        Self::initialized_with_mutated_events_yml(|events_path| {
            // Write garbage that serde_yaml cannot parse as the EventLog
            // struct. A bare unbalanced flow-mapping opener is rejected at
            // the lexer level, so this is robust against future field
            // additions.
            std::fs::write(events_path, b"{ this is : not [ valid yaml\n")
                .expect("write corrupt events.yml");
        })
    }

    /// Init a fresh home, hand the `events.yml` path to `mutate`, then
    /// signed-commit the resulting tree. Shared scaffold for the tampered
    /// and corrupt-YAML fixtures; future fixtures (e.g. tampered signature,
    /// tampered `topo_pos`) fold in as one-line wrappers.
    fn initialized_with_mutated_events_yml(mutate: impl FnOnce(&Path)) -> Self {
        let home = Self::initialized_no_index();
        let notebook_git = home.path().join("notebook.git");
        let events_path = notebook_git.join(".trust").join("events.yml");
        mutate(&events_path);
        commit_tamper(&notebook_git, &home.ssh_home);
        home
    }

    pub fn initialized_with_future_trust_schema() -> Self {
        // Read verbs short-circuit to `NOT_INDEXED` if `index.db` is
        // absent; build it first so the next read traverses past the
        // existence check into `ensure_current`, which is where the
        // schema-version mismatch surfaces.
        let home = Self::initialized_no_index();
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome future-trust-schema seed-index failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let notebook_git = home.path().join("notebook.git");
        let events_path = notebook_git.join(".trust").join("events.yml");
        let original = std::fs::read_to_string(&events_path).expect("read events.yml");
        let mutated = mutate_schema_version(&original, 99);
        assert_ne!(
            mutated, original,
            "schema_version mutation must change file"
        );
        std::fs::write(&events_path, mutated).expect("write future-schema events.yml");
        commit_tamper(&notebook_git, &home.ssh_home);
        home
    }

    /// Initialize a nexum home and run `nexum index` so `index.db` exists
    /// and is fully populated, then overwrite it with a few non-magic
    /// bytes so the `SQLite` header is no longer recognizable. The next
    /// read verb opens the path (existence check passes), then the
    /// `PRAGMA user_version` read in `open_existing_with_flags` fails with
    /// "file is not a database". That `rusqlite::Error` routes through
    /// `query_envelope` to a `STORE_INTEGRITY` envelope with
    /// `context.kind = "rusqlite"`. Used by the corrupt-index e2e test.
    pub fn initialized_with_corrupt_index_db() -> Self {
        let home = Self::initialized_no_index();
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome corrupt-index seed failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let db_path = home.path().join("index.db");
        // Replace the contents with a few bytes that don't match the
        // `SQLite` header magic ("SQLite format 3\0"). The file still
        // exists, so the CLI's `path.exists()` precheck passes; the
        // first SQL on the connection then fails with "file is not a
        // database".
        std::fs::write(&db_path, b"not-a-db").expect("truncate index.db to garbage");
        home
    }

    /// Initialize a nexum home, seed one local YAML record, run
    /// `nexum index`, then insert a sibling row directly into `index.db`
    /// that shares the bare `id` but pins a different `project_id`. A
    /// bare-id lookup against this home returns `AMBIGUOUS_KEY` with two
    /// candidate matches.
    ///
    /// The direct-SQL insertion is necessary because the local adapter
    /// (and the indexer's per-pass candidate map) keys by bare `id` — two
    /// YAML files with the same stem on disk silently dedupe down to one
    /// row at index time. Bypassing the indexer is the smallest path to
    /// the multi-row state the AMBIGUOUS error path requires.
    pub fn initialized_with_two_records_sharing_id(id: &str) -> Self {
        let home = Self::initialized_no_index();
        write_local_yaml_with_project(home.path(), "decisions", id, "alpha-project", "first");
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome ambiguous-index failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        insert_sibling_local_row(home.path(), id, "beta-project");
        home
    }

    /// Initialize a nexum home and plant a non-empty `.reanchor_pending`
    /// sentinel under the home directory. Any verb that runs through
    /// `resolve_runtime` will trip `session::startup::pre_check` and surface
    /// `StartupError::Trust(ReanchorPending)`. Used to assert that the
    /// `--json` path routes that variant through the `REANCHOR_PENDING`
    /// envelope on stdout.
    pub fn initialized_with_reanchor_pending_sentinel() -> Self {
        let home = Self::initialized_no_index();
        std::fs::write(
            home.path().join(".reanchor_pending"),
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "init"
            }"#,
        )
        .expect("write .reanchor_pending sentinel");
        home
    }

    /// Initialize a nexum home, seed a single unsigned local YAML record,
    /// flip `[trust] unsigned_default = "hide"` in `config.toml`, then run
    /// `nexum index`. A bare-id lookup for `id` against this home returns
    /// `HIDDEN_BY_POLICY` because the seed record is unsigned and the
    /// trust policy now suppresses unsigned reads.
    pub fn initialized_with_unsigned_record_under_hide(id: &str) -> Self {
        let home = Self::initialized_no_index();
        write_local_yaml(home.path(), "decisions", id, "hidden body");
        set_unsigned_policy_hide(home.path());
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "TestHome hide-policy-index failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        home
    }

    pub fn path(&self) -> &Path {
        &self.nexum_home
    }

    /// The `NEXUM_HOME` value (alias for [`path`]). Spelled out for tests
    /// that pass the env var into `Command::env` directly rather than
    /// going through [`run`].
    ///
    /// [`path`]: Self::path
    /// [`run`]: Self::run
    pub fn nexum_home(&self) -> &Path {
        &self.nexum_home
    }

    /// The `HOME` value for the per-test ssh-key probe and git config
    /// lookup. Tests that spawn `nexum` directly (rather than via
    /// [`Self::run`]) need this to keep the developer's real `~/.gitconfig`
    /// out of the test.
    pub fn ssh_home(&self) -> &Path {
        &self.ssh_home
    }

    /// Initialize a nexum home and immediately synthesize a Case A
    /// post-reanchor state (pin preserved across recovery). Uses the
    /// production two-event pattern: appends a `KeyAdded(K2)` event then
    /// a `BootstrapReanchor(K1 -> K2)` event, batched into one signed
    /// commit. `regenerate_files` is called via the production code path
    /// so the resulting signer-file shape matches byte-for-byte what the
    /// eventual recovery verb will produce.
    ///
    /// If `stale_signingkey == true`, `user.signingkey` is reset to K1
    /// AFTER the reanchor commit lands — the commit itself is always
    /// signed by K2 (valid). This exercises the "operator completed the
    /// reanchor but forgot to update git signingkey" failure mode tested
    /// by the keys revoke preflights.
    // Straight-line setup of the Case A post-reanchor fixture: K2 keypair,
    // two split commits (KeyAdded then BootstrapReanchor), pin update, and
    // optional stale-signingkey reset. Splitting it would scatter the ordered
    // setup across helpers without making the sequence easier to follow.
    #[allow(clippy::too_many_lines)]
    pub fn initialized_post_reanchor_case_a(stale_signingkey: bool) -> (Self, PostReanchorFixture) {
        let home = Self::initialized_no_index();

        // Step 1: capture K1 path BEFORE any signingkey change.
        let nb_git = home.nexum_home.join("notebook.git");
        let out = Command::new("git")
            .arg("-C")
            .arg(&nb_git)
            .args(["config", "--local", "--get", "user.signingkey"])
            .output()
            .expect("git config user.signingkey");
        assert!(out.status.success(), "user.signingkey unset after init");
        let k1_path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        assert!(
            k1_path.exists(),
            "K1 path '{}' does not exist",
            k1_path.display()
        );

        // K1 fingerprint from the bootstrap pin.
        let cfg_path = home.nexum_home.join("config.toml");
        let cfg: nexum_core::config::types::Config =
            nexum_core::config::io::load(&cfg_path).expect("load config");
        let k1_fp = cfg.trust.bootstrap.fingerprint.clone();

        // Step 2: generate K2 keypair via the ssh_key crate (no ssh-keygen
        // subprocess — same convention as `write_ephemeral_keypair`). Pick
        // a non-default filename so the K1 keypair stays in place.
        let ssh_dir = home.ssh_home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("mkdir ssh-home/.ssh");
        let k2_path = ssh_dir.join("k2-fixture");
        let k2_private = {
            use ssh_key::rand_core::OsRng;
            ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
                .expect("generate ed25519 K2")
        };
        let priv_pem = k2_private
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("to_openssh");
        let pub_line = k2_private
            .public_key()
            .to_openssh()
            .expect("pub to_openssh");
        std::fs::write(&k2_path, priv_pem.as_bytes()).expect("write K2 priv");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k2_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod K2 priv");
        }
        let k2_pub_path = nexum_core::ssh_key::pub_path_for(&k2_path);
        std::fs::write(&k2_pub_path, pub_line.as_bytes()).expect("write K2 pub");
        let k2_pubkey = pub_line;
        let k2_fp =
            nexum_core::ssh_key::compute_fingerprint(&k2_pubkey).expect("compute K2 fingerprint");

        // Step 3: pin a local git identity inside the notebook repo so the
        // signed commits below succeed even on hosts (and CI runners) that
        // ship without a global gitconfig. `git_commit_signed` shells out to
        // git without the GIT_AUTHOR_* env scaffolding that `run_nexum` sets,
        // so the identity has to live in `.git/config`.
        for kv in [
            ("user.name", "nexum-test"),
            ("user.email", "nexum-test@example.invalid"),
        ] {
            let status = Command::new("git")
                .arg("-C")
                .arg(&nb_git)
                .args(["config", "--local", kv.0, kv.1])
                .status()
                .expect("git config local identity");
            assert!(status.success());
        }

        // Step 4: append KeyAdded(K2) via the production load/serialize
        // round-trip and regenerate signer files. The materializer enforces
        // one new event per commit (multi-event appends classify as
        // `Diff::Forbidden{ReorderedDeleted}` and freeze the chain), so the
        // reanchor lands in a separate commit further down.
        let events_path = nb_git.join(".trust/events.yml");
        let trust_dir = nb_git.join(".trust");
        {
            let mut log =
                nexum_core::trust::events::load_events_yml(&events_path).expect("load events.yml");
            log.events.push(nexum_core::trust::events::Event {
                event_id: uuid::Uuid::now_v7(),
                payload: nexum_core::trust::events::EventKind::KeyAdded {
                    fingerprint: k2_fp.clone(),
                    public_key: k2_pubkey.clone(),
                    reason: "reanchor predecessor (test fixture)".to_owned(),
                },
            });
            let yaml = serde_yaml::to_string(&log).expect("serialize events.yml");
            std::fs::write(&events_path, yaml).expect("write events.yml (KeyAdded)");
            nexum_core::trust::regenerate::regenerate_files(&events_path, &trust_dir)
                .expect("regenerate_files (KeyAdded)");
        }

        // Step 5: commit KeyAdded signed by K1 (user.signingkey still points
        // at K1 from init). Stage all four trust files.
        nexum_core::init::git_ops::git_commit_signed(
            &nb_git,
            &[
                Path::new(".trust/events.yml"),
                Path::new(".trust/historical_signers"),
                Path::new(".trust/allowed_signers"),
                Path::new(".trust/revoked_signers"),
            ],
            "trust: add signing key (test fixture KeyAdded)",
        )
        .expect("git_commit_signed (KeyAdded)");

        // Step 6: append BootstrapReanchor(K1 -> K2) and regenerate again.
        {
            let mut log =
                nexum_core::trust::events::load_events_yml(&events_path).expect("load events.yml");
            log.events.push(nexum_core::trust::events::Event {
                event_id: uuid::Uuid::now_v7(),
                payload: nexum_core::trust::events::EventKind::BootstrapReanchor {
                    old_fingerprint: k1_fp.clone(),
                    new_fingerprint: k2_fp.clone(),
                    reason: "test fixture chain-break".to_owned(),
                    acknowledge_chain_anchor_lost: false,
                },
            });
            let yaml = serde_yaml::to_string(&log).expect("serialize events.yml");
            std::fs::write(&events_path, yaml).expect("write events.yml (Reanchor)");
            nexum_core::trust::regenerate::regenerate_files(&events_path, &trust_dir)
                .expect("regenerate_files (Reanchor)");
        }

        // Step 7: switch user.signingkey to K2 for the reanchor commit.
        let status = Command::new("git")
            .arg("-C")
            .arg(&nb_git)
            .args(["config", "--local", "user.signingkey"])
            .arg(&k2_path)
            .status()
            .expect("git config user.signingkey K2");
        assert!(status.success());

        // Step 7b: commit BootstrapReanchor signed by K2. The reanchor
        // authorization rule (Case A: new key already in chain via the
        // prior KeyAdded + bootstrap pin preserved) accepts this signer.
        let reanchor_commit = nexum_core::init::git_ops::git_commit_signed(
            &nb_git,
            &[
                Path::new(".trust/events.yml"),
                Path::new(".trust/historical_signers"),
                Path::new(".trust/allowed_signers"),
                Path::new(".trust/revoked_signers"),
            ],
            "trust: reanchor (test fixture)",
        )
        .expect("git_commit_signed (Reanchor)");

        // Step 7c: verify the reanchor commit (K2 is in historical_signers).
        nexum_core::init::git_ops::git_verify_commit_with_signers(
            &nb_git,
            "HEAD",
            &trust_dir.join("historical_signers"),
        )
        .expect("verify reanchor commit");

        // Step 8: update config.toml [trust.bootstrap] to K2 via production I/O
        // AND rewrite the `.bootstrap-fingerprint` cache so it agrees. The
        // reanchor authorization (in the materializer's `verify_reanchor_*`
        // path) refuses when the cache disagrees with config.toml, so both
        // pinned files must move together.
        let mut cfg = cfg;
        cfg.trust.bootstrap.fingerprint.clone_from(&k2_fp);
        cfg.trust.bootstrap.public_key.clone_from(&k2_pubkey);
        "ssh-ed25519".clone_into(&mut cfg.trust.bootstrap.key_type);
        nexum_core::config::io::save(&cfg_path, &cfg).expect("save config");
        std::fs::write(home.nexum_home.join(".bootstrap-fingerprint"), &k2_fp)
            .expect("write .bootstrap-fingerprint cache");

        // Step 9: if stale, reset user.signingkey back to K1 to simulate the
        // operator who completed the reanchor but forgot to update git's
        // signingkey config.
        if stale_signingkey {
            let status = Command::new("git")
                .arg("-C")
                .arg(&nb_git)
                .args(["config", "--local", "user.signingkey"])
                .arg(&k1_path)
                .status()
                .expect("git config user.signingkey K1 (stale)");
            assert!(status.success());
        }

        // Step 10: index + rebuild the trust_events view.
        let out = home.run(&["index"]);
        assert!(
            out.status.success(),
            "post-reanchor index failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        (
            home,
            PostReanchorFixture {
                k1_fp,
                k2_fp,
                reanchor_commit,
            },
        )
    }

    /// Read the bootstrap-pin fingerprint from `config.toml`. Surfaces the
    /// K1 fingerprint planted by `nexum init` so tests can target it
    /// without re-deriving from the SSH keypair on disk.
    pub fn bootstrap_pin_fingerprint(&self) -> String {
        let cfg: nexum_core::config::types::Config =
            nexum_core::config::io::load(&self.nexum_home.join("config.toml"))
                .expect("load config.toml");
        cfg.trust.bootstrap.fingerprint
    }

    /// Pre-seed `state/extract_acked.json` so the consent gate accepts
    /// `(provider, model_family)` without an interactive prompt. Mirrors
    /// what `nexum extract` would write after a first-run `[y/N]` answer.
    pub fn write_extract_ack(&self, provider: &str, model_family: &str) -> std::io::Result<()> {
        let path = self.nexum_home.join("state").join("extract_acked.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::json!({
            "acked_at": "2026-05-17T00:00:00Z",
            "acked_provider": provider,
            "acked_model_family": model_family,
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&body)?)
    }

    /// Spawn `nexum` with the per-test `NEXUM_HOME` / `HOME` / git-identity
    /// env vars wired from this home. Routes through the canonical
    /// `run_nexum` so every spawn picks up the CI-portable git identity
    /// (see `feedback_ci_runners_need_git_identity`). Use this rather than
    /// open-coding `Command::new(...).env("NEXUM_HOME", ...)`.
    pub fn run(&self, args: &[&str]) -> Output {
        run_nexum(&self.nexum_home, &self.ssh_home, args)
    }
}

/// Run a `--json`-bearing `nexum` invocation against `home` and parse its
/// stdout as an `ErrorEnvelope`. Returns the parsed envelope plus the
/// process exit code.
pub fn run_json(home: &TestHome, args: &[&str]) -> (serde_json::Value, i32) {
    let out = home.run(args);
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout should parse as JSON envelope");
    (parsed, out.status.code().unwrap_or(-1))
}

/// Generate a fresh ed25519 keypair into `dir/id_ed25519{,.pub}`. Returns
/// the private key path. Mirrors the `nexum-core::tests::common` helper —
/// duplicated here because `tests/common/` cannot cross crate boundaries.
pub fn write_ephemeral_keypair(dir: &Path) -> PathBuf {
    use ssh_key::rand_core::OsRng;
    let private = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let priv_pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let pub_line = private.public_key().to_openssh().unwrap();
    let priv_path = dir.join("id_ed25519");
    std::fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(dir.join("id_ed25519.pub"), pub_line).unwrap();
    priv_path
}

/// Spawn the `nexum` binary with `NEXUM_HOME` and `HOME` redirected to
/// per-test temp dirs. The four `GIT_*` env vars override git's normal
/// `user.name`/`user.email` config lookup, which would otherwise return
/// empty strings under a fresh `HOME` and break any subcommand that
/// commits (e.g. `init`'s bootstrap commit). The existing `init_cli.rs`
/// test predates this hardening and relies on the developer's real
/// `~/.gitconfig`; this helper makes the binary CI-portable.
pub fn run_nexum(home: &Path, ssh_home: &Path, args: &[&str]) -> Output {
    Command::new(nexum_bin())
        .args(args)
        .env("NEXUM_HOME", home)
        .env("HOME", ssh_home)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("nexum binary exec failed")
}

/// Write a local-adapter-format YAML record at `home/notebook.git/<sub>/<id>.yml`.
/// Mirrors the equivalent helper in `nexum-core::tests::common`.
pub fn write_local_yaml(home: &Path, sub: &str, id: &str, body: &str) -> PathBuf {
    write_local_yaml_with_project(home, sub, id, "example", body)
}

/// Variant of `write_local_yaml` that lets the caller pin a specific
/// `project_id` in the YAML body. The on-disk layout stays
/// `home/notebook.git/<sub>/<id>.yml` because the local adapter's
/// `discover()` only walks the top-level type directories — nesting under
/// a per-project subdir would silently hide the record.
pub fn write_local_yaml_with_project(
    home: &Path,
    sub: &str,
    id: &str,
    project_id: &str,
    body: &str,
) -> PathBuf {
    let notebook_git = home.join("notebook.git");
    let p = notebook_git.join(sub).join(format!("{id}.yml"));
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all for local yaml");
    }
    let kind = match sub {
        "decisions" => "decision",
        "recommendations" => "recommendation",
        "failures" => "failure",
        _ => "untyped",
    };
    std::fs::write(
        &p,
        format!(
            "schema_version: 1\nid: {id}\nrecord_type: {kind}\ntitle: {id}\nbody: |\n  {body}\nproject_id: {project_id}\ntags: []\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\nconfidence: high\noutcome: working\n"
        ),
    )
    .expect("write local yaml");
    p
}

/// Flip `[trust] unsigned_default` to `"hide"` in an already-initialized
/// home's `config.toml`. Used to set up `HIDDEN_BY_POLICY` test fixtures.
///
/// Uses a structural toml parse + serialize so the edit survives any
/// future change in the seed config's whitespace, quoting, or key order
/// without falling through a brittle string-replace.
pub fn set_unsigned_policy_hide(home: &Path) {
    let cfg_path = home.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).expect("read config.toml");
    let mut doc: toml::Value = toml::from_str(&raw).expect("parse config.toml");
    let trust = doc
        .as_table_mut()
        .and_then(|t| t.get_mut("trust"))
        .and_then(|v| v.as_table_mut())
        .expect("config.toml missing [trust] table");
    trust.insert(
        "unsigned_default".into(),
        toml::Value::String("hide".into()),
    );
    let serialized = toml::to_string(&doc).expect("serialize config.toml");
    std::fs::write(&cfg_path, serialized).expect("write config.toml");
}

/// Replace the first `fingerprint:` line in an `events.yml` payload with a
/// synthetic value. Operates on the raw text to keep the rest of the YAML
/// formatting (`event_id`, `public_key`, `reason`) byte-for-byte identical,
/// so the diff classifier sees only the payload mutation.
fn mutate_first_fingerprint(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut replaced = false;
    for line in raw.lines() {
        if !replaced && line.trim_start().starts_with("fingerprint:") {
            let leading: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out.push_str(&leading);
            out.push_str("fingerprint: \"SHA256:tampered\"");
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(replaced, "events.yml had no fingerprint: line to mutate");
    out
}

fn mutate_schema_version(raw: &str, new_version: u32) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(raw.len());
    let mut replaced = false;
    for line in raw.lines() {
        if !replaced && line.trim_start().starts_with("schema_version:") {
            let leading: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out.push_str(&leading);
            // `write!` into a String is infallible; the unit return is
            // discarded explicitly to satisfy `clippy::format_push_string`.
            let _ = write!(out, "schema_version: {new_version}");
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(replaced, "events.yml had no schema_version: line to mutate");
    out
}

/// Stage `.trust/events.yml` and create a second signed commit on top of
/// the bootstrap. Runs git via subprocess so the SSH signing pipeline (set
/// up by `nexum init` in the same repo) drives the commit. Inherits
/// `HOME` / `XDG_CONFIG_HOME` from `ssh_home` so git's config lookups stay
/// inside the test's tempdir tree.
fn commit_tamper(notebook_git: &Path, ssh_home: &Path) {
    let xdg = ssh_home.join(".config");
    run_git_in(notebook_git, ssh_home, &xdg, &["add", ".trust/events.yml"]);
    run_git_in(
        notebook_git,
        ssh_home,
        &xdg,
        &["commit", "-S", "-m", "trust: tamper test fixture"],
    );
}

/// Run a git subprocess inside `notebook_git` with `HOME` and
/// `XDG_CONFIG_HOME` redirected so the developer's real `~/.gitconfig` does
/// not bleed into the test. The four `GIT_*` env vars override identity for
/// CI runners that ship without a global gitconfig (see
/// `feedback_ci_runners_need_git_identity`).
fn run_git_in(notebook_git: &Path, home: &Path, xdg_config_home: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(notebook_git)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg_config_home)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Insert a `local`-source record straight into `<home>/index.db` that
/// shares `id` with an already-indexed row but pins a different
/// `project_id`. The columns mirror what the indexer would write for a
/// minimal unsigned local record. Used by
/// `initialized_with_two_records_sharing_id` because the adapter pipeline
/// dedupes by bare `id` before reaching the upsert (the dedup happens in
/// `crates/nexum-core/src/indexer/run.rs`'s per-pass candidate map; the
/// long-form discussion lives in the TODO at the top of that file).
///
/// Schema-drift guard: if a future migration adds a NOT-NULL column
/// without a default, this insert will fail with an opaque rusqlite error
/// — that's the signal to extend the column list below to match
/// `crates/nexum-core/src/index/schema.sql`.
pub fn insert_sibling_local_row(home: &Path, id: &str, project_id: &str) {
    let db_path = home.join("index.db");
    let conn = rusqlite::Connection::open(&db_path).expect("open index.db");
    conn.execute(
        "INSERT INTO records (id, source, project_id, record_type, title, body, \
         tags, tags_fts, confidence, outcome, agent, session_refs, files, commits, \
         created, updated, content_hash, index_hash, crypto_result, indexed_at) \
         VALUES (?1, 'local', ?2, 'decision', ?1, '', '[]', '', 'high', 'working', \
         'manual', '[]', '[]', '[]', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', \
         'sibling-content-hash', 'sibling-index-hash', 'no-signature', \
         '2026-04-29T00:00:01Z')",
        rusqlite::params![id, project_id],
    )
    .expect("insert sibling local row");
}
