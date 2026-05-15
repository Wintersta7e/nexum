//! Shared test harness for the `nexum-mcp` integration tests.
//!
//! Two pieces:
//!
//! 1. [`connect`] — wires a real `rmcp` client and a [`NexumServer`] over a
//!    `tokio::io::duplex()` byte-pipe. Tests drive the server through genuine
//!    MCP `initialize` + JSON-RPC framing + `CallToolResult` decoding, without
//!    spawning a subprocess. (The one child-process smoke test lives in its
//!    own file, added later.)
//! 2. [`McpTestHome`] — a self-contained nexum home for fixture-backed tests,
//!    with three constructors covering the startup states the suite needs:
//!    [`McpTestHome::ready`] (initialized + indexed + one seeded record),
//!    [`McpTestHome::unavailable`] (no nexum home — runtime resolution fails),
//!    and [`McpTestHome::indexed_empty`] (initialized + indexed, zero records).
//!
//! Mechanism note: unlike the CLI's `tests/common` `TestHome`, which spawns
//! the `nexum` binary, this harness builds the home **in-process** via
//! `nexum_core::init::run` + `nexum_core::api::index_run` — the same approach
//! `nexum-core`'s own `tests/common` uses. It is the in-process equivalent of
//! the CLI `TestHome` pattern, not a subprocess wrapper.
//!
//! Each integration-test binary imports only the subset it needs;
//! `#![allow(dead_code)]` silences per-binary "unused" warnings.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use nexum_core::config::types::Config;
use nexum_core::init::{InitOpts, run as init_run};
use nexum_core::paths::Paths;
use nexum_mcp::{NexumServer, RuntimeState};
use rmcp::service::{RoleClient, RoleServer, RunningService};
use rmcp::{ServiceExt, model::CallToolResult};
use tempfile::TempDir;

/// A connected in-process MCP client + server pair.
///
/// `client` is the live `rmcp` client handle — `RunningService` derefs to
/// `Peer<RoleClient>`, so call `client.list_tools(..)`, `client.call_tool(..)`,
/// etc. directly on it. `server` is the server's running service; the harness
/// keeps it alive so the server task is not dropped mid-test. Dropping
/// `Connected` (or calling [`Connected::shutdown`]) tears both ends down.
pub struct Connected {
    pub client: RunningService<RoleClient, ()>,
    server: RunningService<RoleServer, NexumServer>,
    // `_home` keeps the fixture's temp dir alive for the duration of the
    // connection — dropping it would delete `index.db` out from under the
    // server. `None` for the `unavailable` fixture, which owns no home.
    _home: Option<TempDir>,
}

impl Connected {
    /// Cleanly cancel both ends. Equivalent to dropping the value, but
    /// explicit at a test's end-point reads clearer.
    pub async fn shutdown(self) {
        let _ = self.client.cancel().await;
        let _ = self.server.cancel().await;
    }
}

/// Wire a fresh `rmcp` client and `server` over an in-memory duplex pipe and
/// run the MCP `initialize` handshake. Returns the connected pair.
///
/// `state` is the server's [`RuntimeState`]; `home` is the fixture's temp dir
/// to keep alive (or `None` for the homeless `unavailable` fixture).
pub async fn connect(state: RuntimeState, home: Option<TempDir>) -> Connected {
    // 64 KiB each way — comfortably larger than any single JSON-RPC frame
    // the read tools produce in tests.
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);

    // MCP `initialize` is a client→server exchange; both ends must be running
    // concurrently or the handshake deadlocks. Spawn the server side as a
    // task so the client `.serve()` below can drive `initialize` against it.
    let server_handle = tokio::spawn(async move { NexumServer::new(state).serve(server_io).await });

    // The unit type `()` is rmcp's no-op client handler — these tests only
    // *drive* the server, they never answer server-initiated requests.
    let client = ().serve(client_io).await.expect("client-side MCP initialize must succeed");

    let server = server_handle
        .await
        .expect("server task panicked")
        .expect("server-side MCP initialize must succeed");

    Connected {
        client,
        server,
        _home: home,
    }
}

/// A self-contained nexum home for fixture-backed MCP tests. Owns the backing
/// temp dir; dropping the value cleans up. Build a [`RuntimeState`] from it
/// with [`McpTestHome::runtime_state`], then hand that to [`connect`].
pub struct McpTestHome {
    root: TempDir,
    /// `None` for [`McpTestHome::unavailable`], which deliberately has no
    /// initialized home.
    paths: Option<Paths>,
    cfg: Option<Config>,
}

impl McpTestHome {
    /// Initialized + indexed, with one seeded local record. The everyday
    /// fixture for "the server can answer a real query" tests.
    pub fn ready() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        write_local_yaml(&paths.notebook_git, "decisions", "seed", "seed record body");
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed but with **zero** records. Exercises the
    /// empty-result-set path (`total_matched = 0`, empty `results`) — distinct
    /// from `unavailable` (no home) and from `NOT_INDEXED` (no `index.db`).
    pub fn indexed_empty() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        // No `write_local_yaml` call — index an empty notebook.
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized but **not** indexed: `init::run` ran cleanly, so
    /// `Paths` + `Config` resolve and the server starts `Ready`, but
    /// `index.db` does not exist yet. Every record verb returns the
    /// `NOT_INDEXED` envelope from the api layer.
    pub fn ready_without_index() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        // Intentionally no `index(&paths, &cfg)` — the index DB stays absent.
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed with two records sharing the bare `id`
    /// but living under different `(source, project_id)` keys. A bare
    /// `get` cannot disambiguate, so the verb returns `AMBIGUOUS_KEY`
    /// with both fully-qualified candidates in `context.matches`.
    ///
    /// The fixture cannot use the local adapter for both rows: the
    /// indexer's upsert pass keys candidates by bare `id` within a
    /// source and last-write-wins on collision, so two YAML files with
    /// the same `id` collapse to one row. The fixture instead inserts
    /// the second row directly into `records` as a `cc-native` row,
    /// mirroring how the `query::get` unit test
    /// (`get_by_partial_key_with_source_only_narrows`) builds its own
    /// ambiguity fixture. The first row lands through the normal
    /// `init` + `index` path; the second is appended with a minimal
    /// raw INSERT against the same schema.
    pub fn ready_with_two_records_same_id(id: &str) -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        // Row 1 — the local-adapter path.
        write_local_yaml(&paths.notebook_git, "decisions", id, "first body");
        index(&paths, &cfg);
        // Row 2 — append a `cc-native` row carrying the same bare id
        // but a distinct `(source, project_id)`. The schema CHECK
        // constraint on `source` accepts `cc-native`; the column set
        // mirrors the indexer's own upsert insert.
        // `open_existing` opens read-only; the fixture writes a row, so
        // `open_or_create` (read-write) is the right opener.
        let conn = nexum_core::indexer::db::open_or_create(&paths.index_db)
            .expect("open index db for ambiguity row insert");
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, \
             tags, tags_fts, agent, confidence, outcome, session_refs, files, \
             commits, created, updated, content_hash, index_hash, crypto_result, \
             indexed_at) VALUES \
             (?1, 'cc-native', 'second-project', 'decision', 'second title', \
              'second body', '[]', '', 'claude-code', 'medium', 'working', \
              '[]', '[]', '[]', \
              '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h2', 'ih2', \
              'no-signature', '2026-04-29T00:01:00Z')",
            [id],
        )
        .expect("insert ambiguity row into index db");
        // Sanity: confirm both rows are in the DB before handing the
        // fixture back. If the count is < 2 the test will fail with a
        // far less informative `NOT_FOUND`; the eprintln keeps the
        // diagnostic local to the fixture.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM records WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .expect("count rows with the shared id");
        assert_eq!(
            count, 2,
            "ambiguity fixture must seed exactly two rows with id `{id}`"
        );
        drop(conn);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed under the default `unsigned_default =
    /// "warn-but-show"` policy with one unsigned record at the given
    /// `id`. Exercises the no-silent-unsigned invariant (every
    /// non-verified row carries a canonical warning) and the
    /// `_meta.policy_warnings` channel (non-empty when any unsigned row
    /// is returned).
    pub fn ready_unsigned_under_warn(id: &str) -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        // Default policy is `warn-but-show`; no override needed.
        write_local_yaml(&paths.notebook_git, "decisions", id, "unsigned body");
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed under `warn-but-show` with at least one
    /// unsigned record. Tests use `require_signed = true` to assert
    /// the stricter override filters every non-verified row out of the
    /// result set, independent of the permissive policy.
    ///
    /// A "verified + unsigned mix" would require an SSH-signed git
    /// commit, which the test harness does not stand up. The minimal
    /// assertion the simpler corpus supports — every returned row has
    /// `signature_status = "verified"` — still proves the stricter
    /// override fires.
    pub fn ready_require_signed_mix() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, cfg) = init_and_resolve(&root);
        // Two unsigned rows; `require_signed = true` must drop both.
        write_local_yaml(&paths.notebook_git, "decisions", "u1", "unsigned one");
        write_local_yaml(&paths.notebook_git, "decisions", "u2", "unsigned two");
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed home with `unsigned_default = "hide"` and one
    /// unsigned record at the given id. Exercises the `HiddenByPolicy` arm
    /// of `get` and the `include_unsigned` override path.
    ///
    /// The local-adapter record written here lands uncommitted in
    /// `notebook.git`, so the indexer's crypto batch finds no
    /// `record_commit_sha` and leaves the adapter's
    /// `CryptoResult::NoSignature` in place — the record projects as
    /// `SignatureStatus::Unsigned`, which the hide policy then suppresses.
    pub fn ready_hide_policy_with_unsigned_record(id: &str) -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, mut cfg) = init_and_resolve(&root);
        cfg.trust.unsigned_default = nexum_core::records::TrustPolicy::Hide;
        write_local_yaml(&paths.notebook_git, "decisions", id, "unsigned body");
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// Initialized + indexed with two records belonging to **different**
    /// `project_id` values, exercising the `list_projects` path:
    ///
    /// - `name:projx` — a registered `name:`-identity project; its path is
    ///   stored in `cfg.projects`.
    /// - `git:abc123def4567890` — an unregistered `git:`-identity project;
    ///   no path entry is stored.
    ///
    /// The fixture mirrors the production shape without requiring a real git
    /// repo: the `project_id` strings are written directly into the YAML
    /// records and the indexer picks them up verbatim.
    pub fn ready_with_two_projects() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        let (paths, mut cfg) = init_and_resolve(&root);

        // Register `projx` as a name-identity project so `list_projects`
        // can resolve its path from `cfg.projects`.
        let mut entry = toml::map::Map::new();
        entry.insert("path".into(), toml::Value::String("/example/projx".into()));
        cfg.projects
            .insert("projx".into(), toml::Value::Table(entry));

        // One record under `name:projx`.
        write_local_yaml_with_project_id(
            &paths.notebook_git,
            "decisions",
            "projx-rec",
            "projx record body",
            "name:projx",
        );
        // One record under a bare git-identity project_id.
        write_local_yaml_with_project_id(
            &paths.notebook_git,
            "decisions",
            "git-rec",
            "git record body",
            "git:abc123def4567890",
        );
        index(&paths, &cfg);
        Self {
            root,
            paths: Some(paths),
            cfg: Some(cfg),
        }
    }

    /// No nexum home at all: the temp dir exists but `nexum init` was never
    /// run, so `resolve_runtime` fails. The server still starts — every tool
    /// call returns a `NOT_INITIALIZED` structured error.
    pub fn unavailable() -> Self {
        let root = TempDir::new().expect("tempdir for McpTestHome");
        Self {
            root,
            paths: None,
            cfg: None,
        }
    }

    /// The home's `.nexum` root path (the `NEXUM_HOME` equivalent).
    pub fn home_root(&self) -> PathBuf {
        self.root.path().join(".nexum")
    }

    /// Build the [`RuntimeState`] this fixture represents.
    ///
    /// - `ready` / `indexed_empty` → [`RuntimeState::Ready`] with the resolved
    ///   `Paths` + `Config`.
    /// - `unavailable` → [`RuntimeState::Unavailable`], built by running the
    ///   real `resolve_runtime` against the un-initialized home and capturing
    ///   the `ErrorEnvelope` it fails with — the exact path `run()` takes in
    ///   production.
    pub fn runtime_state(&self) -> RuntimeState {
        if let (Some(paths), Some(cfg)) = (&self.paths, &self.cfg) {
            RuntimeState::Ready {
                paths: paths.clone(),
                cfg: cfg.clone(),
            }
        } else {
            // Drive the genuine resolver against a home that does not exist;
            // it must fail, and the envelope it fails with is what the server
            // would carry in production.
            let envelope = resolve_runtime_for(&self.home_root())
                .expect_err("resolve_runtime must fail for an un-initialized home");
            RuntimeState::Unavailable(envelope)
        }
    }

    /// Convenience: build the runtime state, connect a client + server over
    /// duplex, and return the connected pair — the one-liner most tool tests
    /// open with. Consumes `self` so the temp dir's lifetime is transferred
    /// into the returned [`Connected`].
    pub async fn connect(self) -> Connected {
        let state = self.runtime_state();
        connect(state, Some(self.root)).await
    }
}

// ───── in-process home construction ────────────────────────────────────────

/// Run `nexum_core::init::run` against `<root>/.nexum` with an ephemeral
/// keypair, then resolve `Paths` + a local-only `Config`. Panics on any
/// failure — this is a test helper, and a broken fixture should fail loud.
fn init_and_resolve(root: &TempDir) -> (Paths, Config) {
    let key_dir = TempDir::new().expect("tempdir for ephemeral keypair");
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let outcome = init_run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(root.path().join(".nexum")),
        force: false,
    })
    .expect("init must succeed in the MCP test harness");

    let paths = Paths::with_home(outcome.root);
    // Local-only config: the harness seeds local YAML records; the cc / codex
    // adapters have no fixture corpus wired here.
    let mut cfg = Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = true;
    (paths, cfg)
}

/// Run an incremental index pass; panic on failure.
fn index(paths: &Paths, cfg: &Config) {
    nexum_core::api::index_run(paths, cfg)
        .expect("index pass must succeed in the MCP test harness");
}

/// Run the production runtime resolver against an arbitrary `.nexum` root.
/// Used by the `unavailable` fixture to capture the real failure envelope.
///
/// `resolve_runtime` reads the home from the `NEXUM_HOME` env var (the same
/// way the CLI and `nexum-mcp`'s `run()` do), so this sets it for the call.
/// Tests using the `unavailable` fixture therefore accept that this env
/// mutation is process-global; the resolver fails fast (before any disk
/// read) for a path with no `.nexum` content, so there is no cross-test
/// interference in practice.
fn resolve_runtime_for(
    home_root: &Path,
) -> Result<(Paths, Config), nexum_core::api::error::ErrorEnvelope> {
    // SAFETY: `set_var` is process-global. The `unavailable` fixture points
    // at a path with no `.nexum` content, so the resolver fails fast on
    // `Paths::resolve` / `load_config` before touching any shared disk
    // state — no cross-test interference in practice. If a future test
    // needs concurrent `unavailable` + `ready` fixtures, switch the resolver
    // to a `&Path`-taking variant (a small `nexum-core` addition).
    unsafe {
        std::env::set_var("NEXUM_HOME", home_root);
    }
    nexum_core::session::resolve_runtime()
}

// ───── record seeding (mirrors the CLI / core test commons) ────────────────

/// Write a local-adapter-format YAML record at
/// `<notebook_git>/<sub>/<id>.yml`. `sub` in {`decisions`, `recommendations`,
/// `failures`} maps to the matching `record_type`; anything else maps to
/// `untyped`. Byte-for-byte the same shape as the CLI / core
/// `write_local_yaml` helpers.
pub fn write_local_yaml(notebook_git: &Path, sub: &str, id: &str, body: &str) -> PathBuf {
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
            "schema_version: 1\nid: {id}\nrecord_type: {kind}\ntitle: {id}\nbody: |\n  {body}\nproject_id: example\ntags: []\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\nconfidence: high\noutcome: working\n"
        ),
    )
    .expect("write local yaml");
    p
}

/// Write a local-adapter-format YAML record with an explicit `project_id`.
///
/// Same shape as [`write_local_yaml`] except the `project_id` field is
/// provided by the caller rather than defaulting to `example`. Used by
/// multi-project fixtures that need distinct `project_id` values in the index.
pub fn write_local_yaml_with_project_id(
    notebook_git: &Path,
    sub: &str,
    id: &str,
    body: &str,
    project_id: &str,
) -> PathBuf {
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
    .expect("write local yaml with project_id");
    p
}

/// Generate a fresh ed25519 keypair into `dir/id_ed25519{,.pub}`; return the
/// private key path. Mirrors the CLI / core `write_ephemeral_keypair` helpers
/// — duplicated because `tests/common/` cannot cross crate boundaries.
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

// ───── shared assertion helpers (used by the tool tests) ───────────────────

/// Pull the structured JSON payload out of a successful `CallToolResult`,
/// panicking with a readable message if the result is an error or carries no
/// structured content.
pub fn expect_structured(result: &CallToolResult) -> &serde_json::Value {
    assert_ne!(
        result.is_error,
        Some(true),
        "expected a success result, got a tool error: {:?}",
        result.structured_content
    );
    result
        .structured_content
        .as_ref()
        .expect("a success result must carry structured content")
}

/// Pull the `error_code` out of an error `CallToolResult`, panicking if the
/// result is not an error or carries no structured envelope.
pub fn expect_error_code(result: &CallToolResult) -> String {
    assert_eq!(
        result.is_error,
        Some(true),
        "expected a tool error, got a success result"
    );
    result
        .structured_content
        .as_ref()
        .and_then(|v| v.get("error_code"))
        .and_then(serde_json::Value::as_str)
        .expect("an error result must carry a structured envelope with error_code")
        .to_string()
}
