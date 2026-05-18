//! `nexum models install bge-m3` — download + verify + smoke the bge-m3
//! ONNX export, then flip `[embed].enabled = true` in config.toml.

use std::io::{Write, stderr};
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::json;

use nexum_core::config;
use nexum_core::embed::install::{install_bge_m3, install_bge_m3_with};
use nexum_core::embed::{EmbedError, InstallReport, ManifestEntry, Reporter};
use nexum_core::session::resolve_runtime;

use super::exit_codes;

/// Install-specific exit codes. Disjoint from generic `exit_codes::*` so
/// agents can branch on retry policy (download -> retry, checksum -> retry,
/// ORT init -> reinstall binary, output shape -> bad model). Reused `1`
/// for generic IO keeps `FAILURE` as the floor for callers that don't
/// branch on the variant.
///
/// The map of variant -> code lives on `EmbedError::install_exit_code`;
/// these constants exist only to give the test assertions readable names.
#[cfg(test)]
mod install_exit_codes {
    pub(super) const MODEL_NOT_INSTALLED: u8 = 9;
    pub(super) const CHECKSUM_MISMATCH: u8 = 12;
    pub(super) const TOKENIZE_FAILED: u8 = 13;
    pub(super) const ORT_INIT_FAILED: u8 = 14;
    pub(super) const ORT_RUN_FAILED: u8 = 15;
    pub(super) const OUTPUT_SHAPE_MISMATCH: u8 = 16;
    pub(super) const OVERSIZE_STREAM: u8 = 17;
}

/// `nexum models …` subcommands. Reserved for future model-management
/// verbs; in this release only `install bge-m3` is supported.
#[derive(Debug, Subcommand)]
pub enum ModelsCmd {
    /// Install an embedding model. Only `bge-m3` is supported in this release.
    Install {
        /// Model name. Only `bge-m3` is supported.
        model: String,
        /// Emit a structured JSON envelope to stdout (success or failure)
        /// instead of the default human-readable stderr output. Mirrors
        /// the `--json` flag on the read verbs.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Override the model base URL for this run only (defaults to the
        /// value in `[embed].model_base_url`). Useful for HF mirrors or
        /// air-gapped staging. Not persisted to `config.toml`.
        #[arg(long)]
        model_base_url: Option<String>,
    },
}

/// Entry point dispatched from `main.rs`.
#[must_use]
pub fn run(cmd: &ModelsCmd) -> ExitCode {
    match cmd {
        ModelsCmd::Install {
            model,
            json,
            model_base_url,
        } => run_install(model, *json, model_base_url.as_deref()),
    }
}

fn run_install(model: &str, emit_json: bool, model_base_url_override: Option<&str>) -> ExitCode {
    if model != "bge-m3" {
        if emit_json {
            let env = json!({
                "ok": false,
                "code": "USAGE",
                "kind": "unsupported_model",
                "model": model,
                "message": format!(
                    "unsupported model '{model}' — only 'bge-m3' is supported in this release"
                ),
            });
            println!("{env:#}");
        } else {
            let _ = writeln!(
                stderr(),
                "error: unsupported model '{model}' — only 'bge-m3' is supported in this release.",
            );
        }
        return ExitCode::from(exit_codes::USAGE);
    }

    let (paths, cfg) = match resolve_runtime() {
        Ok(rt) => rt,
        Err(envelope) => {
            if emit_json {
                // The envelope already carries a stable error_code; surface
                // it verbatim under the install envelope shape so agents
                // never see a raw envelope on stdout for this command.
                let env = json!({
                    "ok": false,
                    "code": envelope.error_code,
                    "kind": "runtime_unavailable",
                    "message": envelope.message,
                });
                println!("{env:#}");
            } else {
                let _ = writeln!(stderr(), "error: {}", envelope.message);
            }
            return ExitCode::from(exit_codes::for_envelope(&envelope));
        }
    };

    let mut effective_cfg = cfg.clone();
    if let Some(url) = model_base_url_override {
        url.clone_into(&mut effective_cfg.embed.model_base_url);
    }

    let mut reporter = StderrReporter::new();
    let install_result = match test_manifest_from_env() {
        Some(fixture) => install_bge_m3_with(
            &paths.models,
            &effective_cfg,
            &mut reporter,
            &fixture.entries,
            /* skip_smoke = */ true,
        ),
        None => install_bge_m3(&paths.models, &effective_cfg, &mut reporter),
    };

    let (report, mut next_cfg): (InstallReport, _) = match install_result {
        Ok(v) => v,
        Err(err) => {
            let exit = err.install_exit_code();
            if emit_json {
                println!("{:#}", embed_error_envelope(&err));
            } else {
                let _ = writeln!(stderr(), "error: {err}");
            }
            return ExitCode::from(exit);
        }
    };

    // Preserve the on-disk mirror URL — the override is one-shot.
    // `install_bge_m3_with` clones `effective_cfg` into `next_cfg` and
    // sets `embed.model_base_url` to whatever the override was; without
    // this line the transient mirror URL would be written to config.toml.
    // NOTE: if a future caller intentionally rewrites the URL (e.g. a
    // `nexum models set-mirror` command), this line will silently undo it
    // — add the new verb to the `Install` arm instead of calling
    // `config::save` a second time.
    next_cfg
        .embed
        .model_base_url
        .clone_from(&cfg.embed.model_base_url);

    if let Err(err) = config::save(&paths.config, &next_cfg) {
        if emit_json {
            let env = json!({
                "ok": false,
                "code": "STORE_INTEGRITY",
                "kind": "config_save",
                "message": format!("failed to update config.toml: {err}"),
            });
            println!("{env:#}");
        } else {
            let _ = writeln!(stderr(), "error: failed to update config.toml: {err}");
        }
        return ExitCode::FAILURE;
    }

    render_install_success(&report, &paths.models, emit_json);
    ExitCode::SUCCESS
}

/// Emit the install-success output — JSON envelope to stdout or prose
/// summary to stderr depending on `emit_json`.
fn render_install_success(report: &InstallReport, models_dir: &std::path::Path, emit_json: bool) {
    if emit_json {
        let model_path = models_dir.join("bge-m3").join("model.onnx");
        // Flatten Option<Duration> → Option<u64> at the serialization
        // boundary: the wire key `smoke_test_ms` stays stable for agent
        // consumers; null signals "smoke test was skipped".
        let smoke_test_ms: Option<u64> = report
            .smoke_test
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let env = json!({
            "ok": true,
            "model": "bge-m3",
            "downloaded": report.downloaded,
            "smoke_test_ms": smoke_test_ms,
            "model_path": model_path.to_string_lossy(),
        });
        println!("{env:#}");
    } else {
        let smoke = report
            .smoke_test
            .map_or_else(|| "skipped".into(), |d| format!("{} ms", d.as_millis()));
        let _ = writeln!(
            stderr(),
            "install complete: downloaded {} bytes; smoke test: {smoke}; embed.enabled=true",
            report.downloaded,
        );
    }
}

/// Build a structured failure envelope for an `EmbedError`. The `code` is
/// the wire-stable `EMBED_FAILED` shared with the api facade; `kind` is
/// the variant-specific `snake_case` tag; variant payload fields are
/// promoted to top-level keys so agents can branch without re-parsing
/// the message.
fn embed_error_envelope(err: &EmbedError) -> serde_json::Value {
    let mut env = json!({
        "ok": false,
        "code": "EMBED_FAILED",
        "kind": err.variant_kind(),
        "message": err.to_string(),
    });
    let obj = env
        .as_object_mut()
        .expect("json!({...}) literal is always an object");
    match err {
        EmbedError::ModelNotInstalled { reason } => {
            obj.insert("reason".into(), json!(reason));
        }
        EmbedError::Io { path, source } => {
            obj.insert("path".into(), json!(path.to_string_lossy()));
            obj.insert("source".into(), json!(source.to_string()));
        }
        EmbedError::Download { file, source } => {
            obj.insert("file".into(), json!(file));
            obj.insert("source".into(), json!(source.to_string()));
        }
        EmbedError::ChecksumMismatch {
            file,
            expected,
            actual,
        } => {
            obj.insert("file".into(), json!(file));
            obj.insert("expected".into(), json!(expected));
            obj.insert("actual".into(), json!(actual));
        }
        EmbedError::Tokenize { message, .. }
        | EmbedError::OrtInit { message, .. }
        | EmbedError::OrtRun { message, .. } => {
            obj.insert("detail".into(), json!(message));
        }
        EmbedError::OutputShapeMismatch { expected, actual } => {
            obj.insert("expected".into(), json!(expected));
            obj.insert("actual".into(), json!(actual));
        }
        EmbedError::OversizeStream {
            file,
            expected_bytes,
            observed_bytes,
        } => {
            obj.insert("file".into(), json!(file));
            obj.insert("expected_bytes".into(), json!(expected_bytes));
            obj.insert("observed_bytes".into(), json!(observed_bytes));
        }
    }
    env
}

/// Test-only manifest override loaded from the
/// `NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST` env var (JSON array of
/// `{name, size, sha256}` entries). Returning `Some` switches the install
/// pipeline to `install_bge_m3_with` with the parsed manifest and a
/// skipped smoke test — the integration test exercises the download +
/// verify + config-write-back path against a stub HTTP server.
struct TestFixture {
    entries: Vec<ManifestEntry>,
}

fn test_manifest_from_env() -> Option<TestFixture> {
    let raw = std::env::var("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST").ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let array = parsed.as_array()?;
    let mut entries = Vec::with_capacity(array.len());
    for v in array {
        let name = v.get("name")?.as_str()?.to_owned();
        let size = v.get("size")?.as_u64()?;
        let sha256 = v.get("sha256")?.as_str()?.to_owned();
        entries.push(ManifestEntry::new(
            // The install pipeline reads `name` and `sha256` as `&'static
            // str` — for the test path we leak the owned strings so the
            // `ManifestEntry` borrow remains satisfied for the lifetime of
            // the process. Acceptable in a one-shot CLI invocation gated
            // behind a test env var.
            Box::leak(name.into_boxed_str()),
            size,
            Box::leak(sha256.into_boxed_str()),
        ));
    }
    Some(TestFixture { entries })
}

/// Reporter that writes coalesced progress to stderr. Debounces byte
/// updates to one line per ~5% of the file or every ~50 MiB, whichever
/// comes first.
struct StderrReporter {
    last_file_bytes: u64,
}

impl StderrReporter {
    fn new() -> Self {
        Self { last_file_bytes: 0 }
    }
}

impl Reporter for StderrReporter {
    fn progress(&mut self, msg: &str) {
        let _ = writeln!(stderr(), "{msg}");
        self.last_file_bytes = 0;
    }

    fn bytes(&mut self, done: u64, total: u64) {
        if total == 0 {
            return;
        }
        // `pct` values are bounded to [0, 100] by `min(100)`; the casts
        // are lossless. `last_pct` is recomputed from `last_file_bytes`
        // so the two values can't drift.
        let pct = u8::try_from((done.saturating_mul(100) / total).min(100)).unwrap_or(100);
        let last_pct = u8::try_from((self.last_file_bytes.saturating_mul(100) / total).min(100))
            .unwrap_or(100);
        let pct_jump = pct >= last_pct.saturating_add(5);
        let byte_jump = done >= self.last_file_bytes + 50 * 1024 * 1024;
        if pct_jump || byte_jump {
            let _ = writeln!(stderr(), "  {pct}% ({done} / {total} bytes)");
            self.last_file_bytes = done;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn install_exit_codes_match_variants() {
        // Pin the variant -> exit-code map. Agents branch on these so any
        // re-shuffle must be deliberate and surface here.
        assert_eq!(
            EmbedError::ModelNotInstalled {
                reason: "n/a".into()
            }
            .install_exit_code(),
            install_exit_codes::MODEL_NOT_INSTALLED
        );
        assert_eq!(
            EmbedError::Io {
                path: PathBuf::from("x"),
                source: io::Error::other("e"),
            }
            .install_exit_code(),
            1
        );
        assert_eq!(
            EmbedError::ChecksumMismatch {
                file: "model.onnx_data".into(),
                expected: "a".into(),
                actual: "b".into(),
            }
            .install_exit_code(),
            install_exit_codes::CHECKSUM_MISMATCH
        );
        assert_eq!(
            EmbedError::Tokenize {
                message: "x".into(),
                source: Box::<dyn std::error::Error + Send + Sync>::from("x"),
            }
            .install_exit_code(),
            install_exit_codes::TOKENIZE_FAILED
        );
        assert_eq!(
            EmbedError::OrtInit {
                message: "x".into(),
                source: Box::<dyn std::error::Error + Send + Sync>::from("x"),
            }
            .install_exit_code(),
            install_exit_codes::ORT_INIT_FAILED
        );
        assert_eq!(
            EmbedError::OrtRun {
                message: "x".into(),
                source: Box::<dyn std::error::Error + Send + Sync>::from("x"),
            }
            .install_exit_code(),
            install_exit_codes::ORT_RUN_FAILED
        );
        assert_eq!(
            EmbedError::OutputShapeMismatch {
                expected: vec![1, 2],
                actual: vec![1, 3],
            }
            .install_exit_code(),
            install_exit_codes::OUTPUT_SHAPE_MISMATCH
        );
        assert_eq!(
            EmbedError::OversizeStream {
                file: "any.onnx".into(),
                expected_bytes: 100,
                observed_bytes: 200,
            }
            .install_exit_code(),
            install_exit_codes::OVERSIZE_STREAM
        );
    }

    #[test]
    fn install_mirror_override_passes_url_to_core() {
        use clap::Parser;

        #[derive(clap::Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: ModelsCmd,
        }

        let cli = TestCli::try_parse_from([
            "test",
            "install",
            "bge-m3",
            "--model-base-url",
            "https://mirror.example.com/bge-m3",
        ])
        .unwrap();
        let ModelsCmd::Install {
            model_base_url,
            model,
            ..
        } = cli.cmd;
        assert_eq!(model, "bge-m3");
        assert_eq!(
            model_base_url.as_deref(),
            Some("https://mirror.example.com/bge-m3")
        );
    }

    #[test]
    fn embed_error_envelope_checksum_mismatch_fields() {
        let err = EmbedError::ChecksumMismatch {
            file: "model.onnx_data".into(),
            expected: "1eebfb28".into(),
            actual: "0000ff".into(),
        };
        let env = embed_error_envelope(&err);
        assert_eq!(env["ok"], serde_json::Value::Bool(false));
        assert_eq!(env["code"], "EMBED_FAILED");
        assert_eq!(env["kind"], "checksum_mismatch");
        assert_eq!(env["file"], "model.onnx_data");
        assert_eq!(env["expected"], "1eebfb28");
        assert_eq!(env["actual"], "0000ff");
    }
}
