//! Integration test: `nexum models install bge-m3` runs the install
//! pipeline end-to-end against a stub HTTP server, then writes
//! `embed.enabled = true` + `embed.model_path` back to `config.toml`.
//!
//! The CLI binary is gated on a `NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST`
//! env var that swaps the production manifest (real bge-m3 SHA256s, ~2 GB
//! files) for a tiny fixture manifest and skips the ORT smoke test. That
//! lets the test exercise the full download + verify + config-write-back
//! path without depending on the real model files.

mod common;

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Tiny single-threaded HTTP server that serves a fixed map of paths to
/// payloads. Returns 404 on unknown paths. Runs until the test process
/// exits.
fn serve_fixed_payloads(payloads: HashMap<&'static str, Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let payloads = Arc::new(payloads);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let payloads = payloads.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut stream = stream;
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                if let Some(body) = payloads.get(path.trim_start_matches('/')) {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(body);
                } else {
                    let _ =
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
            });
        }
    });
    addr
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        // Hex-encode a single byte. `write!` into a `String` is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn set_embed_model_base_url(nexum_home: &std::path::Path, base_url: &str) {
    let cfg_path = nexum_home.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).expect("read config.toml");
    let mut doc: toml::Value = toml::from_str(&raw).expect("parse config.toml");
    let embed = doc
        .as_table_mut()
        .and_then(|t| t.get_mut("embed"))
        .and_then(|v| v.as_table_mut())
        .expect("config.toml missing [embed] table");
    embed.insert(
        "model_base_url".into(),
        toml::Value::String(base_url.to_owned()),
    );
    let serialized = toml::to_string(&doc).expect("serialize config.toml");
    std::fs::write(&cfg_path, serialized).expect("write config.toml");
}

fn load_embed_section(nexum_home: &std::path::Path) -> toml::Value {
    let cfg_path = nexum_home.join("config.toml");
    let raw = std::fs::read_to_string(&cfg_path).expect("read config.toml");
    let doc: toml::Value = toml::from_str(&raw).expect("parse config.toml");
    doc.as_table()
        .and_then(|t| t.get("embed"))
        .cloned()
        .expect("config.toml missing [embed] table")
}

#[test]
fn models_install_bge_m3_flips_embed_enabled() {
    // Tiny fixture payloads. The integration path skips ORT smoke (any
    // bytes work as a model.onnx stand-in) and the verifier only checks
    // SHA256, so we hash the stub bytes here and feed them to the CLI via
    // `NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST`.
    let model_onnx = b"GRAPH".to_vec();
    let model_data = vec![0u8; 1024];
    let constant = b"CONST".to_vec();
    let tokenizer = br#"{"version":"1.0"}"#.to_vec();

    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", model_onnx.clone()),
        ("model.onnx_data", model_data.clone()),
        ("Constant_7_attr__value", constant.clone()),
        ("tokenizer.json", tokenizer.clone()),
    ]);

    let manifest_json = serde_json::json!([
        { "name": "model.onnx", "size": model_onnx.len(), "sha256": sha256_hex(&model_onnx) },
        { "name": "model.onnx_data", "size": model_data.len(), "sha256": sha256_hex(&model_data) },
        { "name": "Constant_7_attr__value", "size": constant.len(), "sha256": sha256_hex(&constant) },
        { "name": "tokenizer.json", "size": tokenizer.len(), "sha256": sha256_hex(&tokenizer) },
    ])
    .to_string();

    let addr = serve_fixed_payloads(payloads);
    let base_url = format!("http://{addr}/");

    // Init a nexum home via the existing helper so the bootstrap, signing
    // key, and seed config.toml all land in place.
    let root = TempDir::new().expect("tempdir");
    let nexum_home = root.path().join(".nexum");
    let ssh_home = root.path().join("ssh-home");
    std::fs::create_dir_all(ssh_home.join(".ssh")).expect("mkdir ssh-home/.ssh");
    let key_path = common::write_ephemeral_keypair(&ssh_home.join(".ssh"));
    let init_out = common::run_nexum(
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
        init_out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init_out.stdout),
        String::from_utf8_lossy(&init_out.stderr)
    );

    set_embed_model_base_url(&nexum_home, &base_url);

    let out = Command::new(common::nexum_bin())
        .args(["models", "install", "bge-m3"])
        .env("NEXUM_HOME", &nexum_home)
        .env("HOME", &ssh_home)
        .env("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST", &manifest_json)
        .env("GIT_AUTHOR_NAME", "nexum-test")
        .env("GIT_AUTHOR_EMAIL", "nexum-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "nexum-test")
        .env("GIT_COMMITTER_EMAIL", "nexum-test@example.invalid")
        .output()
        .expect("nexum binary exec failed");

    let stderr_str = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout_str = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "install failed (exit {:?}):\nstdout={}\nstderr={}",
        out.status.code(),
        stdout_str,
        stderr_str
    );

    assert!(
        stderr_str.contains("downloading model.onnx"),
        "expected `downloading model.onnx` in stderr; got:\n{stderr_str}"
    );
    assert!(
        stderr_str.contains("install complete"),
        "expected `install complete` summary in stderr; got:\n{stderr_str}"
    );

    let embed = load_embed_section(&nexum_home);
    let embed_table = embed.as_table().expect("[embed] must be a table");
    assert_eq!(
        embed_table.get("enabled").and_then(toml::Value::as_bool),
        Some(true),
        "embed.enabled must flip to true"
    );
    let model_path = embed_table
        .get("model_path")
        .and_then(toml::Value::as_str)
        .expect("embed.model_path must be set");
    assert!(
        model_path.ends_with("bge-m3/model.onnx") || model_path.ends_with("bge-m3\\model.onnx"),
        "embed.model_path should point at bge-m3/model.onnx, got {model_path:?}"
    );
}

#[test]
fn models_install_unknown_model_returns_exit_2() {
    let root = TempDir::new().expect("tempdir");
    let nexum_home = root.path().join(".nexum");
    let ssh_home = root.path().join("ssh-home");
    std::fs::create_dir_all(&ssh_home).expect("mkdir ssh-home");

    let out = common::run_nexum(&nexum_home, &ssh_home, &["models", "install", "phi-3"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 (USAGE) for unsupported model; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Shared bootstrap for the install-failure / install-success tests below.
/// Init a nexum home, point `[embed].model_base_url` at the stub server,
/// and return the temp dirs + manifest JSON the CLI will resolve.
struct InstallHarness {
    _root: TempDir,
    nexum_home: std::path::PathBuf,
    ssh_home: std::path::PathBuf,
    manifest_json: String,
}

fn init_install_harness(
    payloads: HashMap<&'static str, Vec<u8>>,
    manifest_json: String,
) -> InstallHarness {
    let addr = serve_fixed_payloads(payloads);
    let base_url = format!("http://{addr}/");
    let root = TempDir::new().expect("tempdir");
    let nexum_home = root.path().join(".nexum");
    let ssh_home = root.path().join("ssh-home");
    std::fs::create_dir_all(ssh_home.join(".ssh")).expect("mkdir ssh-home/.ssh");
    let key_path = common::write_ephemeral_keypair(&ssh_home.join(".ssh"));
    let init_out = common::run_nexum(
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
        init_out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init_out.stdout),
        String::from_utf8_lossy(&init_out.stderr),
    );
    set_embed_model_base_url(&nexum_home, &base_url);
    InstallHarness {
        _root: root,
        nexum_home,
        ssh_home,
        manifest_json,
    }
}

/// Build a fixture manifest whose `model.onnx_data` SHA256 deliberately
/// does not match the served bytes, so the install pipeline trips the
/// checksum-mismatch retry path and surfaces `CHECKSUM_MISMATCH` (12).
fn tampered_checksum_fixture() -> (HashMap<&'static str, Vec<u8>>, String) {
    let model_onnx = b"GRAPH".to_vec();
    let model_data = vec![0u8; 1024];
    let constant = b"CONST".to_vec();
    let tokenizer = br#"{"version":"1.0"}"#.to_vec();
    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", model_onnx.clone()),
        ("model.onnx_data", model_data.clone()),
        ("Constant_7_attr__value", constant.clone()),
        ("tokenizer.json", tokenizer.clone()),
    ]);
    // Wrong sha256 for model.onnx_data so the verifier rejects it on the
    // first pass and the (idempotent stub) second pass.
    let tampered_data_sha = "00".repeat(32);
    let manifest_json = serde_json::json!([
        { "name": "model.onnx", "size": model_onnx.len(), "sha256": sha256_hex(&model_onnx) },
        { "name": "model.onnx_data", "size": model_data.len(), "sha256": tampered_data_sha },
        { "name": "Constant_7_attr__value", "size": constant.len(), "sha256": sha256_hex(&constant) },
        { "name": "tokenizer.json", "size": tokenizer.len(), "sha256": sha256_hex(&tokenizer) },
    ])
    .to_string();
    (payloads, manifest_json)
}

#[test]
fn models_install_checksum_mismatch_returns_exit_12() {
    let (payloads, manifest_json) = tampered_checksum_fixture();
    let harness = init_install_harness(payloads, manifest_json);

    let out = Command::new(common::nexum_bin())
        .args(["models", "install", "bge-m3"])
        .env("NEXUM_HOME", &harness.nexum_home)
        .env("HOME", &harness.ssh_home)
        .env("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST", &harness.manifest_json)
        .output()
        .expect("nexum binary exec failed");

    assert_eq!(
        out.status.code(),
        Some(12),
        "expected exit 12 (CHECKSUM_MISMATCH); stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn models_install_json_success_envelope() {
    let model_onnx = b"GRAPH".to_vec();
    let model_data = vec![0u8; 1024];
    let constant = b"CONST".to_vec();
    let tokenizer = br#"{"version":"1.0"}"#.to_vec();
    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", model_onnx.clone()),
        ("model.onnx_data", model_data.clone()),
        ("Constant_7_attr__value", constant.clone()),
        ("tokenizer.json", tokenizer.clone()),
    ]);
    let manifest_json = serde_json::json!([
        { "name": "model.onnx", "size": model_onnx.len(), "sha256": sha256_hex(&model_onnx) },
        { "name": "model.onnx_data", "size": model_data.len(), "sha256": sha256_hex(&model_data) },
        { "name": "Constant_7_attr__value", "size": constant.len(), "sha256": sha256_hex(&constant) },
        { "name": "tokenizer.json", "size": tokenizer.len(), "sha256": sha256_hex(&tokenizer) },
    ])
    .to_string();
    let total: u64 = model_onnx.len() as u64
        + model_data.len() as u64
        + constant.len() as u64
        + tokenizer.len() as u64;

    let harness = init_install_harness(payloads, manifest_json);

    let out = Command::new(common::nexum_bin())
        .args(["models", "install", "bge-m3", "--json"])
        .env("NEXUM_HOME", &harness.nexum_home)
        .env("HOME", &harness.ssh_home)
        .env("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST", &harness.manifest_json)
        .output()
        .expect("nexum binary exec failed");

    let stdout_str = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "expected exit 0 on --json success; exit={:?}\nstdout={stdout_str}\nstderr={stderr_str}",
        out.status.code(),
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout_str.trim()).expect("stdout must be a single JSON object");
    assert_eq!(parsed["ok"], serde_json::Value::Bool(true));
    assert_eq!(parsed["model"], "bge-m3");
    assert_eq!(
        parsed["downloaded"].as_u64(),
        Some(total),
        "downloaded must match the cumulative fixture bytes",
    );
    // Smoke-test step is skipped under the fixture manifest, so
    // smoke_test_ms is the default 0 — assert the field is present.
    assert!(parsed.get("smoke_test_ms").is_some());
    let model_path = parsed["model_path"]
        .as_str()
        .expect("model_path must be a string");
    assert!(
        model_path.ends_with("bge-m3/model.onnx") || model_path.ends_with("bge-m3\\model.onnx"),
        "model_path should point at bge-m3/model.onnx, got {model_path:?}",
    );
}

#[test]
fn models_install_json_failure_envelope() {
    let (payloads, manifest_json) = tampered_checksum_fixture();
    let harness = init_install_harness(payloads, manifest_json);

    let out = Command::new(common::nexum_bin())
        .args(["models", "install", "bge-m3", "--json"])
        .env("NEXUM_HOME", &harness.nexum_home)
        .env("HOME", &harness.ssh_home)
        .env("NEXUM_TEST_BGE_M3_FIXTURE_MANIFEST", &harness.manifest_json)
        .output()
        .expect("nexum binary exec failed");

    assert_eq!(
        out.status.code(),
        Some(12),
        "expected exit 12 on JSON failure path; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout_str = String::from_utf8_lossy(&out.stdout).into_owned();
    let parsed: serde_json::Value = serde_json::from_str(stdout_str.trim())
        .expect("stdout must be a single JSON object on --json failure");
    assert_eq!(parsed["ok"], serde_json::Value::Bool(false));
    assert_eq!(parsed["code"], "EMBED_FAILED");
    assert_eq!(parsed["kind"], "checksum_mismatch");
    assert_eq!(parsed["file"], "model.onnx_data");
}
