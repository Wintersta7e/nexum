//! Integration test: spin up a tiny HTTP server (stub the four bge-m3
//! files with fixed payloads), point the downloader at it, assert all
//! four files land at the right path with the right byte counts.

use std::collections::HashMap;
use std::io::{Read, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use nexum_core::embed::install::download_bge_m3;
use nexum_core::embed::reporter::NullReporter;

/// Tiny single-threaded HTTP server that serves a fixed map of paths to
/// payloads. Returns 404 on unknown paths. Runs until the test scope ends.
///
/// Every response carries `Connection: close` and the write half is
/// shut down explicitly before the socket drops. Without that, reqwest's
/// HTTP/1.1 keep-alive pool re-uses the connection for the next file,
/// races against the one-shot server thread closing the socket, and
/// surfaces `ECONNRESET` mid-send on the next request.
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
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(body);
                } else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

#[test]
fn download_pulls_four_files_into_model_dir() {
    let _ = NullReporter; // re-export sanity
    let model_onnx = b"GRAPH".to_vec();
    let model_data = vec![0u8; 1024]; // tiny stand-in for the 2.1 GB weights file
    let constant = b"CONST".to_vec();
    let tokenizer = br#"{"version":"1.0"}"#.to_vec();

    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", model_onnx.clone()),
        ("model.onnx_data", model_data.clone()),
        ("Constant_7_attr__value", constant.clone()),
        ("tokenizer.json", tokenizer.clone()),
    ]);

    let addr = serve_fixed_payloads(payloads);
    let base_url = format!("http://{addr}/");

    let temp = tempfile::TempDir::new().unwrap();
    let models_dir: PathBuf = temp.path().join("models");
    std::fs::create_dir_all(&models_dir).unwrap();

    let progress = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut reporter = TestReporter {
        progress: progress.clone(),
    };

    let report = download_bge_m3(&models_dir, &base_url, &mut reporter)
        .expect("download succeeds against stub server");

    // Four files landed at <models_dir>/bge-m3/<name>.
    let bge_dir = models_dir.join("bge-m3");
    assert_eq!(
        std::fs::read(bge_dir.join("model.onnx")).unwrap(),
        model_onnx
    );
    assert_eq!(
        std::fs::read(bge_dir.join("model.onnx_data")).unwrap(),
        model_data
    );
    assert_eq!(
        std::fs::read(bge_dir.join("Constant_7_attr__value")).unwrap(),
        constant
    );
    assert_eq!(
        std::fs::read(bge_dir.join("tokenizer.json")).unwrap(),
        tokenizer
    );

    // Report's `downloaded` matches the cumulative byte total.
    assert_eq!(
        report.downloaded,
        (model_onnx.len() + model_data.len() + constant.len() + tokenizer.len()) as u64
    );

    // Reporter saw at least one progress message per file.
    let msgs = progress.lock().unwrap();
    assert!(msgs.iter().any(|m| m.contains("model.onnx")));
    assert!(msgs.iter().any(|m| m.contains("tokenizer.json")));
}

struct TestReporter {
    progress: Arc<Mutex<Vec<String>>>,
}
impl nexum_core::embed::reporter::Reporter for TestReporter {
    fn progress(&mut self, msg: &str) {
        self.progress.lock().unwrap().push(msg.to_string());
    }
    fn bytes(&mut self, _done: u64, _total: u64) {}
}

/// Test-only manifest matching the four tiny files under
/// `tests/fixtures/embed_install/`. Hashes are the `sha256sum` of each
/// fixture's bytes.
const TEST_MANIFEST: &[nexum_core::embed::ManifestEntry; 4] = &[
    nexum_core::embed::ManifestEntry::new(
        "model.onnx",
        5,
        "f6aac9d445ab169b1fd359463aaaed95faee7808a97d9f840f63273314397708",
    ),
    nexum_core::embed::ManifestEntry::new(
        "model.onnx_data",
        8,
        "44df6bfb223b6a881a58274f56bbbbe35909725f3fc09f6896f0c9154857e134",
    ),
    nexum_core::embed::ManifestEntry::new(
        "Constant_7_attr__value",
        5,
        "3b5d28caea5749e89cc6dd0d73f0a622abeca96772b8680a47b4604ee0f93383",
    ),
    nexum_core::embed::ManifestEntry::new(
        "tokenizer.json",
        9,
        "b8513f1a0c28d8dd9b3b175bee09eabca97c4819614ec9a2df7442a5b4eff8d7",
    ),
];

fn fixture_bytes(name: &str) -> Vec<u8> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("embed_install");
    std::fs::read(dir.join(name)).expect("read fixture")
}

#[test]
fn tampered_file_is_detected_after_retry() {
    // Seed <models_dir>/bge-m3/ with the four fixture files, then flip
    // one byte in Constant_7_attr__value so verify_manifest's first hash
    // call mismatches. The injected redownload closure writes the same
    // bad bytes again so the retry observes the same mismatch and we
    // reach the fail-closed branch.
    let temp = tempfile::TempDir::new().unwrap();
    let bge_dir = temp.path().join("bge-m3");
    std::fs::create_dir_all(&bge_dir).unwrap();
    for entry in TEST_MANIFEST {
        std::fs::write(bge_dir.join(entry.name()), fixture_bytes(entry.name())).unwrap();
    }
    let tampered = bge_dir.join("Constant_7_attr__value");
    let mut bad = fixture_bytes("Constant_7_attr__value");
    bad.push(0xFF);
    std::fs::write(&tampered, &bad).unwrap();

    let mut reporter = NullReporter;
    let mut report = nexum_core::embed::InstallReport {
        downloaded: 0,
        smoke_test: None,
    };
    // Retry closure: write the bad bytes again to force a second-failure.
    let bad_clone = bad.clone();
    let redownload = move |_entry: &nexum_core::embed::ManifestEntry,
                           dest: &std::path::Path|
          -> Result<(), nexum_core::embed::EmbedError> {
        std::fs::write(dest, &bad_clone).map_err(|e| nexum_core::embed::EmbedError::Io {
            path: dest.to_owned(),
            source: e,
        })?;
        Ok(())
    };

    let err = nexum_core::embed::install::verify_and_smoke_with(
        temp.path(),
        TEST_MANIFEST,
        &mut report,
        &mut reporter,
        redownload,
    )
    .expect_err("verify should fail when retry also mismatches");

    match err {
        nexum_core::embed::EmbedError::ChecksumMismatch { file, .. } => {
            assert_eq!(file, "Constant_7_attr__value");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        !tampered.exists(),
        "tampered file should be deleted after final mismatch"
    );
}

#[test]
fn retry_writes_good_bytes_lets_verifier_proceed() {
    // Same setup as the tampered test, but this time the redownload
    // closure writes the CORRECT bytes — verify_manifest should accept
    // them and proceed past Constant_7_attr__value.
    let temp = tempfile::TempDir::new().unwrap();
    let bge_dir = temp.path().join("bge-m3");
    std::fs::create_dir_all(&bge_dir).unwrap();
    for entry in TEST_MANIFEST {
        std::fs::write(bge_dir.join(entry.name()), fixture_bytes(entry.name())).unwrap();
    }
    let tampered = bge_dir.join("Constant_7_attr__value");
    let mut bad = fixture_bytes("Constant_7_attr__value");
    bad.push(0xFF);
    std::fs::write(&tampered, &bad).unwrap();

    let mut reporter = NullReporter;
    let mut report = nexum_core::embed::InstallReport {
        downloaded: 0,
        smoke_test: None,
    };
    let redownload = |entry: &nexum_core::embed::ManifestEntry,
                      dest: &std::path::Path|
     -> Result<(), nexum_core::embed::EmbedError> {
        std::fs::write(dest, fixture_bytes(entry.name())).map_err(|e| {
            nexum_core::embed::EmbedError::Io {
                path: dest.to_owned(),
                source: e,
            }
        })?;
        Ok(())
    };

    // verify_manifest passes; run_smoke then fails because the fixture
    // files aren't a real ONNX model. We only care that verification got
    // past the retry, so an error other than ChecksumMismatch is OK.
    let result = nexum_core::embed::install::verify_and_smoke_with(
        temp.path(),
        TEST_MANIFEST,
        &mut report,
        &mut reporter,
        redownload,
    );
    if let Err(nexum_core::embed::EmbedError::ChecksumMismatch { .. }) = result {
        panic!("retry-with-good-bytes should not surface ChecksumMismatch");
    }
    // After the retry, the file content matches the manifest hash.
    assert_eq!(
        std::fs::read(&tampered).unwrap(),
        fixture_bytes("Constant_7_attr__value")
    );
}

#[test]
#[ignore = "requires real bge-m3 install; gated by NEXUM_TEST_BGE_M3_FIXTURE"]
fn clean_install_verifies_and_smokes() {
    let Some(fixture) = std::env::var_os("NEXUM_TEST_BGE_M3_FIXTURE") else {
        return;
    };
    let real_dir = PathBuf::from(fixture);
    let temp = tempfile::TempDir::new().unwrap();
    let bge_dir = temp.path().join("bge-m3");
    std::fs::create_dir_all(&bge_dir).unwrap();
    for entry in nexum_core::embed::BGE_M3_FILES {
        std::fs::copy(real_dir.join(entry.name()), bge_dir.join(entry.name())).unwrap();
    }

    let mut reporter = NullReporter;
    let mut report = nexum_core::embed::InstallReport {
        downloaded: 0,
        smoke_test: None,
    };
    nexum_core::embed::install::verify_and_smoke(
        temp.path(),
        "http://unused.invalid/",
        &mut report,
        &mut reporter,
    )
    .expect("verify_and_smoke succeeds on a real install");
    let smoke_ms = report
        .smoke_test
        .expect("smoke_test should be Some after verify_and_smoke")
        .as_millis();
    assert!(smoke_ms > 0);
    assert!(smoke_ms < 60_000, "smoke shouldn't take >60s");
}

#[test]
fn stale_part_file_does_not_block_new_download() {
    // Setup: bge_dir contains a stale model.onnx.part with junk bytes from
    // a hypothetical earlier crash. The new download must overwrite it
    // cleanly and produce the correct final file.
    let model_onnx = b"GRAPH".to_vec();
    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", model_onnx.clone()),
        ("model.onnx_data", vec![0u8; 1024]),
        ("Constant_7_attr__value", b"CONST".to_vec()),
        ("tokenizer.json", br#"{"version":"1.0"}"#.to_vec()),
    ]);
    let addr = serve_fixed_payloads(payloads);
    let base_url = format!("http://{addr}/");

    let temp = tempfile::TempDir::new().unwrap();
    let models_dir = temp.path().join("models");
    let bge_dir = models_dir.join("bge-m3");
    std::fs::create_dir_all(&bge_dir).unwrap();
    // Seed a stale `.part` with junk bytes that do not match the upcoming
    // download payload.
    let stale_part = bge_dir.join("model.onnx.part");
    std::fs::write(&stale_part, b"junk-bytes-from-a-prior-crash").unwrap();

    let mut reporter = NullReporter;
    download_bge_m3(&models_dir, &base_url, &mut reporter)
        .expect("download succeeds despite stale .part");

    // The new payload is at the final path with the right bytes.
    assert_eq!(
        std::fs::read(bge_dir.join("model.onnx")).unwrap(),
        model_onnx
    );
    // The stale `.part` is gone after the rename.
    assert!(
        !stale_part.exists(),
        "stale model.onnx.part should be removed after successful download"
    );
}

#[test]
fn no_part_files_left_after_successful_download() {
    let payloads: HashMap<&'static str, Vec<u8>> = HashMap::from([
        ("model.onnx", b"GRAPH".to_vec()),
        ("model.onnx_data", vec![0u8; 1024]),
        ("Constant_7_attr__value", b"CONST".to_vec()),
        ("tokenizer.json", br#"{"version":"1.0"}"#.to_vec()),
    ]);
    let addr = serve_fixed_payloads(payloads);
    let base_url = format!("http://{addr}/");

    let temp = tempfile::TempDir::new().unwrap();
    let models_dir = temp.path().join("models");
    std::fs::create_dir_all(&models_dir).unwrap();
    let mut reporter = NullReporter;
    download_bge_m3(&models_dir, &base_url, &mut reporter).expect("download succeeds");

    let bge_dir = models_dir.join("bge-m3");
    let mut entries: Vec<_> = std::fs::read_dir(&bge_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    // Four expected files; no `.part` siblings.
    assert_eq!(entries.len(), 4, "got {entries:?}");
    for name in &entries {
        assert!(
            !std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("part")),
            "{name} left over"
        );
    }
}
