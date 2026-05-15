//! Integration test: spin up a tiny HTTP server (stub the four bge-m3
//! files with fixed payloads), point the downloader at it, assert all
//! four files land at the right path with the right byte counts.

use std::collections::HashMap;
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use nexum_core::embed::install::download_bge_m3;
use nexum_core::embed::reporter::NullReporter;

/// Tiny single-threaded HTTP server that serves a fixed map of paths to
/// payloads. Returns 404 on unknown paths. Runs until the test scope ends.
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
