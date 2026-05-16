//! bge-m3 install pipeline: download → verify → smoke-test → flip
//! `[embed].enabled = true` in config.toml. This module ships the
//! download leg plus the post-download verification and ORT smoke
//! round-trip.

use std::path::{Path, PathBuf};
use std::time::Instant;

use futures_util::StreamExt as _;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::embedder::Embedder;
use super::manifest::{BGE_M3_FILES, ManifestEntry};
use super::reporter::{NullReporter, Reporter};
use super::types::{EMBED_DIM, EmbedError};
use crate::config::Config;

/// Coalesce byte-progress callbacks to one per ~64 KiB of read body
/// (matching the `Reporter::bytes` doc contract). Without debouncing the
/// chunk loop floods the reporter on slow links where the stream emits
/// 1–16 KiB chunks.
const REPORT_STEP: u64 = 64 * 1024;

/// Summary of one install run. The CLI command surfaces this on success.
#[derive(Debug, Clone, Copy)]
pub struct InstallReport {
    /// Bytes actually pulled across the wire.
    pub downloaded: u64,
    /// Smoke-test inference latency. `None` means the smoke test was
    /// skipped (test-mode); `Some(d)` means it ran and took `d`.
    pub smoke_test: Option<std::time::Duration>,
}

/// Download the four bge-m3 files from `model_base_url` into
/// `<models_dir>/bge-m3/`. Synchronous wrapper around an internal tokio
/// runtime so the CLI command (sync) and the indexer (sync) can both
/// call it without dragging in async.
///
/// # Errors
/// `EmbedError::Io` on filesystem failures (`create_dir`, open, write).
/// `EmbedError::Download` on HTTP-layer failures.
pub fn download_bge_m3(
    models_dir: &Path,
    model_base_url: &str,
    reporter: &mut dyn Reporter,
) -> Result<InstallReport, EmbedError> {
    download_with_manifest(models_dir, model_base_url, BGE_M3_FILES, reporter)
}

/// Manifest-parameterized variant of [`download_bge_m3`]. The public
/// entry point delegates to this with the pinned `BGE_M3_FILES`;
/// integration tests pass a smaller fixture manifest so a stub HTTP
/// server can serve tiny payloads with matching SHA256s.
fn download_with_manifest(
    models_dir: &Path,
    model_base_url: &str,
    manifest: &[ManifestEntry],
    reporter: &mut dyn Reporter,
) -> Result<InstallReport, EmbedError> {
    let runtime = build_blocking_runtime(models_dir)?;
    runtime.block_on(download_async(
        models_dir,
        model_base_url,
        manifest,
        reporter,
    ))
}

/// Build the small current-thread tokio runtime used by the synchronous
/// download entry points. Centralised so both [`download_with_manifest`]
/// and [`default_redownload`] stay in sync; the MCP server's
/// multi-thread runtime is a different shape and lives elsewhere.
fn build_blocking_runtime(path_for_error: &Path) -> Result<tokio::runtime::Runtime, EmbedError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| EmbedError::Io {
            path: path_for_error.to_owned(),
            source: e,
        })
}

async fn download_async(
    models_dir: &Path,
    model_base_url: &str,
    manifest: &[ManifestEntry],
    reporter: &mut dyn Reporter,
) -> Result<InstallReport, EmbedError> {
    let bge_dir = models_dir.join("bge-m3");
    tokio::fs::create_dir_all(&bge_dir)
        .await
        .map_err(|e| EmbedError::Io {
            path: bge_dir.clone(),
            source: e,
        })?;

    let base = model_base_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| EmbedError::Download {
            file: String::new(),
            source: e,
        })?;

    let mut downloaded: u64 = 0;
    for entry in manifest {
        let url = format!("{base}/{}", entry.name());
        let dest = bge_dir.join(entry.name());
        reporter.progress(&format!(
            "downloading {} ({})…",
            entry.name(),
            fmt_size(entry.size())
        ));
        let bytes = download_one(&client, &url, &dest, entry, reporter).await?;
        downloaded += bytes;
    }

    Ok(InstallReport {
        downloaded,
        smoke_test: None,
    })
}

async fn download_one(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    entry: &ManifestEntry,
    reporter: &mut dyn Reporter,
) -> Result<u64, EmbedError> {
    // Stream to a `.part` sibling, then rename atomically once `flush`
    // succeeds. A crash mid-stream leaves the `.part` file behind; the
    // final `dest` only ever exists as a byte-complete download.
    let temp_dest: PathBuf = {
        let mut s = dest.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    // Determine how far a prior run got.
    let existing = tokio::fs::metadata(&temp_dest).await.map_or(0, |m| m.len());

    // Fast-path: the .part is already at the manifest's expected size, so
    // the previous run crashed between flush and rename. Rename in place;
    // verify_manifest catches any corruption via SHA256.
    if existing == entry.size() {
        tokio::fs::rename(&temp_dest, dest)
            .await
            .map_err(|e| EmbedError::Io {
                path: dest.to_owned(),
                source: e,
            })?;
        reporter.bytes(existing, existing);
        return Ok(0);
    }

    // Over-size .part is corrupt: more bytes than the manifest expected.
    // Delete and start fresh so we never silently append to a bogus file.
    let initial_done = if existing > entry.size() {
        let _ = tokio::fs::remove_file(&temp_dest).await;
        0
    } else {
        existing
    };

    // First GET (with Range when resuming). On 416 the server says we are
    // already past EOF, so wipe the .part and retry once without Range (one
    // retry max; propagate whatever the second response brings).
    let resp = send_get(client, url, entry, initial_done).await?;
    let (resp, effective_initial) =
        if resp.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE && initial_done > 0 {
            let _ = tokio::fs::remove_file(&temp_dest).await;
            (send_get(client, url, entry, 0).await?, 0)
        } else {
            // On 206 Partial Content append; on 200 OK (server ignoring
            // Range) truncate and start fresh to avoid duplicating bytes.
            let resume = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT && initial_done > 0;
            (resp, if resume { initial_done } else { 0 })
        };
    let resp = resp.error_for_status().map_err(|e| EmbedError::Download {
        file: entry.name().to_owned(),
        source: e,
    })?;
    download_streaming(resp, &temp_dest, dest, entry, reporter, effective_initial).await
}

/// Issue a GET, optionally with `Range: bytes=<initial_done>-`. Returns the
/// raw response without applying `error_for_status` so the caller can
/// inspect 416 before deciding whether to retry.
async fn send_get(
    client: &reqwest::Client,
    url: &str,
    entry: &ManifestEntry,
    initial_done: u64,
) -> Result<reqwest::Response, EmbedError> {
    let mut req = client.get(url);
    if initial_done > 0 {
        req = req.header("Range", format!("bytes={initial_done}-"));
    }
    req.send().await.map_err(|e| EmbedError::Download {
        file: entry.name().to_owned(),
        source: e,
    })
}

/// Stream `resp` body into `temp_dest`, flush, then rename to `dest`.
/// `initial_done` is the number of bytes already present at the start of
/// the network transfer (non-zero only on a 206 resume). Returns the count
/// of bytes pulled from the network on this call.
async fn download_streaming(
    resp: reqwest::Response,
    temp_dest: &Path,
    dest: &Path,
    entry: &ManifestEntry,
    reporter: &mut dyn Reporter,
    initial_done: u64,
) -> Result<u64, EmbedError> {
    let total: u64 = if initial_done > 0 {
        // saturating_sub guards against a manifest that shrank between
        // runs: an over-size .part is normally caught earlier, but if a
        // server returns 206 without Content-Length against a manifest
        // that we can no longer fully serve, falling back to 0 keeps the
        // reporter denominator sane instead of panicking on underflow.
        initial_done
            + resp
                .content_length()
                .unwrap_or(entry.size().saturating_sub(initial_done))
    } else {
        resp.content_length().unwrap_or(entry.size())
    };

    let mut file = if initial_done > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(temp_dest)
            .await
            .map_err(|e| EmbedError::Io {
                path: temp_dest.to_owned(),
                source: e,
            })?
    } else {
        tokio::fs::File::create(temp_dest)
            .await
            .map_err(|e| EmbedError::Io {
                path: temp_dest.to_owned(),
                source: e,
            })?
    };

    let mut stream = resp.bytes_stream();
    let mut done: u64 = initial_done;
    let mut last_reported: u64 = initial_done;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| EmbedError::Download {
            file: entry.name().to_owned(),
            source: e,
        })?;
        file.write_all(&chunk).await.map_err(|e| EmbedError::Io {
            path: temp_dest.to_owned(),
            source: e,
        })?;
        done += chunk.len() as u64;
        if done - last_reported >= REPORT_STEP || done == total {
            reporter.bytes(done, total);
            last_reported = done;
        }
    }
    file.flush().await.map_err(|e| EmbedError::Io {
        path: temp_dest.to_owned(),
        source: e,
    })?;
    // Release the OS handle before rename — required on Windows, harmless
    // on Unix.
    drop(file);
    tokio::fs::rename(temp_dest, dest)
        .await
        .map_err(|e| EmbedError::Io {
            path: dest.to_owned(),
            source: e,
        })?;
    Ok(done - initial_done)
}

/// Verify each downloaded file's SHA256 against the pinned manifest and
/// run a single ORT inference round-trip. Sets `report.smoke_test` to
/// `Some(elapsed)` on success.
///
/// On checksum mismatch: deletes the offending file and asks the network
/// layer to re-download it once. If the replacement also fails to match,
/// returns `EmbedError::ChecksumMismatch` and leaves no partial file
/// behind.
///
/// # Errors
/// `EmbedError::ChecksumMismatch` if a file's hash still mismatches after
/// one retry. `EmbedError::Io` on filesystem failures.
/// `EmbedError::Download` on retry-time HTTP failures.
/// `EmbedError::OrtInit` / `EmbedError::OrtRun` on ORT failures.
/// `EmbedError::OutputShapeMismatch` if the model's output dim drifts.
pub fn verify_and_smoke(
    models_dir: &Path,
    model_base_url: &str,
    report: &mut InstallReport,
    reporter: &mut dyn Reporter,
) -> Result<(), EmbedError> {
    verify_and_smoke_with(
        models_dir,
        BGE_M3_FILES,
        report,
        reporter,
        default_redownload(model_base_url),
    )
}

/// One-shot install: download → verify → smoke-test. Returns the
/// updated [`Config`] with `embed.enabled = true` and
/// `embed.model_path` set; the caller writes the config back to disk.
///
/// # Errors
///
/// Any `EmbedError` raised by the download, verify, or smoke legs.
pub fn install_bge_m3(
    models_dir: &Path,
    cfg: &Config,
    reporter: &mut dyn Reporter,
) -> Result<(InstallReport, Config), EmbedError> {
    install_bge_m3_with(models_dir, cfg, reporter, BGE_M3_FILES, false)
}

/// Test-friendly variant of [`install_bge_m3`]. Accepts an explicit
/// manifest slice (so integration tests can stub small fixture files
/// with matching SHA256s) and a `skip_smoke` toggle (so tests do not
/// need a real ONNX export on disk). Production callers always go
/// through [`install_bge_m3`].
///
/// # Errors
///
/// Same as [`install_bge_m3`].
#[doc(hidden)]
pub fn install_bge_m3_with(
    models_dir: &Path,
    cfg: &Config,
    reporter: &mut dyn Reporter,
    manifest: &[ManifestEntry],
    skip_smoke: bool,
) -> Result<(InstallReport, Config), EmbedError> {
    reporter.progress("starting bge-m3 install");
    let mut report =
        download_with_manifest(models_dir, &cfg.embed.model_base_url, manifest, reporter)?;
    reporter.progress("download complete; verifying hashes");
    verify_manifest(
        models_dir,
        manifest,
        reporter,
        default_redownload(&cfg.embed.model_base_url),
    )?;
    if skip_smoke {
        reporter.progress("smoke test skipped");
    } else {
        run_smoke(models_dir, &mut report, reporter)?;
    }

    let model_path = models_dir.join("bge-m3").join("model.onnx");
    let mut next = cfg.clone();
    next.embed.enabled = true;
    next.embed.model_path = model_path.to_string_lossy().into_owned();
    Ok((report, next))
}

/// Test-friendly variant of [`verify_and_smoke`] that accepts a manifest
/// and a `redownload` closure (called once per file on first hash
/// mismatch). Production callers go through [`verify_and_smoke`]; this
/// is exposed under `#[doc(hidden)]` so integration tests can swap in a
/// tiny manifest with a controlled retry closure.
#[doc(hidden)]
pub fn verify_and_smoke_with<R>(
    models_dir: &Path,
    manifest: &[ManifestEntry],
    report: &mut InstallReport,
    reporter: &mut dyn Reporter,
    redownload: R,
) -> Result<(), EmbedError>
where
    R: FnMut(&ManifestEntry, &Path) -> Result<(), EmbedError>,
{
    verify_manifest(models_dir, manifest, reporter, redownload)?;
    run_smoke(models_dir, report, reporter)?;
    Ok(())
}

/// Verify every entry's SHA256 against its manifest hash. On the FIRST
/// mismatch, delete the file and ask the caller to re-download it once
/// (via the `redownload` closure); rehash the replacement. If the second
/// hash still mismatches, return `ChecksumMismatch`. Retry once, then
/// fail closed — never accept a hash mismatch.
fn verify_manifest(
    models_dir: &Path,
    manifest: &[ManifestEntry],
    reporter: &mut dyn Reporter,
    mut redownload: impl FnMut(&ManifestEntry, &Path) -> Result<(), EmbedError>,
) -> Result<(), EmbedError> {
    let bge_dir = models_dir.join("bge-m3");
    for entry in manifest {
        let path = bge_dir.join(entry.name());
        reporter.progress(&format!("verifying {}…", entry.name()));

        let first = sha256_hex_of_file(&path).map_err(|e| EmbedError::Io {
            path: path.clone(),
            source: e,
        })?;
        if first == entry.sha256() {
            continue;
        }

        // First-try mismatch. Delete + re-download once + re-hash.
        reporter.progress(&format!(
            "{}: hash mismatch on first download; retrying once…",
            entry.name()
        ));
        let _ = std::fs::remove_file(&path);
        redownload(entry, &path)?;
        let second = sha256_hex_of_file(&path).map_err(|e| EmbedError::Io {
            path: path.clone(),
            source: e,
        })?;
        if second == entry.sha256() {
            continue;
        }

        // Second mismatch — give up.
        let _ = std::fs::remove_file(&path);
        return Err(EmbedError::ChecksumMismatch {
            file: entry.name().to_owned(),
            expected: entry.sha256().to_owned(),
            actual: second,
        });
    }
    Ok(())
}

/// Production `redownload` closure: pull a single file from
/// `model_base_url` via reqwest and overwrite `dest`. Routes through
/// the same streaming + `.part` rename path as the initial download so
/// a multi-GB retry never buffers the full body in memory and a crash
/// mid-stream cannot leave a half-written `dest` behind.
///
/// The retry leg uses a local `NullReporter` for byte-progress callbacks.
/// `verify_manifest` takes both a `&mut dyn Reporter` for outer progress
/// and a `redownload: impl FnMut(…)` closure; Rust cannot allow both to
/// hold a mutable borrow of the same reporter simultaneously. Outer
/// progress (hash-mismatch notice and retry announcement) still reaches
/// the caller via `verify_manifest`'s own `reporter` argument before
/// this closure fires.
fn default_redownload(
    model_base_url: &str,
) -> impl FnMut(&ManifestEntry, &Path) -> Result<(), EmbedError> + '_ {
    move |entry: &ManifestEntry, dest: &Path| -> Result<(), EmbedError> {
        let runtime = build_blocking_runtime(dest)?;
        runtime.block_on(async move {
            let url = format!("{}/{}", model_base_url.trim_end_matches('/'), entry.name());
            let client = reqwest::Client::builder()
                .build()
                .map_err(|e| EmbedError::Download {
                    file: entry.name().to_owned(),
                    source: e,
                })?;
            let mut retry_reporter = NullReporter;
            download_one(&client, &url, dest, entry, &mut retry_reporter).await?;
            Ok(())
        })
    }
}

fn sha256_hex_of_file(path: &Path) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    // 64 KiB read buffer; heap-allocated to keep the stack frame small.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn run_smoke(
    models_dir: &Path,
    report: &mut InstallReport,
    reporter: &mut dyn Reporter,
) -> Result<(), EmbedError> {
    reporter.progress("running ORT smoke test…");
    let bge_dir = models_dir.join("bge-m3");
    let embedder = Embedder::load(&bge_dir)?;
    let t0 = Instant::now();
    let vec = embedder.embed("The quick brown fox jumps over the lazy dog.")?;
    let elapsed = t0.elapsed();
    if vec.len() != EMBED_DIM {
        return Err(EmbedError::OutputShapeMismatch {
            expected: vec![1, EMBED_DIM],
            actual: vec![1, vec.len()],
        });
    }
    report.smoke_test = Some(elapsed);
    reporter.progress(&format!("smoke test passed in {} ms", elapsed.as_millis()));
    Ok(())
}

// Human-readable byte size — used only in progress messages, so the
// f64 rounding past 2^53 is fine (and bge-m3's largest file is ~2 GiB).
#[allow(clippy::cast_precision_loss)]
fn fmt_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.0} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn install_report_smoke_defaults_to_none() {
        let r = InstallReport {
            downloaded: 0,
            smoke_test: None,
        };
        assert!(r.smoke_test.is_none());
    }

    #[test]
    fn install_report_smoke_carries_duration() {
        let r = InstallReport {
            downloaded: 42,
            smoke_test: Some(Duration::from_millis(123)),
        };
        assert_eq!(r.smoke_test.unwrap().as_millis(), 123);
    }
}

#[cfg(test)]
mod resume_tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;

    // 64-char all-zero placeholder; tests bypass SHA256 via direct
    // `download_one` calls so the hash content is irrelevant.
    const DUMMY_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// True when `req` carries a `Range:` header (HTTP header names are
    /// case-insensitive; reqwest sends them lowercased).
    fn request_has_range(req: &str) -> bool {
        req.lines().any(|l| {
            l.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("range"))
        })
    }

    /// Parse the start offset from a `Range: bytes=<N>-` header, defaulting
    /// to 0 when absent or unparseable.
    fn parse_range_start(req: &str) -> usize {
        req.lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                if !name.eq_ignore_ascii_case("range") {
                    return None;
                }
                let bytes = value.trim().strip_prefix("bytes=")?;
                bytes.split('-').next()?.parse::<usize>().ok()
            })
            .unwrap_or(0)
    }

    /// Build the `<dest>.part` sibling path the downloader writes to.
    fn part_path(dest: &Path) -> PathBuf {
        let mut s = dest.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    }

    /// Spin up a tiny async HTTP server that honours `Range: bytes=N-`
    /// requests. Returns a 206 Partial Content slice for range requests and
    /// a 200 OK for plain GETs.
    async fn serve_with_range(body: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = Arc::new(body);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let body = Arc::clone(&body);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    let mut buf = vec![0u8; 4096];
                    let n = tokio::io::AsyncReadExt::read(&mut sock, &mut buf)
                        .await
                        .unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let range_start = parse_range_start(&req);
                    let slice = &body[range_start..];
                    let status = if range_start > 0 {
                        "206 Partial Content"
                    } else {
                        "200 OK"
                    };
                    let header = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                        slice.len(),
                    );
                    let _ = sock.write_all(header.as_bytes()).await;
                    let _ = sock.write_all(slice).await;
                });
            }
        });
        addr
    }

    /// Server that always returns 416 for any Range request.
    async fn serve_416_then_full(body: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = Arc::new(body);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let body = Arc::clone(&body);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    let mut buf = vec![0u8; 4096];
                    let n = tokio::io::AsyncReadExt::read(&mut sock, &mut buf)
                        .await
                        .unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let has_range = request_has_range(&req);
                    if has_range {
                        // Respond 416 to Range requests.
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n",
                            )
                            .await;
                    } else {
                        // Respond 200 with the full body for the retry GET.
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                            body.len(),
                        );
                        let _ = sock.write_all(header.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                    }
                });
            }
        });
        addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resumes_from_existing_part_size() {
        // Pre-populate a .part with the first half of a known body.
        let full: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let half = full[..512].to_vec();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("model.onnx");
        std::fs::write(part_path(&dest), &half).unwrap();

        let addr = serve_with_range(full.clone()).await;
        let entry = ManifestEntry::new("model.onnx", 1024, DUMMY_SHA);
        let url = format!("http://{addr}/model.onnx");
        let client = reqwest::Client::builder().build().unwrap();
        let mut reporter = NullReporter;
        let bytes = download_one(&client, &url, &dest, &entry, &mut reporter)
            .await
            .unwrap();
        // Only the missing half should be pulled across the wire.
        assert_eq!(bytes, 512);
        // The renamed destination must contain the full body.
        assert_eq!(std::fs::read(&dest).unwrap(), full);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn skips_get_when_part_already_complete() {
        // A .part already at the manifest's expected size: skip the network,
        // rename in place; SHA256 verification happens in verify_manifest.
        let body: Vec<u8> = (0u8..=255).cycle().take(64).collect();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("ok.bin");
        std::fs::write(part_path(&dest), &body).unwrap();

        let addr = serve_with_range(body.clone()).await;
        let entry = ManifestEntry::new("ok.bin", 64, DUMMY_SHA);
        let url = format!("http://{addr}/ok.bin");
        let client = reqwest::Client::builder().build().unwrap();
        let mut reporter = NullReporter;
        let bytes = download_one(&client, &url, &dest, &entry, &mut reporter)
            .await
            .unwrap();
        // No bytes pulled across the wire.
        assert_eq!(bytes, 0);
        assert_eq!(std::fs::read(&dest).unwrap(), body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retries_without_range_on_416() {
        // A .part exists (partial), but the server responds 416. The
        // downloader must delete the .part and fetch the full body.
        let full: Vec<u8> = (0u8..=127).collect();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("model.bin");
        let part = part_path(&dest);
        // Seed a .part with half the data (to trigger a Range request).
        std::fs::write(&part, &full[..64]).unwrap();

        let addr = serve_416_then_full(full.clone()).await;
        let entry = ManifestEntry::new("model.bin", 128, DUMMY_SHA);
        let url = format!("http://{addr}/model.bin");
        let client = reqwest::Client::builder().build().unwrap();
        let mut reporter = NullReporter;
        let bytes = download_one(&client, &url, &dest, &entry, &mut reporter)
            .await
            .unwrap();
        // On 416 → retry: full body pulled from network.
        assert_eq!(bytes, 128);
        assert_eq!(std::fs::read(&dest).unwrap(), full);
        // The .part file is gone after the rename.
        assert!(!part.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn over_size_part_is_discarded_and_restarted() {
        // A .part whose byte count exceeds entry.size() is corrupt. The
        // downloader must delete it and pull the full body afresh.
        let full: Vec<u8> = (0u8..=63).collect();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("corrupt.bin");
        // Write more bytes than entry.size() will declare.
        let bloated: Vec<u8> = (0u8..=127).collect();
        std::fs::write(part_path(&dest), &bloated).unwrap();

        let addr = serve_with_range(full.clone()).await;
        // entry.size() is 64, but the .part has 128 bytes.
        let entry = ManifestEntry::new("corrupt.bin", 64, DUMMY_SHA);
        let url = format!("http://{addr}/corrupt.bin");
        let client = reqwest::Client::builder().build().unwrap();
        let mut reporter = NullReporter;
        let bytes = download_one(&client, &url, &dest, &entry, &mut reporter)
            .await
            .unwrap();
        // Full body re-pulled; no Range header sent because .part was wiped.
        assert_eq!(bytes, 64);
        assert_eq!(std::fs::read(&dest).unwrap(), full);
    }
}
