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
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| EmbedError::Download {
            file: entry.name().to_owned(),
            source: e,
        })?;
    let resp = resp.error_for_status().map_err(|e| EmbedError::Download {
        file: entry.name().to_owned(),
        source: e,
    })?;
    let total: u64 = resp.content_length().unwrap_or(entry.size());

    // Stream to a `.part` sibling, then rename atomically once `flush`
    // succeeds. A crash mid-stream leaves the `.part` file behind; the
    // final `dest` only ever exists as a byte-complete download.
    let temp_dest: PathBuf = {
        let mut s = dest.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    let mut file = tokio::fs::File::create(&temp_dest)
        .await
        .map_err(|e| EmbedError::Io {
            path: temp_dest.clone(),
            source: e,
        })?;

    let mut stream = resp.bytes_stream();
    let mut done: u64 = 0;
    let mut last_reported: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| EmbedError::Download {
            file: entry.name().to_owned(),
            source: e,
        })?;
        file.write_all(&chunk).await.map_err(|e| EmbedError::Io {
            path: temp_dest.clone(),
            source: e,
        })?;
        done += chunk.len() as u64;
        if done - last_reported >= REPORT_STEP || done == total {
            reporter.bytes(done, total);
            last_reported = done;
        }
    }
    file.flush().await.map_err(|e| EmbedError::Io {
        path: temp_dest.clone(),
        source: e,
    })?;
    // Release the OS handle before rename — required on Windows, harmless
    // on Unix.
    drop(file);
    tokio::fs::rename(&temp_dest, dest)
        .await
        .map_err(|e| EmbedError::Io {
            path: dest.to_owned(),
            source: e,
        })?;
    Ok(done)
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
