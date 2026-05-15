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
use super::reporter::Reporter;
use super::types::{EMBED_DIM, EmbedError};

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
    /// Manifest total — useful for the CLI to confirm we read the right
    /// amount.
    pub total_bytes: u64,
    /// Smoke-test inference latency. Filled by the verify-and-smoke
    /// step; zero until that step has run successfully.
    pub smoke_test_ms: u64,
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| EmbedError::Io {
            path: models_dir.to_owned(),
            source: e,
        })?;
    runtime.block_on(download_async(models_dir, model_base_url, reporter))
}

async fn download_async(
    models_dir: &Path,
    model_base_url: &str,
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
    for entry in BGE_M3_FILES {
        let url = format!("{base}/{}", entry.name);
        let dest = bge_dir.join(entry.name);
        reporter.progress(&format!(
            "downloading {} ({})…",
            entry.name,
            fmt_size(entry.size)
        ));
        let bytes = download_one(&client, &url, &dest, entry, reporter).await?;
        downloaded += bytes;
    }

    Ok(InstallReport {
        downloaded,
        total_bytes: super::manifest::bge_m3_total_bytes(),
        smoke_test_ms: 0,
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
            file: entry.name.to_owned(),
            source: e,
        })?;
    let resp = resp.error_for_status().map_err(|e| EmbedError::Download {
        file: entry.name.to_owned(),
        source: e,
    })?;
    let total: u64 = resp.content_length().unwrap_or(entry.size);

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
            file: entry.name.to_owned(),
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
/// run a single ORT inference round-trip. Mutates `report.smoke_test_ms`
/// on success.
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
/// hash still mismatches, return `ChecksumMismatch`. This matches the
/// published install contract: retry once, then fail.
fn verify_manifest(
    models_dir: &Path,
    manifest: &[ManifestEntry],
    reporter: &mut dyn Reporter,
    mut redownload: impl FnMut(&ManifestEntry, &Path) -> Result<(), EmbedError>,
) -> Result<(), EmbedError> {
    let bge_dir = models_dir.join("bge-m3");
    for entry in manifest {
        let path = bge_dir.join(entry.name);
        reporter.progress(&format!("verifying {}…", entry.name));

        let first = sha256_hex_of_file(&path).map_err(|e| EmbedError::Io {
            path: path.clone(),
            source: e,
        })?;
        if first == entry.sha256 {
            continue;
        }

        // First-try mismatch. Delete + re-download once + re-hash.
        reporter.progress(&format!(
            "{}: hash mismatch on first download; retrying once…",
            entry.name
        ));
        let _ = std::fs::remove_file(&path);
        redownload(entry, &path)?;
        let second = sha256_hex_of_file(&path).map_err(|e| EmbedError::Io {
            path: path.clone(),
            source: e,
        })?;
        if second == entry.sha256 {
            continue;
        }

        // Second mismatch — give up.
        let _ = std::fs::remove_file(&path);
        return Err(EmbedError::ChecksumMismatch {
            file: entry.name.to_owned(),
            expected: entry.sha256.to_owned(),
            actual: second,
        });
    }
    Ok(())
}

/// Production `redownload` closure: pull a single file from
/// `model_base_url` via reqwest and overwrite `dest`.
fn default_redownload(
    model_base_url: &str,
) -> impl FnMut(&ManifestEntry, &Path) -> Result<(), EmbedError> + '_ {
    move |entry: &ManifestEntry, dest: &Path| -> Result<(), EmbedError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|e| EmbedError::Io {
                path: dest.to_owned(),
                source: e,
            })?;
        runtime.block_on(async move {
            let url = format!("{}/{}", model_base_url.trim_end_matches('/'), entry.name);
            let resp = reqwest::Client::new()
                .get(&url)
                .send()
                .await
                .map_err(|e| EmbedError::Download {
                    file: entry.name.to_owned(),
                    source: e,
                })?
                .error_for_status()
                .map_err(|e| EmbedError::Download {
                    file: entry.name.to_owned(),
                    source: e,
                })?;
            let bytes = resp.bytes().await.map_err(|e| EmbedError::Download {
                file: entry.name.to_owned(),
                source: e,
            })?;
            tokio::fs::write(dest, &bytes)
                .await
                .map_err(|e| EmbedError::Io {
                    path: dest.to_owned(),
                    source: e,
                })?;
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
    let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    report.smoke_test_ms = ms;
    reporter.progress(&format!("smoke test passed in {ms} ms"));
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
