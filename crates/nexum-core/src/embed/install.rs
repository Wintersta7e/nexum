//! bge-m3 install pipeline: download → verify → smoke-test → flip
//! `[embed].enabled = true` in config.toml. This module ships the
//! download leg; verification and the ORT smoke-test land in
//! follow-up changes.

use std::path::Path;

use futures_util::StreamExt as _;
use tokio::io::AsyncWriteExt;

use super::manifest::{BGE_M3_FILES, ManifestEntry};
use super::reporter::Reporter;
use super::types::EmbedError;

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

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| EmbedError::Io {
            path: dest.to_owned(),
            source: e,
        })?;

    let mut stream = resp.bytes_stream();
    let mut done: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| EmbedError::Download {
            file: entry.name.to_owned(),
            source: e,
        })?;
        file.write_all(&chunk).await.map_err(|e| EmbedError::Io {
            path: dest.to_owned(),
            source: e,
        })?;
        done += chunk.len() as u64;
        reporter.bytes(done, total);
    }
    file.flush().await.map_err(|e| EmbedError::Io {
        path: dest.to_owned(),
        source: e,
    })?;
    Ok(done)
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
