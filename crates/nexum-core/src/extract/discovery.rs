//! Discover candidate sessions from CC project dirs and Codex's state DB.
//!
//! Two free functions feed the `extract` CLI's `--since` and `--backfill`
//! triggers: [`discover_cc_sessions`] walks a CC `projects_dir` for
//! per-session `<uuid>.jsonl` files, and [`discover_codex_sessions`] reads
//! the Codex `state_5.sqlite.threads` table. Each emits a [`Candidate`]
//! describing one extractable session.
//!
//! [`parse_since`] converts a duration argument like `"24h"` / `"7d"` /
//! `"30m"` into a `chrono::Duration` so callers can build the cutoff
//! threshold the discovery fns filter against.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use rusqlite::Connection;
use uuid::Uuid;

use crate::extract::digest::{SessionId, SessionKind};
use crate::extract::model::ExtractError;

/// One discovered session candidate. Carries the typed id, the
/// transcript kind, the on-disk path the digest builder reads, and an
/// estimated byte size for cost-projection use cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub session_id: SessionId,
    pub kind: SessionKind,
    pub source_path: PathBuf,
    pub estimated_size_bytes: u64,
}

/// Parse a duration like `24h`, `7d`, `30m` into a `chrono::Duration`.
///
/// # Errors
/// Returns [`ExtractError::Validation`] for any other shape (empty input,
/// non-numeric prefix, or unit char outside `{h,d,m}`).
pub fn parse_since(s: &str) -> Result<Duration, ExtractError> {
    let trimmed = s.trim();
    let Some(last) = trimmed.chars().last() else {
        return Err(ExtractError::Validation {
            reason: "--since is empty".to_owned(),
        });
    };
    if !last.is_ascii_alphabetic() {
        return Err(ExtractError::Validation {
            reason: format!("--since `{trimmed}` is missing a unit suffix (h/d/m)"),
        });
    }
    let unit = last.to_ascii_lowercase();
    let num_part = &trimmed[..trimmed.len() - last.len_utf8()];
    let n: i64 = num_part.parse().map_err(|e| ExtractError::Validation {
        reason: format!("--since numeric part `{num_part}`: {e}"),
    })?;
    match unit {
        'h' => Ok(Duration::hours(n)),
        'd' => Ok(Duration::days(n)),
        'm' => Ok(Duration::minutes(n)),
        other => Err(ExtractError::Validation {
            reason: format!("--since unit `{other}` not in h/d/m"),
        }),
    }
}

/// Codex discovery: read `state_5.sqlite.threads` for non-archived rows
/// whose `created_at_ms >= since` (when supplied).
///
/// Returns an empty `Vec` when `state_db` does not exist — operators who
/// have not run the upstream Codex CLI will not have one.
///
/// # Errors
/// I/O or SQL errors wrapped as [`ExtractError::Io`].
pub fn discover_codex_sessions(
    state_db: &Path,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<Candidate>, ExtractError> {
    if !state_db.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(state_db).map_err(|e| map_sqlite(&e))?;
    let cutoff_ms: i64 = since.map_or(0, |t| t.timestamp_millis());
    let mut stmt = conn
        .prepare(
            "SELECT id, rollout_path \
             FROM threads \
             WHERE archived = 0 \
               AND created_at_ms >= ?1 \
             ORDER BY updated_at_ms DESC",
        )
        .map_err(|e| map_sqlite(&e))?;
    let rows = stmt
        .query_map([cutoff_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| map_sqlite(&e))?;
    let mut out = Vec::new();
    for row in rows {
        let (thread_id, rollout_path) = row.map_err(|e| map_sqlite(&e))?;
        let path = PathBuf::from(&rollout_path);
        let size = std::fs::metadata(&path).map_or(0, |m| m.len());
        out.push(Candidate {
            session_id: SessionId::CodexThread(thread_id.clone()),
            kind: SessionKind::CodexThread { thread_id },
            source_path: path,
            estimated_size_bytes: size,
        });
    }
    Ok(out)
}

/// CC discovery: walk `<projects_dir>/<cwd-slug>/<uuid>.jsonl` (exactly
/// two levels deep) and yield one [`Candidate`] per recognizable file.
///
/// Returns an empty `Vec` when `projects_dir` does not exist. Files
/// whose stem is not a valid UUID are silently skipped — CC's transcript
/// layout uses the session UUID as the filename, so anything else is
/// noise (rotated backups, editor swap files).
///
/// # Errors
/// I/O errors from the metadata read are surfaced as [`ExtractError::Io`].
pub fn discover_cc_sessions(
    projects_dir: &Path,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<Candidate>, ExtractError> {
    if !projects_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(projects_dir)
        .min_depth(2)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
    {
        let metadata = entry
            .metadata()
            .map_err(|e| ExtractError::Io(std::io::Error::other(e.to_string())))?;
        if let Some(cutoff) = since
            && let Some(modified) = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| {
                    let secs = i64::try_from(d.as_secs()).ok()?;
                    DateTime::<Utc>::from_timestamp(secs, d.subsec_nanos())
                })
            && modified < cutoff
        {
            continue;
        }
        let stem = entry
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let Ok(uuid) = Uuid::from_str(stem) else {
            // Not a session-uuid filename; ignore.
            continue;
        };
        out.push(Candidate {
            session_id: SessionId::Cc(uuid),
            kind: SessionKind::CcTranscript,
            source_path: entry.path().to_path_buf(),
            estimated_size_bytes: metadata.len(),
        });
    }
    Ok(out)
}

fn map_sqlite(e: &rusqlite::Error) -> ExtractError {
    ExtractError::Io(std::io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since("24h").unwrap(), Duration::hours(24));
    }

    #[test]
    fn parse_since_days() {
        assert_eq!(parse_since("7d").unwrap(), Duration::days(7));
    }

    #[test]
    fn parse_since_minutes() {
        assert_eq!(parse_since("30m").unwrap(), Duration::minutes(30));
    }

    #[test]
    fn parse_since_rejects_unknown_unit() {
        let err = parse_since("5w").unwrap_err();
        assert!(err.to_string().contains("unit"));
    }
}
