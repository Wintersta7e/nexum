//! Path canonicalization (§13, Linux + WSL2 only — Windows-native fixtures are
//! M1b validation debt).
//!
//! `canonicalize_path` runs:
//!   1. Platform normalization: on WSL2, `C:\path` → `/mnt/c/path`. On Linux
//!      native, no-op (paths are already in the canonical form). Detection
//!      reads `/proc/version` for "microsoft" / "wsl".
//!   2. Symlink resolution: `std::fs::canonicalize`, capped at 32 hops via the
//!      OS's own depth check (we don't manually count; we let the kernel error
//!      out and translate the `EINVAL`/`ELOOP` into `CanonError::SymlinkDepth`).
//!   3. Trailing separator strip.
//!
//! Cross-OS, junctions, subst drives, UNC paths, Git Bash form, and case-
//! insensitive FS are M1b validation debt per spec patch1 §13. This impl skips
//! them; the corresponding fixtures don't exist in M1.
//!
//! `path_hint(canonical)` `SHA256`-hashes the path and returns the first 16 hex
//! chars (= 64 bits of identity) per §13 step 5.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum CanonError {
    #[error("symlink chain depth exceeded ({0} hops)")]
    SymlinkDepth(usize),
    #[error("io error during canonicalization: {0}")]
    Io(#[from] std::io::Error),
}

/// Return the canonical form of `input` per §13 (Linux + WSL2 layer).
///
/// Note: this calls `std::fs::canonicalize`, which means the input MUST exist
/// on disk (or the call returns an io error). Callers that need a "best-effort"
/// canonicalization for nonexistent paths should use a different helper (added
/// in a future phase if needed).
///
/// # Errors
/// Returns `CanonError::SymlinkDepth` if symlink chain exceeds the kernel's hop
/// limit (`ELOOP`); `CanonError::Io` for other filesystem errors (missing path,
/// permission denied, etc.).
pub fn canonicalize_path(input: &Path) -> Result<PathBuf, CanonError> {
    let normalized = wsl_normalize(input);
    let resolved = std::fs::canonicalize(&normalized).map_err(|e| {
        // Translate ELOOP into a more specific error variant.
        if matches!(e.raw_os_error(), Some(40)) {
            // Linux ELOOP = 40
            CanonError::SymlinkDepth(40)
        } else {
            CanonError::Io(e)
        }
    })?;
    Ok(strip_trailing_separator(&resolved))
}

/// `SHA256`-hash a canonicalized path; return first 16 hex chars per §13 step 5.
#[must_use]
pub fn path_hint(canonical: &Path) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(canonical.to_string_lossy().as_bytes());
    let digest = h.finalize();
    digest[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
}

// ---- internals ------------------------------------------------------------

/// On WSL2 only, translate `C:\path` (or `c:\path`, etc.) to `/mnt/c/path`.
/// On Linux native, returns the input unchanged.
fn wsl_normalize(input: &Path) -> PathBuf {
    if !is_wsl() {
        return input.to_owned();
    }
    let s = input.to_string_lossy();
    // Match `<letter>:\path` or `<letter>:/path`. Letter case insensitive.
    let bytes = s.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let tail = s[3..].replace('\\', "/");
        return PathBuf::from(format!("/mnt/{drive}/{tail}"));
    }
    input.to_owned()
}

fn is_wsl() -> bool {
    // /proc/version is Linux-only; on real Linux it doesn't contain "microsoft" or "wsl".
    std::fs::read_to_string("/proc/version").is_ok_and(|s| {
        let lower = s.to_ascii_lowercase();
        lower.contains("microsoft") || lower.contains("wsl")
    })
}

fn strip_trailing_separator(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let trimmed = s.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        // Don't return "" — `/` should canonicalize to `/`, not `""`.
        PathBuf::from("/")
    } else {
        PathBuf::from(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_hint_is_16_hex_chars() {
        let h = path_hint(Path::new("/some/path"));
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn path_hint_is_deterministic() {
        let a = path_hint(Path::new("/a/b/c"));
        let b = path_hint(Path::new("/a/b/c"));
        assert_eq!(a, b);
    }

    #[test]
    fn path_hint_distinguishes_distinct_paths() {
        assert_ne!(path_hint(Path::new("/a")), path_hint(Path::new("/b")));
    }

    #[test]
    fn strip_trailing_separator_removes_one() {
        assert_eq!(
            strip_trailing_separator(Path::new("/a/b/")),
            Path::new("/a/b")
        );
    }

    #[test]
    fn strip_trailing_separator_preserves_root() {
        assert_eq!(strip_trailing_separator(Path::new("/")), Path::new("/"));
    }

    #[test]
    fn strip_trailing_separator_idempotent_when_no_sep() {
        assert_eq!(
            strip_trailing_separator(Path::new("/a/b")),
            Path::new("/a/b")
        );
    }

    #[test]
    fn wsl_normalize_passthrough_on_linux_paths() {
        // Whether or not we're on WSL, an already-Unix path is unchanged.
        assert_eq!(
            wsl_normalize(Path::new("/home/user/foo")),
            PathBuf::from("/home/user/foo")
        );
    }

    #[test]
    fn wsl_normalize_handles_windows_drive_when_on_wsl() {
        if !is_wsl() {
            // Skip this test on non-WSL hosts; the conversion is a no-op and the
            // assertion would be trivially true.
            return;
        }
        assert_eq!(
            wsl_normalize(Path::new(r"C:\Users\foo")),
            PathBuf::from("/mnt/c/Users/foo")
        );
        assert_eq!(
            wsl_normalize(Path::new(r"c:/users/foo")),
            PathBuf::from("/mnt/c/users/foo")
        );
    }

    #[test]
    fn canonicalize_path_resolves_a_real_temp_dir() {
        // Smoke: create a temp dir, canonicalize its path, verify the result
        // exists and is absolute.
        let tmp = tempfile::Builder::new()
            .prefix("canon-test-")
            .tempdir()
            .unwrap();
        let canon = canonicalize_path(tmp.path()).unwrap();
        assert!(canon.exists());
        assert!(canon.is_absolute());
    }
}
