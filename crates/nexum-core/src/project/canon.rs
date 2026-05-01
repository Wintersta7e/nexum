//! Path canonicalization (§13, Linux + WSL2 only — Windows-native fixtures are
//! M1b validation debt).
//!
//! `canonicalize_path` runs:
//!   1. Platform normalization: on WSL2, `C:\path` → `/mnt/c/path`. On Linux
//!      native, no-op (paths are already in the canonical form). Detection
//!      reads `/proc/version` for "microsoft" / "wsl".
//!   2. Symlink resolution: `std::fs::canonicalize`, capped at 32 hops via the
//!      OS's own depth check (we don't manually count; we let the kernel error
//!      out and translate the `EINVAL`/`ELOOP` into `CanonError::SymlinkLoop`).
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
    #[error("symlink chain depth exceeded (ELOOP)")]
    SymlinkLoop,
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
/// Returns `CanonError::SymlinkLoop` if symlink chain exceeds the kernel's hop
/// limit (`ELOOP`); `CanonError::Io` for other filesystem errors (missing path,
/// permission denied, etc.).
pub fn canonicalize_path(input: &Path) -> Result<PathBuf, CanonError> {
    let normalized = wsl_normalize(input);
    let resolved = std::fs::canonicalize(&normalized).map_err(|e| {
        // Translate ELOOP into a more specific error variant.
        if matches!(e.raw_os_error(), Some(40)) {
            // Linux ELOOP = 40 — translate to a typed variant so callers can
            // distinguish symlink loops from generic IO errors.
            CanonError::SymlinkLoop
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

/// Canonicalize a git remote `URL` per §13:
///   1. Strip credentials: `https://user:pass@host/repo.git` → `https://host/repo.git`
///   2. Normalize `SSH` form: `git@github.com:user/repo.git` → `ssh://git@github.com/user/repo.git`
///   3. Strip trailing `.git`
///   4. Lowercase host
///
/// Returns the canonical form. Garbage input is returned best-effort (this is a
/// string transform, not a `URL` validator).
#[must_use]
pub fn canonicalize_git_url(input: &str) -> String {
    let s = input.trim();
    let s = ssh_form_normalize(s);
    let s = strip_credentials(&s);
    let s = strip_trailing_dot_git(&s);
    lowercase_host(&s)
}

/// Hash a canonicalized git `URL`; returns `git:<16-hex>` per §13 step 5.
#[must_use]
pub fn git_url_hint(canonical: &str) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let digest = h.finalize();
    let hex = digest[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        });
    format!("git:{hex}")
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
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        // /proc/version is Linux-only; on real Linux it doesn't contain "microsoft" or "wsl".
        std::fs::read_to_string("/proc/version").is_ok_and(|s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("microsoft") || lower.contains("wsl")
        })
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

fn ssh_form_normalize(s: &str) -> String {
    // SSH short form: `git@host:user/repo.git` (no scheme; `:` separates host from path).
    // Skip if already a `scheme://...` URL.
    if s.contains("://") {
        return s.to_owned();
    }
    if let Some(at_pos) = s.find('@')
        && let Some(colon_pos) = s[at_pos..].find(':')
    {
        let user = &s[..at_pos];
        let host = &s[at_pos + 1..at_pos + colon_pos];
        let path = &s[at_pos + colon_pos + 1..];
        return format!("ssh://{user}@{host}/{path}");
    }
    s.to_owned()
}

fn strip_credentials(s: &str) -> String {
    if let Some(scheme_end) = s.find("://") {
        let after_scheme = &s[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            // For SSH (`ssh://git@host/...`), the user IS the legitimate
            // credential — keep it. Strip only password-bearing forms like
            // `user:pass@host`.
            if after_scheme[..at_pos].contains(':') {
                return format!("{}://{}", &s[..scheme_end], &after_scheme[at_pos + 1..]);
            }
        }
    }
    s.to_owned()
}

fn strip_trailing_dot_git(s: &str) -> String {
    s.strip_suffix(".git").unwrap_or(s).to_owned()
}

fn lowercase_host(s: &str) -> String {
    if let Some(scheme_end) = s.find("://") {
        let rest = &s[scheme_end + 3..];
        // Drop optional `user@` first (we already stripped pass:user pairs).
        let (userinfo, host_and_path) = match rest.find('@') {
            Some(at_pos) => (Some(&rest[..=at_pos]), &rest[at_pos + 1..]),
            None => (None, rest),
        };
        let (host, path) = match host_and_path.find('/') {
            Some(slash_pos) => (&host_and_path[..slash_pos], &host_and_path[slash_pos..]),
            None => (host_and_path, ""),
        };
        return format!(
            "{}://{}{}{}",
            &s[..scheme_end],
            userinfo.unwrap_or(""),
            host.to_ascii_lowercase(),
            path
        );
    }
    s.to_owned()
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

    #[test]
    fn canonicalize_https_strips_creds_and_dot_git() {
        assert_eq!(
            canonicalize_git_url("https://user:pass@github.com/owner/repo.git"),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn canonicalize_ssh_short_form_is_normalized() {
        assert_eq!(
            canonicalize_git_url("git@github.com:owner/repo.git"),
            "ssh://git@github.com/owner/repo"
        );
    }

    #[test]
    fn canonicalize_ssh_long_form_is_idempotent() {
        let canon = canonicalize_git_url("ssh://git@github.com/owner/repo.git");
        assert_eq!(canon, "ssh://git@github.com/owner/repo");
        // Re-canonicalizing produces the same value.
        assert_eq!(canonicalize_git_url(&canon), canon);
    }

    #[test]
    fn canonicalize_lowercases_host_only() {
        assert_eq!(
            canonicalize_git_url("https://GitHub.com/Owner/Repo.git"),
            "https://github.com/Owner/Repo"
        );
    }

    #[test]
    fn canonicalize_trims_whitespace() {
        assert_eq!(
            canonicalize_git_url("  https://github.com/o/r.git  "),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn git_url_hint_has_git_prefix_and_16_hex() {
        let h = git_url_hint("https://github.com/o/r");
        assert!(h.starts_with("git:"));
        assert_eq!(h.len(), 4 + 16);
        assert!(h[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn git_url_hint_is_deterministic() {
        let a = git_url_hint("https://github.com/o/r");
        let b = git_url_hint("https://github.com/o/r");
        assert_eq!(a, b);
    }
}
