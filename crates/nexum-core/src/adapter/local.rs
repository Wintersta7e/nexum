//! Local adapter — reads `notebook.git/{decisions,recommendations,failures}/*.yml`.
//!
//! Each `<id>.yml` parses to one `UnifiedRecord`. The signature status is
//! computed by identifying the commit that last touched the file and
//! redirecting `git verify-commit` through `.trust/historical_signers` (the
//! historical-signers contract). Verifier OK → `Verified` + `TrustBasis::Current`;
//! verifier rejects or no signature → `Unsigned`. The richer trust state
//! machine integration with the materialized `trust_events` view is deferred
//! to a later milestone.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    adapter::trait_def::{
        Adapter, AdapterError, AdapterPass, PassCompleteness, SkipKind, SkipReason,
    },
    init::git_ops::git_verify_commit_with_signers_and_details,
    records::{
        Agent, Confidence, FileEvidence, FileEvidenceKind, Outcome, ProjectId, Provenance,
        RecordId, RecordSummary, RecordType, SessionRef, SignatureStatus, Source, TrustBasis,
        UnifiedRecord, WARNING_VERIFIER_REJECTED, content_hash,
    },
};

/// Local adapter — reads `notebook.git/{decisions,recommendations,failures}/*.yml`.
pub struct LocalAdapter {
    notebook_git: PathBuf,
}

impl LocalAdapter {
    /// Construct from `~/.nexum/notebook.git` path.
    #[must_use]
    pub fn new(notebook_git: PathBuf) -> Self {
        Self { notebook_git }
    }

    fn discover(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for kind in ["decisions", "recommendations", "failures"] {
            let dir = self.notebook_git.join(kind);
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
                {
                    out.push(p);
                }
            }
        }
        out
    }
}

impl Adapter for LocalAdapter {
    fn source(&self) -> Source {
        Source::Local
    }

    fn list(&self) -> Result<AdapterPass, AdapterError> {
        // Detect missing root vs other I/O failures BEFORE walking. The
        // contract is: missing root surfaces as `MissingRoot` (indexer
        // suppresses both upserts and deletes); other I/O errors surface as
        // `Unreadable` (also a hard no-op). Any "directory exists but is
        // empty" case continues into the normal walk below and yields
        // `Authoritative` + zero records.
        //
        // Note: there is a narrow TOCTOU window between this probe and the walk
        // below. If the root disappears in that window the walk surfaces an IO
        // error that propagates as AdapterError::Io, not MissingRoot. Acceptable;
        // the next pass catches it.
        match fs::metadata(&self.notebook_git) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AdapterPass {
                    source: Source::Local,
                    records: Vec::new(),
                    completeness: PassCompleteness::MissingRoot {
                        path: self.notebook_git.clone(),
                    },
                });
            }
            Err(e) => {
                return Ok(AdapterPass {
                    source: Source::Local,
                    records: Vec::new(),
                    completeness: PassCompleteness::Unreadable {
                        path: self.notebook_git.clone(),
                        reason: e.to_string(),
                    },
                });
            }
        }

        let mut records: Vec<RecordSummary> = Vec::new();
        let mut skipped: Vec<SkipReason> = Vec::new();

        for path in self.discover() {
            match parse_local_record(&self.notebook_git, &path) {
                Ok(r) => records.push(RecordSummary {
                    id: r.id.clone(),
                    content_hash: r.content_hash.clone(),
                }),
                Err(LocalParseError::Malformed(reason) | LocalParseError::IoTransient(reason)) => {
                    skipped.push(reason);
                }
            }
        }

        let completeness = if skipped.is_empty() {
            PassCompleteness::Authoritative
        } else {
            PassCompleteness::Partial { skipped }
        };
        Ok(AdapterPass {
            source: Source::Local,
            records,
            completeness,
        })
    }

    fn read(&self, id: &RecordId) -> Result<UnifiedRecord, AdapterError> {
        for path in self.discover() {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if stem == id {
                return parse_local_record(&self.notebook_git, &path)
                    .map(|r| *r)
                    .map_err(|e| match e {
                        LocalParseError::Malformed(r) => AdapterError::MalformedRecord {
                            path: r.path,
                            detail: "local yaml parse failure".into(),
                        },
                        LocalParseError::IoTransient(r) => AdapterError::Io {
                            path: r.path,
                            source: std::io::Error::other("transient i/o"),
                        },
                    });
            }
        }
        Err(AdapterError::Io {
            path: PathBuf::from(id),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, format!("local record {id}")),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct LocalRecordYaml {
    schema_version: u32,
    id: String,
    record_type: String,
    #[serde(default)]
    project_id: Option<String>,
    title: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    agent: Option<String>,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    session_refs: Vec<serde_yaml::Value>,
    #[serde(default)]
    files: Vec<serde_yaml::Value>,
    #[serde(default)]
    commits: Vec<String>,
    #[serde(default)]
    provenance: Option<serde_yaml::Value>,
}

enum LocalParseError {
    Malformed(SkipReason),
    IoTransient(SkipReason),
}

fn parse_local_record(
    notebook_git: &Path,
    path: &Path,
) -> Result<Box<UnifiedRecord>, LocalParseError> {
    let raw = fs::read_to_string(path).map_err(|_| {
        LocalParseError::IoTransient(SkipReason {
            path: path.to_owned(),
            kind: SkipKind::FileTransient,
            at: Utc::now(),
        })
    })?;
    let parsed: LocalRecordYaml = serde_yaml::from_str(&raw).map_err(|_| {
        LocalParseError::Malformed(SkipReason {
            path: path.to_owned(),
            kind: SkipKind::FileMalformed,
            at: Utc::now(),
        })
    })?;

    let record_type = map_record_type(&parsed.record_type);
    let body = parsed.body.unwrap_or_default();
    let hash = content_hash(&parsed.title, parsed.summary.as_deref(), &body);
    let agent = map_agent(parsed.agent.as_deref());
    let outcome = map_outcome(parsed.outcome.as_deref());
    let confidence = map_confidence(parsed.confidence.as_deref());

    let session_refs = decode_session_refs(parsed.session_refs);
    let files = decode_files(parsed.files);

    let project_id: ProjectId = parsed
        .project_id
        .unwrap_or_else(|| "local-no-project".into());

    // TODO: shells out to git twice per record (log + verify-commit). Future
    // verifier work should batch this across all records in one pass.
    let verification = compute_signature_status(notebook_git, path);

    Ok(Box::new(UnifiedRecord {
        id: parsed.id,
        record_type,
        source: Source::Local,
        project_id,
        title: parsed.title,
        summary: parsed.summary,
        body,
        body_origin_path: Some(path.to_owned()),
        tags: parsed.tags,
        agent,
        session_refs,
        files,
        commits: parsed.commits,
        created: parsed.created,
        updated: parsed.updated,
        confidence,
        outcome,
        provenance: Provenance {
            source: Source::Local,
            signature_status: verification.status,
            trust_basis: verification.trust_basis,
            extractor: None,
            digest_hash: None,
            record_commit_sha: verification.record_commit_sha,
            signer_fingerprint: verification.signer_fingerprint,
            warning_code: verification.warning_code,
        },
        extras: HashMap::new(),
        content_hash: hash,
    }))
}

fn map_record_type(s: &str) -> RecordType {
    match s {
        "decision" => RecordType::Decision,
        "recommendation" => RecordType::Recommendation,
        "failure" => RecordType::Failure,
        _ => RecordType::Untyped,
    }
}

fn map_agent(s: Option<&str>) -> Agent {
    match s {
        Some("codex") => Agent::Codex,
        Some("claude-code" | "cc") => Agent::ClaudeCode,
        _ => Agent::Manual,
    }
}

fn map_outcome(s: Option<&str>) -> Outcome {
    match s {
        Some("working") => Outcome::Working,
        Some("reverted") => Outcome::Reverted,
        Some("superseded") => Outcome::Superseded,
        Some("proposed") => Outcome::Proposed,
        Some("promoted") => Outcome::Promoted,
        Some("rejected") => Outcome::Rejected,
        Some("stale") => Outcome::Stale,
        Some("attempted") => Outcome::Attempted,
        _ => Outcome::NotApplicable,
    }
}

fn map_confidence(s: Option<&str>) -> Confidence {
    match s {
        Some("low") => Confidence::Low,
        Some("high") => Confidence::High,
        _ => Confidence::Medium,
    }
}

fn decode_session_refs(raw: Vec<serde_yaml::Value>) -> Vec<SessionRef> {
    // Best-effort coerce; unknown shapes are dropped silently — the local YAML
    // format is canonical, so an unknown shape is a writer bug rather than a
    // parser concern.
    raw.into_iter()
        .filter_map(|v| serde_yaml::from_value::<SessionRef>(v).ok())
        .collect()
}

fn decode_files(raw: Vec<serde_yaml::Value>) -> Vec<FileEvidence> {
    raw.into_iter()
        .filter_map(|v| {
            // Plain-string entries auto-coerce to ParsedFromMemoryBody.
            if let serde_yaml::Value::String(s) = &v {
                return Some(FileEvidence {
                    path: PathBuf::from(s),
                    kind: FileEvidenceKind::ParsedFromMemoryBody,
                });
            }
            serde_yaml::from_value::<FileEvidence>(v).ok()
        })
        .collect()
}

/// Verifier provenance for one record, populated by
/// [`compute_signature_status`]. Schema scaffolding for the verifier
/// pipeline; the next milestone may extend this with rotation /
/// reanchor signals.
#[derive(Debug, Clone)]
struct VerificationResult {
    status: SignatureStatus,
    trust_basis: Option<TrustBasis>,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    warning_code: Option<String>,
}

impl VerificationResult {
    /// Default for a record whose signature could not be evaluated at all
    /// (path outside the notebook, no commit history, missing
    /// `historical_signers`). Treated identically to "no signature
    /// present".
    fn unevaluable() -> Self {
        Self {
            status: SignatureStatus::Unsigned,
            trust_basis: None,
            record_commit_sha: None,
            signer_fingerprint: None,
            warning_code: None,
        }
    }
}

fn compute_signature_status(notebook_git: &Path, record_path: &Path) -> VerificationResult {
    // Step 1: identify the commit that last touched `record_path`.
    let Ok(relative) = record_path.strip_prefix(notebook_git) else {
        return VerificationResult::unevaluable();
    };
    let log_out = Command::new("git")
        .args(["log", "-1", "--format=%H", "--"])
        .arg(relative)
        .current_dir(notebook_git)
        .output();
    let sha = match log_out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        _ => return VerificationResult::unevaluable(),
    };
    if sha.is_empty() {
        return VerificationResult::unevaluable();
    }
    // Step 2: redirect verify-commit through historical_signers.
    let historical_signers = notebook_git.join(".trust").join("historical_signers");
    if !historical_signers.exists() {
        // We have a commit SHA but cannot verify against the notebook's
        // signer set — capture the SHA so a future verifier pass can
        // recompute against a freshly-materialized signer view.
        return VerificationResult {
            status: SignatureStatus::Unsigned,
            trust_basis: Some(TrustBasis::Unsigned),
            record_commit_sha: Some(sha),
            signer_fingerprint: None,
            warning_code: None,
        };
    }
    match git_verify_commit_with_signers_and_details(notebook_git, &sha, &historical_signers) {
        Ok(details) => VerificationResult {
            status: SignatureStatus::Verified,
            trust_basis: Some(TrustBasis::Current),
            record_commit_sha: Some(sha),
            signer_fingerprint: details.signer_fingerprint,
            warning_code: None,
        },
        Err(_) => {
            // The verifier rejected the commit. The current minimum
            // mapping still collapses this to `Unsigned`; the verifier
            // milestone promotes `Invalid` as a distinct status with a
            // richer diagnostic. Emit `warning_code = "verifier-rejected"`
            // so consumers can already distinguish "no signature was
            // attempted" from "a signature failed verification".
            VerificationResult {
                status: SignatureStatus::Unsigned,
                trust_basis: None,
                record_commit_sha: Some(sha),
                signer_fingerprint: None,
                warning_code: Some(WARNING_VERIFIER_REJECTED.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_yaml(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn minimal_yaml(id: &str, kind: &str) -> String {
        format!(
            "schema_version: 1\n\
             id: {id}\n\
             record_type: {kind}\n\
             project_id: example-project\n\
             title: example title\n\
             summary: example summary\n\
             body: |\n  example body line\n\
             tags: [auth, security]\n\
             agent: manual\n\
             created: 2026-04-29T14:32:00Z\n\
             updated: 2026-04-29T14:32:00Z\n\
             confidence: high\n\
             outcome: working\n\
             session_refs: []\n\
             files: []\n\
             commits: []\n\
             provenance:\n  source: nexum-extracted\n\
             content_hash: deadbeef\n"
        )
    }

    #[test]
    fn missing_notebook_dir_returns_missing_root() {
        let dir = TempDir::new().unwrap();
        let expected = dir.path().join("notebook.git");
        let adapter = LocalAdapter::new(expected.clone());
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        match pass.completeness {
            PassCompleteness::MissingRoot { path } => assert_eq!(path, expected),
            other => panic!("expected MissingRoot, got {other:?}"),
        }
    }

    #[test]
    fn empty_notebook_dir_returns_authoritative_zero() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        fs::create_dir_all(&nb).unwrap();
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn one_decision_file_yields_one_record() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_yaml(
            &nb.join("decisions").join("2026-04-29-jwt.yml"),
            &minimal_yaml("2026-04-29-jwt", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1);
        assert_eq!(pass.records[0].id, "2026-04-29-jwt");
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn malformed_yaml_surfaces_as_partial_pass() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        // Two files, one good, one bad.
        write_yaml(
            &nb.join("decisions").join("good.yml"),
            &minimal_yaml("good", "decision"),
        );
        write_yaml(
            &nb.join("recommendations").join("bad.yml"),
            "this is :: not [valid yaml [",
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1, "good record proceeds");
        match pass.completeness {
            PassCompleteness::Partial { skipped } => {
                assert_eq!(skipped.len(), 1);
                assert_eq!(skipped[0].kind, SkipKind::FileMalformed);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn read_returns_full_record_with_unsigned_default() {
        // For test purposes (no git repo), read() uses the same parser path
        // and falls back to SignatureStatus::Unsigned when the verifier can't
        // run. Real verification happens at indexer time, not parser time.
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_yaml(
            &nb.join("decisions").join("2026-04-29-z.yml"),
            &minimal_yaml("2026-04-29-z", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let r = adapter.read(&"2026-04-29-z".to_owned()).expect("read ok");
        assert_eq!(r.title, "example title");
        assert_eq!(r.source, Source::Local);
        // Without a real git history at this path the verifier returns
        // SignatureStatus::Unsigned (the current minimum mapping).
        assert_eq!(r.provenance.signature_status, SignatureStatus::Unsigned);
    }
}
