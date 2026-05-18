//! Local adapter — reads `notebook.git/{decisions,recommendations,failures}/*.yml`.
//!
//! Each `<id>.yml` parses to one `UnifiedRecord`. The adapter only discovers
//! the commit that last touched the record (`git log -1 --format=%H -- <path>`)
//! and stamps it on `Provenance.record_commit_sha`. Cryptographic verification
//! is run once per unique commit by the indexer's crypto-batch step, which
//! then rewrites `crypto_result`, `signer_fingerprint`, and
//! `relevant_trust_events_commit` on every record before upsert. The
//! read-time projection joins the cached crypto outcome with the materialized
//! `trust_events` view to produce the final `signature_status` / `trust_basis`
//! / `warnings`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    adapter::trait_def::{
        Adapter, AdapterError, AdapterPass, PassCompleteness, SkipKind, SkipReason,
    },
    records::{
        Agent, Confidence, CryptoResult, FileEvidence, FileEvidenceKind, Outcome, ProjectId,
        Provenance, RecordId, RecordSummary, RecordType, SessionRef, SignatureStatus, Source,
        UnifiedRecord, content_hash,
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
        let Ok(top) = fs::read_dir(&self.notebook_git) else {
            return out;
        };
        for entry in top.flatten() {
            let p = entry.path();
            let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !p.is_dir() {
                continue;
            }
            // `.git` is the git store; `.trust` holds historical signers and
            // trust events. Neither contains record YAML.
            if name == ".git" || name == ".trust" {
                continue;
            }
            if TYPE_DIRS.contains(&name) {
                // Legacy top-level layout: notebook.git/<type>/*.yml
                push_yml_files(&p, &mut out);
            } else {
                // Per-project layout: notebook.git/<project>/<type>/*.yml
                for type_dir in TYPE_DIRS {
                    push_yml_files(&p.join(type_dir), &mut out);
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
    // `title` is optional because the M2 extract pipeline emits YAML built
    // around the model's schema (`problem`, `chosen`, ...). When `title` is
    // absent we synthesize it from the first line of `problem` so the record
    // remains addressable through the read path.
    #[serde(default)]
    title: Option<String>,
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
    // Model-emitted recommendation/decision shape — used only as a title
    // fallback when the canonical `title` field is absent.
    #[serde(default)]
    problem: Option<String>,
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
    // Legacy records carry a top-level `title`. The M2 extract pipeline
    // serializes the model's schema (`problem`, ...) and omits `title`, so
    // we fall back to the first line of `problem` to keep the record
    // addressable through the read path.
    let title = parsed
        .title
        .or_else(|| {
            parsed
                .problem
                .as_ref()
                .and_then(|p| p.lines().next().map(str::to_owned))
        })
        .unwrap_or_default();
    let hash = content_hash(&title, parsed.summary.as_deref(), &body);
    let agent = map_agent(parsed.agent.as_deref());
    let outcome = map_outcome(parsed.outcome.as_deref());
    let confidence = map_confidence(parsed.confidence.as_deref());

    let session_refs = decode_session_refs(parsed.session_refs);
    let files = decode_files(parsed.files);

    let project_id: ProjectId = parsed
        .project_id
        .or_else(|| derive_project_id_from_path(notebook_git, path))
        .unwrap_or_else(|| "local-no-project".into());

    // The adapter only discovers `record_commit_sha` here. Cryptographic
    // verification runs once per unique commit in the indexer's
    // `crypto_batch` step, which then overwrites `crypto_result`,
    // `signer_fingerprint`, and `relevant_trust_events_commit` on every
    // record. The placeholders below are deliberate stubs.
    let record_commit_sha = compute_record_commit_sha(notebook_git, path);

    Ok(Box::new(UnifiedRecord {
        id: parsed.id,
        record_type,
        source: Source::Local,
        project_id,
        title,
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
            // The read-time projection derives the real signature status
            // from `crypto_result` + `trust_events`; the adapter stamps a
            // placeholder so the struct stays well-formed for callers
            // (e.g., adapter-only unit tests) that bypass the batch.
            signature_status: SignatureStatus::Unsigned,
            extractor: None,
            digest_hash: None,
            record_commit_sha,
            signer_fingerprint: None,
            crypto_result: CryptoResult::NoSignature,
            relevant_trust_events_commit: None,
            trust_basis: None,
            warnings: Vec::new(),
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

/// Record-type subdirectories under both layouts:
/// - legacy top-level: `notebook.git/<type>/<id>.yml`
/// - per-project:      `notebook.git/<project>/<type>/<id>.yml`
const TYPE_DIRS: &[&str] = &["decisions", "recommendations", "failures", "untyped"];

/// Push every `*.yml` file (case-insensitive) in `dir` onto `out`. A missing
/// or unreadable directory is treated as empty — neither layout requires every
/// type subdirectory to exist.
fn push_yml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        {
            out.push(p);
        }
    }
}

/// Derive the project id from `record_path` when it sits under the per-project
/// layout (`notebook.git/<project>/<type>/<id>.yml`). Returns `None` for the
/// legacy top-level layout, leaving the caller to fall back to whatever the
/// YAML body or the wider default supplies.
fn derive_project_id_from_path(notebook_git: &Path, record_path: &Path) -> Option<String> {
    let rel = record_path.strip_prefix(notebook_git).ok()?;
    let mut comps: Vec<_> = rel.components().collect();
    // Drop the filename component so what remains is the directory chain.
    comps.pop()?;
    if comps.len() == 2 {
        comps
            .first()?
            .as_os_str()
            .to_str()
            .map(std::borrow::ToOwned::to_owned)
    } else {
        None
    }
}

/// Identify the SHA of the commit that last touched `record_path` on
/// `notebook_git`. Returns `None` when the path is outside the notebook,
/// when `git log` fails to spawn, or when the file has no history yet
/// (untracked or freshly added in the working tree). The crypto-batch
/// step in `indexer::crypto_batch` consumes this SHA to drive the
/// once-per-commit `git verify` shell-out.
fn compute_record_commit_sha(notebook_git: &Path, record_path: &Path) -> Option<String> {
    let relative = record_path.strip_prefix(notebook_git).ok()?;
    // Route through the shared env-scrubbed `git()` helper so every
    // SHA-resolving path in the workspace sees the same git config view —
    // a user-global `gitconfig` rewriting `core.commitGraph` (or any other
    // history-affecting setting) cannot make this lookup disagree with
    // the verify pass that consumes the resulting SHA.
    let out = crate::trust::git_history::git(notebook_git)
        .args(["log", "-1", "--format=%H", "--"])
        .arg(relative)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if sha.is_empty() { None } else { Some(sha) }
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

    fn minimal_yaml_no_project_id(id: &str, kind: &str) -> String {
        format!(
            "schema_version: 1\n\
             id: {id}\n\
             record_type: {kind}\n\
             title: example title\n\
             summary: example summary\n\
             body: |\n  example body line\n\
             tags: []\n\
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
    fn per_project_layout_record_is_discovered() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_yaml(
            &nb.join("_inbox")
                .join("recommendations")
                .join("2026-05-17-retry.yml"),
            &minimal_yaml("2026-05-17-retry", "recommendation"),
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1);
        assert_eq!(pass.records[0].id, "2026-05-17-retry");
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn mixed_legacy_and_per_project_layout_are_both_walked() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        // Legacy top-level
        write_yaml(
            &nb.join("decisions").join("2026-04-29-legacy.yml"),
            &minimal_yaml("2026-04-29-legacy", "decision"),
        );
        // Per-project
        write_yaml(
            &nb.join("_inbox")
                .join("recommendations")
                .join("2026-05-17-extract.yml"),
            &minimal_yaml("2026-05-17-extract", "recommendation"),
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        let mut ids: Vec<String> = pass.records.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["2026-04-29-legacy", "2026-05-17-extract"]);
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn project_id_is_derived_from_subdir_when_yaml_omits_it() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_yaml(
            &nb.join("_inbox").join("decisions").join("2026-05-17-x.yml"),
            &minimal_yaml_no_project_id("2026-05-17-x", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let r = adapter.read(&"2026-05-17-x".to_owned()).expect("read ok");
        assert_eq!(r.project_id, "_inbox");
    }

    #[test]
    fn yaml_project_id_takes_precedence_over_subdir_name() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        // Sit the file under `foo/` but bake `project_id: example-project`
        // into the YAML. The YAML field is authoritative.
        write_yaml(
            &nb.join("foo").join("decisions").join("2026-05-17-y.yml"),
            &minimal_yaml("2026-05-17-y", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let r = adapter.read(&"2026-05-17-y".to_owned()).expect("read ok");
        assert_eq!(r.project_id, "example-project");
    }

    #[test]
    fn legacy_top_level_record_defaults_to_local_no_project_when_yaml_omits_id() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        write_yaml(
            &nb.join("decisions").join("2026-05-17-legacy.yml"),
            &minimal_yaml_no_project_id("2026-05-17-legacy", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let r = adapter
            .read(&"2026-05-17-legacy".to_owned())
            .expect("read ok");
        assert_eq!(r.project_id, "local-no-project");
    }

    #[test]
    fn reserved_top_level_dirs_are_skipped() {
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        // Plant YAML inside `.git` and `.trust` directories that mimic a type
        // subdir — discover must not walk into them. (`.git` is the git store
        // and `.trust` holds historical signers and trust events; neither
        // contains record YAML in production.)
        write_yaml(
            &nb.join(".git").join("decisions").join("ghost.yml"),
            &minimal_yaml("ghost", "decision"),
        );
        write_yaml(
            &nb.join(".trust").join("recommendations").join("ghost.yml"),
            &minimal_yaml("ghost", "recommendation"),
        );
        // And one real record so we know list succeeds and only finds it.
        write_yaml(
            &nb.join("decisions").join("real.yml"),
            &minimal_yaml("real", "decision"),
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1);
        assert_eq!(pass.records[0].id, "real");
    }

    #[test]
    fn extract_pipeline_yaml_body_parses() {
        // Mirrors what the extract pipeline writes to disk after re-serializing
        // the model's raw YAML mapping. If this parses, `nexum get` will see
        // the record after the discovery walk; if it fails, the read path is
        // still blocked even with the discovery fix.
        let dir = TempDir::new().unwrap();
        let nb = dir.path().join("notebook.git");
        let body = "schema_version: 1\n\
                    id: 2026-05-17-retry-backoff\n\
                    record_type: recommendation\n\
                    outcome: proposed\n\
                    agent: claude-code\n\
                    confidence: medium\n\
                    tags:\n- tooling\n\
                    session_refs:\n- kind: cc_session\n  uuid: 01900000-0000-7000-8000-000000000000\n\
                    created: 2026-05-17T10:00:00Z\n\
                    updated: 2026-05-17T10:00:00Z\n\
                    problem: noisy retry behavior\n\
                    chosen: add a retry-backoff knob\n\
                    options_considered: []\n\
                    rationale: []\n\
                    files: []\n\
                    commits: []\n";
        write_yaml(
            &nb.join("_inbox")
                .join("recommendations")
                .join("2026-05-17-retry-backoff.yml"),
            body,
        );
        let adapter = LocalAdapter::new(nb);
        let pass = adapter.list().expect("list ok");
        assert_eq!(
            pass.records.len(),
            1,
            "extract pipeline YAML must parse via LocalAdapter; completeness={:?}",
            pass.completeness
        );
        // Inspect the resulting record: title falls back to the first line of
        // `problem`, project_id is derived from the subdir, and the record
        // type maps cleanly to Recommendation.
        let r = adapter
            .read(&"2026-05-17-retry-backoff".to_owned())
            .expect("read ok");
        assert_eq!(r.title, "noisy retry behavior");
        assert_eq!(r.project_id, "_inbox");
        assert_eq!(r.record_type, RecordType::Recommendation);
    }
}
