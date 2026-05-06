//! CC adapter — reads `<projects_dir>/*/memory/*.md` and emits `UnifiedRecord`s.
//!
//! - Each per-topic file (`feedback_*.md`, `project_*.md`, `user_*.md`,
//!   `reference_*.md`) is one record.
//! - `MEMORY.md` is the index file — never ingested as a record.
//! - `<session-uuid>.jsonl` at the project root is a session transcript —
//!   skipped by the read path; extraction owns it.
//! - The CC slug encodes the original cwd via `/` → `-` substitution. We
//!   use `crate::project::resolve::resolve` (with a `ProjectInput` whose
//!   `cc_slug` field is set) to compute `project_id`. Ambiguous slugs surface
//!   as `ProjectResolution::Ambiguous`; the adapter falls back to the ranked
//!   first candidate so indexing can proceed.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    adapter::trait_def::{
        Adapter, AdapterError, AdapterPass, PassCompleteness, SkipKind, SkipReason,
    },
    project::{ProjectInput, ProjectResolution, resolve::resolve as resolve_project},
    records::{
        Agent, Confidence, CryptoResult, Outcome, ProjectId, Provenance, RecordId, RecordSummary,
        RecordType, SessionRef, SignatureStatus, Source, UnifiedRecord, content_hash,
    },
};

/// CC adapter — reads `<projects_dir>/*/memory/*.md`. Construct via
/// `CcAdapter::new(projects_dir, max_age_years)`.
pub struct CcAdapter {
    projects_dir: PathBuf,
    /// Records older than `max_age_years` are skipped (configurable via
    /// `[adapters.cc] max_age_years`). Defaults to 2.
    max_age_years: u32,
}

impl CcAdapter {
    /// Construct from the configured `projects_dir`. The adapter does not
    /// materialize on construction — work happens in `list()` / `read()`.
    #[must_use]
    pub fn new(projects_dir: PathBuf, max_age_years: u32) -> Self {
        Self {
            projects_dir,
            max_age_years,
        }
    }

    /// Walk `<projects_dir>/<slug>/memory/<topic>.md` files. Returns one
    /// `(slug, topic_path)` per per-topic file (no MEMORY.md, no JSONLs).
    fn discover(&self) -> Vec<(String, PathBuf)> {
        let Ok(rd) = fs::read_dir(&self.projects_dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for project_entry in rd.flatten() {
            let project_path = project_entry.path();
            if !project_path.is_dir() {
                continue;
            }
            let Some(slug) = project_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let memory_dir = project_path.join("memory");
            let Ok(memory_rd) = fs::read_dir(&memory_dir) else {
                continue;
            };
            for entry in memory_rd.flatten() {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                let Some(file_name) = p.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !has_md_extension(file_name) {
                    continue;
                }
                if file_name == "MEMORY.md" {
                    continue;
                }
                out.push((slug.to_owned(), p));
            }
        }
        out
    }
}

impl Adapter for CcAdapter {
    fn source(&self) -> Source {
        Source::CcNative
    }

    fn list(&self) -> Result<AdapterPass, AdapterError> {
        // Detect missing projects_dir vs other I/O failures BEFORE walking.
        // Missing root surfaces as `MissingRoot` so the indexer can suppress
        // both upserts and deletes (a temporarily absent mount must not
        // prune prior records); other I/O failures surface as `Unreadable`.
        // An existing-but-empty projects_dir falls through to the normal
        // walk below and yields `Authoritative` + zero records.
        //
        // Note: there is a narrow TOCTOU window between this probe and the walk
        // below. If the root disappears in that window the walk surfaces an IO
        // error that propagates as AdapterError::Io, not MissingRoot. Acceptable;
        // the next pass catches it.
        match fs::metadata(&self.projects_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AdapterPass {
                    source: Source::CcNative,
                    records: Vec::new(),
                    completeness: PassCompleteness::MissingRoot {
                        path: self.projects_dir.clone(),
                    },
                });
            }
            Err(e) => {
                return Ok(AdapterPass {
                    source: Source::CcNative,
                    records: Vec::new(),
                    completeness: PassCompleteness::Unreadable {
                        path: self.projects_dir.clone(),
                        reason: e.to_string(),
                    },
                });
            }
        }

        let mut records: Vec<RecordSummary> = Vec::new();
        let mut skipped: Vec<SkipReason> = Vec::new();

        for (slug, path) in self.discover() {
            match parse_per_topic_file(&slug, &path, self.max_age_years) {
                ParseOutcome::Ok(record) => {
                    records.push(RecordSummary {
                        id: record.id.clone(),
                        content_hash: record.content_hash.clone(),
                    });
                }
                ParseOutcome::Skipped(reason) => skipped.push(reason),
                ParseOutcome::TooOld => { /* max-age cutoff: drop silently */ }
            }
        }

        let completeness = if skipped.is_empty() {
            PassCompleteness::Authoritative
        } else {
            PassCompleteness::Partial { skipped }
        };
        Ok(AdapterPass {
            source: Source::CcNative,
            records,
            completeness,
        })
    }

    fn read(&self, id: &RecordId) -> Result<UnifiedRecord, AdapterError> {
        let mut found: Option<(String, PathBuf)> = None;
        for (slug, path) in self.discover() {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if stem == id {
                found = Some((slug, path));
                break;
            }
        }
        let Some((slug, path)) = found else {
            return Err(AdapterError::Io {
                path: PathBuf::from(id),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("cc record {id}"),
                ),
            });
        };
        match parse_per_topic_file(&slug, &path, self.max_age_years) {
            ParseOutcome::Ok(record) => Ok(*record),
            ParseOutcome::Skipped(reason) => Err(AdapterError::MalformedRecord {
                path: reason.path,
                detail: format!("cc frontmatter parse failure ({:?})", reason.kind),
            }),
            ParseOutcome::TooOld => Err(AdapterError::Io {
                path,
                source: std::io::Error::other("record outside max-age cutoff"),
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CcFrontmatter {
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    #[serde(rename = "originSessionId")]
    origin_session_id: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    created: Option<String>,
}

enum ParseOutcome {
    /// Boxed to keep the variant size small — the `clippy::large_enum_variant`
    /// lint flags `UnifiedRecord` as too heavy to inline.
    Ok(Box<UnifiedRecord>),
    Skipped(SkipReason),
    TooOld,
}

/// Parsed pieces of a per-topic file before we assemble the `UnifiedRecord`.
/// Returned by `extract_record_pieces` so `parse_per_topic_file` can stay
/// short enough to satisfy the `clippy::too_many_lines` lint.
struct RecordPieces {
    id: RecordId,
    cc_type: String,
    record_type: RecordType,
    title: String,
    summary: Option<String>,
    body: String,
    session_refs: Vec<SessionRef>,
    tags: Vec<String>,
    project_id: ProjectId,
    /// True when the slug had multiple plausible decodings and we picked the
    /// ranked first one. Surfaced via `extras.project_resolution = "ambiguous"`
    /// so a future `nexum doctor` pass can warn the user.
    project_id_ambiguous: bool,
    created: DateTime<Utc>,
    mtime: DateTime<Utc>,
}

fn parse_per_topic_file(slug: &str, path: &Path, max_age_years: u32) -> ParseOutcome {
    let Ok(raw) = fs::read_to_string(path) else {
        return ParseOutcome::Skipped(SkipReason {
            path: path.to_owned(),
            kind: SkipKind::FileTransient,
            at: Utc::now(),
        });
    };

    let (frontmatter_str, body) = split_frontmatter(&raw);
    let frontmatter: Option<CcFrontmatter> = match frontmatter_str {
        Some(s) => match serde_yaml::from_str::<CcFrontmatter>(s) {
            Ok(fm) => Some(fm),
            Err(_) => {
                return ParseOutcome::Skipped(SkipReason {
                    path: path.to_owned(),
                    kind: SkipKind::FileMalformed,
                    at: Utc::now(),
                });
            }
        },
        None => None,
    };

    let mtime = file_mtime(path);
    if !is_within_max_age(mtime, max_age_years) {
        return ParseOutcome::TooOld;
    }

    let pieces = extract_record_pieces(slug, path, frontmatter.as_ref(), body, mtime);

    let mut extras = HashMap::new();
    extras.insert(
        "cc_type".into(),
        serde_json::Value::String(pieces.cc_type.clone()),
    );
    if pieces.cc_type.eq_ignore_ascii_case("reference") {
        extras.insert("is_reference".into(), serde_json::Value::Bool(true));
    }
    if pieces.project_id_ambiguous {
        extras.insert(
            "project_resolution".into(),
            serde_json::Value::String("ambiguous".into()),
        );
    }

    let hash = content_hash(&pieces.title, pieces.summary.as_deref(), &pieces.body);

    let record = UnifiedRecord {
        id: pieces.id,
        record_type: pieces.record_type,
        source: Source::CcNative,
        project_id: pieces.project_id,
        title: pieces.title,
        summary: pieces.summary,
        body: pieces.body,
        body_origin_path: Some(path.to_owned()),
        tags: pieces.tags,
        agent: Agent::ClaudeCode,
        session_refs: pieces.session_refs,
        files: Vec::new(),
        commits: Vec::new(),
        created: pieces.created,
        updated: pieces.mtime,
        confidence: Confidence::Medium,
        outcome: outcome_for_record_type(pieces.record_type),
        provenance: Provenance {
            source: Source::CcNative,
            signature_status: SignatureStatus::Unsigned,
            extractor: None,
            digest_hash: None,
            record_commit_sha: None,
            signer_fingerprint: None,
            crypto_result: CryptoResult::NoSignature,
            relevant_trust_events_commit: None,
            warnings: Vec::new(),
        },
        extras,
        content_hash: hash,
    };
    ParseOutcome::Ok(Box::new(record))
}

fn extract_record_pieces(
    slug: &str,
    path: &Path,
    frontmatter: Option<&CcFrontmatter>,
    body: Option<&str>,
    mtime: DateTime<Utc>,
) -> RecordPieces {
    let id: RecordId = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .unwrap_or_default();

    let cc_type = frontmatter
        .and_then(|f| f.record_type.clone())
        .unwrap_or_else(|| "unknown".into());
    let record_type = map_cc_type_to_record_type(&cc_type);

    let title = frontmatter
        .and_then(|f| f.name.clone())
        .unwrap_or_else(|| id.clone());
    let summary = frontmatter.and_then(|f| f.description.clone());
    let session_refs = match frontmatter.and_then(|f| f.origin_session_id.clone()) {
        Some(s) => uuid::Uuid::parse_str(&s)
            .map(|uid| vec![SessionRef::CcSession { uuid: uid }])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let tags = frontmatter.and_then(|f| f.tags.clone()).unwrap_or_default();

    let (project_id, project_id_ambiguous) = resolve_cc_project_id(slug);

    let body_str = body.unwrap_or("").trim_start_matches('\n').to_owned();

    let created = frontmatter
        .and_then(|f| f.created.clone())
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map_or_else(|| file_ctime(path, mtime), |dt| dt.with_timezone(&Utc));

    RecordPieces {
        id,
        cc_type,
        record_type,
        title,
        summary,
        body: body_str,
        session_refs,
        tags,
        project_id,
        project_id_ambiguous,
        created,
        mtime,
    }
}

fn file_mtime(path: &Path) -> DateTime<Utc> {
    path.metadata()
        .and_then(|m| m.modified())
        .map_or_else(|_| Utc::now(), DateTime::<Utc>::from)
}

fn file_ctime(path: &Path, fallback: DateTime<Utc>) -> DateTime<Utc> {
    path.metadata()
        .and_then(|m| m.created())
        .map_or(fallback, DateTime::<Utc>::from)
}

fn has_md_extension(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}

/// Pull the YAML frontmatter block (between leading `---\n` and the next
/// `---\n` line) out of a markdown file. Returns `(Some(frontmatter), body)`
/// when both lines are present, or `(None, full)` when no frontmatter found.
fn split_frontmatter(raw: &str) -> (Option<&str>, Option<&str>) {
    if !raw.starts_with("---\n") && !raw.starts_with("---\r\n") {
        return (None, Some(raw));
    }
    let after_open = raw.split_once("---\n").map_or(raw, |(_, rest)| rest);
    let Some((frontmatter, body)) = after_open.split_once("\n---\n") else {
        return (None, Some(raw));
    };
    (Some(frontmatter), Some(body))
}

fn map_cc_type_to_record_type(cc_type: &str) -> RecordType {
    match cc_type.to_ascii_lowercase().as_str() {
        "decision" => RecordType::Decision,
        "recommendation" => RecordType::Recommendation,
        "failure" => RecordType::Failure,
        // feedback / user / reference all map to `untyped` for now;
        // future extraction may classify them more aggressively.
        _ => RecordType::Untyped,
    }
}

fn outcome_for_record_type(rt: RecordType) -> Outcome {
    match rt {
        RecordType::Decision => Outcome::Working,
        RecordType::Recommendation => Outcome::Proposed,
        RecordType::Failure => Outcome::Attempted,
        RecordType::Untyped => Outcome::NotApplicable,
    }
}

fn is_within_max_age(mtime: DateTime<Utc>, max_age_years: u32) -> bool {
    let now = Utc::now();
    let cutoff = now - chrono::Duration::days(i64::from(max_age_years) * 365);
    mtime >= cutoff
}

/// Resolve a CC slug to a `(project_id, was_ambiguous)` pair.
///
/// `was_ambiguous` is true when the slug had multiple plausible decodings
/// and we picked the ranked-first candidate. Callers surface this via
/// `extras.project_resolution = "ambiguous"` so a `nexum doctor` pass can
/// warn the user without blocking ingest.
fn resolve_cc_project_id(slug: &str) -> (ProjectId, bool) {
    let input = ProjectInput {
        cc_slug: Some(slug.to_owned()),
        codex_cwd: None,
        git_origin_url: None,
        registered_name: None,
    };
    match resolve_project(&input) {
        ProjectResolution::Resolved { project_id, .. } => (project_id, false),
        ProjectResolution::Ambiguous { candidates, .. } => {
            let pid = candidates
                .first()
                .map_or_else(|| format!("cc-slug:{slug}"), |c| c.project_id.clone());
            (pid, true)
        }
        ProjectResolution::Unresolved => (format!("cc-slug:{slug}"), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("cc")
            .join("projects")
    }

    #[test]
    fn empty_projects_dir_returns_authoritative_zero_records() {
        let dir = TempDir::new().unwrap();
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn single_per_topic_file_is_ingested() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("-tmp-fixture-projalpha").join("memory");
        write_file(
            &project.join("MEMORY.md"),
            "# index\n\n- [feedback_test](feedback_test.md) — hook\n",
        );
        write_file(
            &project.join("feedback_test.md"),
            "---\nname: example feedback\ndescription: keep tests isolated\ntype: feedback\noriginSessionId: 11111111-1111-4111-8111-111111111111\n---\n\ntests must use NexumTestHome rather than touching $HOME/.nexum directly.\n",
        );
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1, "one per-topic file → one record");
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
        assert_eq!(pass.records[0].id, "feedback_test");
    }

    #[test]
    fn memory_md_is_skipped_as_record() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("-tmp-fixture-empty").join("memory");
        write_file(&project.join("MEMORY.md"), "# empty index\n");
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn project_root_jsonl_is_skipped() {
        let dir = TempDir::new().unwrap();
        let project_root = dir.path().join("-tmp-fixture-projbeta");
        let memory = project_root.join("memory");
        write_file(
            &memory.join("MEMORY.md"),
            "# index\n\n- [project_x](project_x.md)\n",
        );
        write_file(
            &memory.join("project_x.md"),
            "---\nname: x\ndescription: y\ntype: project\noriginSessionId: 11111111-1111-4111-8111-111111111111\n---\nbody\n",
        );
        write_file(
            &project_root.join("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.jsonl"),
            "{\"role\":\"user\",\"content\":\"...\"}\n",
        );
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1, "only the per-topic .md is ingested");
        assert_eq!(pass.records[0].id, "project_x");
    }

    #[test]
    fn malformed_yaml_frontmatter_is_skipped_as_partial() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("-tmp-fixture-projalpha").join("memory");
        write_file(
            &project.join("feedback_bad.md"),
            "---\nname: bad\ntype: : : invalid : :\n---\nbody\n",
        );
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let pass = adapter.list().expect("list ok");
        match pass.completeness {
            PassCompleteness::Partial { skipped } => {
                assert!(skipped.iter().any(|s| s.kind == SkipKind::FileMalformed));
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert_eq!(pass.records.len(), 0);
    }

    #[test]
    fn read_returns_full_record_for_known_id() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("-tmp-fixture-projalpha").join("memory");
        write_file(
            &project.join("feedback_x.md"),
            "---\nname: titlec\ndescription: summc\ntype: feedback\noriginSessionId: 11111111-1111-4111-8111-111111111111\n---\nbodyc\n",
        );
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let r = adapter.read(&"feedback_x".to_owned()).expect("read ok");
        assert_eq!(r.title, "titlec");
        assert_eq!(r.summary.as_deref(), Some("summc"));
        assert_eq!(r.body.trim(), "bodyc");
        assert_eq!(r.source, Source::CcNative);
        assert!(matches!(r.session_refs[0], SessionRef::CcSession { .. }));
    }

    #[test]
    fn realistic_fixture_corpus_yields_expected_record_count() {
        // Fixture has three projects: -tmp-fixture-projalpha (3 per-topic
        // files), -tmp-fixture-projbeta (2 per-topic files + sibling .jsonl),
        // -tmp-fixture-my-hyphenated-app (1 per-topic file). Total: 6 records.
        let root = fixture_root();
        let adapter = CcAdapter::new(root, 2);
        let pass = adapter.list().expect("fixture list ok");
        assert_eq!(pass.records.len(), 6, "fixture corpus must yield 6 records");
    }

    #[test]
    fn missing_projects_dir_returns_missing_root() {
        let expected = PathBuf::from("/nonexistent/cc/projects");
        let adapter = CcAdapter::new(expected.clone(), 2);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        match pass.completeness {
            PassCompleteness::MissingRoot { path } => assert_eq!(path, expected),
            other => panic!("expected MissingRoot, got {other:?}"),
        }
    }

    #[test]
    fn unresolved_slug_falls_through_to_cc_slug_fallback() {
        // Resolver behavior: when no slug-decoded path canonicalizes to a real
        // filesystem path, ProjectResolution::Unresolved fires (NOT Ambiguous),
        // so the marker is not emitted. To exercise the Ambiguous + marker path
        // would require seeding two real paths matching different decodings —
        // out of scope for a unit-level test against synthetic fixtures.
        // (Marker emission is covered by inspection in cc.rs:233-238.)
        let root = fixture_root();
        let adapter = CcAdapter::new(root, 2);
        let r = adapter
            .read(&"feedback_naming".to_owned())
            .expect("read ok");
        // The marker is NOT emitted on the my-hyphenated-app fixture because
        // none of the slug-decoded paths exist on disk; the resolver falls
        // through to Unresolved and the adapter emits the slug fallback id.
        assert!(!r.extras.contains_key("project_resolution"));
        assert!(r.project_id.starts_with("cc-slug:"));
    }

    #[test]
    fn is_reference_marker_is_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("-tmp-fixture-projalpha").join("memory");
        write_file(
            &project.join("reference_x.md"),
            "---\nname: t\ntype: Reference\n---\nbody\n",
        );
        let adapter = CcAdapter::new(dir.path().to_owned(), 2);
        let r = adapter.read(&"reference_x".to_owned()).expect("read ok");
        assert_eq!(
            r.extras
                .get("is_reference")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "type: Reference (mixed case) must still set is_reference"
        );
    }
}
