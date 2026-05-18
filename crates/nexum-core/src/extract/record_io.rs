//! `RawRecord` -> `UnifiedRecord` validation and conversion against the
//! canonical record schema.
//!
//! The model emits YAML; we parse loosely first then enforce the schema in
//! `validate_raw_record`. `raw_to_unified` builds a `UnifiedRecord` ready for
//! the trust-chain commit pipeline. Both the `source` (`Source::Local`) and
//! provenance bookkeeping (`Source::Local` + `SignatureStatus::Unsigned` +
//! `CryptoResult::NoSignature` + `extractor = Some("<provider>:<model>")`) are
//! hard-set by the converter; the model has no say.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::DateTime;
use regex::Regex;
use serde_yaml::Value;

use crate::extract::model::{ExtractError, RawRecord};
use crate::records::{
    Agent, Confidence, CryptoResult, Outcome, Provenance, RecordType, SessionRef, SignatureStatus,
    Source, UnifiedRecord,
};

/// Default extractor identifier baked into provenance for records that came
/// out of the typed-extraction pipeline. Keeps the wire shape stable until the
/// pipeline threads provider+model through every call site.
const DEFAULT_EXTRACTOR: &str = "anthropic:claude-opus-4-7";

/// Default project id for extracted records when the model emits null. Matches
/// the `_inbox` triage bucket the design pins for unattributed records.
const INBOX_PROJECT_ID: &str = "_inbox";

fn id_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}-[a-z0-9-]+$").expect("static regex compiles"))
}

/// Validate the YAML against the record schema. Returns
/// `ExtractError::Validation` with a one-line reason on the first failure.
///
/// Checks: `schema_version` == 1, id matches `YYYY-MM-DD-slug`, `record_type`
/// is one of decision|recommendation|failure, outcome consistent with type,
/// confidence in low|medium|high, agent in codex|claude-code|manual,
/// created/updated are RFC3339, problem is non-empty.
///
/// # Errors
/// `ExtractError::Validation` for any contract violation.
pub fn validate_raw_record(raw: &RawRecord) -> Result<(), ExtractError> {
    let map = raw
        .yaml
        .as_mapping()
        .ok_or_else(|| ExtractError::Validation {
            reason: "record is not a mapping".into(),
        })?;

    require_int(map, "schema_version", 1)?;
    let id = require_str(map, "id")?;
    if !id_regex().is_match(id) {
        return Err(ExtractError::Validation {
            reason: format!("id `{id}` does not match YYYY-MM-DD-slug"),
        });
    }
    let record_type = require_str(map, "record_type")?;
    let outcome = require_str(map, "outcome")?;
    validate_outcome_for_type(record_type, outcome)?;
    let confidence = require_str(map, "confidence")?;
    if !matches!(confidence, "low" | "medium" | "high") {
        return Err(ExtractError::Validation {
            reason: format!("confidence `{confidence}` not in low|medium|high"),
        });
    }
    let agent = require_str(map, "agent")?;
    if !matches!(agent, "codex" | "claude-code" | "manual") {
        return Err(ExtractError::Validation {
            reason: format!("agent `{agent}` not in codex|claude-code|manual"),
        });
    }
    for field in ["created", "updated"] {
        let s = require_str(map, field)?;
        DateTime::parse_from_rfc3339(s).map_err(|e| ExtractError::Validation {
            reason: format!("{field} not RFC3339: {e}"),
        })?;
    }
    let problem = require_str(map, "problem")?;
    if problem.trim().is_empty() {
        return Err(ExtractError::Validation {
            reason: "problem is empty".into(),
        });
    }
    Ok(())
}

fn validate_outcome_for_type(record_type: &str, outcome: &str) -> Result<(), ExtractError> {
    let allowed: &[&str] = match record_type {
        "decision" => &["working", "reverted", "superseded"],
        "recommendation" => &["proposed", "promoted", "rejected", "stale"],
        "failure" => &["attempted"],
        other => {
            return Err(ExtractError::Validation {
                reason: format!("record_type `{other}` not in decision|recommendation|failure"),
            });
        }
    };
    if !allowed.contains(&outcome) {
        return Err(ExtractError::Validation {
            reason: format!("outcome `{outcome}` not valid for record_type `{record_type}`"),
        });
    }
    Ok(())
}

fn require_str<'a>(map: &'a serde_yaml::Mapping, field: &str) -> Result<&'a str, ExtractError> {
    map.get(Value::String(field.into()))
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Validation {
            reason: format!("missing or non-string field `{field}`"),
        })
}

fn require_int(map: &serde_yaml::Mapping, field: &str, expected: i64) -> Result<(), ExtractError> {
    let actual = map
        .get(Value::String(field.into()))
        .and_then(Value::as_i64)
        .ok_or_else(|| ExtractError::Validation {
            reason: format!("missing or non-int `{field}`"),
        })?;
    if actual != expected {
        return Err(ExtractError::Validation {
            reason: format!("expected {field} = {expected}, got {actual}"),
        });
    }
    Ok(())
}

/// Convert a validated `RawRecord` into a `UnifiedRecord` ready for the
/// commit pipeline. The source and provenance bookkeeping are hard-pinned by
/// the converter; callers cannot override.
///
/// # Errors
/// `ExtractError::Validation` if a field that passed shallow validation
/// turns out unparseable at conversion time (e.g. a malformed `session_refs`
/// entry).
pub fn raw_to_unified(raw: &RawRecord) -> Result<UnifiedRecord, ExtractError> {
    validate_raw_record(raw)?;
    // `validate_raw_record` already proved the top-level value is a mapping;
    // re-derive via `ok_or_else` rather than `expect` to keep the function
    // panic-free.
    let map = raw
        .yaml
        .as_mapping()
        .ok_or_else(|| ExtractError::Validation {
            reason: "record is not a mapping".into(),
        })?;
    let id = require_str(map, "id")?;
    let record_type = match require_str(map, "record_type")? {
        "decision" => RecordType::Decision,
        "recommendation" => RecordType::Recommendation,
        "failure" => RecordType::Failure,
        _ => unreachable!("validated to be one of decision|recommendation|failure"),
    };
    let outcome = parse_outcome(require_str(map, "outcome")?)?;
    let confidence = match require_str(map, "confidence")? {
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        _ => unreachable!("validated to be one of low|medium|high"),
    };
    let agent = match require_str(map, "agent")? {
        "codex" => Agent::Codex,
        "claude-code" => Agent::ClaudeCode,
        "manual" => Agent::Manual,
        _ => unreachable!("validated to be one of codex|claude-code|manual"),
    };
    let problem = require_str(map, "problem")?.to_owned();
    let title = problem.lines().next().unwrap_or("").to_owned();
    let created = DateTime::parse_from_rfc3339(require_str(map, "created")?)
        .map_err(|e| ExtractError::Validation {
            reason: e.to_string(),
        })?
        .with_timezone(&chrono::Utc);
    let updated = DateTime::parse_from_rfc3339(require_str(map, "updated")?)
        .map_err(|e| ExtractError::Validation {
            reason: e.to_string(),
        })?
        .with_timezone(&chrono::Utc);

    let tags: Vec<String> = map
        .get(Value::String("tags".into()))
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let session_refs = parse_session_refs(map)?;
    let files = parse_files(map)?;
    let commits = parse_commits(map);

    let provenance = Provenance {
        source: Source::Local,
        signature_status: SignatureStatus::Unsigned,
        extractor: Some(DEFAULT_EXTRACTOR.to_owned()),
        digest_hash: None,
        record_commit_sha: None,
        signer_fingerprint: None,
        crypto_result: CryptoResult::NoSignature,
        relevant_trust_events_commit: None,
        trust_basis: None,
        warnings: Vec::new(),
    };

    let body = serde_yaml::to_string(&raw.yaml).unwrap_or_default();

    Ok(UnifiedRecord {
        id: id.to_owned(),
        record_type,
        source: Source::Local,
        project_id: INBOX_PROJECT_ID.to_owned(),
        title,
        summary: None,
        body,
        body_origin_path: None,
        tags,
        agent,
        session_refs,
        files,
        commits,
        created,
        updated,
        confidence,
        outcome,
        provenance,
        extras: HashMap::new(),
        content_hash: String::new(),
    })
}

fn parse_outcome(s: &str) -> Result<Outcome, ExtractError> {
    Outcome::try_from_user_str(s).ok_or_else(|| ExtractError::Validation {
        reason: format!("unrecognized outcome `{s}`"),
    })
}

fn parse_session_refs(map: &serde_yaml::Mapping) -> Result<Vec<SessionRef>, ExtractError> {
    let Some(seq) = map
        .get(Value::String("session_refs".into()))
        .and_then(Value::as_sequence)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(seq.len());
    for v in seq {
        // SessionRef carries `#[serde(tag = "kind", rename_all = "snake_case")]`
        // and the YAML schema uses the same `kind: <variant>` wire form, so
        // serde's own deserializer handles every variant for free.
        let entry: SessionRef =
            serde_yaml::from_value(v.clone()).map_err(|e| ExtractError::Validation {
                reason: format!("session_refs entry: {e}"),
            })?;
        out.push(entry);
    }
    Ok(out)
}

fn parse_files(
    map: &serde_yaml::Mapping,
) -> Result<Vec<crate::records::FileEvidence>, ExtractError> {
    use crate::records::{FileEvidence, FileEvidenceKind};
    let Some(seq) = map
        .get(Value::String("files".into()))
        .and_then(Value::as_sequence)
    else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(seq.len());
    for v in seq {
        // Plain-string entries are tolerated and coerced to ParsedFromMemoryBody.
        if let Some(s) = v.as_str() {
            out.push(FileEvidence {
                path: s.into(),
                kind: FileEvidenceKind::ParsedFromMemoryBody,
            });
            continue;
        }
        let inner = v.as_mapping().ok_or_else(|| ExtractError::Validation {
            reason: "files entry not a mapping or string".into(),
        })?;
        let path = inner
            .get(Value::String("path".into()))
            .and_then(Value::as_str)
            .ok_or_else(|| ExtractError::Validation {
                reason: "files.path missing".into(),
            })?;
        let kind_str = inner
            .get(Value::String("kind".into()))
            .and_then(Value::as_str)
            .unwrap_or("parsed_from_memory_body");
        let kind = match kind_str {
            "extracted_from_session" => {
                let conf = inner
                    .get(Value::String("confidence".into()))
                    .and_then(Value::as_str)
                    .unwrap_or("medium");
                let confidence = match conf {
                    "low" => Confidence::Low,
                    "high" => Confidence::High,
                    _ => Confidence::Medium,
                };
                FileEvidenceKind::ExtractedFromSession { confidence }
            }
            "committed_at" => {
                let sha = inner
                    .get(Value::String("sha".into()))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                FileEvidenceKind::CommittedAt { sha }
            }
            _ => FileEvidenceKind::ParsedFromMemoryBody,
        };
        out.push(FileEvidence {
            path: path.into(),
            kind,
        });
    }
    Ok(out)
}

fn parse_commits(map: &serde_yaml::Mapping) -> Vec<String> {
    map.get(Value::String("commits".into()))
        .and_then(Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;

    fn well_formed() -> Value {
        let yaml = r"schema_version: 1
id: 2026-04-15-retry-backoff-knob
record_type: recommendation
outcome: proposed
agent: claude-code
confidence: medium
tags: [config, networking]
session_refs:
  - kind: cc_session
    uuid: 11111111-2222-4333-8444-555555555555
created: 2026-04-15T10:00:00Z
updated: 2026-04-15T10:00:00Z
problem: noisy retry behavior
chosen: add a retry-backoff knob
";
        serde_yaml::from_str(yaml).expect("test fixture parses")
    }

    #[test]
    fn well_formed_record_validates() {
        let raw = RawRecord {
            yaml: well_formed(),
        };
        assert!(validate_raw_record(&raw).is_ok());
    }

    #[test]
    fn missing_schema_version_rejected() {
        let mut y = well_formed();
        y.as_mapping_mut()
            .expect("fixture is a mapping")
            .remove(Value::String("schema_version".into()));
        let raw = RawRecord { yaml: y };
        let err = validate_raw_record(&raw).expect_err("must reject");
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn outcome_mismatch_rejected() {
        let mut y = well_formed();
        y.as_mapping_mut()
            .expect("fixture is a mapping")
            .insert("outcome".into(), "working".into());
        // working is a decision outcome; record_type is recommendation -> reject.
        let raw = RawRecord { yaml: y };
        let err = validate_raw_record(&raw).expect_err("must reject");
        assert!(err.to_string().contains("outcome"));
    }

    #[test]
    fn invalid_id_format_rejected() {
        let mut y = well_formed();
        y.as_mapping_mut()
            .expect("fixture is a mapping")
            .insert("id".into(), "no-date-prefix".into());
        let raw = RawRecord { yaml: y };
        let err = validate_raw_record(&raw).expect_err("must reject");
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn empty_problem_rejected() {
        let mut y = well_formed();
        y.as_mapping_mut()
            .expect("fixture is a mapping")
            .insert("problem".into(), "".into());
        let raw = RawRecord { yaml: y };
        let err = validate_raw_record(&raw).expect_err("must reject");
        assert!(err.to_string().contains("problem"));
    }

    #[test]
    fn raw_to_unified_sets_local_source_and_extracted_provenance() {
        let raw = RawRecord {
            yaml: well_formed(),
        };
        let unified = raw_to_unified(&raw).expect("convert");
        assert!(matches!(unified.source, Source::Local));
        assert!(matches!(unified.provenance.source, Source::Local));
        assert!(matches!(
            unified.provenance.signature_status,
            SignatureStatus::Unsigned
        ));
        assert!(matches!(
            unified.provenance.crypto_result,
            CryptoResult::NoSignature
        ));
        assert!(unified.provenance.extractor.is_some());
        assert_eq!(unified.project_id, "_inbox");
        assert!(unified.body_origin_path.is_none());
        assert!(unified.commits.is_empty());
        // The cc_session fixture round-trips into the typed variant.
        assert_eq!(unified.session_refs.len(), 1);
    }
}
