//! Corpus-driven tests for the secret redaction layer.

use std::collections::HashMap;
use std::path::PathBuf;

use nexum_core::extract::redaction::{RedactionEngine, default_engine};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    #[serde(default)]
    hit: Vec<HitCase>,
    #[serde(default)]
    miss: Vec<MissCase>,
}

#[derive(Deserialize)]
struct HitCase {
    name: String,
    input: String,
}

#[derive(Deserialize)]
struct MissCase {
    input: String,
}

fn load_corpus() -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/extract/redaction/test_corpus.toml");
    let text = std::fs::read_to_string(path).expect("read corpus");
    toml::from_str(&text).expect("parse corpus")
}

#[test]
fn every_hit_case_matches_named_pattern() {
    let engine: RedactionEngine = default_engine();
    let corpus = load_corpus();
    let mut names_seen: HashMap<&str, usize> = HashMap::new();
    for case in &corpus.hit {
        let result = engine.redact(&case.input);
        assert_ne!(
            result.text, case.input,
            "expected pattern `{}` to redact input `{}`",
            case.name, case.input,
        );
        assert!(
            result.events.iter().any(|e| e.pattern_name == case.name),
            "expected redaction event named `{}` for input `{}` (got {:?})",
            case.name,
            case.input,
            result
                .events
                .iter()
                .map(|e| e.pattern_name.as_str())
                .collect::<Vec<_>>(),
        );
        *names_seen.entry(case.name.as_str()).or_insert(0) += 1;
    }
    assert!(!names_seen.is_empty());
}

#[test]
fn every_miss_case_is_untouched() {
    let engine = default_engine();
    let corpus = load_corpus();
    for case in &corpus.miss {
        let result = engine.redact(&case.input);
        assert_eq!(
            result.text,
            case.input,
            "expected no redaction for input `{}` but engine emitted {:?}",
            case.input,
            result
                .events
                .iter()
                .map(|e| e.pattern_name.as_str())
                .collect::<Vec<_>>(),
        );
        assert!(result.events.is_empty());
    }
}

#[test]
fn redaction_events_include_before_hash() {
    let engine = default_engine();
    let result = engine.redact("AKIAIOSFODNN7EXAMPLE");
    let event = &result.events[0];
    assert!(event.before_hash.starts_with("sha256:"));
    assert_eq!(event.before_hash.len(), "sha256:".len() + 64);
}

#[test]
fn replacement_uses_named_placeholder() {
    let engine = default_engine();
    let result = engine.redact("AKIAIOSFODNN7EXAMPLE");
    assert!(result.text.contains("[REDACTED:aws_access_key]"));
}

#[test]
fn custom_pattern_loader_round_trip() {
    use nexum_core::extract::redaction::load_custom_patterns;
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(
        tmp.path(),
        b"[[pattern]]\nname = \"internal-hostname\"\nregex = \"\\\\b[a-z0-9-]+\\\\.internal\\\\.example\\\\.com\\\\b\"\nreplacement = \"[REDACTED:internal-hostname]\"\n",
    )
    .unwrap();
    let patterns = load_custom_patterns(tmp.path()).expect("load");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].name, "internal-hostname");
}

#[test]
fn custom_pattern_loader_rejects_invalid_regex() {
    use nexum_core::extract::redaction::{RedactionError, load_custom_patterns};
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(
        tmp.path(),
        b"[[pattern]]\nname = \"broken\"\nregex = \"(unbalanced\"\nreplacement = \"x\"\n",
    )
    .unwrap();
    let err = load_custom_patterns(tmp.path()).unwrap_err();
    assert!(matches!(err, RedactionError::Invalid { ref name, .. } if name == "broken"));
}
