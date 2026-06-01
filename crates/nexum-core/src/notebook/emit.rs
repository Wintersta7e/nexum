use crate::api::ApiError;
use crate::records::types::CommitEvidence;

/// Input to the decision-record YAML emitter. All fields are caller-supplied;
/// the emitter does not derive ids or timestamps.
pub(crate) struct DecisionInput {
    pub decision_id: String,
    pub project_id: String,
    pub source_rec_id: String,
    pub source_rec_title: String,
    /// Mirror the source recommendation's agent (codex|claude-code|manual).
    pub agent: String,
    pub created: chrono::DateTime<chrono::Utc>,
    pub commit_evidence: CommitEvidence,
    pub inherited_warnings: Vec<String>,
}

/// Emit a strict-schema-valid decision record YAML with a tracked
/// `provenance:` block. `outcome: working` (Decision lifecycle).
///
/// The mapping is built field-by-field with insertion order preserved by
/// `serde_yaml::Mapping` so the output is stable and human-readable.
pub(crate) fn build_decision_yaml(input: &DecisionInput) -> String {
    let ts = input
        .created
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut root = serde_yaml::Mapping::new();
    let put = |m: &mut serde_yaml::Mapping, k: &str, v: serde_yaml::Value| {
        m.insert(serde_yaml::Value::String(k.into()), v);
    };

    put(&mut root, "schema_version", 1.into());
    put(&mut root, "id", input.decision_id.clone().into());
    put(&mut root, "record_type", "decision".into());
    put(&mut root, "project_id", input.project_id.clone().into());
    put(&mut root, "outcome", "working".into());
    put(&mut root, "confidence", "high".into());
    put(&mut root, "agent", input.agent.clone().into());
    put(&mut root, "created", ts.clone().into());
    put(&mut root, "updated", ts.into());
    put(
        &mut root,
        "problem",
        format!(
            "Promoted from recommendation {}: {}",
            input.source_rec_id, input.source_rec_title
        )
        .into(),
    );
    put(
        &mut root,
        "commits",
        serde_yaml::Value::Sequence(vec![input.commit_evidence.commit_sha.clone().into()]),
    );

    // provenance block — tracks promotion lineage and commit evidence
    let mut prov = serde_yaml::Mapping::new();
    put(&mut prov, "source", "nexum-promoted".into());
    let mut pf = serde_yaml::Mapping::new();
    put(&mut pf, "source", "local".into());
    put(&mut pf, "project_id", input.project_id.clone().into());
    put(&mut pf, "id", input.source_rec_id.clone().into());
    put(&mut prov, "promoted_from", serde_yaml::Value::Mapping(pf));
    if !input.inherited_warnings.is_empty() {
        put(
            &mut prov,
            "inherited_warnings",
            serde_yaml::to_value(&input.inherited_warnings).unwrap(),
        );
    }
    put(
        &mut prov,
        "commit_evidence",
        serde_yaml::to_value(&input.commit_evidence).unwrap(),
    );
    put(&mut root, "provenance", serde_yaml::Value::Mapping(prov));

    serde_yaml::to_string(&serde_yaml::Value::Mapping(root)).unwrap_or_default()
}

/// Replace the first line whose trimmed start matches `prefix` with
/// `"{indent}{prefix} {new_value}"`, preserving everything else byte-for-byte.
/// Trailing newline is preserved. Returns `Err` if no matching line is found.
pub(crate) fn replace_scalar_line(
    yaml: &str,
    prefix: &str,
    new_value: &str,
) -> Result<String, ApiError> {
    let mut found = false;
    let mut out_lines: Vec<String> = Vec::new();
    for line in yaml.lines() {
        if !found && line.trim_start().starts_with(prefix) {
            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out_lines.push(format!("{indent}{prefix} {new_value}"));
            found = true;
        } else {
            out_lines.push(line.to_owned());
        }
    }
    if !found {
        return Err(ApiError::Other {
            message: format!("record YAML has no `{prefix}` line to replace"),
        });
    }
    let mut out = out_lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Replace the `outcome:` line value, preserving everything else byte-for-byte.
/// Returns `Err` if no `outcome:` line is found.
pub(crate) fn replace_outcome_line(yaml: &str, new_outcome: &str) -> Result<String, ApiError> {
    replace_scalar_line(yaml, "outcome:", new_outcome)
}

/// Upsert a scalar line relative to an anchor line.
///
/// If a `{key_prefix}` line already exists anywhere in `yaml`, replaces its
/// value (same semantics as `replace_scalar_line`). Otherwise inserts a new
/// `"{indent}{key_prefix} {value}"` line immediately after the first line
/// whose trimmed start matches `after_prefix`, inheriting that line's indent.
///
/// Always succeeds: if neither anchor nor key line exists the YAML is returned
/// unchanged (the anchor is expected to exist; callers guarantee it via the
/// `replace_outcome_line` → `upsert_scalar_after` sequencing in
/// `stamp_promoted`).
pub(crate) fn upsert_scalar_after(
    yaml: &str,
    after_prefix: &str,
    key_prefix: &str,
    value: &str,
) -> String {
    // If the key line already exists, replace its value in-place.
    if yaml.lines().any(|l| l.trim_start().starts_with(key_prefix)) {
        // replace_scalar_line can only fail if the key is absent, which we just
        // confirmed it is not — unwrap is safe here.
        return replace_scalar_line(yaml, key_prefix, value).unwrap_or_else(|_| yaml.to_owned());
    }

    // Key absent: insert after the first line matching after_prefix.
    let mut out_lines: Vec<String> = Vec::new();
    let mut inserted = false;
    for line in yaml.lines() {
        out_lines.push(line.to_owned());
        if !inserted && line.trim_start().starts_with(after_prefix) {
            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            out_lines.push(format!("{indent}{key_prefix} {value}"));
            inserted = true;
        }
    }
    let mut out = out_lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Stamp a promotion onto a recommendation YAML: set `outcome: promoted` and
/// insert or replace the `promoted_to:` line immediately after it.
/// Returns `Err` if no `outcome:` line exists.
pub(crate) fn stamp_promoted(yaml: &str, decision_id: &str) -> Result<String, ApiError> {
    let stamped = replace_outcome_line(yaml, "promoted")?;
    Ok(upsert_scalar_after(
        &stamped,
        "outcome:",
        "promoted_to:",
        decision_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter::local::LocalAdapter,
        adapter::trait_def::Adapter,
        records::types::{CommitEvidence, Outcome, TreeFingerprint, VerificationStatus},
    };
    use std::path::PathBuf;

    fn sample_commit_evidence() -> CommitEvidence {
        CommitEvidence {
            repo_identity: "git:abc".into(),
            branch: "main".into(),
            commit_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            commit_time: "2026-05-20T00:00:00Z".parse().unwrap(),
            commit_message_hash: "0".repeat(64),
            tree_changes_fingerprint: TreeFingerprint {
                strict: "1".repeat(64),
                loose: "2".repeat(64),
                file_paths: vec![PathBuf::from("src/lib.rs")],
            },
            verification_status: VerificationStatus::Verified,
        }
    }

    #[test]
    fn emitted_decision_yaml_is_schema_valid_and_round_trips() {
        let ev = sample_commit_evidence();
        let yaml = build_decision_yaml(&DecisionInput {
            decision_id: "2026-05-21-x-decision".into(),
            project_id: "nexum".into(),
            source_rec_id: "2026-04-29-x".into(),
            source_rec_title: "use JWTs over sessions".into(),
            agent: "claude-code".into(),
            created: "2026-05-21T00:00:00Z".parse().unwrap(),
            commit_evidence: ev,
            inherited_warnings: vec![],
        });

        // PRIMARY: the production read path — drive through the public
        // LocalAdapter::read by writing the YAML into a temp notebook at
        // <project>/decisions/<id>.yml and reading it back.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nexum/decisions/2026-05-21-x-decision.yml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &yaml).unwrap();

        let adapter = LocalAdapter::new(dir.path().to_owned());
        let rec = adapter
            .read(&"2026-05-21-x-decision".to_owned())
            .expect("emitted YAML must parse via LocalAdapter::read");

        assert_eq!(rec.outcome, Outcome::Working, "outcome must be Working");
        assert!(
            rec.provenance.commit_evidence.is_some(),
            "commit_evidence must be populated"
        );
        assert_eq!(
            rec.provenance.promoted_from.as_ref().map(|k| k.id.as_str()),
            Some("2026-04-29-x"),
            "promoted_from.id must match the source rec id"
        );
        assert!(
            rec.provenance.inherited_warnings.is_empty(),
            "inherited_warnings should be empty when none passed"
        );
        // commit_sha round-trips through the provenance block
        let ev_back = rec.provenance.commit_evidence.unwrap();
        assert_eq!(
            ev_back.commit_sha,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
    }

    #[test]
    fn emitted_yaml_with_inherited_warnings_round_trips() {
        let ev = sample_commit_evidence();
        let yaml = build_decision_yaml(&DecisionInput {
            decision_id: "2026-05-21-y-decision".into(),
            project_id: "nexum".into(),
            source_rec_id: "2026-04-29-y".into(),
            source_rec_title: "some pre-reanchor recommendation".into(),
            agent: "codex".into(),
            created: "2026-05-21T00:00:00Z".parse().unwrap(),
            commit_evidence: ev,
            inherited_warnings: vec!["pre-recovery-record".to_string()],
        });

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nexum/decisions/2026-05-21-y-decision.yml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &yaml).unwrap();

        let adapter = LocalAdapter::new(dir.path().to_owned());
        let rec = adapter
            .read(&"2026-05-21-y-decision".to_owned())
            .expect("emitted YAML with inherited_warnings must parse");

        assert_eq!(rec.outcome, Outcome::Working);
        assert_eq!(
            rec.provenance.inherited_warnings,
            vec!["pre-recovery-record".to_string()],
            "inherited_warnings must carry through"
        );
    }

    #[test]
    fn emitted_yaml_contains_required_fields() {
        let yaml = build_decision_yaml(&DecisionInput {
            decision_id: "2026-05-21-z-decision".into(),
            project_id: "nexum".into(),
            source_rec_id: "2026-04-29-z".into(),
            source_rec_title: "use connection pooling".into(),
            agent: "manual".into(),
            created: "2026-05-21T00:00:00Z".parse().unwrap(),
            commit_evidence: sample_commit_evidence(),
            inherited_warnings: vec![],
        });

        assert!(yaml.contains("schema_version: 1"), "schema_version");
        assert!(yaml.contains("record_type: decision"), "record_type");
        assert!(yaml.contains("outcome: working"), "outcome");
        assert!(yaml.contains("confidence: high"), "confidence");
        assert!(yaml.contains("agent: manual"), "agent");
        assert!(yaml.contains("source: nexum-promoted"), "provenance source");
        assert!(yaml.contains("promoted_from"), "promoted_from block");
        assert!(yaml.contains("commit_evidence"), "commit_evidence block");
        assert!(yaml.contains("commits:"), "commits list");
    }

    // ── Task 16: minimal-drift recommendation stamping ────────────────────────

    /// Minimal recommendation YAML used as a stamping fixture.
    fn sample_rec_yaml() -> &'static str {
        "schema_version: 1\n\
         id: 2026-04-29-x\n\
         record_type: recommendation\n\
         project_id: nexum\n\
         outcome: proposed\n\
         confidence: medium\n\
         agent: claude-code\n\
         created: 2026-04-29T00:00:00Z\n\
         updated: 2026-04-29T00:00:00Z\n\
         problem: should we use JWTs?\n"
    }

    #[test]
    fn stamp_promoted_sets_outcome_and_inserts_promoted_to() {
        let yaml = sample_rec_yaml();
        let decision_id = "2026-05-21-x-decision";
        let stamped = stamp_promoted(yaml, decision_id).expect("stamp_promoted must succeed");

        // outcome line changed
        assert!(
            stamped.contains("outcome: promoted"),
            "outcome line must be 'promoted'"
        );
        // promoted_to line inserted
        assert!(
            stamped.contains(&format!("promoted_to: {decision_id}")),
            "promoted_to line must be present"
        );
        // trailing newline preserved
        assert!(
            stamped.ends_with('\n'),
            "trailing newline must be preserved"
        );

        // byte-for-byte identical elsewhere: remove the two changed/added lines
        // and compare the remainder against the original minus those lines.
        let orig_lines: Vec<&str> = yaml
            .lines()
            .filter(|l| !l.trim_start().starts_with("outcome:"))
            .collect();
        let stamped_lines: Vec<&str> = stamped
            .lines()
            .filter(|l| {
                !l.trim_start().starts_with("outcome:")
                    && !l.trim_start().starts_with("promoted_to:")
            })
            .collect();
        assert_eq!(
            orig_lines, stamped_lines,
            "all non-stamped lines must be byte-identical"
        );
    }

    #[test]
    fn stamp_promoted_replaces_existing_promoted_to_not_duplicates() {
        // YAML that already has a promoted_to line (from a previous stamp attempt)
        let yaml = "schema_version: 1\n\
                    id: 2026-04-29-x\n\
                    record_type: recommendation\n\
                    outcome: promoted\n\
                    promoted_to: 2026-05-01-old-decision\n\
                    agent: claude-code\n\
                    created: 2026-04-29T00:00:00Z\n\
                    updated: 2026-04-29T00:00:00Z\n";
        let new_id = "2026-05-21-x-decision";
        let stamped = stamp_promoted(yaml, new_id).expect("stamp_promoted must succeed");

        // Only one promoted_to line
        let count = stamped
            .lines()
            .filter(|l| l.trim_start().starts_with("promoted_to:"))
            .count();
        assert_eq!(count, 1, "must not duplicate promoted_to");
        assert!(
            stamped.contains(&format!("promoted_to: {new_id}")),
            "promoted_to must be updated to the new id"
        );
    }

    #[test]
    fn replace_outcome_line_rejected() {
        let yaml = sample_rec_yaml();
        let out = replace_outcome_line(yaml, "rejected").expect("must succeed");
        assert!(
            out.contains("outcome: rejected"),
            "outcome must be rejected"
        );
        // rest identical
        let unchanged: Vec<&str> = out
            .lines()
            .filter(|l| !l.trim_start().starts_with("outcome:"))
            .collect();
        let orig: Vec<&str> = yaml
            .lines()
            .filter(|l| !l.trim_start().starts_with("outcome:"))
            .collect();
        assert_eq!(unchanged, orig);
    }

    #[test]
    fn replace_outcome_line_stale() {
        let yaml = sample_rec_yaml();
        let out = replace_outcome_line(yaml, "stale").expect("must succeed");
        assert!(out.contains("outcome: stale"), "outcome must be stale");
    }

    #[test]
    fn stamp_promoted_errors_on_missing_outcome_line() {
        let yaml = "schema_version: 1\nid: 2026-04-29-x\nrecord_type: recommendation\n";
        let result = stamp_promoted(yaml, "some-decision");
        assert!(
            result.is_err(),
            "stamp_promoted must return Err when outcome: line is absent"
        );
    }

    #[test]
    fn stamped_yaml_round_trips_via_local_adapter() {
        // Build a recommendation YAML with outcome: proposed, stamp it to
        // promoted, write to a temp notebook, read back via LocalAdapter::read.
        let rec_yaml = "schema_version: 1\n\
                        id: 2026-04-29-stamp-test\n\
                        record_type: recommendation\n\
                        project_id: nexum\n\
                        outcome: proposed\n\
                        confidence: medium\n\
                        agent: claude-code\n\
                        created: 2026-04-29T00:00:00Z\n\
                        updated: 2026-04-29T00:00:00Z\n\
                        problem: should we cache responses?\n";
        let decision_id = "2026-05-21-stamp-decision";
        let stamped = stamp_promoted(rec_yaml, decision_id).expect("stamp_promoted must succeed");

        let dir = tempfile::tempdir().unwrap();
        let p = dir
            .path()
            .join("nexum/recommendations/2026-04-29-stamp-test.yml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &stamped).unwrap();

        let adapter = LocalAdapter::new(dir.path().to_owned());
        let rec = adapter
            .read(&"2026-04-29-stamp-test".to_owned())
            .expect("stamped YAML must parse via LocalAdapter::read");

        assert_eq!(
            rec.outcome,
            Outcome::Promoted,
            "read-back outcome must be Promoted"
        );
    }
}
