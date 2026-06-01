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
}
