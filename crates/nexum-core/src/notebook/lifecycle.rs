use crate::records::types::{CommitEvidence, RecordKey, UnifiedRecord};

/// One lifecycle mutation = one signed commit. `Promote` is the only
/// multi-file event (stamps the rec + creates the decision).
pub enum LifecycleEvent {
    Promote {
        rec_ref: RecordKey,
        new_decision: Box<UnifiedRecord>,
        commit_evidence: CommitEvidence,
    },
    Reject {
        rec_ref: RecordKey,
    },
    Stale {
        rec_ref: RecordKey,
    },
}

impl LifecycleEvent {
    pub fn message_for_promote(rec: &RecordKey, decision_id: &str, sha: &str) -> String {
        format!(
            "promote: {} -> {decision_id} via {}",
            rec.id,
            &sha[..sha.len().min(7)]
        )
    }

    pub fn message_for_reject(rec: &RecordKey) -> String {
        format!("reject: {}", rec.id)
    }

    pub fn message_for_stale(rec: &RecordKey) -> String {
        format!("stale: {}", rec.id)
    }
}

#[cfg(test)]
mod tests {
    use super::LifecycleEvent;
    use crate::records::types::{RecordKey, Source};

    fn rk(id: &str) -> RecordKey {
        RecordKey {
            source: Some(Source::Local),
            project_id: Some("nexum".into()),
            id: id.into(),
        }
    }

    #[test]
    fn lifecycle_messages_render_with_prefixes() {
        assert_eq!(
            LifecycleEvent::message_for_reject(&rk("2026-04-29-x")),
            "reject: 2026-04-29-x"
        );
        assert_eq!(
            LifecycleEvent::message_for_promote(
                &rk("2026-04-29-x"),
                "2026-05-21-x-decision",
                "a1b2c3d4e5"
            ),
            "promote: 2026-04-29-x -> 2026-05-21-x-decision via a1b2c3d"
        );
        assert_eq!(
            LifecycleEvent::message_for_stale(&rk("2026-04-29-x")),
            "stale: 2026-04-29-x"
        );
    }
}
