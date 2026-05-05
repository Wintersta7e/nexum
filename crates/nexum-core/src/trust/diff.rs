//! Append-only invariant classifier for `.trust/events.yml` revisions.
//!
//! Allowed mutations: append a new event with a never-before-seen `event_id`.
//! Whitespace-only / comment-only diffs are allowed: the materializer
//! deserializes both sides into [`EventLog`] before classification, so
//! semantically-equivalent YAML formatting collapses through serde and
//! surfaces as [`Diff::NoOp`].
//!
//! Forbidden mutations (each detected and reported via [`Diff::Forbidden`]):
//!
//! - Reorder of existing events.
//! - Delete of an existing event.
//! - Mutate the payload of an existing event (any field except `event_id`).
//! - Reuse of an `event_id` that already appears earlier in the log.

use crate::trust::events::{Event, EventKind, EventLog};

/// Classification of the diff between two consecutive `events.yml` revisions.
///
/// The four arms encode all outcomes the materializer cares about:
/// `Append` is the legitimate single-event append, `Reanchor` carries a
/// `BootstrapReanchor` event whose authorization is left to a downstream
/// task, `NoOp` covers whitespace / comment-only differences that
/// deserialize identically, and `Forbidden` covers any mutation that breaks
/// the append-only invariant.
#[derive(Debug, Clone, PartialEq)]
pub enum Diff {
    /// Allowed: a single new event appended at the end of the log.
    Append(Event),
    /// Allowed special case: a single new `BootstrapReanchor` event. The
    /// inner [`Event`] is consumed by a follow-up task that performs the
    /// reanchor authorization check; this iteration's materializer freezes
    /// the chain unconditionally and ignores the payload.
    #[allow(dead_code)] // Inner Event is consumed by the BootstrapReanchor verifier task.
    Reanchor(Event),
    /// Allowed: whitespace / comment-only difference. Both revisions
    /// deserialized into structurally-identical [`EventLog`] values.
    NoOp,
    /// Forbidden mutation. The materializer writes one row to
    /// `trust_chain_tampering` and freezes the chain from this commit
    /// forward.
    Forbidden {
        kind: TamperingKind,
        event_id: String,
    },
}

/// Forbidden mutation kinds recorded into `trust_chain_tampering.kind`.
/// String form matches the schema `CHECK` constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperingKind {
    /// Existing event reordered or deleted between two revisions.
    ReorderedDeleted,
    /// Existing `event_id`'s payload mutated between two revisions.
    MutatedPayload,
    /// Newly-appended event reuses an `event_id` already present earlier in
    /// the log.
    DuplicateId,
}

impl TamperingKind {
    /// Stable column value matching the `kind` `CHECK` constraint on
    /// `trust_chain_tampering`.
    pub(crate) fn as_db_str(self) -> &'static str {
        match self {
            TamperingKind::ReorderedDeleted => "ReorderedDeleted",
            TamperingKind::MutatedPayload => "MutatedPayload",
            TamperingKind::DuplicateId => "DuplicateId",
        }
    }
}

// Note: an unauthorized `BootstrapReanchor` is intentionally NOT a
// `TamperingKind`. The read-time verifier surfaces it as the
// "broken-trust-chain" warning code, not via `trust_chain_tampering`. The
// materializer persists the freeze via the `chain_frozen_at_topo` meta key.

/// Classify the diff between two consecutive `events.yml` revisions.
///
/// Same-length revisions are either [`Diff::NoOp`] (events compare equal
/// pairwise; the YAML formatting differed) or one of the forbidden kinds.
/// A shrunk revision is always [`TamperingKind::ReorderedDeleted`]. A grown
/// revision must add exactly one event whose `event_id` does not appear
/// earlier; if the new payload is `BootstrapReanchor` it is reported as
/// [`Diff::Reanchor`], otherwise as [`Diff::Append`].
pub fn classify(prev: &EventLog, current: &EventLog) -> Diff {
    let prev_len = prev.events.len();
    let curr_len = current.events.len();

    // Same length → either NoOp (identical events; YAML formatting differed)
    // or a forbidden mutation (mutated payload / reorder of an existing
    // event_id).
    if curr_len == prev_len {
        for (i, p) in prev.events.iter().enumerate() {
            let c = &current.events[i];
            if c != p {
                let kind = if c.event_id == p.event_id {
                    TamperingKind::MutatedPayload
                } else {
                    TamperingKind::ReorderedDeleted
                };
                return Diff::Forbidden {
                    kind,
                    event_id: p.event_id.to_string(),
                };
            }
        }
        return Diff::NoOp;
    }

    // Shrunk → an existing event was removed. Surface the first missing
    // event_id (by topo order) so the tampering row points at a meaningful
    // identifier.
    if curr_len < prev_len {
        let missing = prev
            .events
            .iter()
            .find(|p| !current.events.iter().any(|c| c.event_id == p.event_id))
            .map_or_else(|| "unknown".to_owned(), |p| p.event_id.to_string());
        return Diff::Forbidden {
            kind: TamperingKind::ReorderedDeleted,
            event_id: missing,
        };
    }

    // Grew. The first prev_len events must equal `prev` verbatim; the
    // single-event suffix is the new appended event. A multi-event append
    // is treated as forbidden — exactly one event per commit is the rule.
    if curr_len != prev_len + 1 {
        return Diff::Forbidden {
            kind: TamperingKind::ReorderedDeleted,
            event_id: current.events[prev_len].event_id.to_string(),
        };
    }
    for (i, p) in prev.events.iter().enumerate() {
        let c = &current.events[i];
        if c != p {
            let kind = if c.event_id == p.event_id {
                TamperingKind::MutatedPayload
            } else {
                TamperingKind::ReorderedDeleted
            };
            return Diff::Forbidden {
                kind,
                event_id: p.event_id.to_string(),
            };
        }
    }
    let new_event = current.events[prev_len].clone();
    if prev.events.iter().any(|p| p.event_id == new_event.event_id) {
        return Diff::Forbidden {
            kind: TamperingKind::DuplicateId,
            event_id: new_event.event_id.to_string(),
        };
    }
    if matches!(new_event.payload, EventKind::BootstrapReanchor { .. }) {
        Diff::Reanchor(new_event)
    } else {
        Diff::Append(new_event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn boot(id: Uuid, fp: &str) -> Event {
        Event {
            event_id: id,
            payload: EventKind::BootstrapKey {
                fingerprint: fp.into(),
                public_key: "ssh-ed25519 AAAA test".into(),
                reason: "init".into(),
            },
        }
    }

    fn added(id: Uuid, fp: &str) -> Event {
        Event {
            event_id: id,
            payload: EventKind::KeyAdded {
                fingerprint: fp.into(),
                public_key: format!("ssh-ed25519 BBBB {fp}"),
                reason: "rotation".into(),
            },
        }
    }

    #[test]
    fn append_with_new_event_id_is_allowed() {
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(Uuid::now_v7(), "K1")],
        };
        let mut current = prev.clone();
        current.events.push(added(Uuid::now_v7(), "K2"));
        match classify(&prev, &current) {
            Diff::Append(_) => {}
            other => panic!("expected Append, got {other:?}"),
        }
    }

    #[test]
    fn shrink_is_reordered_deleted() {
        let id = Uuid::now_v7();
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(id, "K1"), added(Uuid::now_v7(), "K2")],
        };
        let current = EventLog {
            schema_version: 1,
            events: vec![boot(id, "K1")],
        };
        assert!(matches!(
            classify(&prev, &current),
            Diff::Forbidden {
                kind: TamperingKind::ReorderedDeleted,
                ..
            }
        ));
    }

    #[test]
    fn payload_mutation_preserves_event_id() {
        let id = Uuid::now_v7();
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(id, "K1")],
        };
        let current = EventLog {
            schema_version: 1,
            events: vec![boot(id, "K1-MUTATED")],
        };
        match classify(&prev, &current) {
            Diff::Forbidden {
                kind: TamperingKind::MutatedPayload,
                event_id,
            } => {
                assert_eq!(event_id, id.to_string());
            }
            other => panic!("expected MutatedPayload, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_event_id_in_appended_event_is_forbidden() {
        let dup = Uuid::now_v7();
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(dup, "K1")],
        };
        let mut current = prev.clone();
        current.events.push(added(dup, "K2")); // reuse event_id
        match classify(&prev, &current) {
            Diff::Forbidden {
                kind: TamperingKind::DuplicateId,
                event_id,
            } => {
                assert_eq!(event_id, dup.to_string());
            }
            other => panic!("expected DuplicateId, got {other:?}"),
        }
    }

    #[test]
    fn reorder_swaps_two_events() {
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(id1, "K1"), added(id2, "K2")],
        };
        let current = EventLog {
            schema_version: 1,
            events: vec![boot(id2, "K1"), added(id1, "K2")],
        };
        assert!(matches!(
            classify(&prev, &current),
            Diff::Forbidden {
                kind: TamperingKind::ReorderedDeleted,
                ..
            }
        ));
    }

    #[test]
    fn identical_logs_are_noop() {
        let prev = EventLog {
            schema_version: 1,
            events: vec![boot(Uuid::now_v7(), "K1")],
        };
        let current = prev.clone();
        assert!(matches!(classify(&prev, &current), Diff::NoOp));
    }
}
