//! Trusted-signer state machine: tracks each fingerprint's state across
//! topological positions in `notebook.git`. Mutated by the materializer as it
//! walks `.trust/events.yml` history; queried at read time by the trust
//! projection helpers.

use std::collections::HashMap;

/// Outcome of a trust-state lookup at a given topological position.
///
/// Populated by [`ChainState::state_of`], which the read-time trust
/// projection consumes (see `crate::query::verify::project_trust`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// Signer is trusted at the current head of events.yml.
    TrustedNow,
    /// Signer was trusted at the queried topo position but has since been
    /// routinely rotated out. No `KeyCompromised` event later.
    Rotated,
    /// Signer has a `KeyCompromised` event in its history.
    Compromised,
    /// Signer was not yet trusted at the queried topo position (commit
    /// predates any event that introduced it).
    NotYetTrustedAtCommit,
    /// Signer is in the pre-reanchor chain (before a `BootstrapReanchor`
    /// event). Case A vs. Case B is determined by pin presence at
    /// materialization time.
    PreReanchor { case: ReanchorCase },
    /// Some events.yml revision was signed by a then-untrusted key, OR an
    /// unauthorized `BootstrapReanchor` was attempted.
    BrokenChain,
}

/// Pre-reanchor disposition for keys carried over from a chain that was
/// later reanchored. `A` = pin intact (records still verify under default
/// policy); `B` = pin lost (records carry a chain-anchor-lost warning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorCase {
    /// Pin intact: the post-reanchor chain root matches the recorded pin.
    A,
    /// Pin lost: no recorded pin, so callers cannot prove the bootstrap
    /// anchor matches the historical one.
    B,
}

/// One trusted-signer entry: when the signer was introduced, optional
/// rotation/compromise positions, and the introducing event id used to
/// populate `chain_validated_by` on subsequent rows. Module-private — the
/// `ChainState` accessors expose only the views callers need.
#[derive(Debug, Clone)]
struct KeyEntry {
    /// Topological position at which this signer became trusted.
    trusted_at_topo: u64,
    /// Topological position at which the signer was routinely rotated out
    /// (`KeyRotatedOut`), or `None` if never rotated.
    rotated_at_topo: Option<u64>,
    /// Topological position at which the signer was marked compromised
    /// (`KeyCompromised`), or `None` if never marked.
    compromised_at_topo: Option<u64>,
    /// `event_id` of the event that introduced this signer (the bootstrap
    /// event, or the `KeyAdded` event). Used by the materializer to populate
    /// `chain_validated_by`.
    introduced_by_event_id: String,
    /// `Some(case)` for keys trusted before a `BootstrapReanchor`; `None`
    /// for keys introduced at or after a reanchor (and for chains that never
    /// reanchored). Set by `ChainState::apply_reanchor` once the materializer
    /// authorizes the reanchor; consumed by `state_of` so the read-time
    /// trust projection can map these to `TrustState::PreReanchor`.
    pre_reanchor: Option<ReanchorCase>,
}

/// Trusted-signer state machine. Mutated by the materializer; queried both
/// internally (to authorize new appends) and externally (by read-time trust
/// projection helpers).
///
/// `ChainState` is `pub` because the integration-test crate constructs it
/// via [`Self::from_view`] when exercising the read-time projection. The
/// mutating helpers (`set_bootstrap`, `apply_*`, `freeze`) stay
/// `pub(crate)` so external code cannot synthesize unauthorized chain
/// state.
#[derive(Debug, Default)]
pub struct ChainState {
    /// All signers ever introduced into the chain, keyed by SSH fingerprint
    /// (`SHA256:...` form). Private — read access is via the typed methods
    /// (`is_trusted_at`, `state_of`, `introducer_of`) so the storage shape
    /// stays an implementation detail.
    keys: HashMap<String, KeyEntry>,
    /// Topological position at which the chain was frozen due to a chain
    /// integrity violation (unauthorized append, malformed reanchor, etc.).
    /// `None` while the chain is healthy.
    frozen_at_topo: Option<u64>,
    /// Current bootstrap fingerprint at the latest applied event. Tracks the
    /// chain's root identity across reanchors. Set by `set_bootstrap` and
    /// updated by `apply_reanchor`; consulted by the materializer's reanchor
    /// authorization check to enforce the "old fingerprint matches the most
    /// recent prior bootstrap" condition correctly across multi-reanchor
    /// chains. `None` only before the first bootstrap is applied.
    current_bootstrap_fp: Option<String>,
}

impl ChainState {
    /// Construct an empty state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record the bootstrap signer at the chain root (topological position 0).
    pub(crate) fn set_bootstrap(&mut self, fingerprint: &str, event_id: &str, topo_pos: u64) {
        self.current_bootstrap_fp = Some(fingerprint.to_owned());
        self.seed_key(fingerprint, event_id, topo_pos);
    }

    /// Apply a `KeyAdded` event for `fingerprint` at `topo_pos`.
    pub(crate) fn apply_key_added(&mut self, fingerprint: &str, event_id: &str, topo_pos: u64) {
        self.seed_key(fingerprint, event_id, topo_pos);
    }

    /// Insert (or replace) a `KeyEntry` for a freshly introduced signer.
    /// Used by both `set_bootstrap` and `apply_key_added`; the named facades
    /// stay so call sites read intent at a glance.
    fn seed_key(&mut self, fingerprint: &str, event_id: &str, topo_pos: u64) {
        self.keys.insert(
            fingerprint.to_owned(),
            KeyEntry {
                trusted_at_topo: topo_pos,
                rotated_at_topo: None,
                compromised_at_topo: None,
                introduced_by_event_id: event_id.to_owned(),
                pre_reanchor: None,
            },
        );
    }

    /// Apply a `KeyRotatedOut` event for `fingerprint` at `topo_pos`.
    /// No-op if the fingerprint is unknown (defensive: such cases should
    /// never reach here because the materializer rejects unauthorized
    /// payloads up-front).
    pub(crate) fn apply_key_rotated_out(&mut self, fingerprint: &str, topo_pos: u64) {
        if let Some(e) = self.keys.get_mut(fingerprint) {
            e.rotated_at_topo = Some(topo_pos);
        }
    }

    /// Apply a `KeyCompromised` event for `fingerprint` at `topo_pos`.
    /// No-op if the fingerprint is unknown (see `apply_key_rotated_out`).
    pub(crate) fn apply_key_compromised(&mut self, fingerprint: &str, topo_pos: u64) {
        if let Some(e) = self.keys.get_mut(fingerprint) {
            e.compromised_at_topo = Some(topo_pos);
        }
    }

    /// Mark the chain as frozen at `at_topo`. Subsequent `state_of` queries
    /// at-or-after this position return `BrokenChain`.
    pub(crate) fn freeze(&mut self, at_topo: u64) {
        self.frozen_at_topo = Some(at_topo);
    }

    /// Apply an authorized `BootstrapReanchor` event. Marks every key trusted
    /// strictly *before* `topo_pos` as pre-reanchor under `case`, then seeds
    /// `new_fp` as the new bootstrap signer at `topo_pos`. Updates
    /// `current_bootstrap_fp` so subsequent reanchor authorization checks
    /// compare against the most recent bootstrap (correct across chained
    /// reanchors). The event payload's `old_fingerprint` is consumed by
    /// the caller's authorization check before this method runs and is
    /// not threaded through here.
    pub(crate) fn apply_reanchor(
        &mut self,
        new_fp: &str,
        new_event_id: &str,
        topo_pos: u64,
        case: ReanchorCase,
    ) {
        for entry in self.keys.values_mut() {
            if entry.trusted_at_topo < topo_pos {
                entry.pre_reanchor = Some(case);
            }
        }
        self.keys.insert(
            new_fp.to_owned(),
            KeyEntry {
                trusted_at_topo: topo_pos,
                rotated_at_topo: None,
                compromised_at_topo: None,
                introduced_by_event_id: new_event_id.to_owned(),
                pre_reanchor: None,
            },
        );
        self.current_bootstrap_fp = Some(new_fp.to_owned());
    }

    /// Returns the current bootstrap fingerprint at the latest applied event,
    /// or `None` if no bootstrap has been applied yet. Used by the
    /// materializer to verify a reanchor's `old_fingerprint` payload matches
    /// the chain's current root before granting authorization.
    #[must_use]
    pub(crate) fn current_bootstrap_fp(&self) -> Option<&str> {
        self.current_bootstrap_fp.as_deref()
    }

    /// True if `fingerprint` is in the trusted set at `topo_pos` — i.e., was
    /// introduced at-or-before this position and has not been rotated out
    /// before this position.
    ///
    /// A `KeyCompromised` event does **not** by itself preclude
    /// `is_trusted_at` returning `true` for verifying historical *records*:
    /// records signed before compromise are still under-default valid (with
    /// a warning surfaced by read-time projection). Use
    /// [`Self::is_authorized_to_extend_chain`] for the stricter predicate
    /// that gates new appends to events.yml.
    #[must_use]
    pub(crate) fn is_trusted_at(&self, fingerprint: &str, topo_pos: u64) -> bool {
        let Some(e) = self.keys.get(fingerprint) else {
            return false;
        };
        if e.trusted_at_topo > topo_pos {
            return false;
        }
        if let Some(rot) = e.rotated_at_topo
            && rot <= topo_pos
        {
            return false;
        }
        true
    }

    /// Stricter predicate used by the materializer to decide whether
    /// `fingerprint` is allowed to author a new event in events.yml at
    /// `topo_pos`. Excludes keys with any `KeyCompromised` event in their
    /// history regardless of order: a compromised key's private material is
    /// by definition in the wrong hands, so accepting any signature from it
    /// as a chain-extension would let the attacker extend trust to
    /// themselves.
    #[must_use]
    pub(crate) fn is_authorized_to_extend_chain(&self, fingerprint: &str, topo_pos: u64) -> bool {
        if !self.is_trusted_at(fingerprint, topo_pos) {
            return false;
        }
        let Some(e) = self.keys.get(fingerprint) else {
            return false;
        };
        if e.compromised_at_topo.is_some() {
            return false;
        }
        true
    }

    /// Returns the trust state of `fingerprint` at `topo_pos` (the commit's
    /// topological position) given the current chain head's view.
    /// Consumed by the read-time trust projection
    /// (`crate::query::verify::project_trust`).
    #[must_use]
    pub(crate) fn state_of(&self, fingerprint: &str, topo_pos: u64) -> TrustState {
        if let Some(frozen) = self.frozen_at_topo
            && topo_pos >= frozen
        {
            return TrustState::BrokenChain;
        }
        let Some(e) = self.keys.get(fingerprint) else {
            return TrustState::NotYetTrustedAtCommit;
        };
        if e.trusted_at_topo > topo_pos {
            return TrustState::NotYetTrustedAtCommit;
        }
        if let Some(case) = e.pre_reanchor {
            return TrustState::PreReanchor { case };
        }
        if e.compromised_at_topo.is_some() {
            return TrustState::Compromised;
        }
        if let Some(rot) = e.rotated_at_topo {
            if rot <= topo_pos {
                // Defensive: post-rotation positions are equivalent to the
                // signer not yet being trusted (the rotation removed them
                // from the trusted set).
                return TrustState::NotYetTrustedAtCommit;
            }
            return TrustState::Rotated;
        }
        TrustState::TrustedNow
    }

    /// Returns the `event_id` of the prior event that introduced
    /// `fingerprint` (the bootstrap event, or the `KeyAdded` event). Used to
    /// populate `chain_validated_by` on each new event row.
    #[must_use]
    pub(crate) fn introducer_of(&self, fingerprint: &str) -> Option<String> {
        self.keys
            .get(fingerprint)
            .map(|e| e.introduced_by_event_id.clone())
    }

    /// Hydrate a `ChainState` from the materialized `trust_events` table
    /// plus the `chain_frozen_at_topo` meta sentinel. Used by query verbs
    /// to reconstruct chain state at read time without re-walking
    /// `notebook.git`.
    ///
    /// Reads two sources of freeze information and applies the earliest:
    /// 1. `trust_chain_tampering` rows (forbidden mutations).
    /// 2. The `chain_frozen_at_topo` meta key (unauthorized reanchor).
    ///
    /// # Errors
    ///
    /// Returns `crate::trust::events::TrustError::Sqlite` if any of the
    /// underlying queries fail.
    pub fn from_view(
        view: &crate::trust::events_view::TrustEventsView<'_>,
    ) -> Result<Self, crate::trust::events::TrustError> {
        let mut chain = Self::new();
        let conn = view.conn();
        let mut stmt = conn.prepare(
            "SELECT event_id, kind, fingerprint, old_fingerprint, new_fingerprint,
                    effective_commit_topo_pos, chain_anchor_lost
             FROM trust_events
             ORDER BY effective_commit_topo_pos ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,         // event_id
                r.get::<_, String>(1)?,         // kind
                r.get::<_, Option<String>>(2)?, // fingerprint
                r.get::<_, Option<String>>(3)?, // old_fingerprint
                r.get::<_, Option<String>>(4)?, // new_fingerprint
                r.get::<_, i64>(5)?,            // topo_pos (i64 in SQL)
                r.get::<_, Option<i64>>(6)?,    // chain_anchor_lost
            ))
        })?;

        for row in rows {
            let (event_id, kind, fp, old_fp, new_fp, topo_pos_i64, chain_anchor_lost) = row?;
            let topo_pos = u64::try_from(topo_pos_i64).unwrap_or(0);
            chain.apply_persisted_event(&PersistedEvent {
                kind: kind.as_str(),
                fp: fp.as_deref(),
                old_fp: old_fp.as_deref(),
                new_fp: new_fp.as_deref(),
                event_id: &event_id,
                topo_pos,
                chain_anchor_lost,
            });
        }

        // Earliest freeze across both persistence sources: tampering rows
        // (forbidden mutations) and the meta sentinel (unauthorized
        // reanchor). The two sources can overlap; take the minimum so a
        // pre-existing tampering freeze isn't masked by a later sentinel.
        let earliest_tamper: Option<i64> = conn
            .query_row(
                "SELECT MIN(at_topo_pos) FROM trust_chain_tampering",
                [],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        let chain_frozen_meta =
            crate::index::meta::read_topo(conn, crate::index::meta::KEY_CHAIN_FROZEN_AT_TOPO)
                .ok()
                .flatten();
        let earliest = match (earliest_tamper, chain_frozen_meta) {
            (Some(a), Some(b)) => Some(a.min(i64::try_from(b).unwrap_or(i64::MAX))),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(i64::try_from(b).unwrap_or(i64::MAX)),
            (None, None) => None,
        };
        if let Some(t) = earliest {
            chain.freeze(u64::try_from(t).unwrap_or(0));
        }
        Ok(chain)
    }

    /// Apply one persisted `trust_events` row to `self`. Encapsulates the
    /// kind dispatch so [`Self::from_view`] stays under the per-function
    /// line budget.
    fn apply_persisted_event(&mut self, ev: &PersistedEvent<'_>) {
        match ev.kind {
            "BootstrapKey" => {
                if let Some(fp) = ev.fp {
                    self.set_bootstrap(fp, ev.event_id, ev.topo_pos);
                }
            }
            "KeyAdded" => {
                if let Some(fp) = ev.fp {
                    self.apply_key_added(fp, ev.event_id, ev.topo_pos);
                }
            }
            "KeyRotatedOut" => {
                if let Some(fp) = ev.fp {
                    self.apply_key_rotated_out(fp, ev.topo_pos);
                }
            }
            "KeyCompromised" => {
                if let Some(fp) = ev.fp {
                    self.apply_key_compromised(fp, ev.topo_pos);
                }
            }
            "BootstrapReanchor" => {
                if let (Some(_old), Some(new)) = (ev.old_fp, ev.new_fp) {
                    let case = if ev.chain_anchor_lost.unwrap_or(0) != 0 {
                        ReanchorCase::B
                    } else {
                        ReanchorCase::A
                    };
                    self.apply_reanchor(new, ev.event_id, ev.topo_pos, case);
                }
            }
            _ => {}
        }
    }
}

/// Per-row shape consumed by [`ChainState::apply_persisted_event`]. Bundles
/// the materializer-row fields so the dispatch helper stays under the
/// strict-clippy `too_many_arguments` cap.
struct PersistedEvent<'a> {
    kind: &'a str,
    fp: Option<&'a str>,
    old_fp: Option<&'a str>,
    new_fp: Option<&'a str>,
    event_id: &'a str,
    topo_pos: u64,
    chain_anchor_lost: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_set_makes_signer_trusted_at_topo_zero() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        assert!(c.is_trusted_at("SHA256:abc", 0));
        assert!(c.is_trusted_at("SHA256:abc", 5));
        assert_eq!(c.state_of("SHA256:abc", 5), TrustState::TrustedNow);
    }

    #[test]
    fn key_added_at_topo_two_makes_signer_trusted_from_two() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        c.apply_key_added("SHA256:def", "ev2", 2);
        assert!(!c.is_trusted_at("SHA256:def", 1));
        assert!(c.is_trusted_at("SHA256:def", 2));
        assert!(c.is_trusted_at("SHA256:def", 5));
    }

    #[test]
    fn rotated_out_state_at_pre_rotation_topo_is_rotated() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        c.apply_key_rotated_out("SHA256:abc", 3);
        assert_eq!(c.state_of("SHA256:abc", 1), TrustState::Rotated);
    }

    #[test]
    fn compromised_dominates_rotated_in_state_lookup() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        c.apply_key_compromised("SHA256:abc", 2);
        assert_eq!(c.state_of("SHA256:abc", 1), TrustState::Compromised);
    }

    #[test]
    fn frozen_chain_returns_broken_chain_for_post_freeze_topo() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        c.freeze(3);
        assert_eq!(c.state_of("SHA256:abc", 5), TrustState::BrokenChain);
        assert_eq!(c.state_of("SHA256:abc", 1), TrustState::TrustedNow);
    }

    #[test]
    fn state_after_rotation_topo_returns_not_yet_trusted() {
        // Once a key is rotated out at topo N, queries at topo >= N must NOT
        // report it as trusted: post-rotation positions fall back to the
        // not-yet-trusted state, mirroring the same handling the verifier
        // gives commits that predate the introducing event.
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:abc", "ev1", 0);
        c.apply_key_rotated_out("SHA256:abc", 3);
        assert_eq!(
            c.state_of("SHA256:abc", 3),
            TrustState::NotYetTrustedAtCommit
        );
        assert_eq!(
            c.state_of("SHA256:abc", 5),
            TrustState::NotYetTrustedAtCommit
        );
    }

    #[test]
    fn apply_reanchor_marks_prior_keys_as_pre_reanchor_and_seeds_new_bootstrap() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:A", "boot1", 0);
        c.apply_key_added("SHA256:B", "ka", 1);
        // Reanchor at topo 5: A → D, Case A (pin preserved).
        c.apply_reanchor("SHA256:D", "reanchor1", 5, ReanchorCase::A);

        // Pre-reanchor signers: A and B both project as PreReanchor { A }.
        assert_eq!(
            c.state_of("SHA256:A", 0),
            TrustState::PreReanchor {
                case: ReanchorCase::A
            }
        );
        assert_eq!(
            c.state_of("SHA256:B", 1),
            TrustState::PreReanchor {
                case: ReanchorCase::A
            }
        );
        // The new bootstrap projects as Trusted from the reanchor topo onward.
        assert_eq!(c.state_of("SHA256:D", 5), TrustState::TrustedNow);
        assert_eq!(c.state_of("SHA256:D", 9), TrustState::TrustedNow);
        // current_bootstrap_fp tracks the most recent bootstrap so a
        // subsequent reanchor's old_fp can be checked against it.
        assert_eq!(c.current_bootstrap_fp(), Some("SHA256:D"));
    }

    #[test]
    fn apply_reanchor_case_b_marks_prior_keys_with_case_b() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:A", "boot1", 0);
        c.apply_reanchor("SHA256:D", "reanchor1", 3, ReanchorCase::B);
        assert_eq!(
            c.state_of("SHA256:A", 0),
            TrustState::PreReanchor {
                case: ReanchorCase::B
            }
        );
    }

    #[test]
    fn chained_reanchor_old_fp_must_match_most_recent_prior_bootstrap() {
        let mut c = ChainState::new();
        c.set_bootstrap("SHA256:A", "boot", 0);
        // R1: A → D.
        c.apply_reanchor("SHA256:D", "r1", 3, ReanchorCase::A);
        assert_eq!(c.current_bootstrap_fp(), Some("SHA256:D"));
        // R2: D → E. After this, current_bootstrap_fp must be E and the
        // would-be R3 must compare its old_fp against E (not the original A).
        c.apply_reanchor("SHA256:E", "r2", 7, ReanchorCase::A);
        assert_eq!(c.current_bootstrap_fp(), Some("SHA256:E"));
        // Both old bootstraps now project as PreReanchor.
        assert_eq!(
            c.state_of("SHA256:A", 0),
            TrustState::PreReanchor {
                case: ReanchorCase::A
            }
        );
        assert_eq!(
            c.state_of("SHA256:D", 3),
            TrustState::PreReanchor {
                case: ReanchorCase::A
            }
        );
        // Latest bootstrap is current.
        assert_eq!(c.state_of("SHA256:E", 8), TrustState::TrustedNow);
    }
}
