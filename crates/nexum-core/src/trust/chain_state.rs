//! Trusted-signer state machine: tracks each fingerprint's state across
//! topological positions in `notebook.git`. Mutated by the materializer as it
//! walks `.trust/events.yml` history; queried at read time by the trust
//! projection helpers.

use std::collections::HashMap;

/// Outcome of a trust-state lookup at a given topological position.
///
/// Forward-looking surface: variants are populated by `state_of`, which the
/// read-time trust projection consumes when its wiring lands. Until then the
/// only callers are the chain-state unit tests.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    /// `Some` for keys carried over from a pre-reanchor chain. `None` for
    /// keys introduced after a reanchor or in chains that never reanchored.
    /// Currently always `None`: the reanchor handler that sets it lands
    /// alongside the bootstrap-reanchor verifier exception.
    #[allow(dead_code)]
    pre_reanchor: Option<ReanchorCase>,
}

/// Trusted-signer state machine. Mutated by the materializer; queried both
/// internally (to authorize new appends) and externally (by read-time trust
/// projection helpers).
#[derive(Debug, Default)]
pub(crate) struct ChainState {
    /// All signers ever introduced into the chain, keyed by SSH fingerprint
    /// (`SHA256:...` form). Private — read access is via the typed methods
    /// (`is_trusted_at`, `state_of`, `introducer_of`) so the storage shape
    /// stays an implementation detail.
    keys: HashMap<String, KeyEntry>,
    /// Topological position at which the chain was frozen due to a chain
    /// integrity violation (unauthorized append, malformed reanchor, etc.).
    /// `None` while the chain is healthy.
    frozen_at_topo: Option<u64>,
}

impl ChainState {
    /// Construct an empty state.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record the bootstrap signer at the chain root (topological position 0).
    pub(crate) fn set_bootstrap(&mut self, fingerprint: &str, event_id: &str, topo_pos: u64) {
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
    ///
    /// Currently only consumed by the chain-state unit tests; the read-time
    /// trust projection wires it once the verifier is end-to-end.
    #[allow(dead_code)]
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
}
