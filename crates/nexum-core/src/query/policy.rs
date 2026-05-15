//! Centralized warn/hide/strict policy decision tree applied uniformly
//! across the read verbs.
//!
//! Each verb collects rows, projects per-row trust state via
//! [`crate::query::verify::project_trust`], and then post-processes the
//! `(row, projected)` pairs through [`apply`]. The result carries the
//! visible items, the per-bucket hidden counters, and the
//! `policy_warnings` envelope codes the meta builder forwards to callers.
//!
//! Decision order — invariants 1-5 from the spec read-path contract:
//!
//! 1. `require_signed` filters out anything that is not `Verified`,
//!    regardless of policy. Stricter override.
//! 2. Strict-revocation hits (`signed-by-compromised-key` overlaid with
//!    `strict-revocation-active`) are always filtered out and counted into
//!    `hidden_compromised`. Independent of [`TrustPolicy`].
//! 3. The remaining rows route through [`TrustPolicy`]:
//!    - `Hide` excludes everything that is not `Verified`.
//!    - `WarnButShow` keeps non-`Verified` rows visible and triggers the
//!      `non-verified-results-included` envelope warning.
//!    - `ShowSilent` passes everything through without an envelope warning.

use crate::query::types::{MetaTrustBasisSummary, MetaTrustSummary};
use crate::query::verify::ProjectedTrust;
use crate::records::{SignatureStatus, TrustBasis, TrustPolicy};

/// Policy inputs collected at the verb call site. `policy` and
/// `require_signed` come from the caller's options or runtime config.
/// The strict-revocation overlay is encoded upstream by
/// [`crate::query::verify::project_trust`] as the
/// `strict-revocation-active` warning, which [`apply`] detects to route
/// rows into the dedicated `hidden_compromised` bucket.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PolicyOpts {
    pub policy: TrustPolicy,
    pub require_signed: bool,
}

/// Outcome of a single [`apply`] call: the surviving rows, the per-bucket
/// hidden counters, the envelope warning codes, plus the pre-policy
/// `trust_summary` and `trust_basis_summary` tallies.
///
/// `trust_summary` and `trust_basis_summary` are populated from EVERY input
/// row regardless of whether the policy filter excluded it. They are the
/// transparency channel: callers surface them on `_meta.trust_summary` /
/// `_meta.trust_basis_summary` so the response describes what the
/// projection produced, not just what the policy filter let through.
#[derive(Debug, Clone)]
pub(crate) struct PolicyOutcome<T> {
    pub visible: Vec<T>,
    pub hidden_unsigned: u32,
    pub hidden_invalid: u32,
    pub hidden_compromised: u32,
    pub policy_warnings: Vec<String>,
    pub trust_summary: MetaTrustSummary,
    pub trust_basis_summary: MetaTrustBasisSummary,
}

// Hand-rolled to avoid the spurious `T: Default` bound a `derive(Default)`
// would add. `Vec<T>: Default` for any `T`, so this impl is unconditional.
impl<T> Default for PolicyOutcome<T> {
    fn default() -> Self {
        Self {
            visible: Vec::new(),
            hidden_unsigned: 0,
            hidden_invalid: 0,
            hidden_compromised: 0,
            policy_warnings: Vec::new(),
            trust_summary: MetaTrustSummary::default(),
            trust_basis_summary: MetaTrustBasisSummary::default(),
        }
    }
}

/// Apply the warn/hide/strict policy filter to a slice of post-projection
/// rows. The `classify` closure plucks the [`ProjectedTrust`] reference
/// out of each row so callers can carry per-verb side data (scores, raw
/// columns) alongside the projection without copying.
pub(crate) fn apply<T, F>(rows: Vec<T>, opts: PolicyOpts, classify: F) -> PolicyOutcome<T>
where
    F: Fn(&T) -> &ProjectedTrust,
{
    let mut out = PolicyOutcome::<T>::default();
    let mut any_non_verified_visible = false;

    for row in rows {
        let projected = classify(&row);
        let status = projected.signature_status;
        let is_strict_revocation_hit = projected
            .warnings
            .iter()
            .any(|w| w == "strict-revocation-active");

        // Pre-policy tally — every row contributes to the transparency
        // summaries regardless of whether the filter excludes it below.
        match status {
            SignatureStatus::Verified => out.trust_summary.verified += 1,
            SignatureStatus::Unsigned => out.trust_summary.unsigned += 1,
            SignatureStatus::Invalid => out.trust_summary.invalid += 1,
            SignatureStatus::Unknown => out.trust_summary.unknown += 1,
        }
        match projected.trust_basis {
            Some(TrustBasis::Current) => out.trust_basis_summary.current += 1,
            Some(TrustBasis::RotatedHistorical) => {
                out.trust_basis_summary.rotated_historical += 1;
            }
            Some(TrustBasis::RotatedHistoricalCompromised) => {
                out.trust_basis_summary.rotated_historical_compromised += 1;
            }
            Some(TrustBasis::PreReanchor) => out.trust_basis_summary.pre_reanchor += 1,
            None => {}
        }

        // 1. Strict-revocation hits are always filtered out and counted
        //    into `hidden_compromised`, regardless of policy or
        //    `require_signed`. Routed first so the dedicated bucket
        //    captures every revocation drop instead of leaking into the
        //    plain `hidden_invalid` bucket under stricter overrides.
        if is_strict_revocation_hit {
            out.hidden_compromised = out.hidden_compromised.saturating_add(1);
            continue;
        }

        // 2. `require_signed`: stricter override regardless of policy.
        if opts.require_signed && status != SignatureStatus::Verified {
            increment_hidden_counter(&mut out, projected);
            continue;
        }

        // 3. Apply policy to the remaining rows.
        match opts.policy {
            TrustPolicy::Hide => {
                if status != SignatureStatus::Verified {
                    increment_hidden_counter(&mut out, projected);
                    continue;
                }
            }
            TrustPolicy::WarnButShow => {
                if status != SignatureStatus::Verified {
                    any_non_verified_visible = true;
                }
            }
            TrustPolicy::ShowSilent => {
                // Pass through; envelope stays silent.
            }
        }

        out.visible.push(row);
    }

    if matches!(opts.policy, TrustPolicy::WarnButShow) && any_non_verified_visible {
        out.policy_warnings
            .push("non-verified-results-included".into());
    }
    out
}

/// Increment the appropriate `hidden_*` bucket for a non-strict-revocation
/// non-verified row. Strict-revocation hits are routed to the
/// `hidden_compromised` bucket directly in [`apply`] before this is
/// called.
fn increment_hidden_counter<T>(out: &mut PolicyOutcome<T>, projected: &ProjectedTrust) {
    if projected.signature_status == SignatureStatus::Unsigned {
        out.hidden_unsigned = out.hidden_unsigned.saturating_add(1);
    } else {
        out.hidden_invalid = out.hidden_invalid.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::TrustBasis;

    fn projected(status: SignatureStatus, warnings: Vec<&str>) -> ProjectedTrust {
        ProjectedTrust {
            signature_status: status,
            trust_basis: if status == SignatureStatus::Verified {
                Some(TrustBasis::Current)
            } else {
                None
            },
            warnings: warnings.into_iter().map(str::to_owned).collect(),
        }
    }

    fn opts(policy: TrustPolicy, require_signed: bool) -> PolicyOpts {
        PolicyOpts {
            policy,
            require_signed,
        }
    }

    fn pluck(item: &(usize, ProjectedTrust)) -> &ProjectedTrust {
        &item.1
    }

    fn rows() -> Vec<(usize, ProjectedTrust)> {
        vec![
            (1, projected(SignatureStatus::Verified, vec![])),
            (2, projected(SignatureStatus::Unsigned, vec!["unsigned"])),
            (
                3,
                projected(SignatureStatus::Invalid, vec!["bad-signature"]),
            ),
            (
                4,
                projected(
                    SignatureStatus::Invalid,
                    vec!["signed-by-compromised-key", "strict-revocation-active"],
                ),
            ),
        ]
    }

    #[test]
    fn warn_but_show_keeps_non_strict_non_verified_and_filters_compromised() {
        let out = apply(rows(), opts(TrustPolicy::WarnButShow, false), pluck);
        assert_eq!(out.visible.len(), 3, "verified + unsigned + bad visible");
        assert_eq!(out.hidden_unsigned, 0);
        assert_eq!(out.hidden_invalid, 0);
        assert_eq!(out.hidden_compromised, 1);
        assert_eq!(
            out.policy_warnings,
            vec!["non-verified-results-included".to_owned()]
        );
    }

    #[test]
    fn hide_filters_all_non_verified() {
        let out = apply(rows(), opts(TrustPolicy::Hide, false), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
        assert!(out.policy_warnings.is_empty());
    }

    #[test]
    fn show_silent_keeps_non_strict_filters_compromised_and_emits_no_warnings() {
        let out = apply(rows(), opts(TrustPolicy::ShowSilent, false), pluck);
        // ShowSilent never adds an envelope warning, but the
        // strict-revocation drop is independent of policy.
        assert_eq!(out.visible.len(), 3);
        assert_eq!(out.hidden_compromised, 1);
        assert!(out.policy_warnings.is_empty());
    }

    #[test]
    fn require_signed_overrides_warn_but_show() {
        let out = apply(rows(), opts(TrustPolicy::WarnButShow, true), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
    }

    #[test]
    fn require_signed_overrides_show_silent() {
        let out = apply(rows(), opts(TrustPolicy::ShowSilent, true), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
    }

    /// Empty input must produce a default outcome — zero counters, no
    /// envelope warnings, empty `visible`. Default-shape covers
    /// `Vec::new()` rows and lets callers default-construct an outcome
    /// when they short-circuit before invoking `apply`.
    #[test]
    fn apply_with_empty_rows_returns_default_outcome() {
        let rows: Vec<(usize, ProjectedTrust)> = Vec::new();
        let out = apply(rows, opts(TrustPolicy::WarnButShow, false), pluck);
        assert!(out.visible.is_empty());
        assert_eq!(out.hidden_unsigned, 0);
        assert_eq!(out.hidden_invalid, 0);
        assert_eq!(out.hidden_compromised, 0);
        assert!(out.policy_warnings.is_empty());
    }

    /// Transparency channel: `trust_summary` counts every projected row,
    /// even ones the policy filter excluded from `visible`. Under `Hide`
    /// the response carries only the verified row, but the summary still
    /// reflects the full pre-policy distribution so callers can see what
    /// the index produced before the filter ran.
    #[test]
    fn trust_summary_tallies_hidden_rows_as_well_as_visible() {
        let out = apply(rows(), opts(TrustPolicy::Hide, false), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
        // Visible-only would report verified=1, unsigned=0, invalid=0.
        // Pre-policy reports all four input rows.
        assert_eq!(out.trust_summary.verified, 1);
        assert_eq!(out.trust_summary.unsigned, 1);
        assert_eq!(out.trust_summary.invalid, 2, "bad-signature + compromised");
        assert_eq!(out.trust_basis_summary.current, 1);
    }
}

#[cfg(test)]
mod cell_tests {
    //! End-to-end policy-cell coverage. Each test seeds a fixture chain,
    //! inserts representative records, and exercises a verb (`search` or
    //! `get`) so the verb-level wire-up of [`super::apply`] is verified
    //! alongside the helper logic.

    use crate::query::test_util::{
        CELL_TOKEN, seed_bootstrap_chain, seed_canonical_records, seed_compromised_key_chain,
    };
    use crate::query::{
        Filters, GetOpts,
        get::get,
        search::{SearchOpts, search},
    };
    use crate::records::{GetOutcome, RecordKey, SignatureStatus, TrustPolicy};
    use rusqlite::Connection;

    /// Open a fresh in-memory DB seeded with both the bootstrap chain and
    /// the compromised-key chain. All records inserted by the cell helpers
    /// reference one of these chains.
    fn open() -> Connection {
        let conn = crate::indexer::db::open_or_create_in_memory_for_tests();
        seed_bootstrap_chain(&conn);
        seed_compromised_key_chain(&conn);
        conn
    }

    fn search_opts(
        policy: TrustPolicy,
        require_signed: bool,
        strict_revocation: bool,
    ) -> SearchOpts {
        let mut opts = SearchOpts::new(CELL_TOKEN);
        opts.top_k = 50;
        opts.trust_policy = policy;
        opts.filters = Filters {
            require_signed,
            strict_revocation,
            ..Filters::default()
        };
        opts
    }

    #[test]
    fn warn_but_show_no_flags_keeps_all_visible_and_warns() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::WarnButShow, false, false)).unwrap();
        assert_eq!(res.results.len(), 4);
        assert_eq!(res.meta.hidden_unsigned, 0);
        assert_eq!(res.meta.hidden_invalid, 0);
        assert_eq!(res.meta.hidden_compromised, 0);
        assert_eq!(
            res.meta.policy_warnings,
            vec!["non-verified-results-included".to_owned()]
        );
    }

    #[test]
    fn warn_but_show_require_signed_keeps_only_verified() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::WarnButShow, true, false)).unwrap();
        // Without strict_revocation, the compromised-key row projects as
        // Verified (rotated-historical-compromised basis) so it survives
        // require_signed alongside the canonical verified row.
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"verified"), "ids: {ids:?}");
        assert!(ids.contains(&"compromised"), "ids: {ids:?}");
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
        assert_eq!(res.meta.hidden_compromised, 0);
    }

    #[test]
    fn warn_but_show_strict_revocation_filters_compromised() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::WarnButShow, false, true)).unwrap();
        // verified + unsigned + bad-sig visible; compromised dropped.
        assert_eq!(res.results.len(), 3);
        assert!(res.results.iter().all(|r| r.id != "compromised"));
        assert_eq!(res.meta.hidden_compromised, 1);
        assert_eq!(res.meta.hidden_unsigned, 0);
        assert_eq!(res.meta.hidden_invalid, 0);
    }

    #[test]
    fn warn_but_show_both_flags_keeps_only_verified_non_compromised() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::WarnButShow, true, true)).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].id, "verified");
        // strict_revocation routes the compromised row to hidden_compromised
        // even when require_signed would also have caught it.
        assert_eq!(res.meta.hidden_compromised, 1);
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
    }

    #[test]
    fn hide_no_flags_keeps_only_verified_rows() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::Hide, false, false)).unwrap();
        // Without strict_revocation, the compromised-key record projects
        // as Verified (rotated-historical-compromised basis) and stays
        // visible under Hide alongside the canonical verified row.
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"verified"), "ids: {ids:?}");
        assert!(ids.contains(&"compromised"), "ids: {ids:?}");
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1, "bad-sig hidden under Hide");
        assert_eq!(res.meta.hidden_compromised, 0);
        assert!(res.meta.policy_warnings.is_empty());
    }

    #[test]
    fn hide_require_signed_keeps_verified_set() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::Hide, true, false)).unwrap();
        // Hide and require_signed are equivalent in their visible-row
        // contract: only Verified rows pass. Without strict_revocation,
        // the compromised row is Verified and stays.
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"verified"), "ids: {ids:?}");
        assert!(ids.contains(&"compromised"), "ids: {ids:?}");
        assert_eq!(res.results.len(), 2);
    }

    #[test]
    fn hide_strict_revocation_routes_compromised_to_hidden_compromised() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::Hide, false, true)).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].id, "verified");
        // Strict-revocation routes the compromised row to hidden_compromised
        // even under Hide; the bad-signature row stays in hidden_invalid.
        assert_eq!(res.meta.hidden_compromised, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
        assert_eq!(res.meta.hidden_unsigned, 1);
    }

    #[test]
    fn hide_both_flags_keeps_only_verified() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::Hide, true, true)).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.meta.hidden_compromised, 1);
    }

    #[test]
    fn show_silent_no_flags_keeps_all_no_warnings() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::ShowSilent, false, false)).unwrap();
        assert_eq!(res.results.len(), 4);
        assert!(res.meta.policy_warnings.is_empty());
    }

    #[test]
    fn show_silent_require_signed_keeps_verified_set() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::ShowSilent, true, false)).unwrap();
        // Without strict_revocation, the compromised-key record projects
        // as Verified and survives require_signed.
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"verified"), "ids: {ids:?}");
        assert!(ids.contains(&"compromised"), "ids: {ids:?}");
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
        assert_eq!(res.meta.hidden_compromised, 0);
    }

    #[test]
    fn show_silent_strict_revocation_filters_compromised() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::ShowSilent, false, true)).unwrap();
        assert_eq!(res.results.len(), 3);
        assert!(res.results.iter().all(|r| r.id != "compromised"));
        assert_eq!(res.meta.hidden_compromised, 1);
        assert!(res.meta.policy_warnings.is_empty());
    }

    #[test]
    fn show_silent_both_flags_keeps_only_verified() {
        let conn = open();
        seed_canonical_records(&conn);
        let res = search(&conn, &search_opts(TrustPolicy::ShowSilent, true, true)).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.meta.hidden_compromised, 1);
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
    }

    #[test]
    fn get_under_hide_returns_hidden_by_policy_for_unsigned_record() {
        let conn = open();
        seed_canonical_records(&conn);
        let outcome = get(
            &conn,
            &RecordKey::bare("unsigned"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::Hide,
                strict_revocation: false,
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            GetOutcome::HiddenByPolicy {
                signature_status: SignatureStatus::Unsigned
            }
        ));
        // The escape hatch bypasses the policy filter and returns the
        // record with its full projection, regardless of trust_policy.
        let outcome = get(
            &conn,
            &RecordKey::bare("unsigned"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::Hide,
                strict_revocation: false,
            },
        )
        .unwrap();
        assert!(matches!(outcome, GetOutcome::Found { .. }));
    }

    /// Under `WarnButShow + include_unsigned=false`, an unsigned record
    /// must surface as `Found` (the policy keeps non-verified rows
    /// visible) and carry the `unsigned` warning in its provenance — the
    /// regression-prone path the per-verb wire-up has to honor.
    #[test]
    fn get_under_warn_but_show_returns_unsigned_record_with_warning() {
        let conn = open();
        seed_canonical_records(&conn);
        let outcome = get(
            &conn,
            &RecordKey::bare("unsigned"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record, .. } = outcome else {
            panic!("expected Found under WarnButShow, got non-Found");
        };
        assert_eq!(record.id, "unsigned");
        assert_eq!(
            record.provenance.signature_status,
            SignatureStatus::Unsigned
        );
        assert!(record.provenance.warnings.contains(&"unsigned".to_owned()));
    }

    /// Same shape for a bad-signature record: `WarnButShow` keeps it
    /// visible, the projection still flags it Invalid with
    /// `bad-signature`. Confirms `get`'s policy delegation does not
    /// incorrectly hide non-Verified rows under `WarnButShow`.
    #[test]
    fn get_under_warn_but_show_returns_invalid_record_with_warning() {
        let conn = open();
        seed_canonical_records(&conn);
        let outcome = get(
            &conn,
            &RecordKey::bare("bad-sig"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record, .. } = outcome else {
            panic!("expected Found under WarnButShow, got non-Found");
        };
        assert_eq!(record.id, "bad-sig");
        assert_eq!(record.provenance.signature_status, SignatureStatus::Invalid);
        assert!(
            record
                .provenance
                .warnings
                .contains(&"bad-signature".to_owned())
        );
    }
}
