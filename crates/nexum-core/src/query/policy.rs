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

use crate::query::verify::ProjectedTrust;
use crate::records::{SignatureStatus, TrustPolicy};

/// Policy inputs collected at the verb call site. `policy` and
/// `require_signed` come from the caller's options or runtime config;
/// `strict_revocation` is the same flag forwarded to
/// [`crate::query::verify::project_trust`] for the projection step.
#[derive(Debug, Clone, Copy)]
pub struct PolicyOpts {
    pub policy: TrustPolicy,
    pub require_signed: bool,
    pub strict_revocation: bool,
}

/// Outcome of a single [`apply`] call: the surviving rows plus the
/// per-bucket hidden counters and the envelope warning codes.
#[derive(Debug, Clone)]
pub struct PolicyOutcome<T> {
    pub visible: Vec<T>,
    pub hidden_unsigned: u32,
    pub hidden_invalid: u32,
    pub hidden_compromised: u32,
    pub policy_warnings: Vec<String>,
}

// Hand-rolled to avoid the spurious `T: Default` bound a derive would add.
impl<T> Default for PolicyOutcome<T> {
    fn default() -> Self {
        Self {
            visible: Vec::new(),
            hidden_unsigned: 0,
            hidden_invalid: 0,
            hidden_compromised: 0,
            policy_warnings: Vec::new(),
        }
    }
}

/// Apply the warn/hide/strict policy filter to a slice of post-projection
/// rows. The `classify` closure plucks the [`ProjectedTrust`] reference
/// out of each row so callers can carry per-verb side data (scores, raw
/// columns) alongside the projection without copying.
pub fn apply<T, F>(rows: Vec<T>, opts: &PolicyOpts, classify: F) -> PolicyOutcome<T>
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

    fn opts(policy: TrustPolicy, require_signed: bool, strict_revocation: bool) -> PolicyOpts {
        PolicyOpts {
            policy,
            require_signed,
            strict_revocation,
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
        let out = apply(rows(), &opts(TrustPolicy::WarnButShow, false, false), pluck);
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
        let out = apply(rows(), &opts(TrustPolicy::Hide, false, false), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
        assert!(out.policy_warnings.is_empty());
    }

    #[test]
    fn show_silent_keeps_non_strict_filters_compromised_and_emits_no_warnings() {
        let out = apply(rows(), &opts(TrustPolicy::ShowSilent, false, false), pluck);
        // ShowSilent never adds an envelope warning, but the
        // strict-revocation drop is independent of policy.
        assert_eq!(out.visible.len(), 3);
        assert_eq!(out.hidden_compromised, 1);
        assert!(out.policy_warnings.is_empty());
    }

    #[test]
    fn require_signed_overrides_warn_but_show() {
        let out = apply(rows(), &opts(TrustPolicy::WarnButShow, true, false), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
    }

    #[test]
    fn require_signed_overrides_show_silent() {
        let out = apply(rows(), &opts(TrustPolicy::ShowSilent, true, false), pluck);
        assert_eq!(out.visible.len(), 1);
        assert_eq!(out.hidden_unsigned, 1);
        assert_eq!(out.hidden_invalid, 1);
        assert_eq!(out.hidden_compromised, 1);
    }
}

#[cfg(test)]
mod cell_tests {
    //! End-to-end policy-cell coverage. Each test seeds a fixture chain,
    //! inserts representative records, and exercises a verb (`search` or
    //! `get`) so the verb-level wire-up of [`super::apply`] is verified
    //! alongside the helper logic.

    use crate::query::test_util::{
        TEST_BOOTSTRAP_FP, TEST_COMPROMISED_FP, TEST_TRUST_COMMIT, TEST_TRUST_COMMIT_COMPROMISED,
        seed_bootstrap_chain, seed_compromised_key_chain,
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

    /// FTS-indexed token shared by every cell-test record so a single
    /// `search` invocation matches the whole canonical set. The
    /// `body` column carries it; FTS5 indexes `title`, `summary`, `body`,
    /// and `tags_fts`.
    const CELL_TOKEN: &str = "celltoken";

    fn insert_record(
        conn: &Connection,
        id: &str,
        crypto_result: &str,
        signer_fp: Option<&str>,
        trust_commit: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO records (
                id, record_type, title, body, source, project_id,
                agent, confidence, outcome,
                session_refs, files, commits,
                crypto_result, signer_fingerprint, relevant_trust_events_commit,
                tags, tags_fts,
                created, updated, content_hash, index_hash, indexed_at
             ) VALUES (?1, 'decision', ?1, ?5, 'local', 'git:test',
                'manual', 'medium', 'working',
                '[]', '[]', '[]',
                ?2, ?3, ?4,
                '[]', '',
                '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', '2026-04-29T00:00:00Z')",
            rusqlite::params![id, crypto_result, signer_fp, trust_commit, CELL_TOKEN],
        )
        .unwrap();
    }

    /// Seed the four canonical record shapes (verified, unsigned,
    /// bad-signature, signed-by-compromised-key) that drive the policy
    /// decision tree's full coverage.
    fn seed_canonical_records(conn: &Connection) {
        insert_record(
            conn,
            "verified",
            "good",
            Some(TEST_BOOTSTRAP_FP),
            Some(TEST_TRUST_COMMIT),
        );
        insert_record(conn, "unsigned", "no-signature", None, None);
        insert_record(conn, "bad-sig", "bad-signature", None, None);
        insert_record(
            conn,
            "compromised",
            "good",
            Some(TEST_COMPROMISED_FP),
            Some(TEST_TRUST_COMMIT_COMPROMISED),
        );
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
        assert!(matches!(outcome, GetOutcome::Found(_)));
    }
}
