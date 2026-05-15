//! Response-invariant suite for the MCP read surface.
//!
//! Five invariants the read-path trust contract is required to uphold;
//! the MCP layer must serialize the core's `ResultSet` straight through
//! without breaking any of them.
//!
//! 1. No silent unsigned — under `warn-but-show`, every non-verified
//!    row carries at least one canonical warning code.
//! 2. Hide policy enforced — under `hide`, non-verified rows are
//!    excluded from `results`, but `_meta.trust_summary` still counts
//!    them so the agent sees what was suppressed.
//! 3. `require_signed = true` overrides policy toward stricter — every
//!    returned row has `signature_status = "verified"` regardless of
//!    the permissive default.
//! 4. `_meta.policy_warnings` is non-empty whenever the response
//!    actually surfaces an unsigned row under `warn-but-show`.
//! 5. `get` never silently returns an unverified record under `hide` —
//!    it returns the `HIDDEN_BY_POLICY` envelope; the
//!    `include_unsigned: true` override bypasses the policy and
//!    returns the record (with the trust fields populated).

mod common;

use common::{McpTestHome, expect_error_code, expect_structured};
use nexum_core::api::error::error_codes;
use rmcp::model::CallToolRequestParams;

/// Canonical warning codes from the read-time warning taxonomy that
/// mark a non-verified record. Invariant 1 requires at least one of
/// these on every non-verified row the response actually returns.
const CANONICAL_UNSIGNED_WARNINGS: &[&str] = &["unsigned", "bad-signature", "unknown-signature"];

#[tokio::test]
async fn warn_but_show_keeps_canonical_warning_and_policy_warnings() {
    // The default policy is `warn-but-show`. The fixture seeds one
    // unsigned record, so `recent` returns it visibly. The response
    // must (a) tag the row with a canonical warning code (no silent
    // unsigned) and (b) raise `_meta.policy_warnings` (the agent-
    // visible "you're consuming unsigned content" signal).
    let connected = McpTestHome::ready_unsigned_under_warn("seed-warn")
        .connect()
        .await;

    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent"))
        .await
        .expect("recent must dispatch under warn-but-show");
    let structured = expect_structured(&result);

    let rows = structured["results"]
        .as_array()
        .expect("results is an array");
    let mut saw_unsigned = false;
    for row in rows {
        if row["signature_status"] != "verified" {
            saw_unsigned = true;
            let warnings = row["warnings"]
                .as_array()
                .expect("non-verified row must carry a warnings array");
            assert!(
                warnings.iter().any(|w| w
                    .as_str()
                    .is_some_and(|s| CANONICAL_UNSIGNED_WARNINGS.contains(&s))),
                "non-verified row lacks a canonical warning code: {row}"
            );
        }
    }
    assert!(
        saw_unsigned,
        "the fixture must surface at least one unsigned row; \
         otherwise the no-silent-unsigned assertion is vacuous"
    );

    let policy_warnings = structured["_meta"]["policy_warnings"]
        .as_array()
        .expect("_meta.policy_warnings must be present and an array");
    assert!(
        !policy_warnings.is_empty(),
        "_meta.policy_warnings must be non-empty when an unsigned row is \
         actually returned under warn-but-show"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn hide_policy_excludes_unsigned_but_trust_summary_counts_them() {
    // Hide policy suppresses non-verified rows from `results`, but
    // `_meta.trust_summary` is the transparency channel — it still
    // counts the rows the projection produced, even the hidden ones.
    let connected = McpTestHome::ready_hide_policy_with_unsigned_record("hidden")
        .connect()
        .await;

    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent"))
        .await
        .expect("recent must dispatch under hide policy");
    let structured = expect_structured(&result);

    // Every returned row is verified — hide policy filtered the rest.
    let rows = structured["results"]
        .as_array()
        .expect("results is an array");
    for row in rows {
        assert_eq!(
            row["signature_status"], "verified",
            "hide policy must exclude non-verified rows: {row}"
        );
    }

    // The hidden row must still show up in the transparency channel.
    let summary = &structured["_meta"]["trust_summary"];
    let counted_non_verified = summary["unsigned"].as_u64().unwrap_or(0)
        + summary["invalid"].as_u64().unwrap_or(0)
        + summary["unknown"].as_u64().unwrap_or(0);
    assert!(
        counted_non_verified > 0,
        "_meta.trust_summary must count the suppressed rows: {summary}"
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn require_signed_overrides_warn_but_show_toward_stricter() {
    // The permissive warn-but-show default would normally surface
    // unsigned rows; `require_signed = true` is the stricter override
    // and must drop them all, regardless of policy.
    //
    // The fixture seeds two unsigned rows and zero verified rows;
    // standing up a verified-signed fixture would require an
    // SSH-signed git commit (a heavyweight setup the test harness does
    // not provide). The simpler corpus still proves the override
    // fires: every returned row must be verified, and with only
    // unsigned rows seeded, the result set is empty.
    let connected = McpTestHome::ready_require_signed_mix().connect().await;

    let mut args = serde_json::Map::new();
    args.insert("require_signed".into(), serde_json::Value::from(true));
    let result = connected
        .client
        .call_tool(CallToolRequestParams::new("recent").with_arguments(args))
        .await
        .expect("recent must dispatch with require_signed=true");
    let structured = expect_structured(&result);

    let rows = structured["results"]
        .as_array()
        .expect("results is an array");
    for row in rows {
        assert_eq!(
            row["signature_status"], "verified",
            "require_signed=true must drop non-verified rows: {row}"
        );
    }
    // The hide-bucket counter on _meta is the audit trail: the rows
    // were dropped by the require_signed override, not silently
    // missed.
    assert!(
        structured["_meta"]["hidden_unsigned"].as_u64().unwrap_or(0) >= 2,
        "_meta.hidden_unsigned must reflect the dropped unsigned rows: {}",
        structured["_meta"]
    );

    connected.shutdown().await;
}

#[tokio::test]
async fn get_under_hide_returns_envelope_unless_include_unsigned_set() {
    // Two calls drive invariant 5:
    //   1. `get` without the override returns the structured
    //      HIDDEN_BY_POLICY envelope — never silently returns the
    //      record.
    //   2. `get` with `include_unsigned = true` bypasses the policy
    //      and returns the record. The returned row carries the trust
    //      fields so the agent can apply its own judgment.
    let connected = McpTestHome::ready_hide_policy_with_unsigned_record("u")
        .connect()
        .await;

    // 1. Default call: structured HIDDEN_BY_POLICY, no record.
    let mut args = serde_json::Map::new();
    args.insert("id".into(), serde_json::Value::from("u"));
    let hidden = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(args))
        .await
        .expect("get must dispatch");
    assert_eq!(
        expect_error_code(&hidden),
        error_codes::HIDDEN_BY_POLICY,
        "get under hide returns the structured envelope, never silently the record"
    );
    let envelope = hidden
        .structured_content
        .as_ref()
        .expect("error result carries a structured envelope");
    assert!(
        envelope["remediation"].is_object(),
        "the HIDDEN_BY_POLICY envelope carries actionable remediation"
    );

    // 2. With the override: the record is returned, success path,
    //    trust fields populated.
    let mut override_args = serde_json::Map::new();
    override_args.insert("id".into(), serde_json::Value::from("u"));
    override_args.insert("include_unsigned".into(), serde_json::Value::from(true));
    let shown = connected
        .client
        .call_tool(CallToolRequestParams::new("get").with_arguments(override_args))
        .await
        .expect("get with include_unsigned must dispatch");
    let structured = expect_structured(&shown);
    assert_eq!(
        structured["record"]["id"], "u",
        "include_unsigned=true returns the record"
    );
    assert!(
        structured["record"]["provenance"]["signature_status"].is_string(),
        "the override path still surfaces the trust fields so the agent can \
         apply its own judgment: {}",
        structured["record"]
    );

    connected.shutdown().await;
}
