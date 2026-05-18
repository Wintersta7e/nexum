//! Pricing table + cost estimation.

use chrono::{DateTime, Utc};

/// RFC3339 timestamp pinning the current pricing snapshot. The dry-run
/// manifest stores this as `pricing_snapshot_at`, and `compute_dry_run_id`
/// folds it into the hash so the id flips whenever the table is bumped.
/// Bump alongside any row in [`default_pricing_table`].
pub const PRICING_SNAPSHOT_AT_RFC3339: &str = "2026-05-18T00:00:00Z";

/// Parse [`PRICING_SNAPSHOT_AT_RFC3339`] into a `DateTime<Utc>`. Centralizes
/// the parse + timezone conversion so callers do not embed the RFC3339
/// string inline (which the dry-run and run paths both need to derive the
/// same `compute_dry_run_id` input).
///
/// # Panics
/// Panics only if the embedded const fails to parse as RFC3339 — that is a
/// build-time invariant covered by `pricing_snapshot_at_rfc3339_const_parses`,
/// so this branch is unreachable in practice.
#[must_use]
pub fn pricing_snapshot_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(PRICING_SNAPSHOT_AT_RFC3339)
        .expect("PRICING_SNAPSHOT_AT_RFC3339 const must parse")
        .with_timezone(&Utc)
}

const MAX_OUTPUT_TOKENS: u32 = 8192;

#[derive(Debug, Clone, PartialEq)]
pub struct Pricing {
    rows: Vec<PricingRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PricingRow {
    pub provider: String,
    pub model: String,
    pub input_usd_per_million: f64,
    pub output_usd_per_million: f64,
}

impl Pricing {
    #[must_use]
    pub fn new(rows: Vec<PricingRow>) -> Self {
        Self { rows }
    }

    /// Find the row matching `(provider, model)` exactly.
    #[must_use]
    pub fn lookup(&self, provider: &str, model: &str) -> Option<&PricingRow> {
        self.rows
            .iter()
            .find(|r| r.provider == provider && r.model == model)
    }
}

#[must_use]
pub fn default_pricing_table() -> Pricing {
    Pricing::new(vec![
        PricingRow {
            provider: "anthropic".into(),
            model: "claude-opus-4-7".into(),
            input_usd_per_million: 15.0,
            output_usd_per_million: 75.0,
        },
        PricingRow {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-6".into(),
            input_usd_per_million: 3.0,
            output_usd_per_million: 15.0,
        },
        PricingRow {
            provider: "anthropic".into(),
            model: "claude-haiku-4-5".into(),
            input_usd_per_million: 1.0,
            output_usd_per_million: 5.0,
        },
    ])
}

/// Conservative output-tokens estimate. Real records average <=25 % of input
/// by tokens; we cap at the runtime `MAX_OUTPUT_TOKENS` ceiling to match
/// what the `messages` request will actually allow the model to emit.
#[must_use]
pub fn estimate_output_tokens(input_tokens: u32) -> u32 {
    let raw = (input_tokens / 4).min(MAX_OUTPUT_TOKENS);
    raw.max(input_tokens.min(64)) // floor -- even tiny digests produce some output
}

#[must_use]
pub fn estimate_cost_usd(input_tokens: u32, output_tokens: u32, row: &PricingRow) -> f64 {
    let input_cost = (f64::from(input_tokens) / 1_000_000.0) * row.input_usd_per_million;
    let output_cost = (f64::from(output_tokens) / 1_000_000.0) * row.output_usd_per_million;
    input_cost + output_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_row_present_with_known_rates() {
        let table = default_pricing_table();
        let row = table
            .lookup("anthropic", "claude-opus-4-7")
            .expect("opus row");
        assert!((row.input_usd_per_million - 15.0).abs() < f64::EPSILON);
        assert!((row.output_usd_per_million - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sonnet_row_present_with_known_rates() {
        let table = default_pricing_table();
        let row = table
            .lookup("anthropic", "claude-sonnet-4-6")
            .expect("sonnet row");
        assert!((row.input_usd_per_million - 3.0).abs() < f64::EPSILON);
        assert!((row.output_usd_per_million - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn haiku_row_present_with_known_rates() {
        let table = default_pricing_table();
        let row = table
            .lookup("anthropic", "claude-haiku-4-5")
            .expect("haiku row");
        assert!((row.input_usd_per_million - 1.0).abs() < f64::EPSILON);
        assert!((row.output_usd_per_million - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn lookup_unknown_model_returns_none() {
        let table = default_pricing_table();
        assert!(table.lookup("anthropic", "no-such-model").is_none());
    }

    #[test]
    fn estimate_cost_uses_input_and_output_rates() {
        let row = PricingRow {
            provider: "anthropic".into(),
            model: "x".into(),
            input_usd_per_million: 10.0,
            output_usd_per_million: 50.0,
        };
        // 1M input @ $10, 250K output @ $50 -> $10 + $12.50 = $22.50
        let cost = estimate_cost_usd(1_000_000, 250_000, &row);
        assert!((cost - 22.5).abs() < 1e-9);
    }

    #[test]
    fn output_estimate_is_quarter_of_input_capped() {
        // 4000 input -> 1000 output (under the cap)
        assert_eq!(estimate_output_tokens(4000), 1000);
        // 100_000 input -> would estimate 25_000, capped at 8192
        assert_eq!(estimate_output_tokens(100_000), 8192);
    }

    #[test]
    fn pricing_snapshot_at_rfc3339_const_parses() {
        // A malformed const here would silently corrupt every dry-run id;
        // the gate catches it instead.
        chrono::DateTime::parse_from_rfc3339(PRICING_SNAPSHOT_AT_RFC3339)
            .expect("PRICING_SNAPSHOT_AT_RFC3339 must parse as RFC3339");
    }

    #[test]
    fn pricing_snapshot_at_returns_utc_datetime_matching_const() {
        // Helper must agree with a direct RFC3339 parse so dry-run and run
        // both feed `compute_dry_run_id` the identical timestamp.
        let via_helper = pricing_snapshot_at();
        let via_const = chrono::DateTime::parse_from_rfc3339(PRICING_SNAPSHOT_AT_RFC3339)
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(via_helper, via_const);
    }
}
