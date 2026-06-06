//! Regenerates the sample report fixtures in `examples/` from the live scoring
//! engine, so the committed samples never drift from real output.
//!
//! Run with: `cargo run --example generate_reports`

use wallet_audit::report::to_json;
use wallet_audit::risk::{generate_report, RiskSignals};

fn main() {
    let low = generate_report(
        "7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2",
        "wallet",
        &RiskSignals {
            newly_deployed_count: 1,
            ..RiskSignals::default()
        },
        "2026-06-06T09:14:52Z",
    );

    let high = generate_report(
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        "wallet",
        &RiskSignals {
            freeze_authority_active: true,
            mint_authority_active: true,
            risky_delegate_count: 2,
            close_authority_set: true,
            upgradeable_program_count: 3,
            malicious_interaction_count: 1,
            ..RiskSignals::default()
        },
        "2026-06-06T09:16:03Z",
    );

    std::fs::write(
        "examples/sample-low-risk-report.json",
        to_json(&low).unwrap(),
    )
    .unwrap();
    std::fs::write(
        "examples/sample-high-risk-report.json",
        to_json(&high).unwrap(),
    )
    .unwrap();

    println!(
        "wrote sample-low-risk-report.json (score {}) and sample-high-risk-report.json (score {})",
        low.score, high.score
    );
}
