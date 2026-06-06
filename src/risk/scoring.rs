//! Scoring functions. The scan layer produces [`RiskSignals`]; this module turns
//! them into findings and an aggregate 0-100 score.

use std::collections::HashSet;

use super::rules::RiskCategory;
use super::{RiskFinding, RiskLevel, RiskReport, RiskSignals, MAX_SCORE};

/// Turn raw signals into one finding per active risk category.
///
/// At most one finding is emitted per category, so the result is already
/// deduplicated by construction.
pub fn build_findings(signals: &RiskSignals) -> Vec<RiskFinding> {
    let mut findings = Vec::new();

    if signals.freeze_authority_active {
        findings.push(RiskFinding::from_category(
            RiskCategory::FreezeAuthority,
            None,
        ));
    }
    if signals.mint_authority_active {
        findings.push(RiskFinding::from_category(
            RiskCategory::MintAuthority,
            None,
        ));
    }
    if signals.risky_delegate_count > 0 {
        findings.push(RiskFinding::from_category(
            RiskCategory::RiskyDelegate,
            Some(format!(
                "{} token account(s) with an active delegate",
                signals.risky_delegate_count
            )),
        ));
    }
    if signals.close_authority_set {
        findings.push(RiskFinding::from_category(
            RiskCategory::CloseAuthority,
            None,
        ));
    }
    if signals.upgradeable_program_count > 0 {
        findings.push(RiskFinding::from_category(
            RiskCategory::UpgradeableProgram,
            Some(format!(
                "{} upgradeable program(s) in recent activity",
                signals.upgradeable_program_count
            )),
        ));
    }
    if signals.malicious_interaction_count > 0 {
        findings.push(RiskFinding::from_category(
            RiskCategory::MaliciousAddress,
            Some(format!(
                "{} known malicious address match(es)",
                signals.malicious_interaction_count
            )),
        ));
    }
    if signals.newly_deployed_count > 0 {
        findings.push(RiskFinding::from_category(
            RiskCategory::NewlyDeployed,
            Some(format!(
                "{} program(s) deployed recently",
                signals.newly_deployed_count
            )),
        ));
    }
    if signals.suspicious_holder_concentration {
        findings.push(RiskFinding::from_category(
            RiskCategory::HolderConcentration,
            None,
        ));
    }

    findings
}

/// Sum finding weights into a 0-100 score.
///
/// Each category counts at most once (findings sharing a category do not stack)
/// and the total is clamped to [`MAX_SCORE`].
pub fn calculate_risk_score(findings: &[RiskFinding]) -> u32 {
    let mut seen = HashSet::new();
    let mut total = 0u32;
    for finding in findings {
        if seen.insert(finding.category.as_str()) {
            total += finding.weight;
        }
    }
    total.min(MAX_SCORE)
}

/// Build a complete report for a target from its signals.
///
/// `generated_at` is injected so this stays deterministic and testable; the
/// caller supplies the timestamp.
pub fn generate_report(
    target: impl Into<String>,
    target_type: impl Into<String>,
    signals: &RiskSignals,
    generated_at: impl Into<String>,
) -> RiskReport {
    let findings = build_findings(signals);
    let score = calculate_risk_score(&findings);
    RiskReport {
        target: target.into(),
        target_type: target_type.into(),
        score,
        level: RiskLevel::from_score(score),
        findings,
        generated_at: generated_at.into(),
    }
}
