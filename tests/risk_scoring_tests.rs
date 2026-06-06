use wallet_audit::risk::rules::RiskCategory;
use wallet_audit::risk::{
    build_findings, calculate_risk_score, generate_report, RiskFinding, RiskLevel, RiskSignals,
};

fn signals() -> RiskSignals {
    RiskSignals::default()
}

#[test]
fn clean_wallet_score_is_zero() {
    let report = generate_report("wallet", "wallet", &signals(), "2026-01-01T00:00:00Z");
    assert_eq!(report.score, 0);
    assert_eq!(report.level, RiskLevel::Minimal);
    assert!(report.findings.is_empty());
}

#[test]
fn high_risk_wallet_score_is_capped_at_100() {
    let s = RiskSignals {
        freeze_authority_active: true,
        mint_authority_active: true,
        risky_delegate_count: 9,
        close_authority_set: true,
        upgradeable_program_count: 4,
        malicious_interaction_count: 3,
        newly_deployed_count: 2,
        suspicious_holder_concentration: true,
    };
    // Raw weights sum to 130; the score must clamp.
    let report = generate_report("wallet", "wallet", &s, "2026-01-01T00:00:00Z");
    assert_eq!(report.score, 100);
    assert_eq!(report.level, RiskLevel::Critical);
}

#[test]
fn freeze_authority_increases_score() {
    let s = RiskSignals {
        freeze_authority_active: true,
        ..signals()
    };
    let report = generate_report("w", "wallet", &s, "t");
    assert_eq!(report.score, 20);
    assert!(report
        .findings
        .iter()
        .any(|f| f.category == "freeze_authority"));
}

#[test]
fn mint_authority_increases_score() {
    let s = RiskSignals {
        mint_authority_active: true,
        ..signals()
    };
    assert_eq!(calculate_risk_score(&build_findings(&s)), 20);
}

#[test]
fn risky_delegate_increases_score() {
    let s = RiskSignals {
        risky_delegate_count: 2,
        ..signals()
    };
    let findings = build_findings(&s);
    assert_eq!(calculate_risk_score(&findings), 15);
    // Count is surfaced in the detail string, not the score.
    assert!(findings[0].detail.as_deref().unwrap().contains('2'));
}

#[test]
fn close_authority_increases_score() {
    let s = RiskSignals {
        close_authority_set: true,
        ..signals()
    };
    assert_eq!(calculate_risk_score(&build_findings(&s)), 10);
}

#[test]
fn malicious_address_increases_score() {
    let s = RiskSignals {
        malicious_interaction_count: 1,
        ..signals()
    };
    assert_eq!(calculate_risk_score(&build_findings(&s)), 25);
}

#[test]
fn upgradeable_program_increases_score() {
    let s = RiskSignals {
        upgradeable_program_count: 1,
        ..signals()
    };
    assert_eq!(calculate_risk_score(&build_findings(&s)), 15);
}

#[test]
fn holder_concentration_increases_score() {
    let s = RiskSignals {
        suspicious_holder_concentration: true,
        ..signals()
    };
    assert_eq!(calculate_risk_score(&build_findings(&s)), 15);
}

#[test]
fn duplicate_risks_do_not_double_count() {
    let finding = RiskFinding::from_category(RiskCategory::FreezeAuthority, None);
    let score = calculate_risk_score(&[finding.clone(), finding.clone(), finding]);
    assert_eq!(score, 20);
}

#[test]
fn every_finding_carries_actionable_metadata() {
    for category in RiskCategory::ALL {
        let finding = RiskFinding::from_category(category, None);
        assert!(!finding.label.is_empty(), "{} label", category.key());
        assert!(
            !finding.explanation.is_empty(),
            "{} explanation",
            category.key()
        );
        assert!(
            !finding.recommendation.is_empty(),
            "{} recommendation",
            category.key()
        );
        assert!(finding.weight > 0, "{} weight", category.key());
    }
}

#[test]
fn risk_levels_track_score_thresholds() {
    assert_eq!(RiskLevel::from_score(0), RiskLevel::Minimal);
    assert_eq!(RiskLevel::from_score(9), RiskLevel::Minimal);
    assert_eq!(RiskLevel::from_score(10), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(30), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(60), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(85), RiskLevel::Critical);
    assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
}
