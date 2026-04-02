use crate::malicious::{MaliciousMatch, RecentProgram};
use crate::mint_risk::MintRiskInfo;
use crate::program_exposure::ProgramExposure;
use crate::scanner::TokenScanResult;

pub struct ScoreBreakdown {
    pub category: String,
    pub deduction: i32,
    pub details: String,
}

pub struct ScoreResult {
    pub score: i32,
    pub breakdown: Vec<ScoreBreakdown>,
}

pub fn calculate_score(
    token_scan: &TokenScanResult,
    programs: &[ProgramExposure],
    mint_risks: &[MintRiskInfo],
    malicious: &[MaliciousMatch],
    recent: &[RecentProgram],
) -> ScoreResult {
    let mut breakdown = Vec::new();
    let mut total = 0i32;

    // Risky delegates
    if !token_scan.risky_delegates.is_empty() {
        let mut ded = token_scan.risky_delegates.len() as i32 * 15;
        for acc in &token_scan.risky_delegates {
            if acc.balance > 10000.0 {
                ded += 10;
            } else if acc.balance > 1000.0 {
                ded += 5;
            }
        }
        breakdown.push(ScoreBreakdown {
            category: "Active Delegates".into(),
            deduction: ded,
            details: format!(
                "{} account(s) with active delegate permissions",
                token_scan.risky_delegates.len()
            ),
        });
        total += ded;
    }

    // Close authorities
    if !token_scan.risky_close_authorities.is_empty() {
        let ded = token_scan.risky_close_authorities.len() as i32 * 10;
        breakdown.push(ScoreBreakdown {
            category: "Close Authorities".into(),
            deduction: ded,
            details: format!(
                "{} account(s) with suspicious close authority",
                token_scan.risky_close_authorities.len()
            ),
        });
        total += ded;
    }

    // Upgradeable programs
    let upgradeable: Vec<_> = programs.iter().filter(|p| p.is_upgradeable).collect();
    if !upgradeable.is_empty() {
        let ded = (upgradeable.len() as i32 * 5).min(25);
        breakdown.push(ScoreBreakdown {
            category: "Upgradeable Programs".into(),
            deduction: ded,
            details: format!(
                "Interacted with {} upgradeable program(s) — admin key compromise risk",
                upgradeable.len()
            ),
        });
        total += ded;
    }

    // Freeze authorities
    if !mint_risks.is_empty() {
        let ded = (mint_risks.len() as i32 * 3).min(15);
        breakdown.push(ScoreBreakdown {
            category: "Freeze Authority".into(),
            deduction: ded,
            details: format!(
                "{} token mint(s) can freeze your holdings",
                mint_risks.len()
            ),
        });
        total += ded;
    }

    // Malicious matches
    if !malicious.is_empty() {
        let ded = malicious.len() as i32 * 25;
        breakdown.push(ScoreBreakdown {
            category: "Known Malicious".into(),
            deduction: ded,
            details: format!(
                "{} match(es) with known exploit/scam addresses",
                malicious.len()
            ),
        });
        total += ded;
    }

    // Recently deployed
    if !recent.is_empty() {
        let ded = (recent.len() as i32 * 10).min(20);
        breakdown.push(ScoreBreakdown {
            category: "Recently Deployed".into(),
            deduction: ded,
            details: format!(
                "{} program(s) deployed within the last 7 days",
                recent.len()
            ),
        });
        total += ded;
    }

    let score = (100 - total).max(0).min(100);

    ScoreResult { score, breakdown }
}
