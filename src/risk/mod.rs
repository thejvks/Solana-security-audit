//! Pure risk model: signals in, scored report out. No RPC, no I/O — every type
//! here is safe to construct in a unit test.

pub mod rules;
pub mod scoring;

use serde::Serialize;

pub use rules::RiskCategory;
pub use scoring::{build_findings, calculate_risk_score, generate_report};

/// Risk score ceiling. Scores are clamped to this value.
pub const MAX_SCORE: u32 = 100;

/// Severity attached to an individual finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Overall risk band derived from the aggregate score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=9 => RiskLevel::Minimal,
            10..=29 => RiskLevel::Low,
            30..=59 => RiskLevel::Medium,
            60..=84 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Minimal => "MINIMAL",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

/// Boolean / count signals extracted from on-chain scans. This is the only
/// surface the risk engine consumes, which keeps scoring decoupled from RPC.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RiskSignals {
    pub freeze_authority_active: bool,
    pub mint_authority_active: bool,
    pub risky_delegate_count: u32,
    pub close_authority_set: bool,
    pub upgradeable_program_count: u32,
    pub malicious_interaction_count: u32,
    pub newly_deployed_count: u32,
    pub suspicious_holder_concentration: bool,
}

/// A single scored risk, with everything a reader needs to act on it.
#[derive(Debug, Clone, Serialize)]
pub struct RiskFinding {
    pub category: String,
    pub label: String,
    pub severity: Severity,
    pub weight: u32,
    pub explanation: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RiskFinding {
    /// Build a finding from its category, optionally attaching a per-scan detail
    /// string (counts, addresses, etc.).
    pub fn from_category(category: RiskCategory, detail: Option<String>) -> Self {
        RiskFinding {
            category: category.key().to_string(),
            label: category.label().to_string(),
            severity: category.severity(),
            weight: category.weight(),
            explanation: category.explanation().to_string(),
            recommendation: category.recommendation().to_string(),
            detail,
        }
    }
}

/// The full audit result for a single target (wallet or token mint).
#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub target: String,
    pub target_type: String,
    pub score: u32,
    pub level: RiskLevel,
    pub findings: Vec<RiskFinding>,
    pub generated_at: String,
}
