//! Risk rule definitions: the weight, severity, and human-facing text for each
//! category of risk the scanner can detect. Weights are the single source of
//! truth for the scoring model and are exercised directly by the test suite.

use super::Severity;

/// A category of risk. Each maps to a fixed weight and severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskCategory {
    FreezeAuthority,
    MintAuthority,
    RiskyDelegate,
    CloseAuthority,
    UpgradeableProgram,
    MaliciousAddress,
    NewlyDeployed,
    HolderConcentration,
}

impl RiskCategory {
    /// All categories, useful for exhaustive tests and documentation.
    pub const ALL: [RiskCategory; 8] = [
        RiskCategory::FreezeAuthority,
        RiskCategory::MintAuthority,
        RiskCategory::RiskyDelegate,
        RiskCategory::CloseAuthority,
        RiskCategory::UpgradeableProgram,
        RiskCategory::MaliciousAddress,
        RiskCategory::NewlyDeployed,
        RiskCategory::HolderConcentration,
    ];

    /// Points contributed to the risk score when this category is present.
    pub fn weight(&self) -> u32 {
        match self {
            RiskCategory::FreezeAuthority => 20,
            RiskCategory::MintAuthority => 20,
            RiskCategory::RiskyDelegate => 15,
            RiskCategory::CloseAuthority => 10,
            RiskCategory::UpgradeableProgram => 15,
            RiskCategory::MaliciousAddress => 25,
            RiskCategory::NewlyDeployed => 10,
            RiskCategory::HolderConcentration => 15,
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            RiskCategory::FreezeAuthority => Severity::High,
            RiskCategory::MintAuthority => Severity::High,
            RiskCategory::RiskyDelegate => Severity::High,
            RiskCategory::CloseAuthority => Severity::Medium,
            RiskCategory::UpgradeableProgram => Severity::Medium,
            RiskCategory::MaliciousAddress => Severity::Critical,
            RiskCategory::NewlyDeployed => Severity::Low,
            RiskCategory::HolderConcentration => Severity::Medium,
        }
    }

    /// Stable snake_case key used in JSON output and score deduplication.
    pub fn key(&self) -> &'static str {
        match self {
            RiskCategory::FreezeAuthority => "freeze_authority",
            RiskCategory::MintAuthority => "mint_authority",
            RiskCategory::RiskyDelegate => "risky_delegate",
            RiskCategory::CloseAuthority => "close_authority",
            RiskCategory::UpgradeableProgram => "upgradeable_program",
            RiskCategory::MaliciousAddress => "malicious_address",
            RiskCategory::NewlyDeployed => "newly_deployed",
            RiskCategory::HolderConcentration => "holder_concentration",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RiskCategory::FreezeAuthority => "Active freeze authority",
            RiskCategory::MintAuthority => "Active mint authority",
            RiskCategory::RiskyDelegate => "Active token delegate",
            RiskCategory::CloseAuthority => "Non-owner close authority",
            RiskCategory::UpgradeableProgram => "Upgradeable program exposure",
            RiskCategory::MaliciousAddress => "Known malicious address interaction",
            RiskCategory::NewlyDeployed => "Recently deployed program",
            RiskCategory::HolderConcentration => "Suspicious holder concentration",
        }
    }

    pub fn explanation(&self) -> &'static str {
        match self {
            RiskCategory::FreezeAuthority => {
                "One or more token mints held by this wallet retain an active freeze \
                 authority, allowing the issuer to freeze the associated token accounts \
                 at any time."
            }
            RiskCategory::MintAuthority => {
                "One or more mints retain an active mint authority and can increase \
                 supply, diluting existing holders."
            }
            RiskCategory::RiskyDelegate => {
                "Token accounts have an active delegate with a non-zero approved amount, \
                 meaning a third party can move those tokens without further approval."
            }
            RiskCategory::CloseAuthority => {
                "Token accounts have a close authority set to an address other than the \
                 owner, which can close the account and reclaim its rent lamports."
            }
            RiskCategory::UpgradeableProgram => {
                "The wallet has interacted with upgradeable programs whose upgrade \
                 authority can change program logic at any time."
            }
            RiskCategory::MaliciousAddress => {
                "An address linked to this wallet (delegate, close authority, or program \
                 authority) matches a known exploit or scam address."
            }
            RiskCategory::NewlyDeployed => {
                "The wallet interacted with upgradeable programs deployed inside the \
                 recent-deployment window, which have limited track record."
            }
            RiskCategory::HolderConcentration => {
                "A single account holds a large share of the token supply, increasing the \
                 risk of price manipulation or a coordinated dump."
            }
        }
    }

    pub fn recommendation(&self) -> &'static str {
        match self {
            RiskCategory::FreezeAuthority => {
                "Confirm the issuer is trusted before holding meaningful balances; \
                 freezeable tokens can be locked without your consent."
            }
            RiskCategory::MintAuthority => {
                "Treat tokens with a live mint authority as inflationary and verify the \
                 authority is a trusted multisig or has been revoked."
            }
            RiskCategory::RiskyDelegate => {
                "Revoke unused delegates (e.g. `spl-token revoke`); stale approvals are a \
                 common drain vector."
            }
            RiskCategory::CloseAuthority => {
                "Review why a third party holds close authority and reset it if it was not \
                 set intentionally."
            }
            RiskCategory::UpgradeableProgram => {
                "Prefer protocols with immutable programs or timelocked, multisig-controlled \
                 upgrade authorities."
            }
            RiskCategory::MaliciousAddress => {
                "Revoke any approvals to the flagged address immediately and move remaining \
                 funds to a fresh wallet."
            }
            RiskCategory::NewlyDeployed => {
                "Be cautious with newly deployed programs; exploits frequently target \
                 freshly launched, unaudited code."
            }
            RiskCategory::HolderConcentration => {
                "Check holder distribution before trading; concentrated supply is a common \
                 trait of pump-and-dump tokens."
            }
        }
    }
}
