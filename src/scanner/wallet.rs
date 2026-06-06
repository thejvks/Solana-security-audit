//! Full-wallet scan orchestration: runs the token, program, and malicious-address
//! scans and reduces them to a [`RiskSignals`] for the scoring engine.

use solana_sdk::pubkey::Pubkey;

use crate::config::Config;
use crate::errors::Result;
use crate::risk::RiskSignals;
use crate::rpc::AuditRpcClient;
use crate::scanner::malicious::{self, MaliciousMatch};
use crate::scanner::program::{self, ProgramExposure, RecentProgram};
use crate::scanner::token::{self, TokenScanResult};

/// Everything gathered for a wallet, plus the signals derived from it.
pub struct WalletScan {
    pub address: String,
    pub token_scan: TokenScanResult,
    pub programs: Vec<ProgramExposure>,
    pub malicious_matches: Vec<MaliciousMatch>,
    pub recent_programs: Vec<RecentProgram>,
    pub signals: RiskSignals,
}

pub fn scan_wallet(client: &AuditRpcClient, owner: &Pubkey, config: &Config) -> Result<WalletScan> {
    let token_scan = token::scan_token_accounts(client, owner)?;
    let programs = program::scan_programs(client, owner, config);

    let recent_programs = match client.get_slot() {
        Ok(slot) => program::recent_programs(&programs, slot, config.recent_deploy_days),
        Err(_) => Vec::new(),
    };

    let mut to_check: Vec<(String, &str)> = Vec::new();
    for acc in &token_scan.risky_delegates {
        if let Some(d) = &acc.delegate {
            to_check.push((d.clone(), "delegate"));
        }
    }
    for acc in &token_scan.risky_close_authorities {
        if let Some(c) = &acc.close_authority {
            to_check.push((c.clone(), "close_authority"));
        }
    }
    for prog in &programs {
        if let Some(a) = &prog.upgrade_authority {
            to_check.push((a.clone(), "upgrade_authority"));
        }
    }
    let malicious_matches = malicious::check_addresses(&to_check);

    let signals = build_signals(&token_scan, &programs, &malicious_matches, &recent_programs);

    Ok(WalletScan {
        address: owner.to_string(),
        token_scan,
        programs,
        malicious_matches,
        recent_programs,
        signals,
    })
}

fn build_signals(
    token_scan: &TokenScanResult,
    programs: &[ProgramExposure],
    malicious: &[MaliciousMatch],
    recent: &[RecentProgram],
) -> RiskSignals {
    RiskSignals {
        freeze_authority_active: token_scan
            .mint_risks
            .iter()
            .any(|m| m.freeze_authority.is_some()),
        mint_authority_active: token_scan
            .mint_risks
            .iter()
            .any(|m| m.mint_authority.is_some()),
        risky_delegate_count: token_scan.risky_delegates.len() as u32,
        close_authority_set: !token_scan.risky_close_authorities.is_empty(),
        upgradeable_program_count: programs.iter().filter(|p| p.is_upgradeable).count() as u32,
        malicious_interaction_count: malicious.len() as u32,
        newly_deployed_count: recent.len() as u32,
        suspicious_holder_concentration: false,
    }
}
