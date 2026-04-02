use solana_client::rpc_client::RpcClient;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use spl_token::state::Mint;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::scanner::TokenAccountInfo;

pub struct MintRiskInfo {
    pub mint: String,
    pub freeze_authority: Option<String>,
    pub mint_authority: Option<String>,
    pub affected_count: usize,
    pub total_balance: f64,
}

pub fn scan_mints(client: &RpcClient, accounts: &[TokenAccountInfo]) -> Vec<MintRiskInfo> {
    // Group by mint
    let mut mint_map: HashMap<String, (usize, f64)> = HashMap::new();
    for acc in accounts {
        let entry = mint_map.entry(acc.mint.clone()).or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += acc.balance;
    }

    let unique_mints: Vec<String> = mint_map.keys().cloned().collect();
    let mut risks = Vec::new();
    let mut checked: HashSet<String> = HashSet::new();

    for mint_addr in &unique_mints {
        if checked.contains(mint_addr) {
            continue;
        }
        checked.insert(mint_addr.clone());

        let pubkey = match Pubkey::from_str(mint_addr) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        let account = match client.get_account(&pubkey) {
            Ok(acc) => acc,
            Err(_) => continue,
        };

        // Try to parse as SPL mint
        let mint_data = match Mint::unpack(&account.data) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let freeze_authority = mint_data
            .freeze_authority
            .map(|fa| fa.to_string());

        let mint_authority = mint_data
            .mint_authority
            .map(|ma| ma.to_string());

        // Only report mints with freeze authority (actual risk)
        if freeze_authority.is_some() {
            let (count, balance) = mint_map.get(mint_addr).unwrap_or(&(0, 0.0));
            risks.push(MintRiskInfo {
                mint: mint_addr.clone(),
                freeze_authority,
                mint_authority,
                affected_count: *count,
                total_balance: *balance,
            });
        }
    }

    risks
}
