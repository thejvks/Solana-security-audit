//! Program exposure scanning.
//!
//! Walks the wallet's recent transactions, collects the programs it invoked, and
//! inspects any BPFLoaderUpgradeable programs to determine whether they remain
//! upgradeable and how recently they were deployed.

use std::collections::HashMap;
use std::str::FromStr;

use solana_sdk::pubkey::Pubkey;

use crate::config::{Config, ACCOUNT_BATCH_SIZE};
use crate::rpc::AuditRpcClient;

const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

/// Approximate slots per day on mainnet (~400ms slots).
const SLOTS_PER_DAY: f64 = 216_000.0;

/// Common programs that are not interesting for exposure analysis.
const SKIP_PROGRAMS: &[&str] = &[
    "11111111111111111111111111111111",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "ComputeBudget111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJBfCR6MNB1fEjAfwA248jtcnFR1LuVkq4S",
];

#[derive(Debug, Clone)]
pub struct ProgramExposure {
    pub program_id: String,
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub interaction_count: u32,
    pub deployed_slot: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RecentProgram {
    pub program_id: String,
    pub age_in_days: f64,
}

/// Collect program invocation counts from the wallet's recent transactions.
fn collect_program_counts(
    client: &AuditRpcClient,
    owner: &Pubkey,
    config: &Config,
) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();

    let signatures = match client.get_signatures(owner) {
        Ok(sigs) => sigs,
        Err(_) => return counts,
    };

    for sig_info in signatures.into_iter().take(config.max_signatures) {
        let signature = match sig_info.signature.parse() {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        let tx = match client.get_transaction(&signature) {
            Ok(tx) => tx,
            Err(_) => continue,
        };
        let Some(meta) = tx.transaction.meta else {
            continue;
        };
        let logs: Option<Vec<String>> = meta.log_messages.into();
        let Some(logs) = logs else { continue };

        for log in logs {
            if let Some(rest) = log.strip_prefix("Program ") {
                if let Some(prog_id) = rest.split(' ').next() {
                    if prog_id.len() >= 32 && !SKIP_PROGRAMS.contains(&prog_id) {
                        *counts.entry(prog_id.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    counts
}

/// Map invoked programs to their upgradeability and deployment slot.
pub fn scan_programs(
    client: &AuditRpcClient,
    owner: &Pubkey,
    config: &Config,
) -> Vec<ProgramExposure> {
    let counts = collect_program_counts(client, owner, config);
    let bpf_loader = Pubkey::from_str(BPF_LOADER_UPGRADEABLE).expect("valid loader id");

    let program_ids: Vec<(String, Pubkey)> = counts
        .keys()
        .filter_map(|id| Pubkey::from_str(id).ok().map(|pk| (id.clone(), pk)))
        .collect();

    // Batch 1: the program accounts themselves.
    let program_accounts = batch_get(client, program_ids.iter().map(|(_, pk)| *pk).collect());

    // Resolve programData addresses for upgradeable programs.
    let mut program_data_targets: Vec<Pubkey> = Vec::new();
    let mut data_index: HashMap<String, usize> = HashMap::new();
    for ((id, _pk), account) in program_ids.iter().zip(program_accounts.iter()) {
        if let Some(account) = account {
            if account.owner == bpf_loader && account.data.len() >= 36 {
                if let Ok(pd) = Pubkey::try_from(&account.data[4..36]) {
                    data_index.insert(id.clone(), program_data_targets.len());
                    program_data_targets.push(pd);
                }
            }
        }
    }

    // Batch 2: the programData accounts.
    let program_data = batch_get(client, program_data_targets);

    let mut exposures = Vec::with_capacity(program_ids.len());
    for (id, _pk) in &program_ids {
        let count = counts.get(id).copied().unwrap_or(0);
        let mut exposure = ProgramExposure {
            program_id: id.clone(),
            is_upgradeable: false,
            upgrade_authority: None,
            interaction_count: count,
            deployed_slot: None,
        };

        if let Some(idx) = data_index.get(id) {
            if let Some(Some(pd)) = program_data.get(*idx) {
                if pd.data.len() >= 45 {
                    exposure.deployed_slot = Some(u64::from_le_bytes(
                        pd.data[4..12].try_into().unwrap_or_default(),
                    ));
                    let has_authority = pd.data[12] == 1;
                    exposure.is_upgradeable = has_authority;
                    if has_authority {
                        exposure.upgrade_authority = Pubkey::try_from(&pd.data[13..45])
                            .ok()
                            .map(|pk| pk.to_string());
                    }
                }
            }
        }

        exposures.push(exposure);
    }

    exposures.sort_by_key(|e| std::cmp::Reverse(e.is_upgradeable));
    exposures
}

/// Filter upgradeable programs deployed inside the recent-deployment window.
///
/// Pure given the program list and reference slot, so it is unit testable.
pub fn recent_programs(
    programs: &[ProgramExposure],
    current_slot: u64,
    recent_days: f64,
) -> Vec<RecentProgram> {
    programs
        .iter()
        .filter_map(|p| {
            let slot = p.deployed_slot?;
            if !p.is_upgradeable || slot == 0 || slot > current_slot {
                return None;
            }
            let age = (current_slot - slot) as f64 / SLOTS_PER_DAY;
            if (0.0..recent_days).contains(&age) {
                Some(RecentProgram {
                    program_id: p.program_id.clone(),
                    age_in_days: (age * 10.0).round() / 10.0,
                })
            } else {
                None
            }
        })
        .collect()
}

fn batch_get(
    client: &AuditRpcClient,
    pubkeys: Vec<Pubkey>,
) -> Vec<Option<solana_sdk::account::Account>> {
    let mut out = Vec::with_capacity(pubkeys.len());
    for chunk in pubkeys.chunks(ACCOUNT_BATCH_SIZE) {
        match client.get_multiple_accounts(chunk) {
            Ok(mut accounts) => out.append(&mut accounts),
            Err(_) => out.extend(std::iter::repeat_with(|| None).take(chunk.len())),
        }
    }
    out
}
