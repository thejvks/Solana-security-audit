use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::str::FromStr;

pub struct ProgramExposure {
    pub program_id: String,
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub interaction_count: u32,
}

const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

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

pub fn scan_programs(client: &RpcClient, owner: &Pubkey) -> Vec<ProgramExposure> {
    let mut program_counts: HashMap<String, u32> = HashMap::new();

    // Fetch recent transaction signatures
    let signatures = match client.get_signatures_for_address(owner) {
        Ok(sigs) => sigs.into_iter().take(50).collect::<Vec<_>>(),
        Err(_) => return Vec::new(),
    };

    // Parse transactions to extract program IDs
    for sig_info in &signatures {
        if let Ok(Some(tx)) = client.get_transaction(
            &sig_info.signature.parse().unwrap_or_default(),
            solana_client::rpc_config::RpcTransactionConfig {
                encoding: Some(solana_account_decoder::UiTransactionEncoding::Json),
                max_supported_transaction_version: Some(0),
                ..Default::default()
            },
        ) {
            if let Some(meta) = tx.transaction.meta {
                // Extract program IDs from log messages (programs that were invoked)
                if let Some(logs) = meta.log_messages {
                    for log in logs {
                        if let Some(prog) = log.strip_prefix("Program ") {
                            if let Some(prog_id) = prog.split(' ').next() {
                                if prog_id.len() >= 32
                                    && !SKIP_PROGRAMS.contains(&prog_id)
                                {
                                    *program_counts.entry(prog_id.to_string()).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let bpf_loader = Pubkey::from_str(BPF_LOADER_UPGRADEABLE).unwrap();

    let mut exposures = Vec::new();

    for (program_id, count) in &program_counts {
        let pubkey = match Pubkey::from_str(program_id) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        let account_info = match client.get_account(&pubkey) {
            Ok(acc) => acc,
            Err(_) => {
                exposures.push(ProgramExposure {
                    program_id: program_id.clone(),
                    is_upgradeable: false,
                    upgrade_authority: None,
                    interaction_count: *count,
                });
                continue;
            }
        };

        if account_info.owner != bpf_loader {
            exposures.push(ProgramExposure {
                program_id: program_id.clone(),
                is_upgradeable: false,
                upgrade_authority: None,
                interaction_count: *count,
            });
            continue;
        }

        // Parse BPFLoaderUpgradeable program account: bytes 4-36 = programData address
        if account_info.data.len() < 36 {
            continue;
        }

        let program_data_pubkey = Pubkey::try_from(&account_info.data[4..36]).unwrap_or_default();

        let program_data = match client.get_account(&program_data_pubkey) {
            Ok(pd) => pd,
            Err(_) => {
                exposures.push(ProgramExposure {
                    program_id: program_id.clone(),
                    is_upgradeable: true,
                    upgrade_authority: None,
                    interaction_count: *count,
                });
                continue;
            }
        };

        // ProgramData layout: 4 bytes type + 8 bytes slot + 1 byte option + 32 bytes authority
        if program_data.data.len() < 45 {
            continue;
        }

        let has_authority = program_data.data[12] == 1;
        let upgrade_authority = if has_authority {
            Some(Pubkey::try_from(&program_data.data[13..45]).unwrap_or_default().to_string())
        } else {
            None
        };

        exposures.push(ProgramExposure {
            program_id: program_id.clone(),
            is_upgradeable: has_authority,
            upgrade_authority,
            interaction_count: *count,
        });
    }

    exposures.sort_by(|a, b| b.is_upgradeable.cmp(&a.is_upgradeable));
    exposures
}
