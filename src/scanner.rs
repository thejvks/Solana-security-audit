use anyhow::Result;
use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use spl_token::state::Account as TokenAccount;
use std::str::FromStr;

pub struct TokenAccountInfo {
    pub pubkey: String,
    pub mint: String,
    pub owner: String,
    pub balance: f64,
    pub decimals: u8,
    pub delegate: Option<String>,
    pub delegated_amount: u64,
    pub close_authority: Option<String>,
    pub is_token_2022: bool,
}

pub struct TokenScanResult {
    pub all_accounts: Vec<TokenAccountInfo>,
    pub risky_delegates: Vec<TokenAccountInfo>,
    pub risky_close_authorities: Vec<TokenAccountInfo>,
    pub empty_accounts: Vec<TokenAccountInfo>,
    pub spl_count: usize,
    pub t22_count: usize,
}

fn fetch_token_accounts(
    client: &RpcClient,
    owner: &Pubkey,
    program_id: &Pubkey,
    is_t22: bool,
) -> Result<Vec<TokenAccountInfo>> {
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(165),
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(32, &owner.to_bytes())),
        ]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = client.get_program_accounts_with_config(program_id, config)?;

    let mut result = Vec::new();
    for (pubkey, account) in accounts {
        if let Ok(token_account) = TokenAccount::unpack(&account.data) {
            let decimals = get_mint_decimals(client, &token_account.mint).unwrap_or(0);
            let balance = token_account.amount as f64 / 10f64.powi(decimals as i32);

            let delegate = if token_account.delegate.is_some() {
                Some(token_account.delegate.unwrap().to_string())
            } else {
                None
            };

            let close_authority = if token_account.close_authority.is_some() {
                Some(token_account.close_authority.unwrap().to_string())
            } else {
                None
            };

            result.push(TokenAccountInfo {
                pubkey: pubkey.to_string(),
                mint: token_account.mint.to_string(),
                owner: token_account.owner.to_string(),
                balance,
                decimals,
                delegate,
                delegated_amount: token_account.delegated_amount,
                close_authority,
                is_token_2022: is_t22,
            });
        }
    }

    Ok(result)
}

fn get_mint_decimals(client: &RpcClient, mint: &Pubkey) -> Result<u8> {
    let account = client.get_account(mint)?;
    let mint_data = spl_token::state::Mint::unpack(&account.data)?;
    Ok(mint_data.decimals)
}

pub fn scan_token_accounts(client: &RpcClient, owner: &Pubkey) -> Result<TokenScanResult> {
    let spl_program = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
    let t22_program = Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")?;

    let spl_accounts = fetch_token_accounts(client, owner, &spl_program, false).unwrap_or_default();
    let t22_accounts = fetch_token_accounts(client, owner, &t22_program, true).unwrap_or_default();

    let spl_count = spl_accounts.len();
    let t22_count = t22_accounts.len();

    let mut all_accounts = Vec::new();
    let mut risky_delegates = Vec::new();
    let mut risky_close_authorities = Vec::new();
    let mut empty_accounts = Vec::new();

    let owner_str = owner.to_string();

    for acc_list in [spl_accounts, t22_accounts] {
        for acc in acc_list {
            if acc.delegate.is_some() && acc.delegated_amount > 0 {
                risky_delegates.push(TokenAccountInfo {
                    pubkey: acc.pubkey.clone(),
                    mint: acc.mint.clone(),
                    owner: acc.owner.clone(),
                    balance: acc.balance,
                    decimals: acc.decimals,
                    delegate: acc.delegate.clone(),
                    delegated_amount: acc.delegated_amount,
                    close_authority: acc.close_authority.clone(),
                    is_token_2022: acc.is_token_2022,
                });
            }

            if let Some(ref close_auth) = acc.close_authority {
                if close_auth != &owner_str {
                    risky_close_authorities.push(TokenAccountInfo {
                        pubkey: acc.pubkey.clone(),
                        mint: acc.mint.clone(),
                        owner: acc.owner.clone(),
                        balance: acc.balance,
                        decimals: acc.decimals,
                        delegate: acc.delegate.clone(),
                        delegated_amount: acc.delegated_amount,
                        close_authority: acc.close_authority.clone(),
                        is_token_2022: acc.is_token_2022,
                    });
                }
            }

            if acc.balance == 0.0 {
                empty_accounts.push(TokenAccountInfo {
                    pubkey: acc.pubkey.clone(),
                    mint: acc.mint.clone(),
                    owner: acc.owner.clone(),
                    balance: acc.balance,
                    decimals: acc.decimals,
                    delegate: acc.delegate.clone(),
                    delegated_amount: acc.delegated_amount,
                    close_authority: acc.close_authority.clone(),
                    is_token_2022: acc.is_token_2022,
                });
            }

            all_accounts.push(acc);
        }
    }

    Ok(TokenScanResult {
        all_accounts,
        risky_delegates,
        risky_close_authorities,
        empty_accounts,
        spl_count,
        t22_count,
    })
}
