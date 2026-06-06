//! Token account and mint scanning.
//!
//! Mint metadata (decimals, freeze/mint authority, supply) is fetched in batched
//! `getMultipleAccounts` calls rather than one request per account, which keeps a
//! wallet holding hundreds of mints to a handful of round trips.

use std::collections::HashMap;
use std::str::FromStr;

use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use spl_token::state::{Account as TokenAccount, Mint};

use crate::config::{ACCOUNT_BATCH_SIZE, CONCENTRATION_THRESHOLD_PCT};
use crate::errors::Result;
use crate::risk::RiskSignals;
use crate::rpc::AuditRpcClient;
use crate::scanner::malicious;

pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct MintRiskInfo {
    pub mint: String,
    pub freeze_authority: Option<String>,
    pub mint_authority: Option<String>,
    pub affected_count: usize,
    pub total_balance: f64,
}

#[derive(Debug, Default)]
pub struct TokenScanResult {
    pub all_accounts: Vec<TokenAccountInfo>,
    pub risky_delegates: Vec<TokenAccountInfo>,
    pub risky_close_authorities: Vec<TokenAccountInfo>,
    pub empty_accounts: Vec<TokenAccountInfo>,
    pub mint_risks: Vec<MintRiskInfo>,
    pub spl_count: usize,
    pub t22_count: usize,
}

/// Result of scanning a single token mint.
#[derive(Debug)]
pub struct TokenMintScan {
    pub mint: String,
    pub decimals: u8,
    pub supply: f64,
    pub freeze_authority: Option<String>,
    pub mint_authority: Option<String>,
    pub top_holder_pct: Option<f64>,
    pub malicious_matches: Vec<malicious::MaliciousMatch>,
    pub signals: RiskSignals,
}

struct MintMeta {
    decimals: u8,
    supply: u64,
    freeze_authority: Option<String>,
    mint_authority: Option<String>,
}

struct RawToken {
    pubkey: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: Option<String>,
    delegated_amount: u64,
    close_authority: Option<String>,
    is_token_2022: bool,
}

/// Parse the base SPL mint layout (first 82 bytes). Works for both classic SPL
/// mints and Token-2022 mints, whose extensions follow the base layout.
fn parse_mint(data: &[u8]) -> Option<MintMeta> {
    if data.len() < Mint::LEN {
        return None;
    }
    let mint = Mint::unpack_from_slice(&data[..Mint::LEN]).ok()?;
    Some(MintMeta {
        decimals: mint.decimals,
        supply: mint.supply,
        freeze_authority: Option::<Pubkey>::from(mint.freeze_authority).map(|p| p.to_string()),
        mint_authority: Option::<Pubkey>::from(mint.mint_authority).map(|p| p.to_string()),
    })
}

fn fetch_raw_tokens(
    client: &AuditRpcClient,
    owner: &Pubkey,
    program_id: &Pubkey,
    is_t22: bool,
) -> Vec<RawToken> {
    let accounts = match client.get_program_accounts(program_id, owner) {
        Ok(accounts) => accounts,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::with_capacity(accounts.len());
    for (pubkey, account) in accounts {
        if let Ok(token) = TokenAccount::unpack(&account.data) {
            out.push(RawToken {
                pubkey,
                mint: token.mint,
                owner: token.owner,
                amount: token.amount,
                delegate: Option::<Pubkey>::from(token.delegate).map(|p| p.to_string()),
                delegated_amount: token.delegated_amount,
                close_authority: Option::<Pubkey>::from(token.close_authority)
                    .map(|p| p.to_string()),
                is_token_2022: is_t22,
            });
        }
    }
    out
}

/// Batch-fetch metadata for the given mints, skipping any that fail to load.
fn fetch_mint_meta(client: &AuditRpcClient, mints: &[Pubkey]) -> HashMap<String, MintMeta> {
    let mut map = HashMap::new();
    for chunk in mints.chunks(ACCOUNT_BATCH_SIZE) {
        let accounts = match client.get_multiple_accounts(chunk) {
            Ok(accounts) => accounts,
            Err(_) => continue,
        };
        for (pubkey, maybe_account) in chunk.iter().zip(accounts) {
            if let Some(account) = maybe_account {
                if let Some(meta) = parse_mint(&account.data) {
                    map.insert(pubkey.to_string(), meta);
                }
            }
        }
    }
    map
}

/// Scan every token account owned by `owner` for delegate, close-authority, and
/// mint-authority risks.
pub fn scan_token_accounts(client: &AuditRpcClient, owner: &Pubkey) -> Result<TokenScanResult> {
    let spl_program = Pubkey::from_str(SPL_TOKEN_PROGRAM).expect("valid program id");
    let t22_program = Pubkey::from_str(TOKEN_2022_PROGRAM).expect("valid program id");

    let mut raw = fetch_raw_tokens(client, owner, &spl_program, false);
    let spl_count = raw.len();
    let t22 = fetch_raw_tokens(client, owner, &t22_program, true);
    let t22_count = t22.len();
    raw.extend(t22);

    let unique_mints: Vec<Pubkey> = {
        let mut seen = std::collections::HashSet::new();
        raw.iter()
            .filter(|t| seen.insert(t.mint))
            .map(|t| t.mint)
            .collect()
    };
    let mint_meta = fetch_mint_meta(client, &unique_mints);

    let owner_str = owner.to_string();
    let mut result = TokenScanResult {
        spl_count,
        t22_count,
        ..TokenScanResult::default()
    };
    let mut mint_rollup: HashMap<String, (usize, f64)> = HashMap::new();

    for token in raw {
        let mint_str = token.mint.to_string();
        let decimals = mint_meta.get(&mint_str).map(|m| m.decimals).unwrap_or(0);
        let balance = token.amount as f64 / 10f64.powi(decimals as i32);

        let info = TokenAccountInfo {
            pubkey: token.pubkey.to_string(),
            mint: mint_str.clone(),
            owner: token.owner.to_string(),
            balance,
            decimals,
            delegate: token.delegate,
            delegated_amount: token.delegated_amount,
            close_authority: token.close_authority,
            is_token_2022: token.is_token_2022,
        };

        let rollup = mint_rollup.entry(mint_str).or_insert((0, 0.0));
        rollup.0 += 1;
        rollup.1 += balance;

        if info.delegate.is_some() && info.delegated_amount > 0 {
            result.risky_delegates.push(info.clone());
        }
        if let Some(close_auth) = &info.close_authority {
            if close_auth != &owner_str {
                result.risky_close_authorities.push(info.clone());
            }
        }
        if info.balance == 0.0 {
            result.empty_accounts.push(info.clone());
        }
        result.all_accounts.push(info);
    }

    for (mint, meta) in &mint_meta {
        if meta.freeze_authority.is_some() || meta.mint_authority.is_some() {
            let (count, balance) = mint_rollup.get(mint).copied().unwrap_or((0, 0.0));
            result.mint_risks.push(MintRiskInfo {
                mint: mint.clone(),
                freeze_authority: meta.freeze_authority.clone(),
                mint_authority: meta.mint_authority.clone(),
                affected_count: count,
                total_balance: balance,
            });
        }
    }
    result.mint_risks.sort_by(|a, b| {
        b.total_balance
            .partial_cmp(&a.total_balance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(result)
}

/// Scan a single token mint for authority and holder-concentration risk.
pub fn scan_token_mint(client: &AuditRpcClient, mint: &Pubkey) -> Result<TokenMintScan> {
    let account = client.get_account(mint)?;
    let meta = parse_mint(&account.data)
        .ok_or_else(|| crate::errors::AuditError::AccountDecode(mint.to_string()))?;

    let supply = meta.supply as f64 / 10f64.powi(meta.decimals as i32);

    let top_holder_pct = match client.get_token_largest_accounts(mint) {
        Ok(holders) => holders
            .first()
            .and_then(|h| h.amount.ui_amount)
            .filter(|_| supply > 0.0)
            .map(|top| (top / supply) * 100.0),
        Err(_) => None,
    };

    let mut to_check: Vec<(String, &str)> = Vec::new();
    if let Some(fa) = &meta.freeze_authority {
        to_check.push((fa.clone(), "freeze_authority"));
    }
    if let Some(ma) = &meta.mint_authority {
        to_check.push((ma.clone(), "mint_authority"));
    }
    let malicious_matches = malicious::check_addresses(&to_check);

    let signals = RiskSignals {
        freeze_authority_active: meta.freeze_authority.is_some(),
        mint_authority_active: meta.mint_authority.is_some(),
        malicious_interaction_count: malicious_matches.len() as u32,
        suspicious_holder_concentration: top_holder_pct
            .map(|p| p >= CONCENTRATION_THRESHOLD_PCT)
            .unwrap_or(false),
        ..RiskSignals::default()
    };

    Ok(TokenMintScan {
        mint: mint.to_string(),
        decimals: meta.decimals,
        supply,
        freeze_authority: meta.freeze_authority,
        mint_authority: meta.mint_authority,
        top_holder_pct,
        malicious_matches,
        signals,
    })
}
