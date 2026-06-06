use std::str::FromStr;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;

use crate::errors::{AuditError, Result};

/// Default mainnet RPC endpoint. Public endpoints are heavily rate limited; pass
/// a dedicated endpoint with `--rpc` for real scans.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Default per-request RPC timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Programs deployed within this many days are flagged as "recently deployed".
pub const RECENT_DEPLOY_DAYS: f64 = 7.0;

/// Number of recent signatures pulled when mapping program exposure.
pub const MAX_SIGNATURES: usize = 50;

/// Max accounts per `getMultipleAccounts` batch (RPC server side limit).
pub const ACCOUNT_BATCH_SIZE: usize = 100;

/// A single holder controlling at least this share of supply is treated as
/// suspicious concentration.
pub const CONCENTRATION_THRESHOLD_PCT: f64 = 50.0;

/// Runtime configuration for a scan.
#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub timeout: Duration,
    pub recent_deploy_days: f64,
    pub max_signatures: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rpc_url: DEFAULT_RPC_URL.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            recent_deploy_days: RECENT_DEPLOY_DAYS,
            max_signatures: MAX_SIGNATURES,
        }
    }
}

impl Config {
    pub fn new(rpc_url: impl Into<String>, timeout_secs: u64) -> Self {
        Config {
            rpc_url: rpc_url.into(),
            timeout: Duration::from_secs(timeout_secs),
            ..Config::default()
        }
    }
}

/// Validate and parse a base58 Solana address.
///
/// Kept free of any RPC so input validation stays unit testable.
pub fn parse_address(input: &str) -> Result<Pubkey> {
    Pubkey::from_str(input.trim()).map_err(|_| AuditError::InvalidAddress(input.to_string()))
}
