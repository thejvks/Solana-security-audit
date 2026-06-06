//! On-chain scanning layer. Each submodule turns RPC responses into plain data
//! the risk engine can score.

pub mod malicious;
pub mod program;
pub mod token;
pub mod wallet;

pub use malicious::{check_addresses, MaliciousMatch};
pub use program::{recent_programs, scan_programs, ProgramExposure, RecentProgram};
pub use token::{
    scan_token_accounts, scan_token_mint, MintRiskInfo, TokenAccountInfo, TokenMintScan,
    TokenScanResult,
};
pub use wallet::{scan_wallet, WalletScan};
