use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{
    RpcAccountInfoConfig, RpcProgramAccountsConfig, RpcTransactionConfig,
};
use solana_sdk::account::Account;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding,
};

use crate::config::Config;
use crate::errors::{AuditError, Result};

/// RPC client wrapper. Every method returns [`Result`] so the scanners degrade
/// gracefully on timeouts and rate limits instead of panicking.
pub struct AuditRpcClient {
    inner: RpcClient,
}

impl AuditRpcClient {
    pub fn new(config: &Config) -> Self {
        let inner = RpcClient::new_with_timeout(config.rpc_url.clone(), config.timeout);
        AuditRpcClient { inner }
    }

    /// Lightweight connectivity probe; also used as the recency reference slot.
    pub fn get_slot(&self) -> Result<u64> {
        self.inner.get_slot().map_err(rpc_err)
    }

    pub fn get_account(&self, pubkey: &Pubkey) -> Result<Account> {
        self.inner.get_account(pubkey).map_err(rpc_err)
    }

    /// Batched account fetch. Callers should chunk inputs to the server limit
    /// (see [`crate::config::ACCOUNT_BATCH_SIZE`]).
    pub fn get_multiple_accounts(&self, pubkeys: &[Pubkey]) -> Result<Vec<Option<Account>>> {
        self.inner.get_multiple_accounts(pubkeys).map_err(rpc_err)
    }

    pub fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        owner: &Pubkey,
    ) -> Result<Vec<(Pubkey, Account)>> {
        use solana_client::rpc_filter::{Memcmp, RpcFilterType};

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

        self.inner
            .get_program_accounts_with_config(program_id, config)
            .map_err(rpc_err)
    }

    pub fn get_signatures(
        &self,
        address: &Pubkey,
    ) -> Result<Vec<solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature>> {
        self.inner
            .get_signatures_for_address(address)
            .map_err(rpc_err)
    }

    pub fn get_transaction(
        &self,
        signature: &Signature,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            max_supported_transaction_version: Some(0),
            ..Default::default()
        };
        self.inner
            .get_transaction_with_config(signature, config)
            .map_err(rpc_err)
    }

    pub fn get_token_largest_accounts(
        &self,
        mint: &Pubkey,
    ) -> Result<Vec<solana_client::rpc_response::RpcTokenAccountBalance>> {
        self.inner.get_token_largest_accounts(mint).map_err(rpc_err)
    }
}

fn rpc_err(e: solana_client::client_error::ClientError) -> AuditError {
    AuditError::Rpc(e.to_string())
}
