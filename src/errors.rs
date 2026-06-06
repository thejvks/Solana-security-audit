use thiserror::Error;

/// Errors surfaced by the audit toolkit.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("invalid Solana address: {0}")]
    InvalidAddress(String),

    #[error("RPC request failed: {0}")]
    Rpc(String),

    #[error("could not decode account data: {0}")]
    AccountDecode(String),

    #[error("report serialization failed: {0}")]
    Serialization(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;
