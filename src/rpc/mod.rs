//! Thin wrapper over the Solana RPC client that maps transport errors into the
//! crate's [`AuditError`] type and centralizes the calls the scanners need.

pub mod client;

pub use client::AuditRpcClient;
