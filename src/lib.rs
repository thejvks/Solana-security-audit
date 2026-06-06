//! Solana wallet security audit toolkit.
//!
//! The crate is split into a pure, testable risk core (`risk`, `report`) and an
//! on-chain scanning layer (`rpc`, `scanner`) that feeds it. The binary in
//! `main.rs` wires the two together through `cli`.

pub mod cli;
pub mod config;
pub mod display;
pub mod errors;
pub mod report;
pub mod risk;
pub mod rpc;
pub mod scanner;
