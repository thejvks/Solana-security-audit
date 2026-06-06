//! Command-line interface and the top-level run logic that wires scanning,
//! scoring, and reporting together.

use clap::{Args, Parser, Subcommand};

use crate::config::{parse_address, Config, DEFAULT_RPC_URL, DEFAULT_TIMEOUT_SECS};
use crate::errors::Result;
use crate::report::{now_timestamp, to_json, write_json};
use crate::risk::generate_report;
use crate::rpc::AuditRpcClient;
use crate::scanner::{scan_token_mint, scan_wallet};
use crate::{display, risk::RiskReport};

#[derive(Parser)]
#[command(
    name = "wallet-audit",
    version,
    about = "Solana wallet security audit CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan a wallet address for security risks
    Scan(ScanArgs),
    /// Scan a single token mint for authority and concentration risks
    Token(TokenArgs),
}

#[derive(Args)]
pub struct ScanArgs {
    /// Wallet address to scan
    pub address: String,

    /// RPC endpoint URL
    #[arg(short, long, default_value = DEFAULT_RPC_URL)]
    pub rpc: String,

    /// Print the JSON report to stdout instead of the human-readable output
    #[arg(long)]
    pub json: bool,

    /// Write the JSON report to a file
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    /// Per-request RPC timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
}

#[derive(Args)]
pub struct TokenArgs {
    /// Token mint address to scan
    pub mint: String,

    #[arg(short, long, default_value = DEFAULT_RPC_URL)]
    pub rpc: String,

    #[arg(long)]
    pub json: bool,

    #[arg(short, long, value_name = "FILE")]
    pub output: Option<String>,

    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Token(args) => run_token(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let pubkey = parse_address(&args.address)?;
    let config = Config::new(&args.rpc, args.timeout);
    let client = AuditRpcClient::new(&config);

    if !args.json {
        display::print_banner();
        display::print_scanning(&pubkey.to_string(), &config.rpc_url);
    }

    let scan = scan_wallet(&client, &pubkey, &config)?;
    let report = generate_report(&scan.address, "wallet", &scan.signals, now_timestamp());

    emit(&report, args.json, args.output.as_deref(), |report| {
        display::print_wallet_report(&scan, report);
    })
}

fn run_token(args: TokenArgs) -> Result<()> {
    let pubkey = parse_address(&args.mint)?;
    let config = Config::new(&args.rpc, args.timeout);
    let client = AuditRpcClient::new(&config);

    if !args.json {
        display::print_banner();
        display::print_scanning(&pubkey.to_string(), &config.rpc_url);
    }

    let scan = scan_token_mint(&client, &pubkey)?;
    let report = generate_report(&scan.mint, "token", &scan.signals, now_timestamp());

    emit(&report, args.json, args.output.as_deref(), |report| {
        display::print_token_report(&scan, report);
    })
}

/// Shared output handling for both subcommands.
fn emit(
    report: &RiskReport,
    json: bool,
    output: Option<&str>,
    print_human: impl FnOnce(&RiskReport),
) -> Result<()> {
    if let Some(path) = output {
        write_json(report, path)?;
    }

    if json {
        println!("{}", to_json(report)?);
    } else {
        print_human(report);
        if let Some(path) = output {
            eprintln!("\nreport written to {path}");
        }
    }

    Ok(())
}
