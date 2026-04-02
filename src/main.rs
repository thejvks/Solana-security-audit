mod scanner;
mod program_exposure;
mod mint_risk;
mod malicious;
mod scoring;
mod display;

use anyhow::Result;
use clap::Parser;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "wallet-audit")]
#[command(about = "Solana wallet security audit — scan any wallet for risks")]
struct Cli {
    /// Solana wallet address to scan
    address: String,

    /// RPC endpoint URL
    #[arg(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let pubkey = Pubkey::from_str(&cli.address)
        .map_err(|_| anyhow::anyhow!("Invalid Solana address: {}", cli.address))?;

    let client = RpcClient::new(&cli.rpc);

    display::print_banner();
    println!(
        "  Scanning: {}\n  RPC: {}\n",
        colored::Colorize::green(cli.address.as_str()),
        cli.rpc
    );

    // Phase 1: Token accounts
    display::print_phase("Scanning token accounts...");
    let token_scan = scanner::scan_token_accounts(&client, &pubkey)?;
    display::print_done(&format!(
        "Found {} token accounts ({} SPL, {} Token-2022)",
        token_scan.all_accounts.len(),
        token_scan.spl_count,
        token_scan.t22_count,
    ));

    // Phase 2: Program exposure
    display::print_phase("Checking program exposure...");
    let programs = program_exposure::scan_programs(&client, &pubkey);
    display::print_done(&format!(
        "Found {} programs ({} upgradeable)",
        programs.len(),
        programs.iter().filter(|p| p.is_upgradeable).count()
    ));

    // Phase 3: Mint risks
    display::print_phase("Checking mint authorities...");
    let mint_risks = mint_risk::scan_mints(&client, &token_scan.all_accounts);
    display::print_done(&format!("Found {} risky mints", mint_risks.len()));

    // Phase 4: Malicious address check
    display::print_phase("Checking known exploit addresses...");
    let mut addresses_to_check: Vec<(&str, &str)> = Vec::new();
    for acc in &token_scan.risky_delegates {
        if let Some(ref d) = acc.delegate {
            addresses_to_check.push((d.as_str(), "delegate"));
        }
    }
    for acc in &token_scan.risky_close_authorities {
        if let Some(ref c) = acc.close_authority {
            addresses_to_check.push((c.as_str(), "close_authority"));
        }
    }
    for prog in &programs {
        if let Some(ref auth) = prog.upgrade_authority {
            addresses_to_check.push((auth.as_str(), "upgrade_authority"));
        }
    }
    let malicious_matches = malicious::check_addresses(&addresses_to_check);
    let recent_programs = malicious::check_recently_deployed(&client, &programs);
    display::print_done(&format!(
        "{} malicious matches, {} recently deployed",
        malicious_matches.len(),
        recent_programs.len()
    ));

    // Phase 5: Risk scoring
    let score_result = scoring::calculate_score(
        &token_scan,
        &programs,
        &mint_risks,
        &malicious_matches,
        &recent_programs,
    );

    // Display results
    println!();
    display::print_results(
        &token_scan,
        &programs,
        &mint_risks,
        &malicious_matches,
        &recent_programs,
        &score_result,
    );

    Ok(())
}
