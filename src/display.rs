use colored::Colorize;

use crate::malicious::{MaliciousMatch, RecentProgram};
use crate::mint_risk::MintRiskInfo;
use crate::program_exposure::ProgramExposure;
use crate::scanner::TokenScanResult;
use crate::scoring::ScoreResult;

fn short(addr: &str) -> String {
    if addr.len() > 8 {
        format!("{}...{}", &addr[..4], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn solscan_url(addr: &str) -> String {
    format!("https://solscan.io/account/{}", addr)
}

pub fn print_banner() {
    println!();
    println!(
        "  {} {}",
        "WALLET".green().bold(),
        "AUDIT".white().bold()
    );
    println!(
        "  {}",
        "Solana Wallet Security Scanner".dimmed()
    );
    println!("{}", "─".repeat(50).dimmed());
}

pub fn print_phase(msg: &str) {
    print!("  {} {}", ">>".cyan(), msg);
}

pub fn print_done(msg: &str) {
    println!("\r  {} {}", "OK".green().bold(), msg);
}

pub fn print_results(
    token_scan: &TokenScanResult,
    programs: &[ProgramExposure],
    mint_risks: &[MintRiskInfo],
    malicious: &[MaliciousMatch],
    recent: &[RecentProgram],
    score: &ScoreResult,
) {
    let upgradeable_count = programs.iter().filter(|p| p.is_upgradeable).count();

    // Score header
    println!("{}", "═".repeat(50).dimmed());
    let score_color = if score.score >= 80 {
        format!("{}", score.score).green().bold()
    } else if score.score >= 50 {
        format!("{}", score.score).yellow().bold()
    } else {
        format!("{}", score.score).red().bold()
    };

    let label = if score.score >= 80 {
        "HEALTHY".green()
    } else if score.score >= 50 {
        "AT RISK".yellow()
    } else {
        "CRITICAL".red()
    };

    println!("  Wallet Health: {}/100  [{}]", score_color, label);
    println!("{}", "─".repeat(50).dimmed());

    // Stats grid
    println!(
        "  Tokens: {}  |  Risky: {}  |  Upgradeable: {}  |  Mint Risks: {}  |  Empty: {}",
        format!("{}", token_scan.all_accounts.len()).white().bold(),
        format!("{}", token_scan.risky_delegates.len() + token_scan.risky_close_authorities.len())
            .red()
            .bold(),
        format!("{}", upgradeable_count).yellow().bold(),
        format!("{}", mint_risks.len()).yellow().bold(),
        format!("{}", token_scan.empty_accounts.len()).dimmed(),
    );
    println!();

    // Score breakdown
    if !score.breakdown.is_empty() {
        println!("  {}", "SCORE BREAKDOWN".white().bold());
        println!("  {}", "─".repeat(46).dimmed());
        for item in &score.breakdown {
            println!(
                "  {:.<36} {}",
                format!("  {} ", item.category).dimmed(),
                format!("-{}", item.deduction).red(),
            );
            println!("  {}", format!("    {}", item.details).dimmed());
        }
        println!();
    }

    // Malicious alerts
    if !malicious.is_empty() {
        println!(
            "  {}",
            "!! MALICIOUS ADDRESSES DETECTED !!".red().bold()
        );
        println!("  {}", "─".repeat(46).dimmed());
        for m in malicious {
            println!(
                "  {} {} ({})",
                "!!".red().bold(),
                m.label.red(),
                m.context.yellow(),
            );
            println!("     {}", solscan_url(&m.address).dimmed());
        }
        println!();
    }

    // Recently deployed programs
    if !recent.is_empty() {
        println!(
            "  {}",
            "RECENTLY DEPLOYED PROGRAMS".yellow().bold()
        );
        println!("  {}", "─".repeat(46).dimmed());
        for r in recent {
            println!(
                "  {} {} — deployed {} days ago",
                "NEW".yellow().bold(),
                short(&r.program_id).white(),
                format!("{:.1}", r.age_in_days).yellow(),
            );
            println!("     {}", solscan_url(&r.program_id).dimmed());
        }
        println!();
    }

    // Risky delegates
    if !token_scan.risky_delegates.is_empty() {
        println!(
            "  {}",
            "ACTIVE DELEGATES".red().bold()
        );
        println!("  {}", "─".repeat(46).dimmed());
        for acc in &token_scan.risky_delegates {
            println!(
                "  {} Mint: {}  Balance: {}  Delegate: {}",
                ">".red(),
                short(&acc.mint).white(),
                format!("{:.4}", acc.balance).white(),
                short(acc.delegate.as_deref().unwrap_or("?")).yellow(),
            );
            println!("     {}", solscan_url(acc.delegate.as_deref().unwrap_or("")).dimmed());
        }
        println!();
    }

    // Close authorities
    if !token_scan.risky_close_authorities.is_empty() {
        println!(
            "  {}",
            "SUSPICIOUS CLOSE AUTHORITIES".yellow().bold()
        );
        println!("  {}", "─".repeat(46).dimmed());
        for acc in &token_scan.risky_close_authorities {
            println!(
                "  {} Mint: {}  CloseAuth: {}",
                ">".yellow(),
                short(&acc.mint).white(),
                short(acc.close_authority.as_deref().unwrap_or("?")).yellow(),
            );
            println!(
                "     {}",
                solscan_url(acc.close_authority.as_deref().unwrap_or("")).dimmed()
            );
        }
        println!();
    }

    // Program exposure
    if !programs.is_empty() {
        println!(
            "  {} ({} total, {} upgradeable)",
            "PROGRAM EXPOSURE".white().bold(),
            programs.len(),
            upgradeable_count,
        );
        println!("  {}", "─".repeat(46).dimmed());
        for prog in programs {
            let status = if prog.is_upgradeable {
                "UPGRADEABLE".yellow().bold()
            } else {
                "immutable".green().into()
            };
            println!(
                "  {} {} [{}] ({}x)",
                if prog.is_upgradeable {
                    ">".yellow()
                } else {
                    " ".normal()
                },
                short(&prog.program_id).white(),
                status,
                prog.interaction_count,
            );
            if let Some(ref auth) = prog.upgrade_authority {
                println!(
                    "     Admin: {}",
                    solscan_url(auth).dimmed()
                );
            }
        }
        println!();
    }

    // Mint risks
    if !mint_risks.is_empty() {
        println!(
            "  {} ({} total)",
            "MINT RISKS".yellow().bold(),
            mint_risks.len(),
        );
        println!("  {}", "─".repeat(46).dimmed());
        for (i, risk) in mint_risks.iter().enumerate() {
            if i >= 10 {
                println!(
                    "  {} ...and {} more",
                    " ".dimmed(),
                    mint_risks.len() - 10
                );
                break;
            }
            println!(
                "  {} {} [FREEZE] Balance: {:.2}",
                ">".yellow(),
                short(&risk.mint).white(),
                risk.total_balance,
            );
            if let Some(ref auth) = risk.freeze_authority {
                println!("     Freeze Auth: {}", solscan_url(auth).dimmed());
            }
        }
        println!();
    }

    // Empty accounts
    if !token_scan.empty_accounts.is_empty() {
        let reclaimable = token_scan.empty_accounts.len() as f64 * 0.00203928;
        println!(
            "  {} — {} empty accounts, ~{:.4} SOL reclaimable",
            "EMPTY ACCOUNTS".dimmed(),
            token_scan.empty_accounts.len(),
            reclaimable,
        );
        println!();
    }

    println!("{}", "═".repeat(50).dimmed());
}
