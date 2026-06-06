//! Human-readable terminal output. Colors map to risk: green is safe, red is bad.

use colored::Colorize;

use crate::risk::{RiskLevel, RiskReport};
use crate::scanner::{TokenMintScan, WalletScan};

const WIDTH: usize = 60;

fn short(addr: &str) -> String {
    if addr.len() > 10 {
        format!("{}…{}", &addr[..4], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn solscan(addr: &str) -> String {
    format!("https://solscan.io/account/{addr}")
}

/// Hide any credential embedded in an RPC URL (an API key in the path or query
/// string) so it never reaches the console, logs, or a screenshot. The scheme
/// and host stay visible for context; anything after the host becomes `/****`.
/// A keyless endpoint (e.g. the public mainnet RPC) is returned unchanged.
fn mask_rpc_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let host_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    let tail = &rest[host_end..];
    if tail.is_empty() || tail == "/" {
        url.to_string()
    } else {
        format!("{scheme}://{host}/****")
    }
}

fn rule(ch: &str, n: usize) -> String {
    ch.repeat(n).dimmed().to_string()
}

pub fn print_banner() {
    println!();
    println!("  {} {}", "WALLET".green().bold(), "AUDIT".white().bold());
    println!("  {}", "Solana wallet security scanner".dimmed());
    println!("{}", rule("─", WIDTH));
}

pub fn print_scanning(target: &str, rpc: &str) {
    let rpc = mask_rpc_url(rpc);
    println!("  Target: {}", target.green());
    println!("  RPC:    {}\n", rpc.dimmed());
}

fn colored_score(report: &RiskReport) -> String {
    let text = format!("{}/100", report.score);
    match report.level {
        RiskLevel::Minimal | RiskLevel::Low => text.green().bold().to_string(),
        RiskLevel::Medium => text.yellow().bold().to_string(),
        RiskLevel::High | RiskLevel::Critical => text.red().bold().to_string(),
    }
}

fn colored_level(level: RiskLevel) -> String {
    match level {
        RiskLevel::Minimal | RiskLevel::Low => level.as_str().green().to_string(),
        RiskLevel::Medium => level.as_str().yellow().to_string(),
        RiskLevel::High | RiskLevel::Critical => level.as_str().red().to_string(),
    }
}

fn print_score_block(report: &RiskReport) {
    println!("{}", rule("═", WIDTH));
    println!(
        "  Risk Score: {}  [{}]",
        colored_score(report),
        colored_level(report.level)
    );
    println!("{}", rule("─", WIDTH));
}

fn print_findings(report: &RiskReport) {
    if report.findings.is_empty() {
        println!("  {}", "No risk signals detected.".green());
        println!();
        return;
    }

    println!("  {}", "FINDINGS".white().bold());
    println!("{}", rule("─", WIDTH));
    for finding in &report.findings {
        let sev = match finding.severity {
            crate::risk::Severity::Critical | crate::risk::Severity::High => {
                finding.severity.as_str().red().bold()
            }
            crate::risk::Severity::Medium => finding.severity.as_str().yellow().bold(),
            _ => finding.severity.as_str().normal(),
        };
        println!(
            "  [{}] {} (+{})",
            sev,
            finding.label.white().bold(),
            finding.weight
        );
        if let Some(detail) = &finding.detail {
            println!("        {}", detail.dimmed());
        }
        println!("        {}", finding.explanation.dimmed());
        println!("        {} {}", "→".cyan(), finding.recommendation);
        println!();
    }
}

pub fn print_wallet_report(scan: &WalletScan, report: &RiskReport) {
    let upgradeable = scan.programs.iter().filter(|p| p.is_upgradeable).count();

    print_score_block(report);
    println!(
        "  Tokens: {}  |  Risky: {}  |  Upgradeable: {}  |  Mint risks: {}  |  Empty: {}",
        scan.token_scan
            .all_accounts
            .len()
            .to_string()
            .white()
            .bold(),
        (scan.token_scan.risky_delegates.len() + scan.token_scan.risky_close_authorities.len())
            .to_string()
            .red()
            .bold(),
        upgradeable.to_string().yellow().bold(),
        scan.token_scan.mint_risks.len().to_string().yellow().bold(),
        scan.token_scan.empty_accounts.len().to_string().dimmed(),
    );
    println!();

    print_findings(report);

    if !scan.malicious_matches.is_empty() {
        println!("  {}", "MALICIOUS ADDRESSES".red().bold());
        println!("{}", rule("─", WIDTH));
        for m in &scan.malicious_matches {
            println!(
                "  {} {} ({})",
                "!!".red().bold(),
                m.label.red(),
                m.context.yellow()
            );
            println!("     {}", solscan(&m.address).dimmed());
        }
        println!();
    }

    if !scan.recent_programs.is_empty() {
        println!("  {}", "RECENTLY DEPLOYED PROGRAMS".yellow().bold());
        println!("{}", rule("─", WIDTH));
        for r in &scan.recent_programs {
            println!(
                "  {} {} — {:.1} days ago",
                "NEW".yellow().bold(),
                short(&r.program_id).white(),
                r.age_in_days
            );
        }
        println!();
    }

    if !scan.token_scan.risky_delegates.is_empty() {
        println!("  {}", "ACTIVE DELEGATES".red().bold());
        println!("{}", rule("─", WIDTH));
        for acc in &scan.token_scan.risky_delegates {
            println!(
                "  {} mint {}  bal {:.4}  delegate {}",
                ">".red(),
                short(&acc.mint).white(),
                acc.balance,
                short(acc.delegate.as_deref().unwrap_or("?")).yellow(),
            );
        }
        println!();
    }

    if !scan.token_scan.risky_close_authorities.is_empty() {
        println!("  {}", "NON-OWNER CLOSE AUTHORITIES".yellow().bold());
        println!("{}", rule("─", WIDTH));
        for acc in &scan.token_scan.risky_close_authorities {
            println!(
                "  {} mint {}  close {}",
                ">".yellow(),
                short(&acc.mint).white(),
                short(acc.close_authority.as_deref().unwrap_or("?")).yellow(),
            );
        }
        println!();
    }

    if upgradeable > 0 {
        println!(
            "  {} ({} of {} interacted programs)",
            "UPGRADEABLE PROGRAMS".yellow().bold(),
            upgradeable,
            scan.programs.len()
        );
        println!("{}", rule("─", WIDTH));
        for prog in scan.programs.iter().filter(|p| p.is_upgradeable) {
            println!(
                "  {} {} ({}x)",
                ">".yellow(),
                short(&prog.program_id).white(),
                prog.interaction_count
            );
            if let Some(auth) = &prog.upgrade_authority {
                println!("     admin {}", short(auth).dimmed());
            }
        }
        println!();
    }

    if !scan.token_scan.empty_accounts.is_empty() {
        let reclaimable = scan.token_scan.empty_accounts.len() as f64 * 0.00203928;
        println!(
            "  {} {} empty accounts, ~{:.4} SOL reclaimable",
            "EMPTY".dimmed(),
            scan.token_scan.empty_accounts.len(),
            reclaimable
        );
        println!();
    }

    println!("{}", rule("═", WIDTH));
}

pub fn print_token_report(scan: &TokenMintScan, report: &RiskReport) {
    print_score_block(report);
    println!("  Mint:     {}", scan.mint.white());
    println!("  Decimals: {}", scan.decimals);
    println!("  Supply:   {:.2}", scan.supply);
    println!(
        "  Freeze:   {}",
        scan.freeze_authority
            .as_deref()
            .map(|a| short(a).red().to_string())
            .unwrap_or_else(|| "none".green().to_string())
    );
    println!(
        "  Mint:     {}",
        scan.mint_authority
            .as_deref()
            .map(|a| short(a).red().to_string())
            .unwrap_or_else(|| "none".green().to_string())
    );
    if let Some(pct) = scan.top_holder_pct {
        println!("  Top holder: {:.1}% of supply", pct);
    }
    println!();
    print_findings(report);
    println!("{}", rule("═", WIDTH));
}

#[cfg(test)]
mod tests {
    use super::mask_rpc_url;

    #[test]
    fn masks_api_key_in_path() {
        assert_eq!(
            mask_rpc_url("https://solana-mainnet.g.alchemy.com/v2/SECRETKEY123"),
            "https://solana-mainnet.g.alchemy.com/****"
        );
    }

    #[test]
    fn masks_api_key_in_query() {
        assert_eq!(
            mask_rpc_url("https://mainnet.helius-rpc.com/?api-key=SECRET"),
            "https://mainnet.helius-rpc.com/****"
        );
    }

    #[test]
    fn leaves_keyless_endpoint_untouched() {
        assert_eq!(
            mask_rpc_url("https://api.mainnet-beta.solana.com"),
            "https://api.mainnet-beta.solana.com"
        );
    }
}
