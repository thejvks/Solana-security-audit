# wallet-audit

Rust CLI tool for auditing Solana wallet security. Scan any wallet address for risky token delegates, upgradeable programs, freeze authorities, known exploit addresses, and recently deployed contracts.

## What it checks

- **Token delegates** — SPL token accounts with active delegate permissions (can spend your tokens)
- **Close authorities** — Accounts with close authority set to a non-owner address
- **Program upgrade authority** — Programs you've interacted with that are upgradeable (admin key compromise risk)
- **Mint freeze authority** — Token mints that can freeze your holdings
- **Known exploit addresses** — Checks delegates and authorities against known Solana exploiters (Wormhole, Mango, Crema, Drift, etc.)
- **Recently deployed programs** — Flags upgradeable programs deployed within the last 7 days

## Usage

```bash
# Scan a wallet using default public RPC
wallet-audit <WALLET_ADDRESS>

# Scan with a custom RPC endpoint
wallet-audit <WALLET_ADDRESS> --rpc https://your-rpc-endpoint.com
```

## Example output

```
  WALLET AUDIT
  Solana Wallet Security Scanner
──────────────────────────────────────────────────
  Scanning: JCNCMFXo5M5qwUPg2Utu1u6YWp3MbygxqBsBeXXJfrw

  OK Found 865 token accounts (860 SPL, 5 Token-2022)
  OK Found 59 programs (4 upgradeable)
  OK Found 78 risky mints
  OK 0 malicious matches, 4 recently deployed

══════════════════════════════════════════════════
  Wallet Health: 0/100  [CRITICAL]
──────────────────────────────────────────────────
  Tokens: 865  |  Risky: 0  |  Upgradeable: 4  |  Mint Risks: 78  |  Empty: 13

  SCORE BREAKDOWN
    Upgradeable Programs ................... -20
    Freeze Authority ....................... -15
    Recently Deployed ...................... -20
```

## Build

```bash
cargo build --release
```

Requires Rust 1.75+ and a C linker (MSVC on Windows, gcc/clang on Linux/Mac).

## Architecture

```
src/
  main.rs              — CLI entry point, orchestrates all scan phases
  scanner.rs           — Token account fetcher (SPL + Token-2022), delegate/authority detection
  program_exposure.rs  — Transaction history analysis, BPFLoaderUpgradeable binary parsing
  mint_risk.rs         — Mint freeze authority scanner
  malicious.rs         — Known exploit address database, recently deployed program detection
  scoring.rs           — Risk score calculator with breakdown
  display.rs           — Terminal output formatting with colors
```

## How it works

1. Fetches all SPL Token and Token-2022 accounts owned by the wallet via `getProgramAccounts`
2. Checks each account for active delegates and suspicious close authorities
3. Pulls last 50 transactions, extracts all program IDs invoked
4. For each program, reads the raw BPFLoaderUpgradeable account data to check if an upgrade authority is set
5. Batch-fetches mint accounts to check for freeze authorities
6. Cross-references all delegates, authorities, and upgrade keys against a known exploit address database
7. Checks deployment slot of upgradeable programs to flag recently deployed ones
8. Calculates a weighted risk score (0-100) with full breakdown

All addresses in the output include Solscan URLs for manual verification.
