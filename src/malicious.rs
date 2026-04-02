use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::str::FromStr;

use crate::program_exposure::ProgramExposure;

pub struct MaliciousMatch {
    pub address: String,
    pub context: String,
    pub label: String,
}

pub struct RecentProgram {
    pub program_id: String,
    pub age_in_days: f64,
}

fn known_malicious() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    map.insert("CxegPrfn2ge5dNiQberUrQJkHCcimeR4VXkeawcFBBka", "Wormhole Exploiter");
    map.insert("4yx1NJ4Vqf2zT1oVLk4SySBhhDJXmXFt88ncm4gPxtL", "Mango Markets Exploiter");
    map.insert("Esmx2QjmDZMjJ15yBJ2nhqisjEt7Gqro4jSkofdoVsvY", "Crema Finance Exploiter");
    map.insert("6D7fgBuVnL7FRoZocfkiz7T1TYEKSbbREnWnuaSzpvGV", "Cashio Exploiter");
    map.insert("HtHYnnLBaBYaKkqJMTHf7nyFCAjjQFELcQuHqWssB7Gn", "Slope Wallet Drainer");
    map.insert("Cft4EEMTiC3pBCiiVAAXiPvAuGbKRiAe2rGBzEoQbJxe", "Nirvana Finance Exploiter");
    map.insert("AgkYBGVKbFakvs4iG2pEfEnsgNdyMqNMSaoLCLwm1EAt", "Raydium Exploiter");
    map.insert("DriFtupJYLTosbwoN8koMbEYSx54aFAVLddWsbksjwg7d", "Drift Protocol Exploiter");
    map.insert("FhVFRJhCdi8qFbc8MFHV3Dv67mi6aKKefThYMDmzSD7P", "Orbit Bridge Exploiter");
    map
}

pub fn check_addresses(addresses: &[(&str, &str)]) -> Vec<MaliciousMatch> {
    let db = known_malicious();
    let mut matches = Vec::new();

    for (addr, context) in addresses {
        if let Some(label) = db.get(addr) {
            matches.push(MaliciousMatch {
                address: addr.to_string(),
                context: context.to_string(),
                label: label.to_string(),
            });
        }
    }

    matches
}

pub fn check_recently_deployed(
    client: &RpcClient,
    programs: &[ProgramExposure],
) -> Vec<RecentProgram> {
    let mut recent = Vec::new();

    let current_slot = match client.get_slot() {
        Ok(s) => s,
        Err(_) => return recent,
    };

    for prog in programs {
        if !prog.is_upgradeable {
            continue;
        }

        let pubkey = match Pubkey::from_str(&prog.program_id) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        let account = match client.get_account(&pubkey) {
            Ok(acc) => acc,
            Err(_) => continue,
        };

        if account.data.len() < 36 {
            continue;
        }

        let program_data_pubkey = match Pubkey::try_from(&account.data[4..36]) {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        let program_data = match client.get_account(&program_data_pubkey) {
            Ok(pd) => pd,
            Err(_) => continue,
        };

        if program_data.data.len() < 12 {
            continue;
        }

        // ProgramData: bytes 4-12 = deployment slot (u64 LE)
        let deployed_slot = u64::from_le_bytes(
            program_data.data[4..12].try_into().unwrap_or_default(),
        );

        if deployed_slot == 0 {
            continue;
        }

        let slots_per_day: f64 = 216_000.0;
        let age_in_days = (current_slot - deployed_slot) as f64 / slots_per_day;

        if age_in_days < 0.0 || age_in_days > 10_000.0 {
            continue;
        }

        if age_in_days < 7.0 {
            recent.push(RecentProgram {
                program_id: prog.program_id.clone(),
                age_in_days: (age_in_days * 10.0).round() / 10.0,
            });
        }
    }

    recent
}
