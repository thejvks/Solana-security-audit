//! Static database of known exploit / scam addresses and the matcher used to
//! cross-reference scanned authorities against it.
//!
//! The list is intentionally small and curated from public post-mortems. It is
//! not a substitute for a maintained threat feed — see the roadmap.

/// A hit against the known-malicious database.
#[derive(Debug, Clone)]
pub struct MaliciousMatch {
    pub address: String,
    pub context: String,
    pub label: String,
}

/// Address -> human label. Sourced from public exploit post-mortems.
const KNOWN_MALICIOUS: &[(&str, &str)] = &[
    (
        "CxegPrfn2ge5dNiQberUrQJkHCcimeR4VXkeawcFBBka",
        "Wormhole exploiter",
    ),
    (
        "4yx1NJ4Vqf2zT1oVLk4SySBhhDJXmXFt88ncm4gPxtL",
        "Mango Markets exploiter",
    ),
    (
        "Esmx2QjmDZMjJ15yBJ2nhqisjEt7Gqro4jSkofdoVsvY",
        "Crema Finance exploiter",
    ),
    (
        "6D7fgBuVnL7FRoZocfkiz7T1TYEKSbbREnWnuaSzpvGV",
        "Cashio exploiter",
    ),
    (
        "HtHYnnLBaBYaKkqJMTHf7nyFCAjjQFELcQuHqWssB7Gn",
        "Slope wallet drainer",
    ),
    (
        "Cft4EEMTiC3pBCiiVAAXiPvAuGbKRiAe2rGBzEoQbJxe",
        "Nirvana Finance exploiter",
    ),
    (
        "AgkYBGVKbFakvs4iG2pEfEnsgNdyMqNMSaoLCLwm1EAt",
        "Raydium exploiter",
    ),
    (
        "DriFtupJYLTosbwoN8koMbEYSx54aFAVLddWsbksjwg7d",
        "Drift Protocol exploiter",
    ),
    (
        "FhVFRJhCdi8qFbc8MFHV3Dv67mi6aKKefThYMDmzSD7P",
        "Orbit Bridge exploiter",
    ),
];

/// Number of addresses in the database.
pub fn known_count() -> usize {
    KNOWN_MALICIOUS.len()
}

fn lookup(address: &str) -> Option<&'static str> {
    KNOWN_MALICIOUS
        .iter()
        .find(|(addr, _)| *addr == address)
        .map(|(_, label)| *label)
}

/// Check `(address, context)` pairs against the database.
pub fn check_addresses(addresses: &[(String, &str)]) -> Vec<MaliciousMatch> {
    let mut matches = Vec::new();
    for (address, context) in addresses {
        if let Some(label) = lookup(address) {
            matches.push(MaliciousMatch {
                address: address.clone(),
                context: (*context).to_string(),
                label: label.to_string(),
            });
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_known_address() {
        let input = vec![(
            "CxegPrfn2ge5dNiQberUrQJkHCcimeR4VXkeawcFBBka".to_string(),
            "delegate",
        )];
        let hits = check_addresses(&input);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].context, "delegate");
    }

    #[test]
    fn ignores_unknown_address() {
        let input = vec![("11111111111111111111111111111111".to_string(), "delegate")];
        assert!(check_addresses(&input).is_empty());
    }
}
