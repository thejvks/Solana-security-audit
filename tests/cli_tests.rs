use std::time::Duration;

use wallet_audit::config::{parse_address, Config};
use wallet_audit::errors::AuditError;
use wallet_audit::report::to_json;
use wallet_audit::risk::{generate_report, RiskSignals};
use wallet_audit::rpc::AuditRpcClient;

#[test]
fn valid_address_parses() {
    // System program id is a well-formed base58 pubkey.
    assert!(parse_address("11111111111111111111111111111111").is_ok());
}

#[test]
fn invalid_address_is_rejected() {
    let err = parse_address("not-a-real-address").unwrap_err();
    assert!(matches!(err, AuditError::InvalidAddress(_)));
}

#[test]
fn json_report_serialization_round_trips() {
    let signals = RiskSignals {
        freeze_authority_active: true,
        malicious_interaction_count: 1,
        ..RiskSignals::default()
    };
    let report = generate_report(
        "So11111111111111111111111111111111111111112",
        "wallet",
        &signals,
        "2026-06-06T12:00:00Z",
    );

    let json = to_json(&report).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");

    assert_eq!(parsed["target_type"], "wallet");
    assert_eq!(parsed["score"], 45);
    assert_eq!(parsed["level"], "medium");
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 2);
    assert_eq!(parsed["findings"][0]["category"], "freeze_authority");
    assert_eq!(parsed["findings"][0]["severity"], "high");
}

#[test]
fn rpc_failure_returns_typed_error() {
    // Port 1 on loopback refuses immediately — exercises the failure path
    // without making any external network call.
    let config = Config {
        rpc_url: "http://127.0.0.1:1".to_string(),
        timeout: Duration::from_secs(2),
        ..Config::default()
    };
    let client = AuditRpcClient::new(&config);
    let result = client.get_slot();
    assert!(matches!(result, Err(AuditError::Rpc(_))));
}
