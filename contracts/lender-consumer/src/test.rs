#![cfg(test)]

use super::*;
use soroban_sdk::{Env, Address, BytesN, String, Bytes, testutils::Address as _};

// We need to import the attestation contract to test integration
// Since we are in the same workspace, we can use the path dependency
// configured in Cargo.toml
use veritasor_attestation::{AttestationContract, AttestationContractClient};

#[test]
fn test_submit_and_verify_revenue() {
    let env = Env::default();
    env.mock_all_auths();

    // 1. Deploy Core Attestation Contract
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    // 2. Deploy Lender Consumer Contract
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    
    // Initialize Lender Contract with Core Address
    lender_client.initialize(&core_id);

    // 3. Prepare Data
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 50_000_00; // $50,000.00
    
    // Calculate root (SHA256 of revenue bytes)
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();

    let timestamp = 1772000000;
    let version = 1;

    // 4. Submit Attestation to Core (Business does this)
    core_client.submit_attestation(&business, &period, &root, &timestamp, &version);

    // 5. Submit Revenue to Lender (Business/Lender does this)
    lender_client.submit_revenue(&business, &period, &revenue);

    // 6. Verify it was stored
    let stored_revenue = lender_client.get_revenue(&business, &period);
    assert_eq!(stored_revenue, Some(revenue));
}

#[test]
#[should_panic(expected = "Revenue data does not match the attested Merkle root in Core")]
fn test_submit_invalid_revenue_panics() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy Core
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    core_client.initialize(&Address::generate(&env));

    // Deploy Lender
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&core_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 50_000_00;

    // Calculate root for 50,000
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();

    // Submit valid attestation
    core_client.submit_attestation(&business, &period, &root, &1772000000, &1);

    // Try to submit DIFFERENT revenue (60,000)
    let fake_revenue: i128 = 60_000_00;
    lender_client.submit_revenue(&business, &period, &fake_revenue);
}

#[test]
fn test_trailing_revenue_and_anomalies() {
    let env = Env::default();
    env.mock_all_auths();

    // Setup
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    core_client.initialize(&Address::generate(&env));

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&core_id);

    let business = Address::generate(&env);

    // Helper to submit
    let submit_period = |period_str: &str, rev: i128| {
        let period = String::from_str(&env, period_str);
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&rev.to_be_bytes());
        let payload = Bytes::from_slice(&env, &buf);
        let root: BytesN<32> = env.crypto().sha256(&payload).into();
        
        core_client.submit_attestation(&business, &period, &root, &100, &1);
        lender_client.submit_revenue(&business, &period, &rev);
    };

    submit_period("2026-01", 1000);
    submit_period("2026-02", 2000);
    submit_period("2026-03", 3000);

    // Check trailing sum
    let periods = soroban_sdk::vec![
        &env, 
        String::from_str(&env, "2026-01"),
        String::from_str(&env, "2026-02"),
        String::from_str(&env, "2026-03")
    ];
    let sum = lender_client.get_trailing_revenue(&business, &periods);
    assert_eq!(sum, 6000);

    // Test Anomaly (negative revenue)
    submit_period("2026-04", -500);
    assert!(lender_client.is_anomaly(&business, &String::from_str(&env, "2026-04")));
    assert!(!lender_client.is_anomaly(&business, &String::from_str(&env, "2026-01")));
}

#[test]
fn test_dispute_status() {
    let env = Env::default();
    env.mock_all_auths();

    let core_id = env.register(AttestationContract, ());
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&core_id); // Initialize even if not used for dispute

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    assert!(!lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&business, &period, &true);
    assert!(lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&business, &period, &false);
    assert!(!lender_client.get_dispute_status(&business, &period));
}
