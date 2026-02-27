#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String};

// We need to import the attestation contract to test integration
// Since we are in the same workspace, we can use the path dependency
// configured in Cargo.toml
use veritasor_attestation::{AttestationContract, AttestationContractClient};
use veritasor_lender_access_list::{
    LenderAccessListContract, LenderAccessListContractClient, LenderMetadata,
};

fn lender_meta(env: &Env, name: &str) -> LenderMetadata {
    LenderMetadata {
        name: String::from_str(env, name),
        url: String::from_str(env, "https://example.com"),
        notes: String::from_str(env, "notes"),
    }
}

#[test]
fn test_submit_and_verify_revenue() {
    let env = Env::default();
    env.mock_all_auths();

    // 1. Deploy Core Attestation Contract
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    // 2. Deploy Access List Contract
    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    // 3. Deploy Lender Consumer Contract
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);

    // Initialize Lender Contract with Core Address
    lender_client.initialize(&core_id);
    
    // Initialize Lender Contract
    lender_client.initialize(&admin, &core_id, &access_list_id);

    // 4. Prepare Data
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000; // $50,000.00

    // Calculate root (SHA256 of revenue bytes)
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();

    let timestamp = 1772000000;
    let version = 1;

    // 5. Submit Attestation to Core (Business does this)
    // 4. Submit Attestation to Core (Business does this)
    core_client.submit_attestation(
        &business, &period, &root, &timestamp, &version, &None, &None,
    );
    core_client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

    // 6. Submit Revenue to Lender (Lender does this)
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    // 7. Verify it was stored
    let stored_revenue = lender_client.get_revenue(&business, &period);
    assert_eq!(stored_revenue, Some(revenue));
}

#[test]
#[should_panic(expected = "lender not allowed")]
fn test_submit_revenue_denied_for_unlisted_lender() {
    let env = Env::default();
    env.mock_all_auths();

    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 50_000_00;

    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();
    core_client.submit_attestation(&business, &period, &root, &1772000000, &1, &None);

    let unlisted = Address::generate(&env);
    lender_client.submit_revenue(&unlisted, &business, &period, &revenue);
}

#[test]
#[should_panic(expected = "Revenue data does not match the attested Merkle root in Core")]
fn test_submit_invalid_revenue_panics() {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy Core
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    // Deploy Access List
    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    // Deploy Lender
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    // Calculate root for 50,000
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();

    // Submit valid attestation
    core_client.submit_attestation(&business, &period, &root, &1772000000, &1, &None, &None);

    // Try to submit DIFFERENT revenue (60,000)
    let fake_revenue: i128 = 6_000_000;
    lender_client.submit_revenue(&business, &period, &fake_revenue);
    core_client.submit_attestation(&business, &period, &root, &1772000000, &1, &None);

    // Try to submit DIFFERENT revenue (60,000)
    let fake_revenue: i128 = 60_000_00;
    lender_client.submit_revenue(&lender, &business, &period, &fake_revenue);
}

#[test]
fn test_trailing_revenue_and_anomalies() {
    let env = Env::default();
    env.mock_all_auths();

    // Setup
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    let business = Address::generate(&env);

    // Helper to submit
    let submit_period = |period_str: &str, rev: i128| {
        let period = String::from_str(&env, period_str);
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&rev.to_be_bytes());
        let payload = Bytes::from_slice(&env, &buf);
        let root: BytesN<32> = env.crypto().sha256(&payload).into();

        core_client.submit_attestation(&business, &period, &root, &100, &1, &None, &None);
        
        core_client.submit_attestation(&business, &period, &root, &100, &1, &None);
        lender_client.submit_revenue(&lender, &business, &period, &rev);
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
    let admin = Address::generate(&env);

    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    let lender_tier2 = Address::generate(&env);
    access_list_client.set_lender(
        &admin,
        &lender_tier2,
        &2u32,
        &lender_meta(&env, "Tier2"),
    );

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    assert!(!lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&lender_tier2, &business, &period, &true);
    assert!(lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&lender_tier2, &business, &period, &false);
    assert!(!lender_client.get_dispute_status(&business, &period));
}

#[test]
fn test_lender_gains_and_loses_access_scenario() {
    let env = Env::default();
    env.mock_all_auths();

    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin);

    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    let lender = Address::generate(&env);

    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 12_345;

    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(&env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();
    core_client.submit_attestation(&business, &period, &root, &1772000000, &1, &None);

    // Initially denied
    let denied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        lender_client.submit_revenue(&lender, &business, &period, &revenue);
    }));
    assert!(denied.is_err());

    // Gain access
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));
    lender_client.submit_revenue(&lender, &business, &period, &revenue);
    assert_eq!(lender_client.get_revenue(&business, &period), Some(revenue));

    // Lose access and get denied again
    access_list_client.remove_lender(&admin, &lender);
    let denied2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        lender_client.submit_revenue(&lender, &business, &period, &revenue);
    }));
    assert!(denied2.is_err());
}
