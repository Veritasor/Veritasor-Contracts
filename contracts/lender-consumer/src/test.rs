#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, String,
};

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

fn setup() -> (Env, AttestationContractClient<'static>, LenderAccessListContractClient<'static>, LenderConsumerContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy Core Attestation Contract
    let core_id = env.register(AttestationContract, ());
    let core_client = AttestationContractClient::new(&env, &core_id);
    let admin = Address::generate(&env);
    core_client.initialize(&admin, &0u64);

    // Deploy Access List Contract
    let access_list_id = env.register(LenderAccessListContract, ());
    let access_list_client = LenderAccessListContractClient::new(&env, &access_list_id);
    access_list_client.initialize(&admin);

    // Deploy Lender Consumer Contract
    let lender_id = env.register(LenderConsumerContract, ());
    let lender_client = LenderConsumerContractClient::new(&env, &lender_id);
    lender_client.initialize(&admin, &core_id, &access_list_id);

    (env, core_client, access_list_client, lender_client, admin)
}

fn submit_attestation(
    env: &Env,
    core_client: &AttestationContractClient,
    business: &Address,
    period: &str,
    revenue: i128,
    expiry: Option<u64>,
) -> BytesN<32> {
    let period_str = String::from_str(env, period);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&revenue.to_be_bytes());
    let payload = Bytes::from_slice(env, &buf);
    let root: BytesN<32> = env.crypto().sha256(&payload).into();

    core_client.submit_attestation(
        business,
        &period_str,
        &root,
        &1000u64,
        &1u32,
        &None,
        &expiry,
    );
    root
}

// ════════════════════════════════════════════════════════════════════
//  Basic Revenue Submission Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_and_verify_revenue() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();
    
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    let stored_revenue = lender_client.get_revenue(&business, &period);
    assert_eq!(stored_revenue, Some(revenue));
}

#[test]
#[should_panic(expected = "lender not allowed")]
fn test_submit_revenue_denied_for_unlisted_lender() {
    let (env, core_client, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 50_000_00;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let unlisted = Address::generate(&env);
    lender_client.submit_revenue(&unlisted, &business, &period, &revenue);
}

#[test]
#[should_panic(expected = "Revenue data does not match")]
fn test_submit_invalid_revenue_panics() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();
    
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    // Try to submit DIFFERENT revenue
    let fake_revenue: i128 = 6_000_000;
    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &fake_revenue);
}

// ════════════════════════════════════════════════════════════════════
//  Trailing Revenue and Anomaly Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_trailing_revenue_and_anomalies() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();
    
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);

    // Helper to submit
    let submit_period = |period_str: &str, rev: i128| {
        submit_attestation(&env, &core_client, &business, period_str, rev, None);
        let period = String::from_str(&env, period_str);
        lender_client.submit_revenue(&lender, &business, &period, &rev);
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
fn test_zero_revenue_not_anomaly() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();
    
    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);

    submit_attestation(&env, &core_client, &business, "2026-01", 0, None);
    let period = String::from_str(&env, "2026-01");
    lender_client.submit_revenue(&lender, &business, &period, &0i128);

    // Zero revenue should not be flagged as anomaly (only negative is)
    assert!(!lender_client.is_anomaly(&business, &period));
}

// ════════════════════════════════════════════════════════════════════
//  Dispute Status Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_dispute_status() {
    let (env, _, access_list_client, lender_client, admin) = setup();

    let lender_tier2 = Address::generate(&env);
    access_list_client.set_lender(
        &admin,
        &lender_tier2,
        &2u32,
        &lender_meta(&env, "Tier2"),
    );

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    assert!(!lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&lender_tier2, &business, &period, &true);
    assert!(lender_client.get_dispute_status(&business, &period));

    lender_client.set_dispute(&lender_tier2, &business, &period, &false);
    assert!(!lender_client.get_dispute_status(&business, &period));
}

#[test]
#[should_panic(expected = "lender not allowed")]
fn test_set_dispute_requires_tier_2() {
    let (env, _, access_list_client, lender_client, admin) = setup();

    let lender_tier1 = Address::generate(&env);
    access_list_client.set_lender(
        &admin,
        &lender_tier1,
        &1u32,
        &lender_meta(&env, "Tier1"),
    );

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");

    // Tier 1 lender should not be able to set dispute
    lender_client.set_dispute(&lender_tier1, &business, &period, &true);
}

// ════════════════════════════════════════════════════════════════════
//  Access Control Scenario Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_lender_gains_and_loses_access_scenario() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 12_345;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

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

// ════════════════════════════════════════════════════════════════════
//  Verification Safeguards Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_verify_with_safeguards_valid() {
    let (env, core_client, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    let root = submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let result = lender_client.verify_with_safeguards(&business, &period, &root);

    assert!(result.is_valid);
    assert_eq!(result.rejection_reason, REJECTION_VALID);
}

#[test]
fn test_verify_with_safeguards_not_found() {
    let (env, _, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    let result = lender_client.verify_with_safeguards(&business, &period, &root);

    assert!(!result.is_valid);
    assert_eq!(result.rejection_reason, REJECTION_NOT_FOUND);
}

#[test]
fn test_verify_with_safeguards_expired() {
    let (env, core_client, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    // Set expiry in the past
    let past_expiry = 100u64;
    let root = submit_attestation(&env, &core_client, &business, "2026-03", revenue, Some(past_expiry));

    // Advance time past expiry
    env.ledger().set_timestamp(1000);

    let period = String::from_str(&env, "2026-03");
    let result = lender_client.verify_with_safeguards(&business, &period, &root);

    assert!(!result.is_valid);
    assert_eq!(result.rejection_reason, REJECTION_EXPIRED);
}

#[test]
fn test_verify_with_safeguards_disputed() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender_tier2 = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender_tier2, &2u32, &lender_meta(&env, "Tier2"));

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    let root = submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    // Set dispute
    lender_client.set_dispute(&lender_tier2, &business, &period, &true);

    let result = lender_client.verify_with_safeguards(&business, &period, &root);

    assert!(!result.is_valid);
    assert_eq!(result.rejection_reason, REJECTION_DISPUTED);
}

#[test]
fn test_verify_with_safeguards_root_mismatch() {
    let (env, core_client, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    // Wrong root
    let wrong_root = BytesN::from_array(&env, &[99u8; 32]);
    let period = String::from_str(&env, "2026-03");
    let result = lender_client.verify_with_safeguards(&business, &period, &wrong_root);

    assert!(!result.is_valid);
    assert_eq!(result.rejection_reason, REJECTION_ROOT_MISMATCH);
}

// ════════════════════════════════════════════════════════════════════
//  Attestation Health Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_attestation_health_valid() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    let health = lender_client.get_attestation_health(&business, &period);

    assert!(health.exists);
    assert!(!health.is_expired);
    assert!(!health.is_revoked);
    assert!(!health.is_disputed);
    assert!(!health.has_revenue);
    assert!(!health.has_anomaly);

    // Submit revenue
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    let health_after = lender_client.get_attestation_health(&business, &period);
    assert!(health_after.has_revenue);
}

#[test]
fn test_get_attestation_health_not_found() {
    let (env, _, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");

    let health = lender_client.get_attestation_health(&business, &period);

    assert!(!health.exists);
    assert!(!health.is_expired);
    assert!(!health.is_revoked);
    assert!(!health.is_disputed);
    assert!(!health.has_revenue);
    assert!(!health.has_anomaly);
}

#[test]
fn test_get_attestation_health_expired() {
    let (env, core_client, _, lender_client, _) = setup();

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    // Set expiry in the past
    let past_expiry = 100u64;
    submit_attestation(&env, &core_client, &business, "2026-03", revenue, Some(past_expiry));

    // Advance time past expiry
    env.ledger().set_timestamp(1000);

    let period = String::from_str(&env, "2026-03");
    let health = lender_client.get_attestation_health(&business, &period);

    assert!(health.exists);
    assert!(health.is_expired);
}

#[test]
fn test_get_attestation_health_disputed() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender_tier2 = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender_tier2, &2u32, &lender_meta(&env, "Tier2"));

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.set_dispute(&lender_tier2, &business, &period, &true);

    let health = lender_client.get_attestation_health(&business, &period);

    assert!(health.exists);
    assert!(health.is_disputed);
}

#[test]
fn test_get_attestation_health_with_anomaly() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = -500; // Negative revenue triggers anomaly

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    let health = lender_client.get_attestation_health(&business, &period);

    assert!(health.has_revenue);
    assert!(health.has_anomaly);
}

// ════════════════════════════════════════════════════════════════════
//  Safeguards Integration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "attestation has expired")]
fn test_submit_revenue_rejects_expired() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    // Set expiry in the past
    let past_expiry = 100u64;
    submit_attestation(&env, &core_client, &business, "2026-03", revenue, Some(past_expiry));

    // Advance time past expiry
    env.ledger().set_timestamp(1000);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);
}

#[test]
#[should_panic(expected = "attestation is under dispute")]
fn test_submit_revenue_rejects_disputed() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let lender_tier2 = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender_tier2, &2u32, &lender_meta(&env, "Tier2"));

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    // Set dispute
    lender_client.set_dispute(&lender_tier2, &business, &period, &true);

    // Try to submit revenue - should fail
    lender_client.submit_revenue(&lender, &business, &period, &revenue);
}

#[test]
#[should_panic(expected = "attestation not found")]
fn test_submit_revenue_rejects_nonexistent() {
    let (env, _, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-03");
    let revenue: i128 = 5_000_000;

    // No attestation submitted - should fail
    lender_client.submit_revenue(&lender, &business, &period, &revenue);
}

// ════════════════════════════════════════════════════════════════════
//  Admin Functions Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_get_admin() {
    let (env, _, _, lender_client, admin) = setup();

    let stored_admin = lender_client.get_admin();
    assert_eq!(stored_admin, admin);
}

#[test]
fn test_clear_anomaly() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = -500;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    assert!(lender_client.is_anomaly(&business, &period));

    // Clear anomaly
    lender_client.clear_anomaly(&admin, &business, &period);

    assert!(!lender_client.is_anomaly(&business, &period));
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn test_clear_anomaly_requires_admin() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = -500;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    // Non-admin tries to clear anomaly
    let non_admin = Address::generate(&env);
    lender_client.clear_anomaly(&non_admin, &business, &period);
}

#[test]
fn test_set_access_list() {
    let (env, _, _, lender_client, admin) = setup();

    let new_access_list = Address::generate(&env);
    lender_client.set_access_list(&admin, &new_access_list);

    let stored = lender_client.get_access_list_address();
    assert_eq!(stored, new_access_list);
}

// ════════════════════════════════════════════════════════════════════
//  Unchecked Revenue Submission Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_submit_revenue_unchecked_bypasses_safeguards() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = 5_000_000;

    // Set expiry in the past
    let past_expiry = 100u64;
    submit_attestation(&env, &core_client, &business, "2026-03", revenue, Some(past_expiry));

    // Advance time past expiry
    env.ledger().set_timestamp(1000);

    let period = String::from_str(&env, "2026-03");
    
    // Unchecked version should succeed despite expiry
    lender_client.submit_revenue_unchecked(&lender, &business, &period, &revenue);

    assert_eq!(lender_client.get_revenue(&business, &period), Some(revenue));
}

// ════════════════════════════════════════════════════════════════════
//  Boundary and Edge Case Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_large_revenue_value() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = i128::MAX;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    assert_eq!(lender_client.get_revenue(&business, &period), Some(revenue));
}

#[test]
fn test_negative_revenue_value() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);
    let revenue: i128 = i128::MIN;

    submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);

    let period = String::from_str(&env, "2026-03");
    lender_client.submit_revenue(&lender, &business, &period, &revenue);

    assert_eq!(lender_client.get_revenue(&business, &period), Some(revenue));
    assert!(lender_client.is_anomaly(&business, &period));
}

#[test]
fn test_multiple_periods_same_business() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let business = Address::generate(&env);

    let periods = [
        "2026-01", "2026-02", "2026-03", "2026-04", "2026-05", "2026-06",
        "2026-07", "2026-08", "2026-09", "2026-10", "2026-11", "2026-12",
    ];

    for (i, period_str) in periods.iter().enumerate() {
        let revenue = ((i + 1) as i128) * 1000;
        submit_attestation(&env, &core_client, &business, period_str, revenue, None);
        let period = String::from_str(&env, period_str);
        lender_client.submit_revenue(&lender, &business, &period, &revenue);
    }

    // Verify all periods
    for (i, period_str) in periods.iter().enumerate() {
        let period = String::from_str(&env, period_str);
        let expected = ((i + 1) as i128) * 1000;
        assert_eq!(lender_client.get_revenue(&business, &period), Some(expected));
    }

    // Test trailing revenue for all 12 months
    let mut periods_vec = soroban_sdk::Vec::new(&env);
    for period_str in periods.iter() {
        periods_vec.push_back(String::from_str(&env, period_str));
    }
    
    let sum = lender_client.get_trailing_revenue(&business, &periods_vec);
    assert_eq!(sum, 78000); // Sum of 1000 + 2000 + ... + 12000
}

#[test]
fn test_multiple_businesses_same_period() {
    let (env, core_client, access_list_client, lender_client, admin) = setup();

    let lender = Address::generate(&env);
    access_list_client.set_lender(&admin, &lender, &1u32, &lender_meta(&env, "Lender"));

    let period = String::from_str(&env, "2026-03");

    for i in 1..=5 {
        let business = Address::generate(&env);
        let revenue = (i as i128) * 10000;
        
        submit_attestation(&env, &core_client, &business, "2026-03", revenue, None);
        lender_client.submit_revenue(&lender, &business, &period, &revenue);
        
        assert_eq!(lender_client.get_revenue(&business, &period), Some(revenue));
    }
}
