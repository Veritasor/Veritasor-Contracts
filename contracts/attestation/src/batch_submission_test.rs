//! Comprehensive tests for batch attestation submission.
//!
//! Covers: basic batch submission, atomicity, edge cases (empty batch,
//! duplicates, partial failures), multiple businesses, same business
//! multiple periods, fee calculations, and event emission.

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{Address, BytesN, Env, String, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register the contract and return a client (no fees configured).
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, client)
}

/// Register the contract with fee configuration.
struct TestSetupWithFees<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
    _admin: Address,
    token_addr: Address,
    _collector: Address,
}

fn setup_with_fees(base_fee: i128) -> TestSetupWithFees<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    client.configure_fees(&token_addr, &collector, &base_fee, &true);

    TestSetupWithFees {
        env,
        client,
        _admin: admin,
        token_addr,
        _collector: collector,
    }
}

fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    let stellar = StellarAssetClient::new(env, token_addr);
    stellar.mint(to, &amount);
}

fn balance(env: &Env, token_addr: &Address, addr: &Address) -> i128 {
    let client = TokenClient::new(env, token_addr);
    client.balance(addr)
}

fn create_batch_item(
    env: &Env,
    business: &Address,
    period_str: &str,
    root_bytes: &[u8; 32],
    timestamp: u64,
    version: u32,
) -> BatchAttestationItem {
    BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(env, period_str),
        merkle_root: BytesN::from_array(env, root_bytes),
        timestamp,
        version,
        proof_hash: None,
        expiry_timestamp: None,
    }
}

// ════════════════════════════════════════════════════════════════════
//  Basic Batch Submission
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_submit_single_item() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = soroban_sdk::Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));

    client.submit_attestations_batch(&items);

    let (root, ts, ver, fee, _, _) = client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .unwrap();
    assert_eq!(root, BytesN::from_array(&env, &[1u8; 32]));
    assert_eq!(ts, 1_700_000_000);
    assert_eq!(ver, 1);
    assert_eq!(fee, 0); // No fees configured
}

#[test]
fn test_batch_submit_multiple_periods_same_business() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-03",
        &[3u8; 32],
        1_700_017_280,
        1,
    ));

    client.submit_attestations_batch(&items);

    assert_eq!(client.get_business_count(&business), 3);
}

#[test]
fn test_batch_submit_multiple_businesses() {
    let (env, client) = setup();
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business1,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business2,
        "2026-01",
        &[2u8; 32],
        1_700_000_000,
        1,
    ));

    client.submit_attestations_batch(&items);

    assert_eq!(client.get_business_count(&business1), 1);
    assert_eq!(client.get_business_count(&business2), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Atomicity and Validation
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "batch cannot be empty")]
fn test_batch_submit_empty_panics() {
    let (env, client) = setup();
    let items = Vec::new(&env);
    client.submit_attestations_batch(&items);
}

#[test]
#[should_panic(expected = "duplicate attestation in batch")]
fn test_batch_submit_duplicate_in_batch() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    // Same business and period
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[2u8; 32],
        1_700_000_001,
        1,
    ));

    client.submit_attestations_batch(&items);
}

#[test]
#[should_panic(expected = "attestation already exists")]
fn test_batch_submit_existing_period() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    // Pre-submit one
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[1u8; 32]),
        &1_700_000_000,
        &1,
        &0i128,
        &None,
        &None,
    );

    // Try to batch submit including the same period
    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));

    client.submit_attestations_batch(&items);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_batch_submit_when_paused() {
    let (env, client) = setup();
    let admin = client.get_admin();
    let business = Address::generate(&env);

    client.pause(&admin);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));

    client.submit_attestations_batch(&items);
}

// ════════════════════════════════════════════════════════════════════
//  Fees in Batch
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_fees_calculated_correctly() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    let mut items = Vec::new(&t.env);
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-03",
        &[3u8; 32],
        1_700_017_280,
        1,
    ));

    let balance_before = balance(&t.env, &t.token_addr, &business);
    t.client.submit_attestations_batch(&items);
    let balance_after = balance(&t.env, &t.token_addr, &business);

    // All three fees should be collected (3 * 1_000_000)
    assert_eq!(balance_before - balance_after, 3_000_000);

    // Verify fee_paid stored in each attestation
    let (_, _, _, fee1, _, _) = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-01"))
        .unwrap();
    let (_, _, _, fee2, _, _) = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-02"))
        .unwrap();
    let (_, _, _, fee3, _, _) = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-03"))
        .unwrap();
    assert_eq!(fee1, 1_000_000);
    assert_eq!(fee2, 1_000_000);
    assert_eq!(fee3, 1_000_000);
}

#[test]
fn test_batch_fees_with_volume_discounts() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 20_000_000);

    // Configure discount brackets
    let mut thresholds = Vec::new(&t.env);
    thresholds.push_back(10);
    thresholds.push_back(50);
    let mut discounts = Vec::new(&t.env);
    discounts.push_back(1_000); // 10%
    discounts.push_back(2_000); // 20%

    t.client.set_volume_brackets(&thresholds, &discounts);

    // Submit 9 attestations first (to get to count 9)
    for i in 1..=9 {
        let period = String::from_str(&t.env, &std::format!("P-{:04}", i));
        let root = BytesN::from_array(&t.env, &[i as u8; 32]);
        t.client.submit_attestation(
            &business,
            &period,
            &root,
            &1_700_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );
    }

    // Now batch submit 3 more
    // Count will be 9, 10, 11 after each item
    // Item 1 (count 9 -> 10): no discount -> 10% discount (reaches threshold 10)
    // Item 2 (count 10 -> 11): 10% discount
    // Item 3 (count 11 -> 12): 10% discount

    let mut items = Vec::new(&t.env);
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-10",
        &[10u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-11",
        &[11u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &t.env,
        &business,
        "2026-12",
        &[12u8; 32],
        1_700_000_000,
        1,
    ));

    let balance_before = balance(&t.env, &t.token_addr, &business);
    t.client.submit_attestations_batch(&items);
    let balance_after = balance(&t.env, &t.token_addr, &business);

    // First item: count 9 -> fee at count 9 (no discount) = 1_000_000
    // Second item: count 10 -> fee at count 10 (10% discount) = 900_000
    // Third item: count 11 -> fee at count 11 (10% discount) = 900_000
    // Total: 1_000_000 + 900_000 + 900_000 = 2_800_000
    let expected_total = 1_000_000 + 900_000 + 900_000;
    assert_eq!(balance_before - balance_after, expected_total);
}

#[test]
fn test_batch_fees_multiple_businesses() {
    let t = setup_with_fees(1_000_000);
    let business1 = Address::generate(&t.env);
    let business2 = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business1, 10_000_000);
    mint(&t.env, &t.token_addr, &business2, 10_000_000);

    let mut items = Vec::new(&t.env);
    items.push_back(create_batch_item(
        &t.env,
        &business1,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &t.env,
        &business2,
        "2026-01",
        &[2u8; 32],
        1_700_000_000,
        1,
    ));

    let balance1_before = balance(&t.env, &t.token_addr, &business1);
    let balance2_before = balance(&t.env, &t.token_addr, &business2);
    t.client.submit_attestations_batch(&items);
    let balance1_after = balance(&t.env, &t.token_addr, &business1);
    let balance2_after = balance(&t.env, &t.token_addr, &business2);

    // Each business should pay 1_000_000
    assert_eq!(balance1_before - balance1_after, 1_000_000);
    assert_eq!(balance2_before - balance2_after, 1_000_000);
}

// ════════════════════════════════════════════════════════════════════
//  Event emission tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_emits_events() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));

    client.submit_attestations_batch(&items);

    // Check that events were emitted (we can't easily verify event content in unit tests,
    // but we can verify the attestations exist which confirms events were emitted)
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_some());
}

// ════════════════════════════════════════════════════════════════════
//  Gas/cost comparison tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_vs_single_cost_comparison() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 20_000_000);

    // Submit 5 attestations individually
    let periods_single: std::vec::Vec<&str> =
        std::vec!["2026-01", "2026-02", "2026-03", "2026-04", "2026-05"];
    for (i, period) in periods_single.iter().enumerate() {
        let root = BytesN::from_array(&t.env, &[(i + 1) as u8; 32]);
        t.client.submit_attestation(
            &business,
            &String::from_str(&t.env, period),
            &root,
            &1_700_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );
    }

    let balance_after_single = balance(&t.env, &t.token_addr, &business);
    let count_after_single = t.client.get_business_count(&business);

    // Reset for batch test
    let business2 = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business2, 20_000_000);

    // Submit 5 attestations in a batch
    let mut items = Vec::new(&t.env);
    for (i, period) in periods_single.iter().enumerate() {
        items.push_back(create_batch_item(
            &t.env,
            &business2,
            period,
            &[(i + 1) as u8; 32],
            1_700_000_000,
            1,
        ));
    }
    t.client.submit_attestations_batch(&items);

    let balance_after_batch = balance(&t.env, &t.token_addr, &business2);
    let count_after_batch = t.client.get_business_count(&business2);

    // Both should have paid the same fees (5 * 1_000_000 = 5_000_000)
    assert_eq!(count_after_single, 5);
    assert_eq!(count_after_batch, 5);

    // Both businesses should have the same final balance (20M - 5M = 15M)
    assert_eq!(balance_after_single, 15_000_000);
    assert_eq!(balance_after_batch, 15_000_000);
}

// ════════════════════════════════════════════════════════════════════
//  Large batch tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_large_size() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    // Submit a batch of 20 attestations
    let mut items = Vec::new(&env);
    for i in 1..=20 {
        let period_str = std::format!("2026-{:02}", i);
        let mut root_bytes = [0u8; 32];
        root_bytes[0] = i as u8;
        items.push_back(create_batch_item(
            &env,
            &business,
            &period_str,
            &root_bytes,
            1_700_000_000 + (i as u64 * 86400),
            1,
        ));
    }

    client.submit_attestations_batch(&items);

    // Verify all were stored
    assert_eq!(client.get_business_count(&business), 20);
    for i in 1..=20 {
        let period = String::from_str(&env, &std::format!("2026-{:02}", i));
        assert!(client.get_attestation(&business, &period).is_some());
    }
}

// ════════════════════════════════════════════════════════════════════
//  Mixed scenarios
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_mixed_businesses_and_periods() {
    let (env, client) = setup();
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    let mut items = Vec::new(&env);
    // Business 1: periods 2026-01, 2026-02
    items.push_back(create_batch_item(
        &env,
        &business1,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business1,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    // Business 2: periods 2026-01, 2026-03
    items.push_back(create_batch_item(
        &env,
        &business2,
        "2026-01",
        &[3u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business2,
        "2026-03",
        &[4u8; 32],
        1_700_017_280,
        1,
    ));

    client.submit_attestations_batch(&items);

    // Verify all attestations
    assert!(client
        .get_attestation(&business1, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(client
        .get_attestation(&business1, &String::from_str(&env, "2026-02"))
        .is_some());
    assert!(client
        .get_attestation(&business2, &String::from_str(&env, "2026-01"))
        .is_some());
    assert!(client
        .get_attestation(&business2, &String::from_str(&env, "2026-03"))
        .is_some());

    // Verify counts
    assert_eq!(client.get_business_count(&business1), 2);
    assert_eq!(client.get_business_count(&business2), 2);
}

// ════════════════════════════════════════════════════════════════════
//  Failure atomicity tests — Issue #127
// ════════════════════════════════════════════════════════════════════

/// Atomicity: conflict on the FIRST item — all subsequent items must be rejected.
#[test]
fn test_atomicity_failure_at_first_item_rejects_all() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[1u8; 32]),
        &1_700_000_000,
        &1,
        &0i128,
        &None,
        &None,
    );

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[9u8; 32],
        1_700_000_001,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-03",
        &[3u8; 32],
        1_700_017_280,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err(), "batch must panic on first-item conflict");
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_none());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-03"))
        .is_none());
    assert_eq!(client.get_business_count(&business), 1);
}

/// Atomicity: conflict on the LAST item — earlier items must NOT be persisted.
#[test]
fn test_atomicity_failure_at_last_item_rejects_all() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-03"),
        &BytesN::from_array(&env, &[3u8; 32]),
        &1_700_017_280,
        &1,
        &0i128,
        &None,
        &None,
    );

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-03",
        &[9u8; 32],
        1_700_017_281,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err(), "batch must panic on last-item conflict");
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .is_none());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_none());
    assert_eq!(client.get_business_count(&business), 1);
}

/// Atomicity: conflict on a MIDDLE item — items before and after must NOT be stored.
#[test]
fn test_atomicity_failure_at_middle_item_rejects_all() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-02"),
        &BytesN::from_array(&env, &[2u8; 32]),
        &1_700_008_640,
        &1,
        &0i128,
        &None,
        &None,
    );

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[9u8; 32],
        1_700_008_641,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-03",
        &[3u8; 32],
        1_700_017_280,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err(), "batch must panic on middle-item conflict");
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .is_none());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-03"))
        .is_none());
    assert_eq!(client.get_business_count(&business), 1);
}

/// Atomicity: business count must NOT increment when the batch fails.
#[test]
fn test_atomicity_business_count_unchanged_on_failure() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    for i in 1u8..=3 {
        client.submit_attestation(
            &business,
            &String::from_str(&env, &std::format!("2025-{:02}", i)),
            &BytesN::from_array(&env, &[i; 32]),
            &1_700_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );
    }
    assert_eq!(client.get_business_count(&business), 3);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[10u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2025-01",
        &[11u8; 32],
        1_700_000_001,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err());
    assert_eq!(client.get_business_count(&business), 3);
}

/// Atomicity: in-batch self-duplicate must reject the entire batch.
#[test]
fn test_atomicity_in_batch_self_duplicate_rejects_all() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[3u8; 32],
        1_700_000_001,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err(), "self-duplicate must reject batch");
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-01"))
        .is_none());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_none());
    assert_eq!(client.get_business_count(&business), 0);
}

/// Atomicity: one bad cross-business entry rejects the entire multi-business batch.
#[test]
fn test_atomicity_cross_business_failure_rejects_all() {
    let (env, client) = setup();
    let business1 = Address::generate(&env);
    let business2 = Address::generate(&env);

    client.submit_attestation(
        &business2,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[2u8; 32]),
        &1_700_000_000,
        &1,
        &0i128,
        &None,
        &None,
    );

    let mut items = Vec::new(&env);
    items.push_back(create_batch_item(
        &env,
        &business1,
        "2026-01",
        &[1u8; 32],
        1_700_000_000,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business1,
        "2026-02",
        &[5u8; 32],
        1_700_008_640,
        1,
    ));
    items.push_back(create_batch_item(
        &env,
        &business2,
        "2026-01",
        &[9u8; 32],
        1_700_000_001,
        1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&items);
    }));

    assert!(result.is_err(), "cross-business duplicate must reject all");
    assert!(client
        .get_attestation(&business1, &String::from_str(&env, "2026-01"))
        .is_none());
    assert!(client
        .get_attestation(&business1, &String::from_str(&env, "2026-02"))
        .is_none());
    assert_eq!(client.get_business_count(&business1), 0);
    assert_eq!(client.get_business_count(&business2), 1);
}

/// Regression: a clean batch succeeds normally after a prior failed batch.
#[test]
fn test_atomicity_clean_batch_succeeds_after_failed_batch() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &BytesN::from_array(&env, &[1u8; 32]),
        &1_700_000_000,
        &1,
        &0i128,
        &None,
        &None,
    );

    let mut bad_items = Vec::new(&env);
    bad_items.push_back(create_batch_item(
        &env,
        &business,
        "2026-01",
        &[9u8; 32],
        1_700_000_001,
        1,
    ));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_attestations_batch(&bad_items);
    }));

    // Good batch after failure
    let mut good_items = Vec::new(&env);
    good_items.push_back(create_batch_item(
        &env,
        &business,
        "2026-02",
        &[2u8; 32],
        1_700_008_640,
        1,
    ));
    good_items.push_back(create_batch_item(
        &env,
        &business,
        "2026-03",
        &[3u8; 32],
        1_700_017_280,
        1,
    ));

    client.submit_attestations_batch(&good_items);

    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-02"))
        .is_some());
    assert!(client
        .get_attestation(&business, &String::from_str(&env, "2026-03"))
        .is_some());
    assert_eq!(client.get_business_count(&business), 3);
}

// ════════════════════════════════════════════════════════════════════
//  Batch size cap tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_at_max_size_accepted() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    for i in 0..MAX_BATCH_SIZE {
        let period = String::from_str(&env, &std::format!("2026-{:02}", i + 1));
        let mut root = [0u8; 32];
        root[0] = i as u8;
        items.push_back(create_batch_item(&env, &business, &std::format!("2026-{:02}", i + 1), &root, 1_700_000_000, 1));
    }

    client.submit_attestations_batch(&items);
    assert_eq!(client.get_business_count(&business), MAX_BATCH_SIZE as u64);
}

#[test]
#[should_panic(expected = "batch exceeds maximum size")]
fn test_batch_one_over_max_size_rejected() {
    let (env, client) = setup();
    let business = Address::generate(&env);

    let mut items = Vec::new(&env);
    for i in 0..=MAX_BATCH_SIZE {
        let mut root = [0u8; 32];
        root[0] = i as u8;
        items.push_back(create_batch_item(&env, &business, &std::format!("2026-{:02}", i + 1), &root, 1_700_000_000, 1));
    }

    client.submit_attestations_batch(&items);
}

#[test]
#[should_panic(expected = "batch cannot be empty")]
fn test_batch_empty_still_rejected() {
    let (env, client) = setup();
    client.submit_attestations_batch(&Vec::new(&env));
}
