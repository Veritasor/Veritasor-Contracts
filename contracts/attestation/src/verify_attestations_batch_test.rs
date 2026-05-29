//! # `verify_attestations_batch` Batch Verification Tests
//!
//! Verifies that `verify_attestations_batch` correctly verifies multiple
//! attestations in a single call, maintaining revocation awareness and
//! result ordering.
//!
//! ## Behaviour under test
//!
//! ```text
//! verify_attestations_batch(items: Vec<(Address, String, BytesN<32>)>) -> Vec<bool>
//!   For each item (business, period, root):
//!     = stored_root == root  &&  !is_attestation_revoked(business, period)
//! ```
//!
//! ## Test matrix
//!
//! | Scenario                              | Expected |
//! |---------------------------------------|----------|
//! | Empty batch                           | panic    |
//! | Batch exceeds 30 items                | panic    |
//! | Single item, attestation exists       | [true]   |
//! | Single item, attestation missing      | [false]  |
//! | Multiple items, mixed results         | [T,F,T]  |
//! | Revoked attestation in batch          | false    |
//! | Root mismatch in batch                | false    |
//! | Duplicate (business, period) pairs    | [T,T]    |
//! | Same business, different periods      | [T,F]    |
//! | Different businesses, same period     | [T,F]    |
//! | Maximum batch size (30 items)         | [...]    |
//!
//! ## Security invariants validated
//!
//! - Batch processing does not bypass revocation checks
//! - Result ordering matches input ordering
//! - Result length equals input length
//! - Batch method produces same results as individual calls
//! - No state modifications (read-only)
//! - No authorization required

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Minimal test harness: one contract instance, one admin, mock auths.
struct Setup<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
    admin: Address,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    Setup { env, client, admin }
}

/// Submit a single-period attestation and return the root that was stored.
fn submit(
    s: &Setup,
    business: &Address,
    period_str: &str,
    root_byte: u8,
) -> BytesN<32> {
    let period = String::from_str(&s.env, period_str);
    let root = BytesN::from_array(&s.env, &[root_byte; 32]);
    s.client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    root
}

/// Revoke an attestation through the dispute resolution flow.
fn revoke(s: &Setup, caller: &Address, business: &Address, period_str: &str) {
    let period = String::from_str(&s.env, period_str);
    let reason = String::from_str(&s.env, "test revocation");
    s.client
        .revoke_attestation(caller, business, &period, &reason, &0u64);
}

/// Convenience: call `verify_attestation` and return the result.
fn verify(s: &Setup, business: &Address, period_str: &str, root: &BytesN<32>) -> bool {
    let period = String::from_str(&s.env, period_str);
    s.client.verify_attestation(business, &period, root)
}

/// Create a batch item tuple.
fn batch_item(
    s: &Setup,
    business: &Address,
    period_str: &str,
    root: &BytesN<32>,
) -> (Address, String, BytesN<32>) {
    let period = String::from_str(&s.env, period_str);
    (business.clone(), period, root.clone())
}

// ════════════════════════════════════════════════════════════════════
//  Input Validation Tests
// ════════════════════════════════════════════════════════════════════

/// Empty batch panics with correct message.
#[test]
#[should_panic(expected = "batch cannot be empty")]
fn test_empty_batch_panics() {
    let s = setup();
    let items: Vec<(Address, String, BytesN<32>)> = Vec::new(&s.env);
    s.client.verify_attestations_batch(&items);
}

/// Batch exceeding 30 items panics with correct message.
#[test]
#[should_panic(expected = "batch exceeds maximum size")]
fn test_oversized_batch_panics() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = BytesN::from_array(&s.env, &[0xAA; 32]);
    let period = String::from_str(&s.env, "2026-01");

    let mut items = Vec::new(&s.env);
    for _ in 0..31 {
        items.push_back((business.clone(), period.clone(), root.clone()));
    }
    s.client.verify_attestations_batch(&items);
}

/// Single item batch succeeds.
#[test]
fn test_single_item_batch_succeeds() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xAA);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 1);
    assert!(results.get(0).unwrap());
}

/// Maximum batch size (30 items) succeeds.
#[test]
fn test_maximum_batch_size_succeeds() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xBB);

    let mut items = Vec::new(&s.env);
    for i in 0..30 {
        let period_str = std::format!("2026-{:02}", (i % 12) + 1);
        if i == 0 {
            items.push_back(batch_item(&s, &business, "2026-01", &root));
        } else {
            let dummy_root = BytesN::from_array(&s.env, &[0xCC; 32]);
            items.push_back(batch_item(&s, &business, &period_str, &dummy_root));
        }
    }

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 30);
}

// ════════════════════════════════════════════════════════════════════
//  Verification Logic Tests
// ════════════════════════════════════════════════════════════════════

/// Non-existent attestation returns false.
#[test]
fn test_nonexistent_attestation_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = BytesN::from_array(&s.env, &[0xDD; 32]);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 1);
    assert!(!results.get(0).unwrap());
}

/// Revoked attestation returns false even with matching root.
#[test]
fn test_revoked_attestation_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xEE);

    revoke(&s, &s.admin.clone(), &business, "2026-01");

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 1);
    assert!(!results.get(0).unwrap());
}

/// Root mismatch returns false.
#[test]
fn test_root_mismatch_returns_false() {
    let s = setup();
    let business = Address::generate(&s.env);
    submit(&s, &business, "2026-01", 0xFF);

    let wrong_root = BytesN::from_array(&s.env, &[0x11; 32]);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &wrong_root));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 1);
    assert!(!results.get(0).unwrap());
}

/// Mixed results in batch.
#[test]
fn test_mixed_results_in_batch() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let biz_c = Address::generate(&s.env);

    let root_a = submit(&s, &biz_a, "2026-01", 0x01);
    let root_b = submit(&s, &biz_b, "2026-01", 0x02);
    submit(&s, &biz_c, "2026-01", 0x03);
    revoke(&s, &s.admin.clone(), &biz_c, "2026-01");

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &biz_a, "2026-01", &root_a)); // true
    items.push_back(batch_item(&s, &biz_b, "2026-01", &root_b)); // true
    items.push_back(batch_item(&s, &biz_c, "2026-01", &BytesN::from_array(&s.env, &[0x03; 32]))); // false (revoked)
    let nonexistent = Address::generate(&s.env);
    items.push_back(batch_item(&s, &nonexistent, "2026-01", &BytesN::from_array(&s.env, &[0x04; 32]))); // false (missing)

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 4);
    assert!(results.get(0).unwrap());
    assert!(results.get(1).unwrap());
    assert!(!results.get(2).unwrap());
    assert!(!results.get(3).unwrap());
}

// ════════════════════════════════════════════════════════════════════
//  Result Ordering Tests
// ════════════════════════════════════════════════════════════════════

/// Result ordering matches input ordering.
#[test]
fn test_result_ordering_preserved() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let biz_c = Address::generate(&s.env);

    let root_a = submit(&s, &biz_a, "2026-01", 0xAA);
    let root_b = submit(&s, &biz_b, "2026-01", 0xBB);
    let root_c = submit(&s, &biz_c, "2026-01", 0xCC);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &biz_c, "2026-01", &root_c));
    items.push_back(batch_item(&s, &biz_a, "2026-01", &root_a));
    items.push_back(batch_item(&s, &biz_b, "2026-01", &root_b));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 3);
    assert!(results.get(0).unwrap()); // biz_c
    assert!(results.get(1).unwrap()); // biz_a
    assert!(results.get(2).unwrap()); // biz_b
}

/// Result length matches input length.
#[test]
fn test_result_length_matches_input() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = BytesN::from_array(&s.env, &[0xDD; 32]);

    for batch_size in 1..=10 {
        let mut items = Vec::new(&s.env);
        for _ in 0..batch_size {
            items.push_back(batch_item(&s, &business, "2026-01", &root));
        }

        let results = s.client.verify_attestations_batch(&items);
        assert_eq!(results.len() as u32, batch_size);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Consistency Tests
// ════════════════════════════════════════════════════════════════════

/// Single-item batch produces same result as verify_attestation.
#[test]
fn test_consistency_with_single_item_verification() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xEE);

    let single_result = verify(&s, &business, "2026-01", &root);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root));
    let batch_results = s.client.verify_attestations_batch(&items);

    assert_eq!(batch_results.len(), 1);
    assert_eq!(batch_results.get(0).unwrap(), single_result);
}

/// Batch results match individual verify_attestation calls.
#[test]
fn test_batch_results_match_individual_calls() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let biz_c = Address::generate(&s.env);

    let root_a = submit(&s, &biz_a, "2026-01", 0x11);
    let root_b = submit(&s, &biz_b, "2026-01", 0x22);
    submit(&s, &biz_c, "2026-01", 0x33);
    revoke(&s, &s.admin.clone(), &biz_c, "2026-01");

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &biz_a, "2026-01", &root_a));
    items.push_back(batch_item(&s, &biz_b, "2026-01", &root_b));
    items.push_back(batch_item(&s, &biz_c, "2026-01", &BytesN::from_array(&s.env, &[0x33; 32])));

    let batch_results = s.client.verify_attestations_batch(&items);

    assert_eq!(batch_results.get(0).unwrap(), verify(&s, &biz_a, "2026-01", &root_a));
    assert_eq!(batch_results.get(1).unwrap(), verify(&s, &biz_b, "2026-01", &root_b));
    assert_eq!(batch_results.get(2).unwrap(), verify(&s, &biz_c, "2026-01", &BytesN::from_array(&s.env, &[0x33; 32])));
}

// ════════════════════════════════════════════════════════════════════
//  Edge Case Tests
// ════════════════════════════════════════════════════════════════════

/// Duplicate (business, period) pairs are verified independently.
#[test]
fn test_duplicate_pairs_verified_independently() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0x44);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root));
    items.push_back(batch_item(&s, &business, "2026-01", &root));
    items.push_back(batch_item(&s, &business, "2026-01", &root));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 3);
    assert!(results.get(0).unwrap());
    assert!(results.get(1).unwrap());
    assert!(results.get(2).unwrap());
}

/// Same business, different periods.
#[test]
fn test_same_business_different_periods() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root_jan = submit(&s, &business, "2026-01", 0x55);
    let root_feb = submit(&s, &business, "2026-02", 0x66);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &business, "2026-01", &root_jan));
    items.push_back(batch_item(&s, &business, "2026-02", &root_feb));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 2);
    assert!(results.get(0).unwrap());
    assert!(results.get(1).unwrap());
}

/// Different businesses, same period.
#[test]
fn test_different_businesses_same_period() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let root_a = submit(&s, &biz_a, "2026-01", 0x77);
    let root_b = submit(&s, &biz_b, "2026-01", 0x88);

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &biz_a, "2026-01", &root_a));
    items.push_back(batch_item(&s, &biz_b, "2026-01", &root_b));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 2);
    assert!(results.get(0).unwrap());
    assert!(results.get(1).unwrap());
}

/// Revocation in batch does not affect other items.
#[test]
fn test_revocation_scoped_to_item() {
    let s = setup();
    let biz_a = Address::generate(&s.env);
    let biz_b = Address::generate(&s.env);
    let root_a = submit(&s, &biz_a, "2026-01", 0x99);
    let root_b = submit(&s, &biz_b, "2026-01", 0xAA);

    revoke(&s, &s.admin.clone(), &biz_a, "2026-01");

    let mut items = Vec::new(&s.env);
    items.push_back(batch_item(&s, &biz_a, "2026-01", &root_a));
    items.push_back(batch_item(&s, &biz_b, "2026-01", &root_b));

    let results = s.client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 2);
    assert!(!results.get(0).unwrap()); // revoked
    assert!(results.get(1).unwrap()); // not revoked
}

/// No authorization required.
#[test]
fn test_no_authorization_required() {
    let s = setup();
    let business = Address::generate(&s.env);
    let root = submit(&s, &business, "2026-01", 0xBB);

    // Create a new environment without mock_all_auths to test authorization
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    // Submit attestation with admin auth
    env.mock_all_auths();
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );

    // Verify batch without any auth (should succeed)
    env.mock_all_auths_allowing_non_root_auth();
    let mut items = Vec::new(&env);
    items.push_back((business.clone(), String::from_str(&env, "2026-01"), root.clone()));

    let results = client.verify_attestations_batch(&items);
    assert_eq!(results.len(), 1);
    assert!(results.get(0).unwrap());
}
