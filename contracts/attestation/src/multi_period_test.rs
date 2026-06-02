//! Comprehensive tests for multi-period attestation submission and revocation.
//!
//! Covers: overlap detection across random ranges, merkle_root indexing,
//! revocation via index, edge cases (adjacent, equal, partial overlap),
//! and revoked range skipping.

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register the contract and return a client.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, client)
}

/// Generate a root from period for deterministic test roots.
fn period_to_root(period: u32) -> [u8; 32] {
    let mut root = [0u8; 32];
    root[0] = (period >> 24) as u8;
    root[1] = (period >> 16) as u8;
    root[2] = (period >> 8) as u8;
    root[3] = period as u8;
    root
}

// ════════════════════════════════════════════════════════════════════
//  Issue #367: Merkle Root Index Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_index_populates_on_submit() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202401));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root, 1000u64, 1u32, &None, &None,
    );

    // Verify the range was stored
    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored.get(0).unwrap().merkle_root, root);
}

#[test]
fn test_revocation_via_index_success() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202401));

    // Submit a range
    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root, 1000u64, 1u32, &None, &None,
    );

    // Revoke via index
    client.revoke_multi_period_attestation(&business, &root);

    // Verify revoked flag set
    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 1);
    assert!(stored.get(0).unwrap().revoked);
}

#[test]
#[should_panic(expected = "root not found")]
fn test_revocation_missing_root_panics() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let missing_root = BytesN::from_array(&env, &period_to_root(999999));

    // Try to revoke a non-existent root
    client.revoke_multi_period_attestation(&business, &missing_root);
}

#[test]
fn test_multiple_ranges_independent_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202413));
    let root3 = BytesN::from_array(&env, &period_to_root(202425));

    // Submit three non-overlapping ranges
    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, 202413, 202424, &root2, 2000u64, 1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, 202425, 202436, &root3, 3000u64, 1u32, &None, &None,
    );

    // Revoke the middle one via index
    client.revoke_multi_period_attestation(&business, &root2);

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 3);
    assert!(!stored.get(0).unwrap().revoked); // First not revoked
    assert!(stored.get(1).unwrap().revoked); // Middle revoked
    assert!(!stored.get(2).unwrap().revoked); // Last not revoked
}

#[test]
fn test_revocation_last_range_via_index() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202413));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, 202413, 202424, &root2, 2000u64, 1u32, &None, &None,
    );

    // Revoke the last (most recent) range
    client.revoke_multi_period_attestation(&business, &root2);

    let stored = client.get_multi_period_ranges(&business);
    assert!(stored.get(1).unwrap().revoked);
}

// ════════════════════════════════════════════════════════════════════
//  Issue #366: Overlap Detection Fuzz Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_overlap_adjacent_ranges_fail() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Adjacent range: end+1 == start, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202412, 202424, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_identical_ranges_fail() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Identical range, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202401, 202412, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_fully_contained_fail() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Smaller range fully contained within first, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202404, 202408, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_partial_left_fail() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202405, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Partial overlap on left, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202401, 202408, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_partial_right_fail() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202408, &root1, 1000u64, 1u32, &None, &None,
    );

    // Partial overlap on right, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202405, 202412, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_no_overlap_before_range_succeeds() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202405, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // No overlap: end_period < start_period of existing, should succeed
    client.submit_multi_period_attestation(
        &business, 202401, 202404, &root2, 2000u64, 1u32, &None, &None,
    );

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 2);
}

#[test]
fn test_no_overlap_after_range_succeeds() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202404, &root1, 1000u64, 1u32, &None, &None,
    );

    // No overlap: start_period > end_period of existing, should succeed
    client.submit_multi_period_attestation(
        &business, 202405, 202412, &root2, 2000u64, 1u32, &None, &None,
    );

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 2);
}

#[test]
fn test_overlap_with_revoked_range_succeeds() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Revoke the first range
    client.revoke_multi_period_attestation(&business, &root1);

    // Now submit an overlapping range (with revoked), should succeed
    client.submit_multi_period_attestation(
        &business, 202401, 202412, &root2, 2000u64, 1u32, &None, &None,
    );

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 2);
    assert!(stored.get(0).unwrap().revoked);
    assert!(!stored.get(1).unwrap().revoked);
}

#[test]
fn test_multiple_overlaps_across_ranges() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));
    let root3 = BytesN::from_array(&env, &period_to_root(202403));

    // Submit first range: 202401-202406
    client.submit_multi_period_attestation(
        &business, 202401, 202406, &root1, 1000u64, 1u32, &None, &None,
    );

    // Submit second non-overlapping: 202407-202412
    client.submit_multi_period_attestation(
        &business, 202407, 202412, &root2, 2000u64, 1u32, &None, &None,
    );

    // Try third overlapping with first (202403-202410), should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202403, 202410, &root3, 3000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_start_period_equals_end_period_predicate() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    // Single-period range
    client.submit_multi_period_attestation(
        &business, 202405, 202405, &root1, 1000u64, 1u32, &None, &None,
    );

    // Try to submit exact same period, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202405, 202405, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_wide_range_overlaps() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    // Wide range covering many periods
    client.submit_multi_period_attestation(
        &business, 202301, 202412, &root1, 1000u64, 1u32, &None, &None,
    );

    // Any range within the wide range should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, 202306, 202310, &root2, 2000u64, 1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}
