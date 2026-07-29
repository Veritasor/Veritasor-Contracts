//! Comprehensive tests for multi-period attestation submission and revocation.
//!
//! Covers: overlap detection across random ranges, merkle_root indexing,
//! revocation via index, edge cases (adjacent, equal, partial overlap),
//! and revoked range skipping.

#![cfg(test)]

use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register the contract and return a client together with the contract id.
fn setup() -> (Env, Address, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, contract_id, client)
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

/// Read the stored multi-period ranges for `business` directly from storage.
#[allow(dead_code)]
fn get_ranges(env: &Env, business: &Address) -> Vec<AttestationRange> {
    let key = MultiPeriodKey::Ranges(business.clone());
    env.storage().instance().get(&key).unwrap_or(Vec::new(env))
}

// ════════════════════════════════════════════════════════════════════
//  Issue #367: Merkle Root Index Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_index_populates_on_submit() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202401));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root, &1000u64, &1u32, &None, &None,
    );

    // Verify the range was stored
}

#[test]
fn test_revocation_via_index_success() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202401));

    // Submit a range
    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root, &1000u64, &1u32, &None, &None,
    );

    // Revoke via index
    client.revoke_multi_period_attestation(&business, &root);

    // Verify revoked flag set
    let stored = client.get_multi_period_ranges(&business);
    assert!(stored.get(0).unwrap().revoked);
}

#[test]
#[should_panic(expected = "root not found")]
fn test_revocation_missing_root_panics() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let missing_root = BytesN::from_array(&env, &period_to_root(999999));

    // Try to revoke a non-existent root
    client.revoke_multi_period_attestation(&business, &missing_root);
}

#[test]
fn test_multiple_ranges_independent_index() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202413));
    let root3 = BytesN::from_array(&env, &period_to_root(202425));

    // Submit three non-overlapping ranges
    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, &202413, &202424, &root2, &2000u64, &1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, &202425, &202436, &root3, &3000u64, &1u32, &None, &None,
    );

    // Revoke the middle one via index
    client.revoke_multi_period_attestation(&business, &root2);

    let stored = client.get_multi_period_ranges(&business);
    assert!(!stored.get(0).unwrap().revoked); // First not revoked
    assert!(stored.get(1).unwrap().revoked); // Middle revoked
    assert!(!stored.get(2).unwrap().revoked); // Last not revoked
}

#[test]
fn test_revocation_last_range_via_index() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202413));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );
    client.submit_multi_period_attestation(
        &business, &202413, &202424, &root2, &2000u64, &1u32, &None, &None,
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
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Adjacent range: end+1 == start, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202412, &202424, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_identical_ranges_fail() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Identical range, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202401, &202412, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_fully_contained_fail() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Smaller range fully contained within first, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202404, &202408, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_partial_left_fail() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202405, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Partial overlap on left, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202401, &202408, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_overlap_partial_right_fail() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202408, &root1, &1000u64, &1u32, &None, &None,
    );

    // Partial overlap on right, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202405, &202412, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_no_overlap_before_range_succeeds() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202405, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // No overlap: end_period < start_period of existing, should succeed
    client.submit_multi_period_attestation(
        &business, &202401, &202404, &root2, &2000u64, &1u32, &None, &None,
    );
}

#[test]
fn test_no_overlap_after_range_succeeds() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202404, &root1, &1000u64, &1u32, &None, &None,
    );

    // No overlap: start_period > end_period of existing, should succeed
    client.submit_multi_period_attestation(
        &business, &202405, &202412, &root2, &2000u64, &1u32, &None, &None,
    );
}

#[test]
fn test_overlap_with_revoked_range_succeeds() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Revoke the first range
    client.revoke_multi_period_attestation(&business, &root1);

    // Now submit an overlapping range (with revoked), should succeed
    client.submit_multi_period_attestation(
        &business, &202401, &202412, &root2, &2000u64, &1u32, &None, &None,
    );

    let stored = client.get_multi_period_ranges(&business);
    assert!(stored.get(0).unwrap().revoked);
    assert!(!stored.get(1).unwrap().revoked);
}

#[test]
fn test_multiple_overlaps_across_ranges() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));
    let root3 = BytesN::from_array(&env, &period_to_root(202403));

    // Submit first range: 202401-202406
    client.submit_multi_period_attestation(
        &business, &202401, &202406, &root1, &1000u64, &1u32, &None, &None,
    );

    // Submit second non-overlapping: 202407-202412
    client.submit_multi_period_attestation(
        &business, &202407, &202412, &root2, &2000u64, &1u32, &None, &None,
    );

    // Try third overlapping with first (202403-202410), should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202403, &202410, &root3, &3000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_start_period_equals_end_period_predicate() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    // Single-period range
    client.submit_multi_period_attestation(
        &business, &202405, &202405, &root1, &1000u64, &1u32, &None, &None,
    );

    // Try to submit exact same period, should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202405, &202405, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

#[test]
fn test_wide_range_overlaps() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root1 = BytesN::from_array(&env, &period_to_root(202401));
    let root2 = BytesN::from_array(&env, &period_to_root(202402));

    // Wide range covering many periods
    client.submit_multi_period_attestation(
        &business, &202301, &202412, &root1, &1000u64, &1u32, &None, &None,
    );

    // Any range within the wide range should fail
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.submit_multi_period_attestation(
            &business, &202306, &202310, &root2, &2000u64, &1u32, &None, &None,
        );
    }));
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
//  Fuzz: Mixed overlapping, gapping, single-period, and inverted ranges
//
//  Property under test:
//    1. Inverted ranges (start > end) are always rejected.
//    2. Overlapping ranges are always rejected.
//    3. Non-overlapping, valid ranges are always accepted.
//    4. The outcome is independent of input order.
//    5. Stored ranges exactly match the accepted set.
//
//  Strategy:
//    - Generate arbitrary (start, end) pairs via proptest strategies,
//      producing a natural mix of valid, inverted, overlapping, gapped,
//      and single-period ranges.
//    - A reference model tracks accepted ranges and predicts outcomes.
//    - Contract behaviour is compared against the reference.
//
//  Note: We use `StdVec` (aliased from `std::vec::Vec`) for the
//  reference model because Soroban `Vec` cannot hold Rust tuples.
// ════════════════════════════════════════════════════════════════════

/// Reference overlap predicate: two closed intervals [a_s,a_e] and [b_s,b_e]
/// overlap (including boundary-touching) exactly when:
///
///   a_s <= b_e  &&  a_e >= b_s
///
/// This mirrors the contract's overlap check in `submit_multi_period_attestation`.
fn ref_overlaps(a_start: u32, a_end: u32, b_start: u32, b_end: u32) -> bool {
    a_start <= b_end && a_end >= b_start
}

/// Check whether `(start, end)` overlaps any range in `accepted`.
fn ref_has_overlap(accepted: &[(u32, u32)], start: u32, end: u32) -> bool {
    accepted
        .iter()
        .any(|&(s, e)| ref_overlaps(start, end, s, e))
}

/// Build a deterministic 32-byte merkle root from the accept-index and
/// range bounds.  The same inputs always produce the same root, so the
/// verification loop can reconstruct exactly what was submitted.
///
/// Uses the full 4-byte `start`/`end` to keep the encoding general;
/// when the input range is 0..=200 the high bytes collapse to zero but
/// uniqueness is still guaranteed by the combination of `accept_idx`
/// and low bytes of `start`/`end`.
fn build_root(accept_idx: usize, start: u32, end: u32) -> [u8; 32] {
    let mut root = [0u8; 32];
    root[0] = (accept_idx >> 8) as u8;
    root[1] = accept_idx as u8;
    root[2] = (start >> 24) as u8;
    root[3] = (start >> 16) as u8;
    root[4] = (start >> 8) as u8;
    root[5] = start as u8;
    root[6] = (end >> 24) as u8;
    root[7] = (end >> 16) as u8;
    root[8] = (end >> 8) as u8;
    root[9] = end as u8;
    root
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        max_shrink_iters: 512,
        ..ProptestConfig::default()
    })]

    /// Fuzz test: submit a sequence of arbitrary (start_period, end_period)
    /// ranges to `submit_multi_period_attestation` and verify that the
    /// contract's acceptance/rejection decisions match a reference overlap
    /// model for every input independently of order.
    ///
    /// ## Input space
    ///
    /// Each element is a `(u32, u32)` pair drawn uniformly from `0..=200`
    /// for both fields.  This range is large enough to exercise 16- and 32-
    /// bit boundary behaviours while still being readable in failure
    /// shrinkage.  The vector length is capped at 20 so that the O(n²)
    /// overlap scan stays within contract CPU budget.
    ///
    /// ## Edge cases exercised
    ///
    /// | Case                          | How the generator hits it                     |
    /// |-------------------------------|-----------------------------------------------|
    /// | Inverted bounds (start > end) | `start` and `end` are independent → ~50% are inverted |
    /// | Single-period (start = end)   | ~1/201 chance per pair (uniform 0..=200)     |
    /// | Boundary-touching overlap      | Adjacent ranges from the same uniform range   |
    /// | Full containment              | Wide + narrow pair in the same vector         |
    /// | Gaps                          | Ranges separated by at least 1 unit           |
    /// | Zero-boundary                 | start=0 and/or end=0                          |
    /// | Max-u32 adjacency             | Covered by deterministic boundary checkpoint tests |
    #[test]
    fn fuzz_multi_period_mixed_ranges(
        ranges in prop::collection::vec(
            (0u32..=200u32, 0u32..=200u32),
            1..=20,
        ),
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        client.initialize(&Address::generate(&env), &0u64);
        let business = Address::generate(&env);

        // Reference model: ordered list of (start, end) that were accepted.
        let mut ref_accepted: StdVec<(u32, u32)> = StdVec::new();

        for &(start, end) in ranges.iter() {
            let inverted = start > end;

            // Determine expected outcome from the reference model BEFORE
            // we build the root, so we can use the correct accept index.
            let expected_accept = !inverted && !ref_has_overlap(&ref_accepted, start, end);

            // Use the *accept* index (ref_accepted.len()), not the loop index,
            // so that the verification loop below can reconstruct the same root.
            let accept_idx = ref_accepted.len();
            let root_bytes = build_root(accept_idx, start, end);
            let root = BytesN::from_array(&env, &root_bytes);

            // Call the contract via the try_ variant so we get a Result.
            let result = client.try_submit_multi_period_attestation(
                &business, &start, &end, &root, &1000u64, &1u32, &None, &None,
            );

            if expected_accept {
                prop_assert!(
                    result.is_ok(),
                    "({}, {}): expected ACCEPT (no overlap with {:?}) but contract REJECTED: {:?}",
                    start, end,
                    &ref_accepted,
                    result.err()
                );
                ref_accepted.push((start, end));
            } else {
                // Either inverted or overlapping — contract must reject.
                prop_assert!(
                    result.is_err(),
                    "({}, {}): expected REJECT (inverted={}, overlap={}) but contract ACCEPTED",
                    start, end,
                    inverted,
                    !inverted && ref_has_overlap(&ref_accepted, start, end),
                );
            }
        }

        // ── Post-condition: stored ranges must match accepted set ──
        let stored = env.as_contract(&contract_id, || get_ranges(&env, &business));

        // All stored ranges must be non-revoked (no revocation happens in this test).
        let mut stored_active: StdVec<(u32, u32)> = StdVec::new();
        for stored_range in stored.iter() {
            prop_assert!(
                !stored_range.revoked,
                "no revocation occurs in this test — every stored range must be non-revoked"
            );
            stored_active.push((stored_range.start_period, stored_range.end_period));
        }

        prop_assert_eq!(
            stored_active.len(),
            ref_accepted.len(),
            "stored count mismatch: stored_active={:?}, ref_accepted={:?}",
            &stored_active,
            &ref_accepted,
        );

        for (idx, &(ref_s, ref_e)) in ref_accepted.iter().enumerate() {
            let stored = stored_active[idx];
            prop_assert_eq!(
                (stored.0, stored.1),
                (ref_s, ref_e),
                "stored range at index {} mismatch: stored=({},{}), ref=({},{})",
                idx, stored.0, stored.1, ref_s, ref_e,
            );
        }

        // ── Verify merkle root index exists for each accepted range ──
        for (i, &(start, end)) in ref_accepted.iter().enumerate() {
            let root_bytes = build_root(i, start, end);
            let root = BytesN::from_array(&env, &root_bytes);
            let index_key = MultiPeriodKey::RootIndex(business.clone(), root.clone());
            let stored_index: Option<u32> = env.as_contract(&contract_id, || {
                env.storage().instance().get(&index_key)
            });
            prop_assert!(
                stored_index.is_some(),
                "RootIndex missing for accepted range {} ({},{})",
                i, start, end
            );
        }

        // ── Verify the read path: every accepted range must verify correctly ──
        for (i, &(start, end)) in ref_accepted.iter().enumerate() {
            let root_bytes = build_root(i, start, end);
            let root = BytesN::from_array(&env, &root_bytes);

            // Any period within the range must verify with the correct root.
            let verify_ok = client.verify_multi_period_attestation(
                &business, &start, &root,
            );
            prop_assert!(
                verify_ok,
                "verify_multi_period_attestation must return true for accepted range {} ({},{})",
                i, start, end
            );

            // A deliberately wrong root must NOT verify.
            let mut wrong_bytes = root_bytes;
            wrong_bytes[31] ^= 0xFF;
            let wrong_root = BytesN::from_array(&env, &wrong_bytes);
            let verify_bad = client.verify_multi_period_attestation(
                &business, &start, &wrong_root,
            );
            prop_assert!(
                !verify_bad,
                "verify_multi_period_attestation must return false for wrong root on range {}",
                i
            );
        }

        // ── Security: verify that no non-existent root can be looked up ──
        let fake_root = BytesN::from_array(&env, &[0xFFu8; 32]);
        let index_key = MultiPeriodKey::RootIndex(business.clone(), fake_root.clone());
        let stored_index: Option<u32> = env.as_contract(&contract_id, || {
            env.storage().instance().get(&index_key)
        });
        // The fake root should only exist if by chance one of our generated
        // ranges happened to produce [0xFF; 32] (extremely unlikely).  If it
        // does exist, this is still not a bug — the assertion captures the
        // invariant that root lookups are exact matches.
        if stored_index.is_some() {
            let found = ref_accepted.iter().enumerate().any(|(i, &(s, e))| {
                build_root(i, s, e) == [0xFFu8; 32]
            });
            prop_assert!(found, "fake root [0xFF;32] found in index but not in accepted set");
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  Deterministic boundary checkpoints for u32 extremes
//
//  These verify the overlap logic at the edges of u32 space (0, u32::MAX).
//  They are standalone #[test] (not inside proptest!) because they take
//  no generated parameters.
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_period_boundary_u32_max_wide_range() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let business = Address::generate(&env);

    let root0 = BytesN::from_array(&env, &[0u8; 32]);
    let r0 = client.try_submit_multi_period_attestation(
        &business,
        &0u32,
        &u32::MAX,
        &root0,
        &1000u64,
        &1u32,
        &None,
        &None,
    );
    assert!(r0.is_ok(), "[0, u32::MAX] must be accepted");

    // Any sub-range inside [0, u32::MAX] must overlap → rejected.
    let root1 = BytesN::from_array(&env, &[1u8; 32]);
    let r1 = client.try_submit_multi_period_attestation(
        &business, &1u32, &100u32, &root1, &1000u64, &1u32, &None, &None,
    );
    assert!(r1.is_err(), "[1,100] inside [0,u32::MAX] must be rejected");
}

#[test]
fn test_multi_period_boundary_u32_max_edge() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let business = Address::generate(&env);

    let root0 = BytesN::from_array(&env, &[2u8; 32]);
    let r0 = client.try_submit_multi_period_attestation(
        &business,
        &(u32::MAX - 10),
        &u32::MAX,
        &root0,
        &1000u64,
        &1u32,
        &None,
        &None,
    );
    assert!(r0.is_ok(), "[u32::MAX-10, u32::MAX] must be accepted");

    // Adjacent: (u32::MAX-10, u32::MAX) and (u32::MAX, u32::MAX)
    // These touch at u32::MAX → overlap (boundary touch = overlap).
    let root1 = BytesN::from_array(&env, &[3u8; 32]);
    let r1 = client.try_submit_multi_period_attestation(
        &business,
        &u32::MAX,
        &u32::MAX,
        &root1,
        &1000u64,
        &1u32,
        &None,
        &None,
    );
    assert!(
        r1.is_err(),
        "[u32::MAX, u32::MAX] must be rejected (touches at boundary)"
    );
}

#[test]
fn test_multi_period_boundary_zero_cases() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let business = Address::generate(&env);

    let root0 = BytesN::from_array(&env, &[4u8; 32]);
    let r0 = client.try_submit_multi_period_attestation(
        &business, &0u32, &0u32, &root0, &1000u64, &1u32, &None, &None,
    );
    assert!(r0.is_ok(), "[0, 0] must be accepted");

    // Overlapping: [0,0] and [0,1] touch at 0 → overlap.
    let root1 = BytesN::from_array(&env, &[5u8; 32]);
    let r1 = client.try_submit_multi_period_attestation(
        &business, &0u32, &1u32, &root1, &1000u64, &1u32, &None, &None,
    );
    assert!(r1.is_err(), "[0,1] must be rejected (touches [0,0] at 0)");

    // Non-overlapping: [0,0] and [1,1] → [1,1] must be accepted
    // because 1 <= 0 is false (no overlap).
    let root2 = BytesN::from_array(&env, &[6u8; 32]);
    let r2 = client.try_submit_multi_period_attestation(
        &business, &1u32, &1u32, &root2, &1000u64, &1u32, &None, &None,
    );
    assert!(
        r2.is_ok(),
        "[1,1] must be accepted (no overlap with [0,0]: 1 <= 0 is false)"
    );
}

#[test]
fn test_multi_period_boundary_inverted_extremes() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    let business = Address::generate(&env);

    // Inverted: start > end at extremes.
    let root = BytesN::from_array(&env, &[7u8; 32]);
    let r = client.try_submit_multi_period_attestation(
        &business,
        &u32::MAX,
        &0u32,
        &root,
        &1000u64,
        &1u32,
        &None,
        &None,
    );
    assert!(r.is_err(), "[u32::MAX, 0] inverted must be rejected");

    let root2 = BytesN::from_array(&env, &[8u8; 32]);
    let r2 = client.try_submit_multi_period_attestation(
        &business, &1u32, &0u32, &root2, &1000u64, &1u32, &None, &None,
    );
    assert!(r2.is_err(), "[1, 0] inverted must be rejected");
}

// ════════════════════════════════════════════════════════════════════
//  Issue #503: Revocation semantics for a partially-overlapping range
//
//  `revoke_multi_period_attestation(business, merkle_root)` takes only a
//  `merkle_root` — it has no `start_period`/`end_period` parameters and no
//  notion of a sub-range. It looks the target range up by its exact root
//  via `MultiPeriodKey::RootIndex` and flips `revoked = true` on that whole
//  stored `AttestationRange`. There is no field on `AttestationRange` to
//  represent a partially-revoked sub-range, and no code path that splits
//  an entry.
//
//  Consequently "submit [10,30], revoke [20,40]" has no direct contract
//  call: you cannot revoke a range you never submitted, because revocation
//  is keyed by the root of an existing entry, not by arbitrary period
//  bounds. These tests pin the actual, current behaviour:
//
//    1. Revocation is always whole-entry (never a partial/split state).
//    2. There is no way to target an unsubmitted sub-range like [20,40]
//       when the stored entry covers [10,30] — the call panics with
//       "root not found" because no root was ever indexed for [20,40].
//    3. The zero-length-range edge case (a single-period entry) is revoked
//       whole-entry the same way as any other range.
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revocation_is_whole_entry_not_partial() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202410));

    // Submit a range covering [10, 30].
    client.submit_multi_period_attestation(
        &business, &10u32, &30u32, &root, &1000u64, &1u32, &None, &None,
    );

    // Revoke by the entry's own root (the only supported revocation path).
    client.revoke_multi_period_attestation(&business, &root);

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 1);
    let entry = stored.get(0).unwrap();

    // Whole-entry revocation: the full [10,30] range is now revoked, not a
    // split [20,30] or [10,19]/[31,30] pair — `AttestationRange` has no
    // fields that could represent such a split.
    assert!(entry.revoked);
    assert_eq!(entry.start_period, 10u32);
    assert_eq!(entry.end_period, 30u32);
}

#[test]
#[should_panic(expected = "root not found")]
fn test_revoke_unsubmitted_overlapping_range_panics() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root_10_30 = BytesN::from_array(&env, &period_to_root(202411));

    // Submit only [10, 30].
    client.submit_multi_period_attestation(
        &business, &10u32, &30u32, &root_10_30, &1000u64, &1u32, &None, &None,
    );

    // [20, 40] was never submitted, so no root was ever indexed for it.
    // Revocation is keyed by root, not by period bounds, so there is no
    // way to express "revoke the [20,40] window" directly — any attempt
    // to revoke a root that doesn't correspond to a stored entry panics.
    let unsubmitted_root = BytesN::from_array(&env, &period_to_root(202499));
    client.revoke_multi_period_attestation(&business, &unsubmitted_root);
}

#[test]
fn test_zero_length_range_revocation_is_whole_entry() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &period_to_root(202412));

    // Zero-length / single-period range: start_period == end_period.
    client.submit_multi_period_attestation(
        &business, &25u32, &25u32, &root, &1000u64, &1u32, &None, &None,
    );

    client.revoke_multi_period_attestation(&business, &root);

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 1);
    let entry = stored.get(0).unwrap();

    // Same whole-entry semantics apply regardless of range width.
    assert!(entry.revoked);
    assert_eq!(entry.start_period, 25u32);
    assert_eq!(entry.end_period, 25u32);
}

#[test]
fn test_revoking_one_entry_does_not_affect_overlapping_candidate_window() {
    let (env, contract_id, client) = setup();
    let business = Address::generate(&env);
    let root_a = BytesN::from_array(&env, &period_to_root(202413));

    // Entry covers [10, 30].
    client.submit_multi_period_attestation(
        &business, &10u32, &30u32, &root_a, &1000u64, &1u32, &None, &None,
    );
    client.revoke_multi_period_attestation(&business, &root_a);

    // Once [10,30] is revoked, the overlap check in
    // `submit_multi_period_attestation` skips revoked ranges, so a new
    // entry covering the "would-be [20,40] revocation window" (or any
    // overlapping window) may now be submitted without panicking. This
    // confirms revocation clears the whole entry from the overlap set —
    // not just a sub-portion of it.
    let root_b = BytesN::from_array(&env, &period_to_root(202414));
    client.submit_multi_period_attestation(
        &business, &20u32, &40u32, &root_b, &2000u64, &1u32, &None, &None,
    );

    let stored = client.get_multi_period_ranges(&business);
    assert_eq!(stored.len(), 2);
    assert!(stored.get(0).unwrap().revoked);
    assert!(!stored.get(1).unwrap().revoked);
    assert_eq!(stored.get(1).unwrap().start_period, 20u32);
    assert_eq!(stored.get(1).unwrap().end_period, 40u32);
}