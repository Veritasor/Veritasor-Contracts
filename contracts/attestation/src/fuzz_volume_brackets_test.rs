//! # Fuzz Test: `set_volume_brackets` Non-Monotonic Input Rejection
//!
//! ## Purpose
//!
//! Guards [`set_volume_brackets`] against non-monotonic threshold vectors and
//! out-of-bounds discounts via property-based fuzzing with [`proptest`].
//!
//! Unlike the parametric §G tests in `property_test.rs` (which use hand-picked
//! static inputs), this module generates **arbitrary-length vectors** of random
//! `u64` thresholds and `u32` discounts and checks that the contract's
//! accept/reject decision always matches a reference predicate computed in pure
//! Rust — with zero false positives.
//!
//! ## Invariants Verified
//!
//! | ID   | Invariant                                                                  |
//! |------|----------------------------------------------------------------------------|
//! | F1   | `set_volume_brackets` accepts iff thresholds are strictly ascending AND   |
//! |      | all discounts ≤ 10 000 bps AND lengths are equal                          |
//! | F2   | Any adjacent equal threshold (non-strict) causes rejection                |
//! | F3   | Any descending adjacent pair causes rejection                              |
//! | F4   | Any discount > 10 000 bps causes rejection                                |
//! | F5   | Length mismatch between thresholds and discounts causes rejection          |
//! | F6   | Empty brackets are always accepted (degenerate-valid case)                 |
//! | F7   | Single-bracket inputs are accepted iff discount ≤ 10 000 bps              |
//! | F8   | False-positive rate is zero: every accepted input is genuinely valid       |
//!
//! ## Security Notes
//!
//! - Non-monotonic thresholds could allow an attacker to craft inputs that
//!   cause `volume_discount_for_count` to return an unexpected (higher)
//!   discount by exploiting bracket ordering ambiguity.
//! - Discounts > 10 000 bps (> 100%) would allow fee underflow to zero for
//!   non-zero `base_fee`, effectively bypassing fee collection.
//! - The reference predicate is a pure-Rust mirror of the contract's
//!   validation logic; any divergence between the two indicates a bug.
//! - `catch_unwind` is used to capture panics from the contract without
//!   aborting the test process, allowing the fuzzer to continue.

#![cfg(test)]

extern crate std;

use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec as svec, Address, Env};

// ════════════════════════════════════════════════════════════════════
//  Reference predicate
//  Pure-Rust mirror of set_volume_brackets validation logic.
//  Contract accepts iff ALL of these hold:
//    1. thresholds.len() == discounts.len()
//    2. All adjacent threshold pairs are strictly ascending
//    3. All discounts are ≤ 10_000
// ════════════════════════════════════════════════════════════════════

/// Returns `true` iff the given bracket input should be accepted by the contract.
///
/// This is the reference implementation used to verify the contract's behavior.
/// It mirrors `set_volume_brackets` validation logic exactly.
fn should_accept(thresholds: &[u64], discounts: &[u32]) -> bool {
    // F5: lengths must match
    if thresholds.len() != discounts.len() {
        return false;
    }
    // F2 / F3: thresholds must be strictly ascending
    for i in 1..thresholds.len() {
        if thresholds[i] <= thresholds[i - 1] {
            return false;
        }
    }
    // F4: each discount must be ≤ 10_000 bps
    for &d in discounts {
        if d > 10_000 {
            return false;
        }
    }
    true
}

// ════════════════════════════════════════════════════════════════════
//  Env helpers
// ════════════════════════════════════════════════════════════════════

/// Call `set_volume_brackets` inside `catch_unwind`.
/// Returns `Ok(())` if the call succeeded, `Err(msg)` if it panicked.
fn try_set_brackets(thresholds: &[u64], discounts: &[u32]) -> Result<(), std::string::String> {
    let t_own: std::vec::Vec<u64> = thresholds.to_vec();
    let d_own: std::vec::Vec<u32> = discounts.to_vec();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AttestationContract, ());
        let client = AttestationContractClient::new(&env, &contract_id);
        client.initialize(&Address::generate(&env), &0u64);

        let soroban_t = {
            let mut v = svec![&env];
            for &t in &t_own {
                v.push_back(t);
            }
            v
        };
        let soroban_d = {
            let mut v = svec![&env];
            for &d in &d_own {
                v.push_back(d);
            }
            v
        };

        client.set_volume_brackets(&soroban_t, &soroban_d);
    }));

    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            let msg = if let Some(s) = err.downcast_ref::<&str>() {
                std::string::String::from(*s)
            } else if let Some(s) = err.downcast_ref::<std::string::String>() {
                s.clone()
            } else {
                std::string::String::from("(non-string panic)")
            };
            Err(msg)
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  Fuzz strategies
// ════════════════════════════════════════════════════════════════════

/// Generate a vector of up to 8 `u64` thresholds (arbitrary, not sorted).
fn arb_thresholds() -> impl Strategy<Value = std::vec::Vec<u64>> {
    prop::collection::vec(any::<u64>(), 0..=8)
}

/// Generate a vector of up to 8 `u32` discounts in full `u32` range
/// so we exercise values both inside and outside the valid 0–10_000 range.
fn arb_discounts() -> impl Strategy<Value = std::vec::Vec<u32>> {
    prop::collection::vec(any::<u32>(), 0..=8)
}

/// Generate a pair where both vectors have the same length (equal-length fuzz).
fn arb_equal_len_brackets() -> impl Strategy<Value = (std::vec::Vec<u64>, std::vec::Vec<u32>)> {
    (0usize..=8).prop_flat_map(|n| {
        (
            prop::collection::vec(any::<u64>(), n),
            prop::collection::vec(any::<u32>(), n),
        )
    })
}

/// Generate a strictly ascending threshold vector (should always be accepted
/// when paired with valid discounts, used for F8 false-positive check).
fn arb_strictly_ascending(len: usize) -> impl Strategy<Value = std::vec::Vec<u64>> {
    prop::collection::vec(1u64..=u64::MAX / 16, len).prop_map(|mut v| {
        v.sort_unstable();
        v.dedup();
        v
    })
}

// ════════════════════════════════════════════════════════════════════
//  F1 — Core accept/reject agrees with reference predicate
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F1: For any equal-length pair, the contract's accept/reject decision
    /// matches `should_accept` exactly.
    ///
    /// This is the primary correctness property: the contract must never
    /// accept what the reference rejects, and must never reject what the
    /// reference accepts.
    #[test]
    fn fuzz_accept_reject_matches_reference(
        (thresholds, discounts) in arb_equal_len_brackets(),
    ) {
        let expected = should_accept(&thresholds, &discounts);
        let actual = try_set_brackets(&thresholds, &discounts);

        match (expected, actual) {
            (true, Ok(())) => {} // both agree: valid input accepted
            (false, Err(_)) => {} // both agree: invalid input rejected
            (true, Err(msg)) => prop_assert!(
                false,
                "false negative — reference says ACCEPT but contract REJECTED: \
                 thresholds={thresholds:?} discounts={discounts:?} panic='{msg}'"
            ),
            (false, Ok(())) => prop_assert!(
                false,
                "false positive — reference says REJECT but contract ACCEPTED: \
                 thresholds={thresholds:?} discounts={discounts:?}"
            ),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  F2 / F3 — Adjacent equal or descending thresholds rejected
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F2: Any pair of adjacent equal thresholds always causes rejection.
    #[test]
    fn fuzz_adjacent_equal_thresholds_rejected(
        prefix in prop::collection::vec(1u64..1_000_000u64, 0..=4),
        dup in 1u64..1_000_000u64,
        suffix in prop::collection::vec(1u64..1_000_000u64, 0..=4),
    ) {
        // Build thresholds with a deliberate duplicate in the middle.
        let mut thresholds = prefix;
        thresholds.push(dup);
        thresholds.push(dup); // equal — violates strict ascending
        thresholds.extend(suffix);

        let len = thresholds.len();
        // All-zero discounts (valid) so the only violation is ordering.
        let discounts = std::vec![0u32; len];

        let result = try_set_brackets(&thresholds, &discounts);
        prop_assert!(
            result.is_err(),
            "adjacent equal thresholds {dup},{dup} must be rejected, got Ok"
        );
    }

    /// F3: Any descending adjacent pair always causes rejection.
    #[test]
    fn fuzz_descending_thresholds_rejected(
        lo in 1u64..1_000_000u64,
        hi in 1u64..1_000_000u64,
    ) {
        // Ensure hi > lo so the pair (hi, lo) is strictly descending.
        let (lo, hi) = if lo < hi { (lo, hi) } else { (hi + 1, lo + 2) };
        let thresholds = std::vec![hi, lo]; // descending
        let discounts = std::vec![0u32, 0u32];

        let result = try_set_brackets(&thresholds, &discounts);
        prop_assert!(
            result.is_err(),
            "descending thresholds [{hi},{lo}] must be rejected"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  F4 — Discount > 10_000 bps always rejected
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F4: Any discount exceeding 10_000 bps (100%) causes rejection,
    /// regardless of how many other brackets are present.
    #[test]
    fn fuzz_over_cap_discount_rejected(
        bad_discount in 10_001u32..=u32::MAX,
        position in 0usize..=4,
        len in 1usize..=5,
    ) {
        // Build a valid strictly ascending threshold vector.
        let thresholds: std::vec::Vec<u64> = (0..len).map(|i| (i as u64 + 1) * 100).collect();
        let pos = position.min(len - 1);

        // All valid discounts except for one slot which is out-of-range.
        let mut discounts = std::vec![500u32; len];
        discounts[pos] = bad_discount;

        let result = try_set_brackets(&thresholds, &discounts);
        prop_assert!(
            result.is_err(),
            "discount {bad_discount} bps at position {pos} must be rejected"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  F5 — Length mismatch always rejected
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F5: Mismatched lengths between thresholds and discounts always reject.
    #[test]
    fn fuzz_length_mismatch_rejected(
        t_len in 0usize..=6,
        d_len in 0usize..=6,
    ) {
        // Only run when lengths genuinely differ.
        prop_assume!(t_len != d_len);

        let thresholds: std::vec::Vec<u64> = (0..t_len).map(|i| (i as u64 + 1) * 10).collect();
        let discounts = std::vec![0u32; d_len];

        let result = try_set_brackets(&thresholds, &discounts);
        prop_assert!(
            result.is_err(),
            "length mismatch (thresholds={t_len}, discounts={d_len}) must be rejected"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  F6 — Empty brackets always accepted
// ════════════════════════════════════════════════════════════════════

#[test]
fn fuzz_empty_brackets_always_accepted() {
    let result = try_set_brackets(&[], &[]);
    assert!(result.is_ok(), "empty brackets must always be accepted");
}

// ════════════════════════════════════════════════════════════════════
//  F7 — Single bracket accepted iff discount ≤ 10_000
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F7-a: Single bracket with valid discount accepted.
    #[test]
    fn fuzz_single_bracket_valid_accepted(
        threshold in any::<u64>(),
        discount in 0u32..=10_000u32,
    ) {
        let result = try_set_brackets(&[threshold], &[discount]);
        prop_assert!(
            result.is_ok(),
            "single bracket (threshold={threshold}, discount={discount}) must be accepted"
        );
    }

    /// F7-b: Single bracket with invalid discount rejected.
    #[test]
    fn fuzz_single_bracket_invalid_discount_rejected(
        threshold in any::<u64>(),
        bad_discount in 10_001u32..=u32::MAX,
    ) {
        let result = try_set_brackets(&[threshold], &[bad_discount]);
        prop_assert!(
            result.is_err(),
            "single bracket discount {bad_discount} bps must be rejected"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  F8 — Zero false positives: every valid input is accepted
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// F8: Genuinely valid inputs (strictly ascending thresholds, all discounts
    /// ≤ 10_000) must NEVER be rejected. This verifies false-positive rate = 0.
    #[test]
    fn fuzz_valid_input_always_accepted(
        len in 0usize..=6,
        discounts_raw in prop::collection::vec(0u32..=10_000u32, 0..=6),
    ) {
        // Build a fresh strictly ascending threshold vector of the right length.
        // We use (i+1)*7 + i as a simple strictly-increasing sequence.
        let thresholds: std::vec::Vec<u64> = (0..len).map(|i| (i as u64 + 1) * 100 + i as u64).collect();
        // Truncate or pad discounts to match length.
        let mut discounts = discounts_raw;
        discounts.resize(len, 0u32);

        prop_assert!(
            should_accept(&thresholds, &discounts),
            "test precondition: input must be valid before testing contract"
        );

        let result = try_set_brackets(&thresholds, &discounts);
        prop_assert!(
            result.is_ok(),
            "false positive: valid input rejected — thresholds={thresholds:?} discounts={discounts:?}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  Deterministic edge-case regression tests
//  (complement the proptest fuzzer with known boundary inputs)
// ════════════════════════════════════════════════════════════════════

/// Adjacent equal thresholds at boundary values.
#[test]
fn fuzz_edge_adjacent_equal_u64_max() {
    let result = try_set_brackets(&[u64::MAX, u64::MAX], &[0, 0]);
    assert!(result.is_err(), "u64::MAX adjacent equal must be rejected");
}

#[test]
fn fuzz_edge_adjacent_equal_zero() {
    let result = try_set_brackets(&[0, 0], &[0, 0]);
    assert!(result.is_err(), "zero adjacent equal must be rejected");
}

/// Discount exactly at boundary.
#[test]
fn fuzz_edge_discount_exactly_10000_accepted() {
    let result = try_set_brackets(&[1], &[10_000]);
    assert!(result.is_ok(), "discount == 10_000 bps must be accepted");
}

#[test]
fn fuzz_edge_discount_10001_rejected() {
    let result = try_set_brackets(&[1], &[10_001]);
    assert!(result.is_err(), "discount == 10_001 bps must be rejected");
}

/// Three-bracket valid case sanity check.
#[test]
fn fuzz_edge_three_bracket_valid() {
    let result = try_set_brackets(&[10, 50, 100], &[500, 1_000, 2_000]);
    assert!(result.is_ok(), "three valid brackets must be accepted");
}

/// Three-bracket with middle equal — rejected.
#[test]
fn fuzz_edge_three_bracket_middle_equal_rejected() {
    let result = try_set_brackets(&[10, 50, 50], &[500, 1_000, 2_000]);
    assert!(
        result.is_err(),
        "three brackets with trailing equal must be rejected"
    );
}

/// Three-bracket with out-of-order middle — rejected.
#[test]
fn fuzz_edge_three_bracket_out_of_order_rejected() {
    let result = try_set_brackets(&[100, 50, 150], &[500, 1_000, 2_000]);
    assert!(
        result.is_err(),
        "three brackets with out-of-order middle must be rejected"
    );
}

/// Discount overflow: u32::MAX must be rejected.
#[test]
fn fuzz_edge_discount_u32_max_rejected() {
    let result = try_set_brackets(&[1], &[u32::MAX]);
    assert!(result.is_err(), "discount u32::MAX must be rejected");
}
