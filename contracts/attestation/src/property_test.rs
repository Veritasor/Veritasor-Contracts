//! # Property-Based Tests for the Attestation Contract
//!
//! ## Testing Strategy
//!
//! This module implements two complementary styles of property-based testing:
//!
//! ### 1. Pure-Arithmetic Properties (`proptest!` macros)
//!
//! The [`compute_fee`] function is a pure function with no `Env` dependency.
//! It accepts raw integer inputs and performs deterministic arithmetic, making it
//! an ideal candidate for `proptest!`. The framework generates thousands of random
//! inputs, checks each property, and automatically shrinks any failing case to its
//! minimal counterexample.
//!
//! ### 2. Parametric Contract State Properties (manual iteration)
//!
//! All other invariants require a Soroban [`Env`]. Because `Env` is neither
//! `Send` nor `Sync` nor `UnwindSafe`, proptest's cross-test-case shrinking
//! does not apply. Instead we use the **parametric** pattern: define a
//! representative input matrix covering boundary conditions, then iterate over
//! it inside a single `#[test]`, constructing a fresh `Env` per case.
//!
//! For tests that must catch panics, each `Env` is constructed **inside** the
//! `std::panic::catch_unwind` closure (since `Env` cannot be captured by an
//! `UnwindSafe` closure from the outer scope).
//!
//! ## Invariant Catalog
//!
//! | ID  | Invariant                                                                        | Section |
//! |-----|---------------------------------------------------------------------------------|---------|
//! | P1  | `0 ≤ compute_fee(b,t,v) ≤ b` for all `b ≥ 0, 0 ≤ t,v ≤ 10_000`               | §A      |
//! | P2  | `compute_fee(b,0,0) = b`                                                        | §A      |
//! | P3  | `compute_fee` is monotonically non-increasing in each discount axis             | §A      |
//! | P4  | `get_attestation` returns exactly what `submit_attestation` stored              | §B      |
//! | P5  | `get_business_count` increases by exactly 1 per `submit_attestation` call       | §B      |
//! | P6  | `verify_attestation(b,p,r) ⟺ (exists ∧ ¬revoked ∧ stored_root = r)`           | §C      |
//! | P7  | After `revoke_attestation`, `verify_attestation` returns false for **any** root | §C      |
//! | P8  | Duplicate `(business, period)` always panics "attestation already exists"       | §D      |
//! | P9  | `migrate_attestation` panics iff `new_version ≤ old_version`                   | §E      |
//! | P10 | `set_tier_discount` panics iff `discount_bps > 10_000`                         | §F      |
//! | P11 | `set_volume_brackets` panics iff lengths mismatch or thresholds not ascending   | §G      |
//! | P12 | Business A's state (count, attestation, revocation) never affects Business B's  | §H      |
//! | P13 | `submit_attestation` panics with "contract is paused" while contract is paused  | §I      |
//! | P14 | `get_fee_quote()` before submit equals actual token deduction during submit      | §J      |

extern crate std;

use super::*;
use dynamic_fees::compute_fee;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{vec, Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Shared setup helpers
//  (Mirror the patterns in test.rs and dynamic_fees_test.rs)
// ════════════════════════════════════════════════════════════════════

/// Minimal environment: no fee configuration.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, client)
}

/// Full environment: live Stellar asset token + enabled fees.
///
/// Returns `(env, client, admin, token_addr, collector)`.
#[allow(clippy::type_complexity)]
fn setup_with_fees(
    base_fee: i128,
) -> (
    Env,
    AttestationContractClient<'static>,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin);
    let token_addr = token_contract.address().clone();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    client.configure_fees(&token_addr, &collector, &base_fee, &true);
    (env, client, admin, token_addr, collector)
}

fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token_addr).mint(to, &amount);
}

fn token_balance(env: &Env, token_addr: &Address, who: &Address) -> i128 {
    TokenClient::new(env, token_addr).balance(who)
}

/// Extract a human-readable message from a `catch_unwind` error payload.
fn panic_message(err: &std::boxed::Box<dyn std::any::Any + Send>) -> std::string::String {
    if let Some(s) = err.downcast_ref::<&str>() {
        std::string::String::from(*s)
    } else if let Some(s) = err.downcast_ref::<std::string::String>() {
        s.clone()
    } else {
        std::string::String::from("(non-string panic payload)")
    }
}

// ════════════════════════════════════════════════════════════════════
//  §A — Pure arithmetic properties for compute_fee  (proptest!)
//
//  Invariant P1: 0 ≤ compute_fee(b,t,v) ≤ b  for all valid inputs
//  Invariant P2: compute_fee(b,0,0) = b
//  Invariant P3: compute_fee is non-increasing in each discount axis
//
//  `compute_fee` has no Env dependency so proptest can generate
//  inputs, check properties, and shrink failing cases automatically.
//
//  Safe overflow bound: max intermediate = 1e12 * 10_000 * 10_000 = 1e20
//  i128::MAX ≈ 1.7e38, so values up to 1 trillion are overflow-safe.
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// P1-a: Fee is always non-negative.
    ///
    /// Both discount factors are ≥ 0, so the product is ≥ 0,
    /// and `base_fee ≥ 0` ensures the overall result is ≥ 0.
    #[test]
    fn prop_fee_is_non_negative(
        base in 0i128..=1_000_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        prop_assert!(compute_fee(base, tier, vol) >= 0);
    }

    /// P1-b: Fee never exceeds the base fee.
    ///
    /// Both discount factors are ≤ 1 (i.e. ≤ 10_000/10_000),
    /// so their product is also ≤ 1, meaning fee ≤ base.
    #[test]
    fn prop_fee_never_exceeds_base(
        base in 0i128..=1_000_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        prop_assert!(compute_fee(base, tier, vol) <= base);
    }

    /// P2: Zero discounts leave the fee unchanged.
    ///
    /// `base * 10_000 * 10_000 / 100_000_000 = base * 1 = base`
    #[test]
    fn prop_fee_no_discounts_equals_base(base in 0i128..=1_000_000_000i128) {
        prop_assert_eq!(compute_fee(base, 0, 0), base);
    }

    /// P2-a: Full tier discount (10 000 bps = 100 %) makes fee zero.
    #[test]
    fn prop_full_tier_discount_is_free(
        base in 0i128..=1_000_000_000i128,
        vol  in 0u32..=10_000u32,
    ) {
        prop_assert_eq!(compute_fee(base, 10_000, vol), 0);
    }

    /// P2-b: Full volume discount (10 000 bps = 100 %) makes fee zero.
    #[test]
    fn prop_full_volume_discount_is_free(
        base in 0i128..=1_000_000_000i128,
        tier in 0u32..=10_000u32,
    ) {
        prop_assert_eq!(compute_fee(base, tier, 10_000), 0);
    }

    /// P2-c: Zero base always yields zero fee regardless of discounts.
    #[test]
    fn prop_zero_base_always_zero(
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        prop_assert_eq!(compute_fee(0, tier, vol), 0);
    }

    /// P3-a: Increasing tier discount never increases the fee.
    ///
    /// The tier factor `(10_000 - tier_bps)` is a decreasing function
    /// of `tier_bps`, so a larger tier discount always produces a
    /// fee that is ≤ the fee at the lower discount.
    #[test]
    fn prop_fee_non_increasing_with_tier_discount(
        base  in 1i128..=1_000_000_000i128,
        vol   in 0u32..=10_000u32,
        tier1 in 0u32..10_000u32,
        extra in 1u32..=100u32,
    ) {
        let tier2 = (tier1 + extra).min(10_000);
        let fee1 = compute_fee(base, tier1, vol);
        let fee2 = compute_fee(base, tier2, vol);
        prop_assert!(
            fee2 <= fee1,
            "fee with higher tier discount ({tier2} bps) must be ≤ fee at lower discount ({tier1} bps): {fee2} vs {fee1}"
        );
    }

    /// P3-b: Increasing volume discount never increases the fee.
    #[test]
    fn prop_fee_non_increasing_with_volume_discount(
        base  in 1i128..=1_000_000_000i128,
        tier  in 0u32..=10_000u32,
        vol1  in 0u32..10_000u32,
        extra in 1u32..=100u32,
    ) {
        let vol2 = (vol1 + extra).min(10_000);
        let fee1 = compute_fee(base, tier, vol1);
        let fee2 = compute_fee(base, tier, vol2);
        prop_assert!(
            fee2 <= fee1,
            "fee with higher volume discount ({vol2} bps) must be ≤ fee at lower discount ({vol1} bps): {fee2} vs {fee1}"
        );
    }

    /// Overflow safety: large but realistic inputs do not overflow i128.
    ///
    /// Maximum intermediate: 1_000_000_000_000 * 10_000 * 10_000 = 1e20
    /// i128::MAX ≈ 1.7e38, so this is well within range.
    #[test]
    fn prop_fee_no_overflow(
        base in 0i128..=1_000_000_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        // Must not panic (overflow would cause a panic in debug or abort in release).
        let _ = compute_fee(base, tier, vol);
    }
}

// ════════════════════════════════════════════════════════════════════
//  §B — Data integrity and counter monotonicity  (parametric)
//
//  Invariant P4: get_attestation returns exactly submitted values
//  Invariant P5: get_business_count increments by exactly 1 per submit
//
//  Each row in DATA_INTEGRITY_CASES gets a fresh Env to prevent
//  any cross-case state leakage.
// ════════════════════════════════════════════════════════════════════

/// Helper to build the alternating-byte root constant (0x55/0xAA pattern).
const fn alternating_root() -> [u8; 32] {
    let mut b = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        b[i] = if i % 2 == 0 { 0x55 } else { 0xAA };
        i += 1;
    }
    b
}

/// Test matrix: (root_bytes, period_str, timestamp, version)
///
/// Edge cases covered:
///
/// | Category     | Values tested                                             |
/// |-------------|-----------------------------------------------------------|
/// | Root        | all-zero, all-0xFF, all-0x01, alternating 0x55/0xAA, 0x7F |
/// | Period      | ISO date, quarter, single char, long string, pure numeric |
/// | Timestamp   | 0, 1, realistic epoch, u64::MAX/2                        |
/// | Version     | 0, 1, u32::MAX                                           |
const DATA_INTEGRITY_CASES: &[([u8; 32], &str, u64, u32)] = &[
    ([0u8; 32], "2026-01", 1_700_000_000, 1),
    ([255u8; 32], "2025-Q4", 0, 0),
    ([1u8; 32], "2020-06", 1, u32::MAX),
    ([127u8; 32], "X", u64::MAX / 2, 42),
    (
        [128u8; 32],
        "long-period-aaabbbcccdddeee000111222",
        999,
        100,
    ),
    (alternating_root(), "Q3-2025", 1_000_000, 5),
    ([42u8; 32], "20261231", u64::MAX, 1),
    ([0u8; 32], "period-with-hyphens-and-123456789", 12345, 0),
];

/// P4 + P5: submit, then verify retrieved data matches exactly and
/// the counter incremented correctly.
#[test]
fn prop_data_integrity_and_counter_monotonicity() {
    for (idx, &(root_bytes, period_str, timestamp, version)) in
        DATA_INTEGRITY_CASES.iter().enumerate()
    {
        // Fresh Env per case — no cross-case state.
        let (env, client) = setup();
        let business = Address::generate(&env);
        let period = String::from_str(&env, period_str);
        let root = BytesN::from_array(&env, &root_bytes);

        // P5 precondition: fresh business starts at count 0.
        assert_eq!(
            client.get_business_count(&business),
            0,
            "case {idx} [{period_str}]: initial count must be 0"
        );

        client.submit_attestation(
            &business, &period, &root, &timestamp, &version, &0i128, &None, &None,
        );

        // P4: Every field must round-trip exactly.
        let (got_root, got_ts, got_ver, got_fee, _, _) = client
            .get_attestation(&business, &period)
            .unwrap_or_else(|| {
                panic!("case {idx} [{period_str}]: attestation must exist after submit")
            });

        assert_eq!(got_root, root, "case {idx} [{period_str}]: root mismatch");
        assert_eq!(
            got_ts, timestamp,
            "case {idx} [{period_str}]: timestamp mismatch"
        );
        assert_eq!(
            got_ver, version,
            "case {idx} [{period_str}]: version mismatch"
        );
        assert_eq!(
            got_fee, 0i128,
            "case {idx} [{period_str}]: fee_paid must be 0 (no fees configured)"
        );

        // P5: Count after first submit is exactly 1.
        assert_eq!(
            client.get_business_count(&business),
            1,
            "case {idx} [{period_str}]: count after first submit must be 1"
        );

        // P5 continued: second submit (different period) increments to 2.
        let period2 = String::from_str(&env, &std::format!("{period_str}-v2"));
        client.submit_attestation(
            &business, &period2, &root, &timestamp, &version, &0i128, &None, &None,
        );
        assert_eq!(
            client.get_business_count(&business),
            2,
            "case {idx} [{period_str}]: count after second submit must be 2"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §C — verify_attestation consistency and revocation permanence
//
//  Invariant P6: verify(b,p,r) ⟺ (exists ∧ ¬revoked ∧ stored_root = r)
//  Invariant P7: once revoked, verify returns false for any root
// ════════════════════════════════════════════════════════════════════

/// (submitted_root, wrong_root_a, wrong_root_b)
const VERIFY_CASES: &[([u8; 32], [u8; 32], [u8; 32])] = &[
    ([1u8; 32], [2u8; 32], [0u8; 32]),
    ([255u8; 32], [254u8; 32], [128u8; 32]),
    ([0u8; 32], [1u8; 32], [255u8; 32]),
    ([42u8; 32], [43u8; 32], [41u8; 32]),
];

/// P6: verify returns true only for the exact submitted root.
#[test]
fn prop_verify_consistency() {
    for (idx, &(sub_bytes, wrong_a, wrong_b)) in VERIFY_CASES.iter().enumerate() {
        let (env, client) = setup();
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-01");
        let submitted_root = BytesN::from_array(&env, &sub_bytes);
        let wrong_root_a = BytesN::from_array(&env, &wrong_a);
        let wrong_root_b = BytesN::from_array(&env, &wrong_b);

        // Before submit: verify must return false for any root.
        assert!(
            !client.verify_attestation(&business, &period, &submitted_root),
            "case {idx}: verify before submit must be false"
        );
        assert!(
            !client.verify_attestation(&business, &period, &wrong_root_a),
            "case {idx}: verify before submit with wrong root must be false"
        );

        client.submit_attestation(
            &business,
            &period,
            &submitted_root,
            &1_700_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );

        // After submit: correct root → true, wrong roots → false.
        assert!(
            client.verify_attestation(&business, &period, &submitted_root),
            "case {idx}: verify with correct root must be true"
        );
        assert!(
            !client.verify_attestation(&business, &period, &wrong_root_a),
            "case {idx}: verify with wrong root A must be false"
        );
        assert!(
            !client.verify_attestation(&business, &period, &wrong_root_b),
            "case {idx}: verify with wrong root B must be false"
        );

        // is_revoked must be false before any revoke call.
        assert!(
            !client.is_revoked(&business, &period),
            "case {idx}: must not be revoked before revoke call"
        );
    }
}

/// All roots to cross-test against after revocation.
const REVOKE_ROOTS: &[[u8; 32]] = &[
    [0u8; 32],
    [1u8; 32],
    [42u8; 32],
    [128u8; 32],
    [254u8; 32],
    [255u8; 32],
];

/// P7: After revocation, verify always returns false for every possible root.
#[test]
fn prop_revocation_permanence() {
    for (idx, &sub_bytes) in REVOKE_ROOTS.iter().enumerate() {
        let (env, client) = setup();
        let admin = client.get_admin();
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-01");
        let submitted_root = BytesN::from_array(&env, &sub_bytes);

        client.submit_attestation(
            &business,
            &period,
            &submitted_root,
            &1_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );

        // Sanity: verifies before revocation.
        assert!(
            client.verify_attestation(&business, &period, &submitted_root),
            "case {idx}: must verify before revocation"
        );

        let reason = String::from_str(&env, "property-test revocation");
        client.revoke_attestation(&admin, &business, &period, &reason, &0u64);

        // P7: No root whatsoever verifies after revocation.
        for &test_bytes in REVOKE_ROOTS {
            let test_root = BytesN::from_array(&env, &test_bytes);
            assert!(
                !client.verify_attestation(&business, &period, &test_root),
                "case {idx}: verify must return false for any root after revocation"
            );
        }

        assert!(
            client.is_revoked(&business, &period),
            "case {idx}: is_revoked must be true after revoke"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §D — Uniqueness: duplicate (business, period) always panics
//
//  Invariant P8: ∀ (business, period), submitting twice always panics
//                with "attestation already exists"
//
//  Env is not UnwindSafe, so each test case must construct its own
//  Env inside the catch_unwind closure.
// ════════════════════════════════════════════════════════════════════

const DUPLICATE_PERIOD_CASES: &[&str] = &[
    "2026-01",
    "2025-Q4",
    "SINGLE",
    "X",
    "period-that-is-quite-long-0000000000000000000",
    "20260101",
];

/// P8: Duplicate submission always panics with the expected message.
#[test]
fn prop_duplicate_attestation_panics() {
    for period_str in DUPLICATE_PERIOD_CASES {
        let period_owned = std::string::String::from(*period_str);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Env is created inside the closure — it is not UnwindSafe
            // and cannot be safely captured from the outer scope.
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env), &0u64);
            let business = Address::generate(&env);
            let period = String::from_str(&env, &period_owned);
            let root = BytesN::from_array(&env, &[1u8; 32]);
            client.submit_attestation(
                &business, &period, &root, &1_000_000, &1, &0i128, &None, &None,
            );
            // Second call for the same (business, period) must panic.
            client.submit_attestation(
                &business, &period, &root, &2_000_000, &2, &0i128, &None, &None,
            );
        }));

        let err = result.expect_err(&std::format!(
            "period '{period_str}': duplicate submission must panic"
        ));
        let msg = panic_message(&err);
        assert!(
            msg.contains("attestation already exists"),
            "period '{period_str}': panic message '{msg}' does not contain expected text"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §E — Migration version ordering
//
//  Invariant P9: migrate panics iff new_version <= old_version
// ════════════════════════════════════════════════════════════════════

/// (old_version, new_version) — all must succeed.
const MIGRATION_VALID_PAIRS: &[(u32, u32)] = &[
    (0, 1),
    (1, 2),
    (0, u32::MAX),
    (1, u32::MAX),
    (u32::MAX - 1, u32::MAX),
    (100, 101),
    (0, 1_000_000),
];

/// P9-a: Migration with a strictly greater version always succeeds.
#[test]
fn prop_migration_succeeds_for_increasing_version() {
    for &(old_ver, new_ver) in MIGRATION_VALID_PAIRS {
        let (env, client) = setup();
        let admin = client.get_admin();
        let business = Address::generate(&env);
        let period = String::from_str(&env, "2026-01");
        let old_root = BytesN::from_array(&env, &[1u8; 32]);
        let new_root = BytesN::from_array(&env, &[2u8; 32]);

        client.submit_attestation(
            &business, &period, &old_root, &1_000_000, &old_ver, &0i128, &None, &None,
        );
        client.migrate_attestation(&admin, &business, &period, &new_root, &new_ver);

        let (got_root, _, got_ver, _, _, _) = client.get_attestation(&business, &period).unwrap();
        assert_eq!(
            got_root, new_root,
            "old={old_ver}, new={new_ver}: root must be updated"
        );
        assert_eq!(
            got_ver, new_ver,
            "old={old_ver}, new={new_ver}: version must be updated"
        );
    }
}

/// (old_version, attempted_new_version) — all must panic.
const MIGRATION_INVALID_PAIRS: &[(u32, u32)] = &[
    (1, 1),               // equal
    (2, 1),               // decreasing
    (u32::MAX, u32::MAX), // equal at maximum
    (100, 50),            // large decrease
    (1, 0),               // decrease to zero
];

/// P9-b: Migration panics when new_version <= old_version.
#[test]
fn prop_migration_panics_for_non_increasing_version() {
    for &(old_ver, bad_new_ver) in MIGRATION_INVALID_PAIRS {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            let admin_addr = Address::generate(&env);
            client.initialize(&admin_addr, &0u64);
            let business = Address::generate(&env);
            let period = String::from_str(&env, "2026-01");
            let old_root = BytesN::from_array(&env, &[1u8; 32]);
            let new_root = BytesN::from_array(&env, &[2u8; 32]);
            client.submit_attestation(
                &business, &period, &old_root, &1_000_000, &old_ver, &0i128, &None, &None,
            );
            client.migrate_attestation(&admin_addr, &business, &period, &new_root, &bad_new_ver);
        }));

        let err = result.expect_err(&std::format!(
            "migrate old={old_ver}, new={bad_new_ver} must panic"
        ));
        let msg = panic_message(&err);
        assert!(
            msg.contains("new version must be greater than old version"),
            "old={old_ver}, new={bad_new_ver}: panic '{msg}' does not contain expected text"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §F — Tier discount bounds enforcement
//
//  Invariant P10: set_tier_discount panics iff discount_bps > 10_000
// ════════════════════════════════════════════════════════════════════

/// P10-a: All values in [0, 10_000] must be accepted without panic.
#[test]
fn prop_tier_discount_valid_range_succeeds() {
    let valid: &[u32] = &[0, 1, 100, 1_000, 5_000, 9_999, 10_000];
    for &discount in valid {
        let (_env, client) = setup();
        // Must not panic.
        client.set_tier_discount(&0u32, &discount);
    }
}

/// P10-b: Values > 10_000 must always panic.
#[test]
fn prop_tier_discount_over_bound_panics() {
    let invalid: &[u32] = &[10_001, 10_002, 20_000, u32::MAX / 2, u32::MAX];
    for &discount in invalid {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env), &0u64);
            client.set_tier_discount(&0u32, &discount);
        }));

        let err = result.expect_err(&std::format!("set_tier_discount({discount}) must panic"));
        let msg = panic_message(&err);
        assert!(
            msg.contains("discount cannot exceed 10 000 bps"),
            "discount={discount}: panic '{msg}' does not contain expected text"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §G — Volume bracket ordering and length validation
//
//  Invariant P11: set_volume_brackets panics iff lengths mismatch
//                 or thresholds not strictly ascending
//                 or any discount > 10_000
// ════════════════════════════════════════════════════════════════════

/// P11-a: Valid bracket configurations must succeed.
#[test]
fn prop_volume_brackets_valid_configs() {
    // (thresholds_slice, discounts_slice)
    let valid_configs: &[(&[u64], &[u32])] = &[
        (&[], &[]),                             // empty — valid
        (&[1], &[500]),                         // single bracket
        (&[1, 2], &[500, 1_000]),               // minimal two-bracket
        (&[10, 50, 100], &[500, 1_000, 2_000]), // typical three-bracket
        (&[1, 2, u64::MAX], &[0, 0, 10_000]),   // max-u64 threshold
    ];

    for (idx, &(thresholds, discounts)) in valid_configs.iter().enumerate() {
        let (env, client) = setup();
        let soroban_t = {
            let mut v = vec![&env];
            for &t in thresholds {
                v.push_back(t);
            }
            v
        };
        let soroban_d = {
            let mut v = vec![&env];
            for &d in discounts {
                v.push_back(d);
            }
            v
        };
        // Must not panic.
        client.set_volume_brackets(&soroban_t, &soroban_d);
        let _ = idx; // suppress unused warning
    }
}

/// P11-b: Non-strictly-ascending thresholds must panic.
#[test]
fn prop_volume_brackets_unordered_panics() {
    let invalid: &[&[u64]] = &[
        &[10, 5],        // descending
        &[10, 10],       // equal (not *strictly* ascending)
        &[1, 2, 2],      // trailing equal
        &[100, 50, 150], // middle out-of-order
    ];

    for thresholds in invalid {
        let t_clone: std::vec::Vec<u64> = thresholds.to_vec();
        let discounts: std::vec::Vec<u32> = std::vec![0u32; thresholds.len()];

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env), &0u64);
            let soroban_t = {
                let mut v = vec![&env];
                for &t in &t_clone {
                    v.push_back(t);
                }
                v
            };
            let soroban_d = {
                let mut v = vec![&env];
                for &d in &discounts {
                    v.push_back(d);
                }
                v
            };
            client.set_volume_brackets(&soroban_t, &soroban_d);
        }));

        result.expect_err(&std::format!(
            "set_volume_brackets with unordered thresholds {:?} must panic",
            thresholds
        ));
    }
}

/// P11-c: Mismatched lengths must panic.
#[test]
fn prop_volume_brackets_length_mismatch_panics() {
    let mismatched: &[(&[u64], &[u32])] = &[
        (&[10, 20], &[500]),    // 2 thresholds, 1 discount
        (&[10], &[500, 1_000]), // 1 threshold, 2 discounts
        (&[], &[500]),          // empty thresholds, 1 discount
    ];

    for &(thresholds, discounts) in mismatched {
        let t_clone: std::vec::Vec<u64> = thresholds.to_vec();
        let d_clone: std::vec::Vec<u32> = discounts.to_vec();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env), &0u64);
            let soroban_t = {
                let mut v = vec![&env];
                for &t in &t_clone {
                    v.push_back(t);
                }
                v
            };
            let soroban_d = {
                let mut v = vec![&env];
                for &d in &d_clone {
                    v.push_back(d);
                }
                v
            };
            client.set_volume_brackets(&soroban_t, &soroban_d);
        }));

        result.expect_err(&std::format!(
            "mismatched lengths thresholds={:?} discounts={:?} must panic",
            thresholds,
            discounts
        ));
    }
}

// ════════════════════════════════════════════════════════════════════
//  §H — Business state isolation
//
//  Invariant P12: Attestations, revocations, and counts for
//  business A must never affect business B or C.
// ════════════════════════════════════════════════════════════════════

/// P12: Three businesses share one Env; their state is fully independent.
#[test]
fn prop_business_isolation() {
    let (env, client) = setup();
    let biz_a = Address::generate(&env);
    let biz_b = Address::generate(&env);
    let biz_c = Address::generate(&env); // never submits

    let period = String::from_str(&env, "2026-01");
    let root_a = BytesN::from_array(&env, &[1u8; 32]);
    let root_b = BytesN::from_array(&env, &[2u8; 32]);

    client.submit_attestation(&biz_a, &period, &root_a, &1_000, &1, &0i128, &None, &None);
    client.submit_attestation(&biz_b, &period, &root_b, &2_000, &2, &0i128, &None, &None);

    // biz_c has no attestation.
    assert!(
        client.get_attestation(&biz_c, &period).is_none(),
        "biz_c must not have an attestation"
    );
    assert_eq!(
        client.get_business_count(&biz_c),
        0,
        "biz_c count must be 0"
    );
    assert!(
        !client.verify_attestation(&biz_c, &period, &root_a),
        "verify for biz_c must be false"
    );

    // biz_a and biz_b have independent data.
    let (a_root, _, a_ver, _, _, _) = client.get_attestation(&biz_a, &period).unwrap();
    let (b_root, _, b_ver, _, _, _) = client.get_attestation(&biz_b, &period).unwrap();
    assert_eq!(a_root, root_a, "biz_a root must match what was submitted");
    assert_eq!(b_root, root_b, "biz_b root must match what was submitted");
    assert_ne!(a_ver, b_ver, "versions were different and must differ");

    // Cross-verify: biz_b's root does not verify against biz_a's key.
    assert!(!client.verify_attestation(&biz_a, &period, &root_b));
    assert!(!client.verify_attestation(&biz_b, &period, &root_a));

    // Revoke biz_a only.
    let admin = client.get_admin();
    let reason = String::from_str(&env, "isolation-test");
    client.revoke_attestation(&admin, &biz_a, &period, &reason, &0u64);

    // Revocation of biz_a must not affect biz_b.
    assert!(client.is_revoked(&biz_a, &period), "biz_a must be revoked");
    assert!(
        !client.is_revoked(&biz_b, &period),
        "biz_b must NOT be revoked"
    );
    assert!(
        !client.verify_attestation(&biz_a, &period, &root_a),
        "biz_a verify must be false after revocation"
    );
    assert!(
        client.verify_attestation(&biz_b, &period, &root_b),
        "biz_b verify must still be true"
    );

    // Counts are independent.
    assert_eq!(client.get_business_count(&biz_a), 1);
    assert_eq!(client.get_business_count(&biz_b), 1);
    assert_eq!(client.get_business_count(&biz_c), 0);
}

// ════════════════════════════════════════════════════════════════════
//  §I — Pause state invariant
//
//  Invariant P13: Submissions always panic with "contract is paused"
//                 while the contract is paused.
//  Corollary: After unpause, submissions succeed normally.
// ════════════════════════════════════════════════════════════════════

const PAUSE_PERIOD_CASES: &[&str] = &["2026-01", "2025-12", "ANYTIME"];

/// P13: Every submission panics while paused, for any period string.
#[test]
fn prop_pause_blocks_all_submissions() {
    for period_str in PAUSE_PERIOD_CASES {
        let period_owned = std::string::String::from(*period_str);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            let admin = Address::generate(&env);
            client.initialize(&admin, &0u64);
            client.pause(&client.get_admin());
            let business = Address::generate(&env);
            let period = String::from_str(&env, &period_owned);
            let root = BytesN::from_array(&env, &[1u8; 32]);
            client.submit_attestation(&business, &period, &root, &1_000, &1, &0i128, &None, &None);
        }));

        let err = result.expect_err(&std::format!(
            "period '{period_str}': submit while paused must panic"
        ));
        let msg = panic_message(&err);
        assert!(
            msg.contains("contract is paused"),
            "period '{period_str}': panic '{msg}' does not contain expected text"
        );
    }
}

/// Corollary to P13: unpause restores normal submission behavior.
#[test]
fn prop_unpause_restores_submission() {
    let (env, client) = setup();
    let admin = client.get_admin();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.pause(&client.get_admin());
    client.unpause(&client.get_admin());

    // Must succeed after unpause.
    client.submit_attestation(&business, &period, &root, &1_000, &1, &0i128, &None, &None);
    assert!(
        client.get_attestation(&business, &period).is_some(),
        "attestation must exist after unpause + submit"
    );
}

// ════════════════════════════════════════════════════════════════════
//  §J — Fee quote matches actual token deduction
//
//  Invariant P14: get_fee_quote() before submit == actual token deduction
//
//  Tests the full round-trip: calculated quote → on-chain token transfer
//  → balance delta matches quote → stored fee_paid field also matches.
// ════════════════════════════════════════════════════════════════════

/// (base_fee, tier_discount_bps, volume_threshold, volume_discount_bps)
///
/// volume_threshold is the number of "warm-up" submissions to make before
/// the test submission, so the volume discount bracket is active.
const FEE_QUOTE_CASES: &[(i128, u32, u64, u32)] = &[
    (1_000_000, 0, 0, 0),         // flat fee, no discounts
    (1_000_000, 2_000, 0, 0),     // tier discount only
    (1_000_000, 0, 5, 500),       // volume discount only
    (1_000_000, 2_000, 5, 1_000), // combined tier + volume
    (500_000, 1_000, 3, 500),     // different base fee
    (100_000, 5_000, 10, 2_000),  // high tier discount
    (0, 0, 0, 0),                 // zero base fee → fee must be 0
];

/// P14: `get_fee_quote` before submission equals actual token deduction.
#[test]
fn prop_fee_quote_matches_actual_charge() {
    for &(base_fee, tier_disc, vol_threshold, vol_disc) in FEE_QUOTE_CASES {
        let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);
        let business = Address::generate(&env);

        // Configure tier discount.
        if tier_disc > 0 {
            client.set_tier_discount(&1u32, &tier_disc);
            client.set_business_tier(&business, &1u32);
        }

        // Configure volume discount bracket.
        if vol_threshold > 0 {
            let thresholds = vec![&env, vol_threshold];
            let discounts = vec![&env, vol_disc];
            client.set_volume_brackets(&thresholds, &discounts);
        }

        // Fund the business: 10× the maximum possible fee to avoid insufficiency.
        let budget = (base_fee * 100).max(1_000_000);
        mint(&env, &token_addr, &business, budget);

        // Submit warm-up attestations to cross the volume threshold.
        // Each uses a unique period so there's no duplicate-submission panic.
        for i in 0..vol_threshold {
            let warm_period = String::from_str(&env, &std::format!("WARM-{i:05}"));
            let warm_root = BytesN::from_array(&env, &[i as u8; 32]);
            client.submit_attestation(
                &business,
                &warm_period,
                &warm_root,
                &1,
                &1,
                &0i128,
                &None,
                &None,
            );
        }

        // Capture quote and balance immediately before the test submission.
        let quote = client.get_fee_quote(&business);
        let before = token_balance(&env, &token_addr, &business);

        let test_period = String::from_str(&env, "TEST-FINAL");
        let test_root = BytesN::from_array(&env, &[99u8; 32]);
        client.submit_attestation(
            &business,
            &test_period,
            &test_root,
            &1_000_000,
            &1,
            &0i128,
            &None,
            &None,
        );

        let after = token_balance(&env, &token_addr, &business);
        let charged = before - after;

        // P14-a: Quote matches balance deduction.
        assert_eq!(
            charged, quote,
            "base={base_fee}, tier={tier_disc}, vol_thr={vol_threshold}: charged={charged} != quote={quote}"
        );

        // P14-b: fee_paid field in the stored attestation record also matches.
        let (_, _, _, fee_in_record, _, _) =
            client.get_attestation(&business, &test_period).unwrap();
        assert_eq!(
            fee_in_record, quote,
            "stored fee_paid must equal the pre-submit quote"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §K — Fee Monotonicity: Pure Arithmetic Proptest Extensions
//
//  Invariant P15: compute_fee is monotonically non-decreasing in base_fee
//                 (higher base always produces higher-or-equal fee)
//  Invariant P16: Multiplicative decomposition:
//                 compute_fee(b, t, v) ≈ compute_fee(b, t, 0)
//                 × (10_000 − v) / 10_000  (within ±1 integer truncation)
//  Invariant P17: Discount combination is commutative:
//                 compute_fee(b, t, v) = compute_fee(b, v, t)
//  Invariant P18: Additive approximation over-discounts vs. multiplicative:
//                 compute_fee(b, t+v, 0) ≤ compute_fee(b, t, v) for t+v ≤ 10_000
//  Invariant P19: Strict monotonicity in base_fee when discounts are partial
//  Invariant P20: Fee additivity across independent businesses (no cross-state)
//
//  Security note: These invariants protect against fee model manipulation
//  via discount ordering or base-fee inflation attacks.
// ════════════════════════════════════════════════════════════════════

proptest! {
    /// P15: Higher base fee produces a fee that is ≥ the fee for a lower base,
    /// with all discount parameters held constant.
    ///
    /// This ensures fee is monotonically non-decreasing in `base_fee`,
    /// which is essential for protocol revenue predictability.
    #[test]
    fn prop_fee_monotone_in_base(
        base1 in 0i128..=500_000_000i128,
        extra in 0i128..=500_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        let base2 = base1 + extra;
        let fee1 = compute_fee(base1, tier, vol);
        let fee2 = compute_fee(base2, tier, vol);
        prop_assert!(
            fee2 >= fee1,
            "fee(base2={base2}) must be ≥ fee(base1={base1}) at tier={tier}, vol={vol}: {fee2} < {fee1}"
        );
    }

    /// P16: Multiplicative decomposition holds to within ±1 integer truncation.
    ///
    /// The fee formula decomposes as:
    ///   compute_fee(b, t, v) ≈ compute_fee(b, t, 0) × (10_000 − v) / 10_000
    ///
    /// The absolute difference must be at most 1 (integer division truncation).
    #[test]
    fn prop_fee_multiplicative_decomposition(
        base in 1i128..=1_000_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        let combined  = compute_fee(base, tier, vol);
        let tier_only = compute_fee(base, tier, 0);
        let vol_factor = 10_000i128 - vol as i128;
        let reconstructed = tier_only * vol_factor / 10_000i128;
        let diff = (combined - reconstructed).abs();
        prop_assert!(
            diff <= 1,
            "decomposition error={} (combined={}, reconstructed={}) \
             for base={}, tier={}, vol={}",
            diff, combined, reconstructed, base, tier, vol
        );
    }

    /// P17: The fee formula is symmetric in tier and volume discount axes.
    ///
    /// Because (10_000 − t) × (10_000 − v) = (10_000 − v) × (10_000 − t),
    /// swapping tier_bps and vol_bps must yield the same fee.
    #[test]
    fn prop_fee_discount_axis_symmetry(
        base in 0i128..=1_000_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
    ) {
        let fee_tv = compute_fee(base, tier, vol);
        let fee_vt = compute_fee(base, vol, tier);
        prop_assert_eq!(
            fee_tv, fee_vt,
            "discount axis symmetry failed for base={}, tier={}, vol={}: {} ≠ {}",
            base, tier, vol, fee_tv, fee_vt
        );
    }

    /// P18: Multiplicative compounding preserves more revenue than additive.
    ///
    /// Applying t and v bps independently (multiplicative) always produces
    /// a fee ≥ applying (t + v) bps as a single discount (additive).
    /// This formally captures the key economic property from the docs.
    ///
    ///   compute_fee(b, t+v, 0) ≤ compute_fee(b, t, v)  when t+v ≤ 10_000
    #[test]
    fn prop_additive_over_discounts_vs_multiplicative(
        base  in 1i128..=1_000_000_000i128,
        tier  in 0u32..5_000u32,
        vol   in 0u32..5_000u32,
    ) {
        let combined_bps = tier + vol;
        let fee_additive       = compute_fee(base, combined_bps, 0);
        let fee_multiplicative = compute_fee(base, tier, vol);
        prop_assert!(
            fee_multiplicative >= fee_additive,
            "multiplicative={} must be ≥ additive={} \
             for base={}, tier={}, vol={}",
            fee_multiplicative, fee_additive, base, tier, vol
        );
    }

    /// P19: A positive base increment always produces a non-decreasing fee.
    #[test]
    fn prop_fee_non_decreasing_in_base_with_increment(
        base  in 0i128..=999_999_999i128,
        tier  in 0u32..=10_000u32,
        vol   in 0u32..=10_000u32,
        extra in 1i128..=100_000i128,
    ) {
        let base2 = base + extra;
        let fee1 = compute_fee(base, tier, vol);
        let fee2 = compute_fee(base2, tier, vol);
        prop_assert!(
            fee2 >= fee1,
            "fee must be non-decreasing for base={}→{}, tier={}, vol={}: {} < {}",
            base, base2, tier, vol, fee2, fee1
        );
    }

    /// P20: N calls to compute_fee with identical parameters always sum to N × single_fee.
    ///
    /// Validates pure-function referential transparency and statelessness.
    #[test]
    fn prop_fee_pure_function_referential_transparency(
        base in 0i128..=100_000_000i128,
        tier in 0u32..=10_000u32,
        vol  in 0u32..=10_000u32,
        n    in 1usize..=10usize,
    ) {
        let per_fee = compute_fee(base, tier, vol);
        let repeated: i128 = (0..n).map(|_| compute_fee(base, tier, vol)).sum();
        prop_assert_eq!(
            repeated, per_fee * n as i128,
            "sum of {} identical fee calls must equal {}×per_fee={}: got {}",
            n, n, per_fee, repeated
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §L — End-to-End Fee Monotonicity via Contract State  (parametric)
//
//  Invariant P21: The effective fee quoted by the contract never increases
//                 as the business's tier discount increases (admin-assigned).
//  Invariant P22: The effective fee never increases as the business's
//                 cumulative attestation count crosses upward into higher
//                 volume-discount brackets.
//  Invariant P23: The fee stored in sequential attestation records is
//                 monotonically non-increasing for a single business.
//
//  These use parametric contract-state tests (fresh Env per case).
// ════════════════════════════════════════════════════════════════════

/// Tier discount schedule for P21 (strictly ascending discounts).
///
/// | Tier | Discount (bps) | Effective fee on 1_000_000 base |
/// |------|----------------|----------------------------------|
/// | 0    | 0              | 1_000_000                        |
/// | 1    | 1_000 (10%)    | 900_000                          |
/// | 2    | 2_500 (25%)    | 750_000                          |
/// | 3    | 5_000 (50%)    | 500_000                          |
/// | 4    | 7_500 (75%)    | 250_000                          |
/// | 5    | 10_000 (100%)  | 0                                |
const TIER_MONOTONICITY_DISCOUNTS: &[(u32, u32)] = &[
    (0, 0),
    (1, 1_000),
    (2, 2_500),
    (3, 5_000),
    (4, 7_500),
    (5, 10_000),
];

/// P21: As tier level increases (with strictly ascending discounts),
/// `get_fee_quote` must be monotonically non-increasing.
///
/// Security implication: no tier assignment can accidentally increase the fee.
#[test]
fn prop_tier_upgrade_fee_monotonicity() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);

    for &(tier_level, discount_bps) in TIER_MONOTONICITY_DISCOUNTS {
        client.set_tier_discount(&tier_level, &discount_bps);
    }

    let business = Address::generate(&env);
    mint(&env, &token_addr, &business, base_fee * 100);

    let mut prev_quote = i128::MAX;

    for &(tier_level, discount_bps) in TIER_MONOTONICITY_DISCOUNTS {
        client.set_business_tier(&business, &tier_level);
        let quote = client.get_fee_quote(&business);

        // P21: Quote must be ≤ previous quote.
        assert!(
            quote <= prev_quote,
            "tier={tier_level} (discount={discount_bps} bps): quote={quote} must be ≤ prev_quote={prev_quote}"
        );

        // Cross-check against formula.
        let expected = compute_fee(base_fee, discount_bps, 0);
        assert_eq!(
            quote, expected,
            "tier={tier_level}: contract quote={quote} != formula={expected}"
        );

        prev_quote = quote;
    }

    // Confirm full discount yields zero fee.
    assert_eq!(prev_quote, 0, "full tier discount must yield fee = 0");
}

/// Volume bracket schedule for P22.
///
/// | Count range | Discount (bps) | Fee on 1_000_000 base |
/// |-------------|----------------|-----------------------|
/// | 0–4         | 0              | 1_000_000             |
/// | 5–9         | 500            | 950_000               |
/// | 10–24       | 1_000          | 900_000               |
/// | 25–49       | 2_000          | 800_000               |
/// | 50+         | 4_000          | 600_000               |
const VOLUME_BRACKET_THRESHOLDS: &[u64] = &[5, 10, 25, 50];
const VOLUME_BRACKET_DISCOUNTS: &[u32] = &[500, 1_000, 2_000, 4_000];

/// P22: Fee quote must be monotonically non-increasing as the business's
/// cumulative count crosses volume-bracket thresholds.
///
/// Security implication: volume brackets cannot create a fee increase,
/// which would create a perverse incentive against high-volume usage.
#[test]
fn prop_volume_bracket_crossing_fee_monotonicity() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);

    let soroban_thresholds = {
        let mut v = vec![&env];
        for &t in VOLUME_BRACKET_THRESHOLDS {
            v.push_back(t);
        }
        v
    };
    let soroban_discounts = {
        let mut v = vec![&env];
        for &d in VOLUME_BRACKET_DISCOUNTS {
            v.push_back(d);
        }
        v
    };
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let business = Address::generate(&env);
    let total_submissions = VOLUME_BRACKET_THRESHOLDS.last().copied().unwrap_or(0) + 5;
    mint(
        &env,
        &token_addr,
        &business,
        base_fee * total_submissions as i128 * 2,
    );

    let checkpoints: &[(u64, u32)] = &[(0, 0), (5, 500), (10, 1_000), (25, 2_000), (50, 4_000)];

    let mut prev_quote = i128::MAX;
    let mut submission_idx: u64 = 0;

    for &(target_count, expected_disc_bps) in checkpoints {
        while submission_idx < target_count {
            let period = String::from_str(&env, &std::format!("VOL-MONO-{submission_idx:05}"));
            let root = BytesN::from_array(&env, &[(submission_idx % 256) as u8; 32]);
            client.submit_attestation(
                &business, &period, &root, &1_000_000, &1, &0i128, &None, &None,
            );
            submission_idx += 1;
        }

        let quote = client.get_fee_quote(&business);
        let expected = compute_fee(base_fee, 0, expected_disc_bps);

        // P22-a: Non-increasing.
        assert!(
            quote <= prev_quote,
            "count={target_count}: fee={quote} increased from prev={prev_quote}"
        );
        // P22-b: Matches formula for active bracket.
        assert_eq!(
            quote, expected,
            "count={target_count}: quote={quote} != expected={expected} (disc={expected_disc_bps} bps)"
        );

        prev_quote = quote;
    }
}

/// P23: Fees stored in sequential attestation records are monotonically
/// non-increasing for a single business (no tier change, advancing brackets).
#[test]
fn prop_sequential_stored_fees_non_increasing() {
    let base_fee: i128 = 2_000_000;
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);

    // Brackets: ≥3 → 10%, ≥8 → 25%, ≥15 → 40%.
    let soroban_thresholds = vec![&env, 3u64, 8u64, 15u64];
    let soroban_discounts = vec![&env, 1_000u32, 2_500u32, 4_000u32];
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let business = Address::generate(&env);
    mint(&env, &token_addr, &business, base_fee * 30);

    let mut prev_fee_paid = i128::MAX;

    for i in 0u64..20 {
        let period = String::from_str(&env, &std::format!("SEQ-{i:04}"));
        let root = BytesN::from_array(&env, &[(i % 256) as u8; 32]);
        client.submit_attestation(
            &business, &period, &root, &1_000_000, &1, &0i128, &None, &None,
        );

        let (_, _, _, fee_paid, _, _) = client.get_attestation(&business, &period).unwrap();

        // P23: Each record's fee_paid ≤ previous record's fee_paid.
        assert!(
            fee_paid <= prev_fee_paid,
            "attestation {i}: fee_paid={fee_paid} increased from prev={prev_fee_paid}"
        );

        prev_fee_paid = fee_paid;
    }
}

// ════════════════════════════════════════════════════════════════════
//  §M — Combined Tier + Volume Monotonicity Matrix
//
//  Invariant P24: When both tier and volume discounts increase
//                 (or one increases and the other stays), fee never rises.
//  Invariant P25: The protocol quote always equals the formula value
//                 for the same tier + volume discount configuration.
// ════════════════════════════════════════════════════════════════════

/// Matrix of (tier_bps, vol_bps) pairs — non-decreasing in ≥1 axis per row.
const COMBINED_MONOTONICITY_MATRIX: &[(u32, u32)] = &[
    (0, 0),         // Baseline: full fee
    (500, 0),       // Tier increases
    (500, 500),     // Volume also increases
    (1_000, 500),   // Tier increases further
    (1_000, 1_000), // Volume catches up
    (2_000, 1_500), // Both increase
    (3_000, 2_000),
    (5_000, 3_000),
    (5_000, 5_000), // Equal large discounts
    (7_500, 5_000),
    (10_000, 5_000),  // Full tier discount
    (10_000, 10_000), // Both fully discounted → 0
];

/// P24 + P25: For each matrix row, effective fee must be ≤ prevous row's fee
/// and must exactly match `compute_fee`.
#[test]
fn prop_combined_tier_volume_fee_monotonicity() {
    let base_fee: i128 = 1_000_000;
    let mut prev_fee = i128::MAX;

    for &(tier_bps, vol_bps) in COMBINED_MONOTONICITY_MATRIX {
        // Fresh Env per case — no cross-case state.
        let (env, client, _admin, _token_addr, _collector) = setup_with_fees(base_fee);
        let business = Address::generate(&env);

        client.set_tier_discount(&1u32, &tier_bps);
        client.set_business_tier(&business, &1u32);

        if vol_bps > 0 {
            let soroban_thresholds = vec![&env, 0u64];
            let soroban_discounts = vec![&env, vol_bps];
            client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);
        }

        let quote = client.get_fee_quote(&business);
        let formula = compute_fee(base_fee, tier_bps, vol_bps);

        // P24: Non-increasing.
        assert!(
            quote <= prev_fee,
            "tier={tier_bps}, vol={vol_bps}: quote={quote} > prev_fee={prev_fee}"
        );
        // P25: Matches formula exactly.
        assert_eq!(
            quote, formula,
            "tier={tier_bps}, vol={vol_bps}: quote={quote} != formula={formula}"
        );

        prev_fee = quote;
    }

    assert_eq!(
        prev_fee, 0,
        "fee must be 0 with full tier + volume discount"
    );
}

// ════════════════════════════════════════════════════════════════════
//  §N — Boundary Arithmetic Precision
//
//  Invariant P26: Exact arithmetic spot-checks at critical BPS boundaries
//                 — ensures integer truncation is deterministic.
//  Invariant P27: Fee on maximum valid base (1 trillion) does not overflow.
//  Invariant P28: A minimal positive discount (1 bps) strictly reduces
//                 the fee for bases ≥ 10_000 (enough to survive truncation).
// ════════════════════════════════════════════════════════════════════

/// Spot-check table: (base_fee, tier_bps, vol_bps, expected_fee)
///
/// Formula: base × (10_000 − tier) × (10_000 − vol) / 100_000_000
const ARITHMETIC_SPOT_CHECKS: &[(i128, u32, u32, i128)] = &[
    // Zero base always yields zero.
    (0, 0, 0, 0),
    (0, 5_000, 5_000, 0),
    (0, 10_000, 10_000, 0),
    // No discounts: fee = base.
    (1_000_000, 0, 0, 1_000_000),
    (999_999_999, 0, 0, 999_999_999),
    // Single-bps tier discount:
    //   1_000_000 × 9_999 × 10_000 / 100_000_000 = 999_900
    (1_000_000, 1, 0, 999_900),
    // Single-bps volume discount (symmetric):
    (1_000_000, 0, 1, 999_900),
    // Both 1 bps:
    //   1_000_000 × 9_999 × 9_999 / 100_000_000 = 999_800 (truncation)
    (1_000_000, 1, 1, 999_800),
    // Near-full tier discount (9_999 bps):
    //   1_000_000 × 1 × 10_000 / 100_000_000 = 100
    (1_000_000, 9_999, 0, 100),
    // Full tier discount → 0.
    (1_000_000, 10_000, 0, 0),
    // Full volume discount → 0.
    (1_000_000, 0, 10_000, 0),
    // Both full → 0.
    (1_000_000, 10_000, 10_000, 0),
    // 50% × 50% = 25% effective:
    //   1_000_000 × 5_000 × 5_000 / 100_000_000 = 250_000
    (1_000_000, 5_000, 5_000, 250_000),
    // Worked example from docs (20% tier + 10% volume = 72% effective):
    //   1_000_000 × 8_000 × 9_000 / 100_000_000 = 720_000
    (1_000_000, 2_000, 1_000, 720_000),
    // Large base, moderate discounts (40% tier + 20% volume = 48% effective):
    //   100_000_000 × 6_000 × 8_000 / 100_000_000 = 48_000_000
    (100_000_000, 4_000, 2_000, 48_000_000),
];

/// P26: Exact arithmetic spot-checks covering critical boundary values.
///
/// Any deviation indicates a regression in the fee calculation formula.
#[test]
fn prop_arithmetic_boundary_spot_checks() {
    for &(base, tier, vol, expected) in ARITHMETIC_SPOT_CHECKS {
        let actual = compute_fee(base, tier, vol);
        assert_eq!(
            actual, expected,
            "compute_fee({base}, {tier}, {vol}) = {actual}, expected {expected}"
        );
    }
}

/// P27: No overflow on maximum safe base fee (1 trillion stroops).
///
/// Maximum intermediate: 1_000_000_000_000 × 10_000 × 10_000 = 10^20
/// i128::MAX ≈ 1.7 × 10^38 → safely within range.
#[test]
fn prop_no_overflow_at_max_base() {
    let max_base: i128 = 1_000_000_000_000;
    for &(tier, vol) in &[(0u32, 0u32), (0, 10_000), (10_000, 0), (10_000, 10_000)] {
        let fee = compute_fee(max_base, tier, vol);
        assert!(
            fee >= 0 && fee <= max_base,
            "overflow or bound violation at base={max_base}, tier={tier}, vol={vol}: fee={fee}"
        );
    }
}

/// P28: A minimal positive discount (1 bps) strictly reduces the fee
/// when the base is large enough (≥ 10_000) to survive integer truncation.
#[test]
fn prop_minimal_discount_strictly_reduces_fee() {
    let bases: &[i128] = &[10_000, 100_000, 1_000_000, 100_000_000, 1_000_000_000];
    for &base in bases {
        let full_fee = compute_fee(base, 0, 0);
        let discounted_fee = compute_fee(base, 1, 0);
        assert!(
            discounted_fee < full_fee,
            "1 bps discount must strictly reduce fee for base={}: full={}, discounted={}",
            base,
            full_fee,
            discounted_fee
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  §O — Adversarial Fee Manipulation Resistance
//
//  Invariant P29: Valid tier assignments (0–10_000 bps) never produce
//                 a fee above the base fee.
//  Invariant P30: Toggling fees on/off produces deterministic quotes.
//  Invariant P31: A volume bracket with threshold=0 applies immediately
//                 to all businesses (including new ones at count=0).
//  Invariant P32: Rapid tier reassignment converges to the last assigned
//                 tier — no intermediate state leakage.
// ════════════════════════════════════════════════════════════════════

/// P29: Tier assignment cannot inflate fees beyond the base fee.
///
/// An adversary controlling the admin cannot use valid tier configurations
/// (0–10_000 bps) to produce a fee above the base fee.
#[test]
fn prop_tier_assignment_cannot_inflate_fee() {
    let base_fee: i128 = 500_000;
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);
    let business = Address::generate(&env);
    mint(&env, &token_addr, &business, base_fee * 10);

    for discount_bps in (0u32..=10_000).step_by(500) {
        client.set_tier_discount(&99u32, &discount_bps);
        client.set_business_tier(&business, &99u32);
        let quote = client.get_fee_quote(&business);
        assert!(
            quote <= base_fee,
            "discount={discount_bps} bps produced fee={quote} > base_fee={base_fee}"
        );
        assert!(
            quote >= 0,
            "discount={discount_bps} bps produced negative fee={quote}"
        );
    }
}

/// P30: Toggling fees on/off produces fully deterministic, idempotent quotes.
///
/// When enabled:  quote = compute_fee(base, tier, vol)
/// When disabled: quote = 0
/// Re-enabling restores exactly the original quote.
#[test]
fn prop_fee_toggle_determinism() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, _token_addr, _collector) = setup_with_fees(base_fee);
    let business = Address::generate(&env);

    client.set_tier_discount(&1u32, &2_000u32);
    client.set_business_tier(&business, &1u32);

    let soroban_thresholds = vec![&env, 0u64];
    let soroban_discounts = vec![&env, 1_000u32];
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    // Expected fee: 1_000_000 × 0.80 × 0.90 = 720_000
    let expected_fee = compute_fee(base_fee, 2_000, 1_000);

    for cycle in 0..5u32 {
        client.set_fee_enabled(&true);
        let enabled_quote = client.get_fee_quote(&business);
        assert_eq!(
            enabled_quote, expected_fee,
            "cycle={cycle}: enabled quote={enabled_quote} != expected={expected_fee}"
        );

        client.set_fee_enabled(&false);
        let disabled_quote = client.get_fee_quote(&business);
        assert_eq!(
            disabled_quote, 0,
            "cycle={cycle}: disabled quote must be 0, got {disabled_quote}"
        );
    }
}

/// P31: A volume bracket with threshold=0 applies to all businesses immediately
/// (even a new business with count=0).
///
/// Tests the edge case in `volume_discount_for_count` where the first bracket
/// has threshold 0.
#[test]
fn prop_zero_threshold_volume_bracket_applies_immediately() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(base_fee);

    let soroban_thresholds = vec![&env, 0u64];
    let soroban_discounts = vec![&env, 3_000u32]; // 30% off
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let business = Address::generate(&env);
    let expected = compute_fee(base_fee, 0, 3_000); // 700_000

    let quote = client.get_fee_quote(&business);
    assert_eq!(
        quote, expected,
        "zero-threshold bracket must apply immediately: quote={quote}, expected={expected}"
    );

    // Verify the actual submission charges exactly this amount.
    mint(&env, &token_addr, &business, base_fee * 2);
    let before = token_balance(&env, &token_addr, &business);
    let period = String::from_str(&env, "ZERO-THRESH");
    let root = BytesN::from_array(&env, &[77u8; 32]);
    client.submit_attestation(
        &business, &period, &root, &1_000_000, &1, &0i128, &None, &None,
    );
    let after = token_balance(&env, &token_addr, &business);
    assert_eq!(
        before - after,
        expected,
        "zero-threshold bracket must produce correct charge on submit"
    );
}

/// P32: Multiple rapid tier reassignments converge to the last assigned tier.
///
/// No intermediate tier state must leak into the fee quote.
#[test]
fn prop_tier_reassignment_no_state_leakage() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, _token_addr, _collector) = setup_with_fees(base_fee);
    let business = Address::generate(&env);

    let tiers: &[(u32, u32)] = &[(0, 0), (1, 1_000), (2, 5_000), (3, 10_000)];
    for &(tier, disc) in tiers {
        client.set_tier_discount(&tier, &disc);
    }

    // Cycle through tiers in arbitrary order; settle on tier 2.
    for &t in &[3u32, 1, 0, 2, 3, 0, 1, 2] {
        client.set_business_tier(&business, &t);
    }

    let final_quote = client.get_fee_quote(&business);
    let expected = compute_fee(base_fee, 5_000, 0); // 500_000

    assert_eq!(
        final_quote, expected,
        "after rapid reassignment, final quote={final_quote} must equal expected={expected}"
    );

    let stored_tier = client.get_business_tier(&business);
    assert_eq!(stored_tier, 2, "stored tier must be 2 (last assigned)");
}

// ════════════════════════════════════════════════════════════════════
//  §P — Regression and Determinism Tests
//
//  Invariant P33: Multi-business simulation revenue is always reproducible.
//  Invariant P34: The documented worked example from attestation-dynamic-fees.md
//                 produces exactly 720_000 stroops.
//  Invariant P35: `get_fee_quote` is idempotent — no side effects.
// ════════════════════════════════════════════════════════════════════

/// P34: The exact worked example from `docs/attestation-dynamic-fees.md`
/// produces the documented result of 720_000 stroops.
///
/// Pure arithmetic:
///   1_000_000 × (10_000 − 2_000) × (10_000 − 1_000) / 100_000_000
///   = 1_000_000 × 8_000 × 9_000 / 100_000_000
///   = 720_000
///
/// Contract state: tier 1 = 20% discount, volume bracket ≥10 = 10% discount,
/// business has made 12 submissions (≥10 threshold active).
#[test]
fn prop_regression_docs_worked_example() {
    // Pure arithmetic layer.
    let result = compute_fee(1_000_000, 2_000, 1_000);
    assert_eq!(
        result, 720_000,
        "compute_fee docs worked example must return 720_000"
    );

    // Contract layer: reproduce the docs scenario end-to-end.
    let (env, client, _admin, token_addr, _collector) = setup_with_fees(1_000_000);

    client.set_tier_discount(&1u32, &2_000u32); // 20%

    let soroban_thresholds = vec![&env, 10u64];
    let soroban_discounts = vec![&env, 1_000u32]; // 10%
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let business = Address::generate(&env);
    client.set_business_tier(&business, &1u32);
    mint(&env, &token_addr, &business, 1_000_000 * 25);

    // Submit 12 attestations → count = 12 (≥10 bracket active).
    for i in 0u64..12 {
        let period = String::from_str(&env, &std::format!("DOC-EX-{i:03}"));
        let root = BytesN::from_array(&env, &[(i % 256) as u8; 32]);
        client.submit_attestation(
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

    let quote = client.get_fee_quote(&business);
    assert_eq!(
        quote, 720_000,
        "contract fee quote at count=12 must match docs worked example: got {quote}"
    );
}

/// P35: `get_fee_quote` is idempotent — repeated calls return the same value
/// and the business count must not change.
#[test]
fn prop_get_fee_quote_is_idempotent() {
    let base_fee: i128 = 750_000;
    let (env, client, _admin, _token_addr, _collector) = setup_with_fees(base_fee);

    client.set_tier_discount(&1u32, &1_500u32);
    let business = Address::generate(&env);
    client.set_business_tier(&business, &1u32);

    let soroban_thresholds = vec![&env, 0u64];
    let soroban_discounts = vec![&env, 1_000u32];
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let first_quote = client.get_fee_quote(&business);

    for call_idx in 0..10u32 {
        let repeat_quote = client.get_fee_quote(&business);
        assert_eq!(
            repeat_quote, first_quote,
            "get_fee_quote must be idempotent: call {call_idx} returned {repeat_quote} != {first_quote}"
        );
        assert_eq!(
            client.get_business_count(&business),
            0,
            "get_fee_quote must not mutate business count (call {call_idx})"
        );
    }
}

/// P33: Protocol revenue regression — a reproducible multi-business simulation
/// must always yield exactly the same total.
///
/// Configuration:
///   - 3 businesses: Standard (0%), Professional (15%), Enterprise (30%)
///   - Volume brackets: ≥5 → 5%, ≥10 → 10%
///   - Base fee: 1_000_000 stroops, 12 attestations each
///
/// Pre-calculated expected totals:
///
///   Standard (0% tier):
///     Attestations 1–5   (count 0–4): 1_000_000 × 1.00 × 1.00 = 1_000_000 × 5  = 5_000_000
///     Attestations 6–10  (count 5–9): 1_000_000 × 1.00 × 0.95 =   950_000 × 5  = 4_750_000
///     Attestations 11–12 (count 10+): 1_000_000 × 1.00 × 0.90 =   900_000 × 2  = 1_800_000
///     Total = 11_550_000
///
///   Professional (15% tier):
///     Attestations 1–5:  1_000_000 × 0.85 × 1.00 = 850_000 × 5 = 4_250_000
///     Attestations 6–10: 1_000_000 × 0.85 × 0.95 = 807_500 × 5 = 4_037_500
///     Attestations 11–12:1_000_000 × 0.85 × 0.90 = 765_000 × 2 = 1_530_000
///     Total = 9_817_500
///
///   Enterprise (30% tier):
///     Attestations 1–5:  1_000_000 × 0.70 × 1.00 = 700_000 × 5 = 3_500_000
///     Attestations 6–10: 1_000_000 × 0.70 × 0.95 = 665_000 × 5 = 3_325_000
///     Attestations 11–12:1_000_000 × 0.70 × 0.90 = 630_000 × 2 = 1_260_000
///     Total = 8_085_000
///
///   Grand total = 11_550_000 + 9_817_500 + 8_085_000 = 29_452_500
#[test]
fn prop_regression_protocol_revenue_determinism() {
    let base_fee: i128 = 1_000_000;
    let (env, client, _admin, token_addr, collector) = setup_with_fees(base_fee);

    client.set_tier_discount(&0u32, &0u32);
    client.set_tier_discount(&1u32, &1_500u32); // 15%
    client.set_tier_discount(&2u32, &3_000u32); // 30%

    let soroban_thresholds = vec![&env, 5u64, 10u64];
    let soroban_discounts = vec![&env, 500u32, 1_000u32];
    client.set_volume_brackets(&soroban_thresholds, &soroban_discounts);

    let biz_standard = Address::generate(&env);
    let biz_professional = Address::generate(&env);
    let biz_enterprise = Address::generate(&env);

    client.set_business_tier(&biz_standard, &0u32);
    client.set_business_tier(&biz_professional, &1u32);
    client.set_business_tier(&biz_enterprise, &2u32);

    let mint_amount = base_fee * 20;
    for biz in [&biz_standard, &biz_professional, &biz_enterprise] {
        mint(&env, &token_addr, biz, mint_amount);
    }

    for i in 0u32..12 {
        for (biz, prefix) in [
            (&biz_standard, "S"),
            (&biz_professional, "P"),
            (&biz_enterprise, "E"),
        ] {
            let period = String::from_str(&env, &std::format!("{prefix}-{i:03}"));
            let root = BytesN::from_array(&env, &[(i % 256) as u8; 32]);
            client.submit_attestation(
                biz,
                &period,
                &root,
                &1_700_000_000,
                &1,
                &0i128,
                &None,
                &None,
            );
        }
    }

    assert_eq!(client.get_business_count(&biz_standard), 12);
    assert_eq!(client.get_business_count(&biz_professional), 12);
    assert_eq!(client.get_business_count(&biz_enterprise), 12);

    let standard_spent = mint_amount - token_balance(&env, &token_addr, &biz_standard);
    let pro_spent = mint_amount - token_balance(&env, &token_addr, &biz_professional);
    let ent_spent = mint_amount - token_balance(&env, &token_addr, &biz_enterprise);

    assert_eq!(
        standard_spent, 11_550_000,
        "Standard total spend regression"
    );
    assert_eq!(pro_spent, 9_817_500, "Professional total spend regression");
    assert_eq!(ent_spent, 8_085_000, "Enterprise total spend regression");

    let total_revenue = token_balance(&env, &token_addr, &collector);
    assert_eq!(
        total_revenue, 29_452_500,
        "Protocol revenue regression: expected 29_452_500, got {total_revenue}"
    );

    // Verify monotonicity across tiers at the final quote (count=12, vol disc=10%).
    let std_next = client.get_fee_quote(&biz_standard);
    let pro_next = client.get_fee_quote(&biz_professional);
    let ent_next = client.get_fee_quote(&biz_enterprise);

    assert_eq!(
        std_next,
        compute_fee(base_fee, 0, 1_000),
        "Standard next-quote regression"
    );
    assert_eq!(
        pro_next,
        compute_fee(base_fee, 1_500, 1_000),
        "Professional next-quote regression"
    );
    assert_eq!(
        ent_next,
        compute_fee(base_fee, 3_000, 1_000),
        "Enterprise next-quote regression"
    );

    // Cross-tier monotonicity: higher tier → lower fee.
    assert!(std_next >= pro_next, "Standard ≥ Professional fee");
    assert!(pro_next >= ent_next, "Professional ≥ Enterprise fee");
}


