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
    client.initialize(&Address::generate(&env));
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
    client.initialize(&admin);
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

        client.submit_attestation(&business, &period, &root, &timestamp, &version, &None);

        // P4: Every field must round-trip exactly.
        let (got_root, got_ts, got_ver, got_fee, _) = client
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
        client.submit_attestation(&business, &period2, &root, &timestamp, &version, &None);
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

        client.submit_attestation(&business, &period, &submitted_root, &1_000_000, &1, &None);

        // Sanity: verifies before revocation.
        assert!(
            client.verify_attestation(&business, &period, &submitted_root),
            "case {idx}: must verify before revocation"
        );

        let reason = String::from_str(&env, "property-test revocation");
        client.revoke_attestation(&admin, &business, &period, &reason);

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

        let result = std::panic::catch_unwind(|| {
            // Env is created inside the closure — it is not UnwindSafe
            // and cannot be safely captured from the outer scope.
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env));
            let business = Address::generate(&env);
            let period = String::from_str(&env, &period_owned);
            let root = BytesN::from_array(&env, &[1u8; 32]);
            client.submit_attestation(&business, &period, &root, &1_000_000, &1, &None);
            // Second call for the same (business, period) must panic.
            client.submit_attestation(&business, &period, &root, &2_000_000, &2, &None);
        });

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

        client.submit_attestation(&business, &period, &old_root, &1_000_000, &old_ver, &None);
        client.migrate_attestation(&admin, &business, &period, &new_root, &new_ver);

        let (got_root, _, got_ver, _, _) = client.get_attestation(&business, &period).unwrap();
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
        let result = std::panic::catch_unwind(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            let admin_addr = Address::generate(&env);
            client.initialize(&admin_addr);
            let business = Address::generate(&env);
            let period = String::from_str(&env, "2026-01");
            let old_root = BytesN::from_array(&env, &[1u8; 32]);
            let new_root = BytesN::from_array(&env, &[2u8; 32]);
            client.submit_attestation(&business, &period, &old_root, &1_000_000, &old_ver, &None);
            client.migrate_attestation(&admin_addr, &business, &period, &new_root, &bad_new_ver);
        });

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
        let result = std::panic::catch_unwind(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env));
            client.set_tier_discount(&0u32, &discount);
        });

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

        let result = std::panic::catch_unwind(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env));
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
        });

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

        let result = std::panic::catch_unwind(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            client.initialize(&Address::generate(&env));
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
        });

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

    client.submit_attestation(&biz_a, &period, &root_a, &1_000, &1, &None);
    client.submit_attestation(&biz_b, &period, &root_b, &2_000, &2, &None);

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
    let (a_root, _, a_ver, _, _) = client.get_attestation(&biz_a, &period).unwrap();
    let (b_root, _, b_ver, _, _) = client.get_attestation(&biz_b, &period).unwrap();
    assert_eq!(a_root, root_a, "biz_a root must match what was submitted");
    assert_eq!(b_root, root_b, "biz_b root must match what was submitted");
    assert_ne!(a_ver, b_ver, "versions were different and must differ");

    // Cross-verify: biz_b's root does not verify against biz_a's key.
    assert!(!client.verify_attestation(&biz_a, &period, &root_b));
    assert!(!client.verify_attestation(&biz_b, &period, &root_a));

    // Revoke biz_a only.
    let admin = client.get_admin();
    let reason = String::from_str(&env, "isolation-test");
    client.revoke_attestation(&admin, &biz_a, &period, &reason);

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

        let result = std::panic::catch_unwind(|| {
            let env = Env::default();
            env.mock_all_auths();
            let contract_id = env.register(AttestationContract, ());
            let client = AttestationContractClient::new(&env, &contract_id);
            let admin = Address::generate(&env);
            client.initialize(&admin);
            client.pause(&admin);
            let business = Address::generate(&env);
            let period = String::from_str(&env, &period_owned);
            let root = BytesN::from_array(&env, &[1u8; 32]);
            client.submit_attestation(&business, &period, &root, &1_000, &1, &None);
        });

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

    client.pause(&admin);
    client.unpause(&admin);

    // Must succeed after unpause.
    client.submit_attestation(&business, &period, &root, &1_000, &1, &None);
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
            client.submit_attestation(&business, &warm_period, &warm_root, &1, &1, &None);
        }

        // Capture quote and balance immediately before the test submission.
        let quote = client.get_fee_quote(&business);
        let before = token_balance(&env, &token_addr, &business);

        let test_period = String::from_str(&env, "TEST-FINAL");
        let test_root = BytesN::from_array(&env, &[99u8; 32]);
        client.submit_attestation(&business, &test_period, &test_root, &1_000_000, &1, &None);

        let after = token_balance(&env, &token_addr, &business);
        let charged = before - after;

        // P14-a: Quote matches balance deduction.
        assert_eq!(
            charged, quote,
            "base={base_fee}, tier={tier_disc}, vol_thr={vol_threshold}: charged={charged} != quote={quote}"
        );

        // P14-b: fee_paid field in the stored attestation record also matches.
        let (_, _, _, fee_in_record, _) = client.get_attestation(&business, &test_period).unwrap();
        assert_eq!(
            fee_in_record, quote,
            "stored fee_paid must equal the pre-submit quote"
        );
    }
}
