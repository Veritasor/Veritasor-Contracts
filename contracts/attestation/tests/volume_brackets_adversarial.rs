//! Adversarial coverage for `set_volume_brackets` (issue #975).
//!
//! These live in `tests/` rather than in the `full-tests`-gated
//! `src/dynamic_fees_test.rs` module so that they compile and run under a plain
//! `cargo test -p veritasor-attestation`, linking the contract as a normal
//! dependency instead of pulling in the legacy inline test modules.
//!
//! The properties they pin down are the ones the existing validation tests leave
//! unobserved:
//!
//!   1. Atomicity — a rejected `set_volume_brackets` call must not mutate either
//!      stored vector; the last accepted configuration survives and keeps driving
//!      `volume_discount_for_count`.
//!   2. Determinism at the boundaries — non-strict monotonicity, the exact
//!      10_000 bps cap, anti-monotone discounts and extreme thresholds must fold
//!      into a single, reproducible bracket selection.

extern crate std;

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{vec, Address, BytesN, Env, String};
use veritasor_attestation::{AttestationContract, AttestationContractClient, ROLE_BUSINESS};

// ════════════════════════════════════════════════════════════════════
//  Helpers (mirroring the `full-tests` module so the cases below are a
//  like-for-like copy of the ones authored against it)
// ════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
struct TestSetup<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
    admin: Address,
    token_addr: Address,
    collector: Address,
}

fn setup_with_fees(base_fee: i128) -> TestSetup<'static> {
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

    TestSetup {
        env,
        client,
        admin,
        token_addr,
        collector,
    }
}

fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token_addr).mint(to, &amount);
}

#[allow(dead_code)]
fn balance(env: &Env, token_addr: &Address, who: &Address) -> i128 {
    TokenClient::new(env, token_addr).balance(who)
}

/// Register and approve `business` so `submit_attestation` clears the
/// `registry::require_active_business` gate.
fn register_business(
    client: &AttestationContractClient,
    env: &Env,
    admin: &Address,
    business: &Address,
) {
    if client.is_business_active(business) {
        return;
    }
    if client.get_business(business).is_none() {
        client.grant_role(admin, business, &ROLE_BUSINESS);
        client.register_business(
            business,
            &BytesN::from_array(env, &[1u8; 32]),
            &soroban_sdk::Symbol::new(env, "US"),
            &soroban_sdk::Vec::new(env),
        );
    }
    client.approve_business(admin, business);
}

fn submit(client: &AttestationContractClient, env: &Env, business: &Address, index: u32) {
    let admin = client.get_admin();
    register_business(client, env, &admin, business);
    let period = String::from_str(env, &std::format!("P-{index:04}"));
    let root = BytesN::from_array(env, &[index as u8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

// ════════════════════════════════════════════════════════════════════
//  Adversarial `set_volume_brackets` coverage (issue #975)
//
//  The validation tests above assert that invalid inputs *panic*. These
//  tests additionally pin down the two properties the earlier tests leave
//  unobserved:
//
//    1. Atomicity — a rejected `set_volume_brackets` call must not mutate
//       either stored vector; the last accepted configuration survives and
//       keeps driving `volume_discount_for_count`.
//    2. Determinism at the boundaries — non-strict monotonicity, the exact
//       10_000 bps cap, anti-monotone discounts and extreme thresholds must
//       fold into a single, reproducible bracket selection.
//
//  A contract panic unwinds back to the test harness, which is why the
//  state assertions live *outside* the `catch_unwind` closure: the `Env`
//  and client created by `setup_with_fees` stay usable afterwards (the same
//  pattern used by `pause_test.rs` for rolled-back submissions).
// ════════════════════════════════════════════════════════════════════

/// A rejected length-mismatch call must leave the previously accepted
/// brackets intact, in both the direct and reverse direction.
#[test]
fn test_set_volume_brackets_rejected_length_mismatch_leaves_state_unchanged() {
    let t = setup_with_fees(1_000_000);

    let good_t = vec![&t.env, 5u64, 10u64];
    let good_d = vec![&t.env, 500u32, 1_500u32];
    t.client.set_volume_brackets(&good_t, &good_d);

    // thresholds longer than discounts.
    let long_t = vec![&t.env, 5u64, 10u64];
    let short_d = vec![&t.env, 500u32];
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&long_t, &short_d);
    }));
    assert!(
        first.is_err(),
        "thresholds longer than discounts must be rejected"
    );

    // discounts longer than thresholds (the reverse direction).
    let short_t = vec![&t.env, 5u64];
    let long_d = vec![&t.env, 500u32, 1_500u32];
    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&short_t, &long_d);
    }));
    assert!(
        second.is_err(),
        "discounts longer than thresholds must be rejected"
    );

    // Neither rejected call may have touched storage.
    let (got_t, got_d) = t.client.get_volume_brackets();
    assert_eq!(got_t, good_t);
    assert_eq!(got_d, good_d);

    // The surviving configuration still drives bracket selection.
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);
    assert_eq!(t.client.get_volume_discount(&business), 0);
    for i in 1..=5 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_business_count(&business), 5);
    assert_eq!(t.client.get_volume_discount(&business), 500);
}

/// Every other rejection reason (non-strict ordering, descending order and
/// an out-of-cap discount) must also be atomic: the last valid config stays.
#[test]
fn test_set_volume_brackets_rejected_validation_leaves_state_unchanged() {
    let t = setup_with_fees(1_000_000);

    let good_t = vec![&t.env, 2u64, 7u64];
    let good_d = vec![&t.env, 250u32, 900u32];
    t.client.set_volume_brackets(&good_t, &good_d);

    // Non-strict monotonicity: adjacent duplicates.
    let dup_t = vec![&t.env, 5u64, 5u64];
    let dup_d = vec![&t.env, 100u32, 200u32];
    let r_dup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&dup_t, &dup_d);
    }));
    assert!(r_dup.is_err(), "adjacent equal thresholds must be rejected");

    // Descending thresholds.
    let down_t = vec![&t.env, 9u64, 3u64];
    let down_d = vec![&t.env, 100u32, 200u32];
    let r_down = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&down_t, &down_d);
    }));
    assert!(r_down.is_err(), "descending thresholds must be rejected");

    // One out-of-range discount with otherwise valid inputs.
    let cap_t = vec![&t.env, 3u64, 6u64];
    let cap_d = vec![&t.env, 100u32, 10_001u32];
    let r_cap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&cap_t, &cap_d);
    }));
    assert!(r_cap.is_err(), "discount above 10 000 bps must be rejected");

    let (got_t, got_d) = t.client.get_volume_brackets();
    assert_eq!(got_t, good_t);
    assert_eq!(got_d, good_d);
}

/// Rejecting a call on a virgin (never-configured) contract must keep the
/// stored brackets empty rather than leaving a partially written vector.
#[test]
fn test_set_volume_brackets_rejection_on_unset_state_keeps_empty() {
    let t = setup_with_fees(1_000_000);

    let (t0, d0) = t.client.get_volume_brackets();
    assert_eq!(t0.len(), 0);
    assert_eq!(d0.len(), 0);

    let bad_t = vec![&t.env, 10u64, 5u64];
    let bad_d = vec![&t.env, 100u32, 200u32];
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&bad_t, &bad_d);
    }));
    assert!(rejected.is_err(), "descending thresholds must be rejected");

    let (t1, d1) = t.client.get_volume_brackets();
    assert_eq!(t1.len(), 0);
    assert_eq!(d1.len(), 0);

    // With no brackets stored, every count resolves to a zero discount.
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);
    for i in 1..=6 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_business_count(&business), 6);
    assert_eq!(t.client.get_volume_discount(&business), 0);
}

/// An unauthorized caller must be rejected by `require_admin` and, because
/// the authorization guard runs before any write, the stored brackets must
/// not change.
#[test]
fn test_set_volume_brackets_unauthorized_caller_rejected_and_state_unchanged() {
    let t = setup_with_fees(1_000_000);

    let good_t = vec![&t.env, 4u64];
    let good_d = vec![&t.env, 1_000u32];
    // The admin can configure the brackets.
    t.client.set_volume_brackets(&good_t, &good_d);

    // Drop every mocked authorization: the next call is now unauthorized.
    t.env.mock_auths(&[]);
    let new_t = vec![&t.env, 8u64];
    let new_d = vec![&t.env, 2_000u32];
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.client.set_volume_brackets(&new_t, &new_d);
    }));
    assert!(
        rejected.is_err(),
        "a caller without admin authorization must be rejected"
    );

    // Authorization failure must not have mutated the configuration.
    let (got_t, got_d) = t.client.get_volume_brackets();
    assert_eq!(got_t, good_t);
    assert_eq!(got_d, good_d);
}

/// Discounts are allowed to *decrease* as thresholds grow, and the contract
/// must deterministically return the discount bound to the highest eligible
/// threshold.
#[test]
fn test_set_volume_brackets_discounts_may_decrease_with_higher_threshold() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 2_000u32, 500u32]; // 20% then 5%
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    assert_eq!(t.client.get_volume_discount(&business), 0);
    for i in 1..=4 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_business_count(&business), 4);
    assert_eq!(t.client.get_volume_discount(&business), 0);

    submit(&t.client, &t.env, &business, 5);
    assert_eq!(t.client.get_volume_discount(&business), 2_000);
    assert_eq!(t.client.get_fee_quote(&business), 800_000);

    for i in 6..=10 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_business_count(&business), 10);
    assert_eq!(t.client.get_volume_discount(&business), 500);
    assert_eq!(t.client.get_fee_quote(&business), 950_000);
}

/// The discount cap is inclusive at 10_000 bps and exclusive at 10_001,
/// checked at every bracket position; the rejected updates stay atomic.
#[test]
fn test_set_volume_brackets_discount_cap_boundary_is_exact() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 1u64, 2u64, 3u64];
    let discounts = vec![&t.env, 10_000u32, 10_000u32, 10_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let (got_t, got_d) = t.client.get_volume_brackets();
    assert_eq!(got_t, thresholds);
    assert_eq!(got_d, discounts);

    // Exactly one bps over the cap at any position must be rejected.
    for pos in 0..3u32 {
        let mut bad = vec![&t.env, 0u32, 0u32, 0u32];
        bad.set(pos, 10_001u32);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.client.set_volume_brackets(&thresholds, &bad);
        }));
        assert!(
            rejected.is_err(),
            "discount 10_001 at position {} must be rejected",
            pos
        );
    }

    // None of the rejected updates changed the accepted (all-10_000) config.
    let (got_t2, got_d2) = t.client.get_volume_brackets();
    assert_eq!(got_t2, thresholds);
    assert_eq!(got_d2, discounts);
}

/// Setting empty vectors is a valid operation that must atomically clear a
/// previously configured bracket set.
#[test]
fn test_set_volume_brackets_empty_vectors_clear_previous_configuration() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32, 1_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let (before_t, before_d) = t.client.get_volume_brackets();
    assert_eq!(before_t, thresholds);
    assert_eq!(before_d, discounts);

    let empty_t = vec![&t.env];
    let empty_d = vec![&t.env];
    t.client.set_volume_brackets(&empty_t, &empty_d);

    let (after_t, after_d) = t.client.get_volume_brackets();
    assert_eq!(after_t.len(), 0);
    assert_eq!(after_d.len(), 0);

    // Selection falls back to zero discount once cleared.
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);
    for i in 1..=11 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_business_count(&business), 11);
    assert_eq!(t.client.get_volume_discount(&business), 0);
}

/// Extreme but strictly ascending thresholds (`0` and `u64::MAX`) are valid;
/// selection must be deterministic and the unreachable bracket must never
/// leak its discount.
#[test]
fn test_set_volume_brackets_extreme_threshold_bounds_are_deterministic() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 0u64, u64::MAX];
    let discounts = vec![&t.env, 100u32, 10_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let (got_t, got_d) = t.client.get_volume_brackets();
    assert_eq!(got_t, thresholds);
    assert_eq!(got_d, discounts);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // count = 0 already satisfies the 0-threshold bracket.
    assert_eq!(t.client.get_volume_discount(&business), 100);

    submit(&t.client, &t.env, &business, 1);
    assert_eq!(t.client.get_business_count(&business), 1);
    // The u64::MAX bracket is unreachable at any realistic count, so the
    // 10_000 bps discount must not apply here.
    assert_eq!(t.client.get_volume_discount(&business), 100);
    assert_ne!(t.client.get_volume_discount(&business), 10_000);
}
