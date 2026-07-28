//! Tests for tier bounds enforcement in set_business_tier and set_tier_discount.
//! Issue #318: validate tier and discount bounds at write time.
//! Issue #498: regression test for zero discount at MIN_TIER.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

struct TierTestSetup<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
}

fn setup() -> TierTestSetup<'static> {
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
    client.configure_fees(&token_addr, &collector, &1_000_000i128, &true);

    TierTestSetup { env, client }
}

// ── set_business_tier bounds ────────────────────────────────────────

#[test]
fn test_set_business_tier_zero_accepted() {
    let t = setup();
    let biz = Address::generate(&t.env);
    t.client.set_business_tier(&biz, &0);
}

#[test]
fn test_set_business_tier_one_accepted() {
    let t = setup();
    let biz = Address::generate(&t.env);
    t.client.set_business_tier(&biz, &1);
}

#[test]
fn test_set_business_tier_at_max_accepted() {
    let t = setup();
    let biz = Address::generate(&t.env);
    t.client.set_business_tier(&biz, &dynamic_fees::MAX_TIER);
}

#[test]
#[should_panic(expected = "tier exceeds MAX_TIER")]
fn test_set_business_tier_above_max_panics() {
    let t = setup();
    let biz = Address::generate(&t.env);
    t.client
        .set_business_tier(&biz, &(dynamic_fees::MAX_TIER + 1));
}

#[test]
#[should_panic(expected = "tier exceeds MAX_TIER")]
fn test_set_business_tier_u32_max_panics() {
    let t = setup();
    let biz = Address::generate(&t.env);
    t.client.set_business_tier(&biz, &u32::MAX);
}

// ── set_tier_discount bounds ────────────────────────────────────────

#[test]
fn test_set_tier_discount_zero_accepted() {
    let t = setup();
    t.client.set_tier_discount(&0, &5_000);
}

#[test]
fn test_set_tier_discount_one_accepted() {
    let t = setup();
    t.client.set_tier_discount(&1, &5_000);
}

#[test]
fn test_set_tier_discount_at_max_tier_accepted() {
    let t = setup();
    t.client.set_tier_discount(&dynamic_fees::MAX_TIER, &5_000);
}

#[test]
#[should_panic(expected = "tier exceeds MAX_TIER")]
fn test_set_tier_discount_above_max_panics() {
    let t = setup();
    t.client
        .set_tier_discount(&(dynamic_fees::MAX_TIER + 1), &5_000);
}

#[test]
#[should_panic(expected = "tier exceeds MAX_TIER")]
fn test_set_tier_discount_u32_max_panics() {
    let t = setup();
    t.client.set_tier_discount(&u32::MAX, &0);
}

/// Tier check fires before discount-bps check.
#[test]
#[should_panic(expected = "tier exceeds MAX_TIER")]
fn test_tier_checked_before_discount_bps() {
    let t = setup();
    t.client
        .set_tier_discount(&(dynamic_fees::MAX_TIER + 1), &10_001);
}

/// discount_bps > 10 000 is still rejected when tier is valid.
#[test]
#[should_panic(expected = "discount cannot exceed 10 000 bps")]
fn test_discount_over_100_pct_rejected_for_valid_tier() {
    let t = setup();
    t.client.set_tier_discount(&0, &10_001);
}

// ── Edge cases ──────────────────────────────────────────────────────

#[test]
fn test_unconfigured_tier_discount_returns_zero() {
    let t = setup();
    // Valid tier but not configured returns 0
    assert_eq!(dynamic_fees::get_tier_discount(&t.env, 3), 0);
    // Out of bounds tier lookup also returns 0 without panicking
    assert_eq!(
        dynamic_fees::get_tier_discount(&t.env, dynamic_fees::MAX_TIER + 1),
        0
    );
}

#[test]
fn test_set_business_tier_overwritten() {
    let t = setup();
    let biz = Address::generate(&t.env);

    t.client.set_business_tier(&biz, &1);
    assert_eq!(dynamic_fees::get_business_tier(&t.env, &biz), 1);

    // Overwriting the tier works and no explicit removal is needed
    t.client.set_business_tier(&biz, &dynamic_fees::MAX_TIER);
    assert_eq!(
        dynamic_fees::get_business_tier(&t.env, &biz),
        dynamic_fees::MAX_TIER
    );
}

#[test]
fn test_set_tier_discount_overwritten() {
    let t = setup();

    t.client.set_tier_discount(&1, &2_000);
    assert_eq!(dynamic_fees::get_tier_discount(&t.env, 1), 2_000);

    // Overwriting the discount works
    t.client.set_tier_discount(&1, &5_000);
    assert_eq!(dynamic_fees::get_tier_discount(&t.env, 1), 5_000);
}

// ── MIN_TIER zero-discount regression (#498) ───────────────────────

/// At MIN_TIER the discount must be exactly zero.
///
/// This is a regression guard: a future refactor must not silently apply a
/// nonzero discount to the base tier.  The test combines the tier with
/// zero volume to isolate the tier factor.
#[test]
fn test_tier_min_zero_discount() {
    let t = setup();
    let base_fee: i128 = 1_000_000;

    // 1. Unconfigured MIN_TIER discount must be 0 bps.
    let discount = dynamic_fees::get_tier_discount(&t.env, dynamic_fees::MIN_TIER);
    assert_eq!(
        discount, 0,
        "MIN_TIER (tier {}) discount must be 0, got {}",
        dynamic_fees::MIN_TIER, discount
    );

    // 2. Explicitly setting MIN_TIER discount to 0 persists correctly.
    t.client.set_tier_discount(&dynamic_fees::MIN_TIER, &0);
    let discount = dynamic_fees::get_tier_discount(&t.env, dynamic_fees::MIN_TIER);
    assert_eq!(
        discount, 0,
        "MIN_TIER (tier {}) discount must be 0 after explicit set, got {}",
        dynamic_fees::MIN_TIER, discount
    );

    // 3. compute_fee at MIN_TIER with zero volume discount must equal base_fee.
    let fee = dynamic_fees::compute_fee(base_fee, 0, 0);
    assert_eq!(
        fee, base_fee,
        "compute_fee(base_fee={}, tier_discount=0, vol_discount=0) must equal base_fee, got {}",
        base_fee, fee
    );

    // 4. Combined edge: zero tier discount + zero volume discount with zero base.
    let fee_zero = dynamic_fees::compute_fee(0, 0, 0);
    assert_eq!(
        fee_zero, 0,
        "compute_fee(base_fee=0, tier_discount=0, vol_discount=0) must be 0, got {}",
        fee_zero
    );
}
