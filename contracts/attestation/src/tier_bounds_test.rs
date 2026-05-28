//! Tests for MAX_TIER enforcement in set_business_tier and set_tier_discount.
//! Issue #318: validate tier and discount bounds at write time.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
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
