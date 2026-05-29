//! Comprehensive tests for the dynamic fee schedule.
//!
//! Covers: pure arithmetic, tier discounts, volume brackets, combined
//! discounts, tier upgrades, fee toggling, admin access control,
//! initialization guard, fee-quote accuracy, bracket validation,
//! and a multi-business economic simulation.

extern crate std;

use super::*;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{vec, Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Helpers
// ════════════════════════════════════════════════════════════════════

/// Register the attestation contract, initialize it, and optionally
/// set up a token with fee configuration.
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

    // Deploy a Stellar asset token for fee payment.
    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    // Register and initialize the attestation contract.
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Configure fees.
    client.configure_fees(&token_addr, &collector, &base_fee, &true);

    TestSetup {
        env,
        client,
        admin,
        token_addr,
        collector,
    }
}

/// Mint tokens to an address.
fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    let stellar = StellarAssetClient::new(env, token_addr);
    stellar.mint(to, &amount);
}

/// Read token balance.
fn balance(env: &Env, token_addr: &Address, who: &Address) -> i128 {
    let token = TokenClient::new(env, token_addr);
    token.balance(who)
}

/// Submit an attestation for a unique period derived from `index`.
fn submit(client: &AttestationContractClient, env: &Env, business: &Address, index: u32) {
    let period = String::from_str(env, &std::format!("P-{index:04}"));
    let root = BytesN::from_array(env, &[index as u8; 32]);
    client.submit_attestation(
        business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &None,
        &None,
        &0u64,
    );
}

#[test]
fn test_compute_fee_no_discounts() {
    assert_eq!(compute_fee(1_000_000, 0, 0), 1_000_000);
}

#[test]
fn test_compute_fee_tier_only() {
    assert_eq!(compute_fee(1_000_000, 2_000, 0), 800_000);
}

#[test]
fn test_compute_fee_volume_only() {
    assert_eq!(compute_fee(1_000_000, 0, 1_000), 900_000);
}

#[test]
fn test_compute_fee_combined() {
    assert_eq!(compute_fee(1_000_000, 2_000, 1_000), 720_000);
}

#[test]
fn test_compute_fee_full_tier_discount() {
    assert_eq!(compute_fee(1_000_000, 10_000, 0), 0);
}

#[test]
fn test_compute_fee_full_volume_discount() {
    assert_eq!(compute_fee(1_000_000, 0, 10_000), 0);
}

#[test]
fn test_compute_fee_zero_base() {
    assert_eq!(compute_fee(0, 5_000, 5_000), 0);
}

#[test]
fn test_flat_fee_no_discounts() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    assert_eq!(t.client.get_fee_quote(&business), 1_000_000);

    submit(&t.client, &t.env, &business, 1);

    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 1_000_000);

    let period = String::from_str(&t.env, "P-0001");
    let (_, _, _, fee_paid, _, _) = t.client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 1_000_000);
}

#[test]
fn test_tier_discounts() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&1, &2_000);
    t.client.set_tier_discount(&2, &4_000);

    let biz_standard = Address::generate(&t.env);
    let biz_pro = Address::generate(&t.env);
    let biz_ent = Address::generate(&t.env);

    t.client.set_business_tier(&biz_pro, &1);
    t.client.set_business_tier(&biz_ent, &2);

    assert_eq!(t.client.get_fee_quote(&biz_standard), 1_000_000);
    assert_eq!(t.client.get_fee_quote(&biz_pro), 800_000);
    assert_eq!(t.client.get_fee_quote(&biz_ent), 600_000);

    assert_eq!(t.client.get_business_tier(&biz_standard), 0);
    assert_eq!(t.client.get_business_tier(&biz_pro), 1);
    assert_eq!(t.client.get_business_tier(&biz_ent), 2);
}

#[test]
fn test_volume_brackets() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32, 1_500u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    for i in 1..=5 {
        assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_fee_quote(&business), 950_000);

    for i in 6..=10 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_fee_quote(&business), 850_000);
}

#[test]
fn test_combined_tier_and_volume_discounts() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&1, &2_000);
    let thresholds = vec![&t.env, 3u64];
    let discounts = vec![&t.env, 1_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    t.client.set_business_tier(&business, &1);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    assert_eq!(t.client.get_fee_quote(&business), 800_000);

    for i in 1..=3 {
        submit(&t.client, &t.env, &business, i);
    }
    assert_eq!(t.client.get_fee_quote(&business), 720_000);
}

#[test]
fn test_tier_upgrade() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&1, &2_000);
    t.client.set_tier_discount(&2, &5_000);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
    submit(&t.client, &t.env, &business, 1);

    t.client.set_business_tier(&business, &1);
    assert_eq!(t.client.get_fee_quote(&business), 800_000);
    submit(&t.client, &t.env, &business, 2);

    t.client.set_business_tier(&business, &2);
    assert_eq!(t.client.get_fee_quote(&business), 500_000);
    submit(&t.client, &t.env, &business, 3);

    assert_eq!(t.client.get_business_count(&business), 3);
}

#[test]
fn test_fees_disabled() {
    let t = setup_with_fees(1_000_000);
    t.client.set_fee_enabled(&false);

    let business = Address::generate(&t.env);
    assert_eq!(t.client.get_fee_quote(&business), 0);
    submit(&t.client, &t.env, &business, 1);

    let period = String::from_str(&t.env, "P-0001");
    let (_, _, _, fee_paid, _, _) = t.client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 0);
}

#[test]
fn test_fees_toggled_on_off() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    submit(&t.client, &t.env, &business, 1);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);

    t.client.set_fee_enabled(&false);
    submit(&t.client, &t.env, &business, 2);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);

    t.client.set_fee_enabled(&true);
    submit(&t.client, &t.env, &business, 3);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 8_000_000);
}

#[test]
fn test_no_fee_config_free() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let business = Address::generate(&env);
    assert_eq!(client.get_fee_quote(&business), 0);

    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1u64, &1u32, &None, &None, &0u64);

    let (_, _, _, fee_paid, _, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 0);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    client.initialize(&admin, &0u64);
}

#[test]
fn test_fee_quote_matches_actual_charge() {
    let t = setup_with_fees(500_000);
    t.client.set_tier_discount(&1, &1_000);

    let thresholds = vec![&t.env, 2u64];
    let discounts = vec![&t.env, 500u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    t.client.set_business_tier(&business, &1);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    for i in 1..=2 {
        let quote = t.client.get_fee_quote(&business);
        let before = balance(&t.env, &t.token_addr, &business);
        submit(&t.client, &t.env, &business, i);
        let after = balance(&t.env, &t.token_addr, &business);
        assert_eq!(before - after, quote);
    }

    let quote = t.client.get_fee_quote(&business);
    assert_eq!(quote, 427_500);
    let before = balance(&t.env, &t.token_addr, &business);
    submit(&t.client, &t.env, &business, 3);
    let after = balance(&t.env, &t.token_addr, &business);
    assert_eq!(before - after, 427_500);
}

#[test]
#[should_panic(expected = "thresholds and discounts must have equal length")]
fn test_mismatched_brackets_panics() {
    let t = setup_with_fees(1_000_000);
    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32];
    t.client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic(expected = "thresholds must be strictly ascending")]
fn test_unordered_thresholds_panics() {
    let t = setup_with_fees(1_000_000);
    let thresholds = vec![&t.env, 10u64, 5u64];
    let discounts = vec![&t.env, 500u32, 1_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic(expected = "discount cannot exceed 10 000 bps")]
fn test_tier_discount_over_100_pct_panics() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&0, &10_001);
}

#[test]
#[should_panic(expected = "discount cannot exceed 10 000 bps")]
fn test_volume_discount_over_100_pct_panics() {
    let t = setup_with_fees(1_000_000);
    let thresholds = vec![&t.env, 1u64];
    let discounts = vec![&t.env, 10_001u32];
    t.client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic(expected = "base_fee must be non-negative")]
fn test_negative_base_fee_panics() {
    let t = setup_with_fees(1_000_000);
    t.client.configure_fees(&t.token_addr, &t.collector, &-1i128, &true);
}

#[test]
fn test_economic_simulation() {
    let t = setup_with_fees(100_000);

    t.client.set_tier_discount(&0, &0);
    t.client.set_tier_discount(&1, &1_500);
    t.client.set_tier_discount(&2, &3_000);

    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32, 1_200u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let biz_s = Address::generate(&t.env);
    let biz_p = Address::generate(&t.env);
    let biz_e = Address::generate(&t.env);
    t.client.set_business_tier(&biz_p, &1);
    t.client.set_business_tier(&biz_e, &2);

    for biz in [&biz_s, &biz_p, &biz_e] {
        mint(&t.env, &t.token_addr, biz, 100_000_000);
    }

    for i in 1..=10u32 {
        submit(&t.client, &t.env, &biz_s, i);
        submit(&t.client, &t.env, &biz_p, 100 + i);
        submit(&t.client, &t.env, &biz_e, 200 + i);
    }

    assert_eq!(t.client.get_business_count(&biz_s), 10);
    assert_eq!(t.client.get_business_count(&biz_p), 10);
    assert_eq!(t.client.get_business_count(&biz_e), 10);

    let standard_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_s);
    assert_eq!(standard_spent, 975_000);

    let pro_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_p);
    assert_eq!(pro_spent, 828_750);

    let ent_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_e);
    assert_eq!(ent_spent, 682_500);

    let total_revenue = balance(&t.env, &t.token_addr, &t.collector);
    assert_eq!(total_revenue, 2_486_250);

    assert_eq!(t.client.get_fee_quote(&biz_s), 88_000);
    assert_eq!(t.client.get_fee_quote(&biz_p), 74_800);
    assert_eq!(t.client.get_fee_quote(&biz_e), 61_600);
}

#[test]
fn test_compute_fee_rounding_and_precision() {
    // 1 unit base fee, 1 bps discount (0.01%)
    // factor = (10000-0) * (10000-1) = 100,000,000 * 0.9999 = 99,990,000
    // 1 * 99,990,000 / 100,000,000 = 0 (truncation)
    assert_eq!(compute_fee(1, 0, 1), 0);

    // 100 units, 1 bps discount -> 100 * 0.9999 = 99.99 -> 99
    assert_eq!(compute_fee(100, 0, 1), 99);

    // 10,000 units, 1 bps discount -> 10,000 * 10,000 * 9,999 / 100,000,000 = 9,999
    assert_eq!(compute_fee(10_000, 0, 1), 9_999);
}

#[test]
fn test_compute_fee_magnitudes() {
    // Extremely large base_fee (e.g. for high-precision tokens)
    let large_fee = 1_000_000_000_000_000_000_000_000i128; // 10^24
    // 10% discount across both (1000 bps)
    // factor = 9000 * 9000 = 81,000,000
    // result = 10^24 * 0.81 = 8.1 * 10^23
    assert_eq!(compute_fee(large_fee, 1_000, 1_000), 810_000_000_000_000_000_000_000i128);

    // Zero base fee
    assert_eq!(compute_fee(0, 1_000, 1_000), 0);
}

#[test]
fn test_bracket_boundary_transitions() {
    let t = setup_with_fees(1_000_000);
    // Bracket at 10 attestations, 50% discount
    let thresholds = vec![&t.env, 10u64];
    let discounts = vec![&t.env, 5_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // 9th submission: still full price
    for i in 1..=9 {
        assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
        submit(&t.client, &t.env, &business, i);
    }

    // 10th submission: boundary hit, 50% discount applies to NEXT
    assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
    submit(&t.client, &t.env, &business, 10);

    // 11th submission: should have discount
    assert_eq!(t.client.get_fee_quote(&business), 500_000);
}

#[test]
fn test_config_change_mid_period_consistency() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    // First submission at 1M
    submit(&t.client, &t.env, &business, 1);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 1_000_000);

    // Admin changes base fee mid-period
    t.client.configure_fees(&t.token_addr, &t.collector, &500_000, &true);
    
    // Second submission should be at 500k
    submit(&t.client, &t.env, &business, 2);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 1_500_000);

    // Admin changes discount mid-period
    t.client.set_tier_discount(&0, &2_000); // 20% off for Tier 0
    submit(&t.client, &t.env, &business, 3);
    // 500k * 0.8 = 400k
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 1_900_000);
}

#[test]
fn test_max_discount_combinations() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&1, &10_000); // 100% discount
    t.client.set_tier_discount(&2, &5_000);  // 50% discount
    
    let thresholds = vec![&t.env, 5u64];
    let discounts = vec![&t.env, 10_000u32]; // 100% discount
    t.client.set_volume_brackets(&thresholds, &discounts);

    let biz_tier_100 = Address::generate(&t.env);
    let biz_vol_100 = Address::generate(&t.env);
    t.client.set_business_tier(&biz_tier_100, &1);

    // Tier 100% discount -> free regardless of volume
    assert_eq!(t.client.get_fee_quote(&biz_tier_100), 0);

    // Volume 100% discount -> free after 5 submissions
    for i in 1..=5 {
        submit(&t.client, &t.env, &biz_vol_100, i);
    }
    assert_eq!(t.client.get_fee_quote(&biz_vol_100), 0);

    // Combined 50% tier + 100% volume -> free
    let biz_combined = Address::generate(&t.env);
    t.client.set_business_tier(&biz_combined, &2);
    for i in 1..=5 {
        submit(&t.client, &t.env, &biz_combined, i);
    }
    assert_eq!(t.client.get_fee_quote(&biz_combined), 0);
}


#[test]
fn test_get_volume_brackets_empty() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let (thresholds, discounts) = client.get_volume_brackets();
    assert_eq!(thresholds.len(), 0);
    assert_eq!(discounts.len(), 0);
}

#[test]
fn test_get_volume_brackets_round_trip() {
    let t = setup_with_fees(1_000_000);

    let thresholds = vec![&t.env, 5u64, 10u64, 50u64];
    let discounts = vec![&t.env, 500u32, 1_500u32, 3_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let (got_thresholds, got_discounts) = t.client.get_volume_brackets();
    assert_eq!(got_thresholds, thresholds);
    assert_eq!(got_discounts, discounts);
}
