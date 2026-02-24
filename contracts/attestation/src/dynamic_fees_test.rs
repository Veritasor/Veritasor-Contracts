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
    client.initialize(&admin);

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
    client.submit_attestation(business, &period, &root, &1_700_000_000u64, &1u32, &None);
}

// ════════════════════════════════════════════════════════════════════
//  Pure arithmetic
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_compute_fee_no_discounts() {
    // 1 000 000 stroops, no discounts → full fee.
    assert_eq!(compute_fee(1_000_000, 0, 0), 1_000_000);
}

#[test]
fn test_compute_fee_tier_only() {
    // 20 % tier discount → 80 % of base.
    assert_eq!(compute_fee(1_000_000, 2_000, 0), 800_000);
}

#[test]
fn test_compute_fee_volume_only() {
    // 10 % volume discount → 90 % of base.
    assert_eq!(compute_fee(1_000_000, 0, 1_000), 900_000);
}

#[test]
fn test_compute_fee_combined() {
    // 20 % tier + 10 % volume → 0.8 × 0.9 = 0.72 → 720 000.
    assert_eq!(compute_fee(1_000_000, 2_000, 1_000), 720_000);
}

#[test]
fn test_compute_fee_full_tier_discount() {
    // 100 % tier discount → free.
    assert_eq!(compute_fee(1_000_000, 10_000, 0), 0);
}

#[test]
fn test_compute_fee_full_volume_discount() {
    // 100 % volume discount → free.
    assert_eq!(compute_fee(1_000_000, 0, 10_000), 0);
}

#[test]
fn test_compute_fee_zero_base() {
    // Zero base fee always yields zero regardless of discounts.
    assert_eq!(compute_fee(0, 5_000, 5_000), 0);
}

// ════════════════════════════════════════════════════════════════════
//  Flat fee (no tiers, no volume brackets)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_flat_fee_no_discounts() {
    let t = setup_with_fees(1_000_000);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    // Fee quote before submission should equal base fee.
    assert_eq!(t.client.get_fee_quote(&business), 1_000_000);

    submit(&t.client, &t.env, &business, 1);

    // Business paid the fee, collector received it.
    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 1_000_000);

    // Attestation records the fee paid.
    let period = String::from_str(&t.env, "P-0001");
    let (_, _, _, fee_paid, _) = t.client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 1_000_000);
}

// ════════════════════════════════════════════════════════════════════
//  Tier discounts
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_tier_discounts() {
    let t = setup_with_fees(1_000_000);
    // Tier 0 = 0 % (default), Tier 1 = 20 %, Tier 2 = 40 %.
    t.client.set_tier_discount(&1, &2_000);
    t.client.set_tier_discount(&2, &4_000);

    let biz_standard = Address::generate(&t.env);
    let biz_pro = Address::generate(&t.env);
    let biz_ent = Address::generate(&t.env);

    t.client.set_business_tier(&biz_pro, &1);
    t.client.set_business_tier(&biz_ent, &2);

    assert_eq!(t.client.get_fee_quote(&biz_standard), 1_000_000); // full
    assert_eq!(t.client.get_fee_quote(&biz_pro), 800_000); // 20 % off
    assert_eq!(t.client.get_fee_quote(&biz_ent), 600_000); // 40 % off

    // Verify tier read-back.
    assert_eq!(t.client.get_business_tier(&biz_standard), 0);
    assert_eq!(t.client.get_business_tier(&biz_pro), 1);
    assert_eq!(t.client.get_business_tier(&biz_ent), 2);
}

// ════════════════════════════════════════════════════════════════════
//  Volume discounts
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_volume_brackets() {
    let t = setup_with_fees(1_000_000);

    // Brackets: >=5 → 500 bps (5 %), >=10 → 1500 bps (15 %).
    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32, 1_500u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // Submissions 1–5: no volume discount (count 0–4 before each).
    for i in 1..=5 {
        assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
        submit(&t.client, &t.env, &business, i);
    }
    // After 5 submissions, count is 5 → 5 % discount.
    assert_eq!(t.client.get_fee_quote(&business), 950_000);

    // Submissions 6–10.
    for i in 6..=10 {
        submit(&t.client, &t.env, &business, i);
    }
    // After 10 submissions, count is 10 → 15 % discount.
    assert_eq!(t.client.get_fee_quote(&business), 850_000);
}

// ════════════════════════════════════════════════════════════════════
//  Combined tier + volume
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_combined_tier_and_volume_discounts() {
    let t = setup_with_fees(1_000_000);

    // Tier 1 = 20 % discount.
    t.client.set_tier_discount(&1, &2_000);

    // Volume: >=3 → 10 % discount.
    let thresholds = vec![&t.env, 3u64];
    let discounts = vec![&t.env, 1_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    t.client.set_business_tier(&business, &1);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // Before volume discount kicks in (count < 3): tier only.
    // 1_000_000 × 0.80 = 800_000.
    assert_eq!(t.client.get_fee_quote(&business), 800_000);

    // Submit 3 attestations to reach volume threshold.
    for i in 1..=3 {
        submit(&t.client, &t.env, &business, i);
    }

    // Now count=3 → volume 10 % + tier 20 %.
    // 1_000_000 × 0.80 × 0.90 = 720_000.
    assert_eq!(t.client.get_fee_quote(&business), 720_000);
}

// ════════════════════════════════════════════════════════════════════
//  Tier upgrade mid-usage
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_tier_upgrade() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&1, &2_000);
    t.client.set_tier_discount(&2, &5_000);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // Start at tier 0 → full fee.
    assert_eq!(t.client.get_fee_quote(&business), 1_000_000);
    submit(&t.client, &t.env, &business, 1);

    // Upgrade to tier 1 → 20 % off.
    t.client.set_business_tier(&business, &1);
    assert_eq!(t.client.get_fee_quote(&business), 800_000);
    submit(&t.client, &t.env, &business, 2);

    // Upgrade to tier 2 → 50 % off.
    t.client.set_business_tier(&business, &2);
    assert_eq!(t.client.get_fee_quote(&business), 500_000);
    submit(&t.client, &t.env, &business, 3);

    assert_eq!(t.client.get_business_count(&business), 3);
}

// ════════════════════════════════════════════════════════════════════
//  Fees disabled / toggled
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_fees_disabled() {
    let t = setup_with_fees(1_000_000);
    t.client.set_fee_enabled(&false);

    let business = Address::generate(&t.env);
    // No need to mint — fees are off.
    assert_eq!(t.client.get_fee_quote(&business), 0);
    submit(&t.client, &t.env, &business, 1);

    let period = String::from_str(&t.env, "P-0001");
    let (_, _, _, fee_paid, _) = t.client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 0);
}

#[test]
fn test_fees_toggled_on_off() {
    let t = setup_with_fees(1_000_000);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 10_000_000);

    // Enabled → pays fee.
    submit(&t.client, &t.env, &business, 1);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);

    // Disable → free.
    t.client.set_fee_enabled(&false);
    submit(&t.client, &t.env, &business, 2);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 9_000_000);

    // Re-enable → pays again.
    t.client.set_fee_enabled(&true);
    submit(&t.client, &t.env, &business, 3);
    assert_eq!(balance(&t.env, &t.token_addr, &business), 8_000_000);
}

// ════════════════════════════════════════════════════════════════════
//  No fee config (backward compatibility)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_no_fee_config_free() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    // Never called configure_fees → attestation is free.
    let business = Address::generate(&env);
    assert_eq!(client.get_fee_quote(&business), 0);

    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1u64, &1u32, &None);

    let (_, _, _, fee_paid, _) = client.get_attestation(&business, &period).unwrap();
    assert_eq!(fee_paid, 0);
}

// ════════════════════════════════════════════════════════════════════
//  Initialization guard
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    client.initialize(&admin); // second call panics
}

// ════════════════════════════════════════════════════════════════════
//  Fee quote matches actual charge
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_fee_quote_matches_actual_charge() {
    let t = setup_with_fees(500_000);
    t.client.set_tier_discount(&1, &1_000); // 10 %

    let thresholds = vec![&t.env, 2u64];
    let discounts = vec![&t.env, 500u32]; // 5 % after 2
    t.client.set_volume_brackets(&thresholds, &discounts);

    let business = Address::generate(&t.env);
    t.client.set_business_tier(&business, &1);
    mint(&t.env, &t.token_addr, &business, 100_000_000);

    // Submit twice to cross volume threshold.
    for i in 1..=2 {
        let quote = t.client.get_fee_quote(&business);
        let before = balance(&t.env, &t.token_addr, &business);
        submit(&t.client, &t.env, &business, i);
        let after = balance(&t.env, &t.token_addr, &business);
        assert_eq!(before - after, quote, "quote must match actual deduction");
    }

    // Third submission: volume discount now active.
    let quote = t.client.get_fee_quote(&business);
    // 500_000 × 0.90 (tier) × 0.95 (vol) = 427_500.
    assert_eq!(quote, 427_500);
    let before = balance(&t.env, &t.token_addr, &business);
    submit(&t.client, &t.env, &business, 3);
    let after = balance(&t.env, &t.token_addr, &business);
    assert_eq!(before - after, 427_500);
}

// ════════════════════════════════════════════════════════════════════
//  Bracket validation
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "thresholds and discounts must have equal length")]
fn test_mismatched_brackets_panics() {
    let t = setup_with_fees(1_000_000);
    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32]; // length mismatch
    t.client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic(expected = "thresholds must be strictly ascending")]
fn test_unordered_thresholds_panics() {
    let t = setup_with_fees(1_000_000);
    let thresholds = vec![&t.env, 10u64, 5u64]; // not ascending
    let discounts = vec![&t.env, 500u32, 1_000u32];
    t.client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic(expected = "discount cannot exceed 10 000 bps")]
fn test_tier_discount_over_100_pct_panics() {
    let t = setup_with_fees(1_000_000);
    t.client.set_tier_discount(&0, &10_001); // > 100 %
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
    t.client
        .configure_fees(&t.token_addr, &t.collector, &-1i128, &true);
}

// ════════════════════════════════════════════════════════════════════
//  Economic simulation: three businesses across tiers + volume
// ════════════════════════════════════════════════════════════════════

/// Simulates 30 attestations across three businesses at different tiers
/// with volume brackets, and verifies total protocol revenue.
///
/// ## Economic Rationale
///
/// The multiplicative discount model ensures:
/// 1. **Volume rewards loyalty** — heavy users always pay less per-unit.
/// 2. **Tier rewards commitment** — enterprises negotiate better rates.
/// 3. **Revenue is predictable** — the formula is deterministic and auditable.
/// 4. **Discounts compound fairly** — a 20 % tier + 10 % volume = 28 % total
///    (not 30 %), preserving protocol revenue at scale.
#[test]
fn test_economic_simulation() {
    let t = setup_with_fees(100_000); // 0.1 token per attestation base

    // Tier setup: Standard 0 %, Professional 15 %, Enterprise 30 %.
    t.client.set_tier_discount(&0, &0);
    t.client.set_tier_discount(&1, &1_500);
    t.client.set_tier_discount(&2, &3_000);

    // Volume brackets: >=5 → 5 %, >=10 → 12 %.
    let thresholds = vec![&t.env, 5u64, 10u64];
    let discounts = vec![&t.env, 500u32, 1_200u32];
    t.client.set_volume_brackets(&thresholds, &discounts);

    // Three businesses.
    let biz_s = Address::generate(&t.env); // Standard
    let biz_p = Address::generate(&t.env); // Professional
    let biz_e = Address::generate(&t.env); // Enterprise
    t.client.set_business_tier(&biz_p, &1);
    t.client.set_business_tier(&biz_e, &2);

    // Fund them generously.
    for biz in [&biz_s, &biz_p, &biz_e] {
        mint(&t.env, &t.token_addr, biz, 100_000_000);
    }

    // Each submits 10 attestations.
    for i in 1..=10u32 {
        submit(&t.client, &t.env, &biz_s, i);
        submit(&t.client, &t.env, &biz_p, 100 + i);
        submit(&t.client, &t.env, &biz_e, 200 + i);
    }

    // Verify counts.
    assert_eq!(t.client.get_business_count(&biz_s), 10);
    assert_eq!(t.client.get_business_count(&biz_p), 10);
    assert_eq!(t.client.get_business_count(&biz_e), 10);

    // Calculate expected fees for Standard (tier discount = 0 bps):
    //   Attestations 1–5:  count 0–4, vol discount 0 bps  → 100_000 each = 500_000
    //   Attestations 6–10: count 5–9, vol discount 500 bps → 95_000 each  = 475_000
    //   Total Standard = 975_000
    let standard_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_s);
    assert_eq!(standard_spent, 975_000);

    // Professional (tier discount = 1500 bps = 15 %):
    //   Attestations 1–5:  100_000 × 0.85 × 1.00 = 85_000 each = 425_000
    //   Attestations 6–10: 100_000 × 0.85 × 0.95 = 80_750 each = 403_750
    //   Total Professional = 828_750
    let pro_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_p);
    assert_eq!(pro_spent, 828_750);

    // Enterprise (tier discount = 3000 bps = 30 %):
    //   Attestations 1–5:  100_000 × 0.70 × 1.00 = 70_000 each = 350_000
    //   Attestations 6–10: 100_000 × 0.70 × 0.95 = 66_500 each = 332_500
    //   Total Enterprise = 682_500
    let ent_spent = 100_000_000 - balance(&t.env, &t.token_addr, &biz_e);
    assert_eq!(ent_spent, 682_500);

    // Total protocol revenue.
    let total_revenue = balance(&t.env, &t.token_addr, &t.collector);
    assert_eq!(total_revenue, 975_000 + 828_750 + 682_500);
    assert_eq!(total_revenue, 2_486_250);

    // Verify next-attestation quotes now include the 12 % volume bracket
    // (count = 10 for all).
    // Standard:    100_000 × 1.00 × 0.88 = 88_000
    // Professional: 100_000 × 0.85 × 0.88 = 74_800
    // Enterprise:   100_000 × 0.70 × 0.88 = 61_600
    assert_eq!(t.client.get_fee_quote(&biz_s), 88_000);
    assert_eq!(t.client.get_fee_quote(&biz_p), 74_800);
    assert_eq!(t.client.get_fee_quote(&biz_e), 61_600);
}
