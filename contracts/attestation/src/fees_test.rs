//! # Fee Collection End-to-End Tests
//!
//! Verifies that `submit_attestation` correctly transfers tokens from the
//! business wallet to the configured collector(s) and that the stored
//! `fee_paid` field (tuple index `.3`) equals the sum of all fees charged.
//!
//! ## Coverage
//!
//! | Test | Scenario |
//! |------|----------|
//! | `test_collect_flat_fee_success` | Flat fee only — balance delta + record.3 |
//! | `test_flat_fee_disabled` | Flat fee disabled — no transfer |
//! | `test_zero_flat_fee` | Flat fee amount = 0 — no transfer |
//! | `test_flat_fee_insufficient_balance` | Panics when balance < fee |
//! | `test_combined_fees` | Dynamic + flat — both collectors credited |
//! | `test_only_flat_fee_transfers_to_flat_collector` | Only flat configured |
//! | `test_only_dynamic_fee_transfers_to_dynamic_collector` | Only dynamic configured |
//! | `test_both_fees_disabled_no_transfer` | Both disabled — zero balance OK |
//! | `test_fee_paid_equals_dynamic_plus_flat_exact_decomposition` | Exact sum assertion |
//! | `test_tier_discount_reduces_dynamic_fee_and_record` | Tier discount applied |
//! | `test_volume_discount_reduces_dynamic_fee_after_threshold` | Volume bracket applied |
//! | `test_collector_balance_accumulates_across_submissions` | Running total |
//! | `test_balance_delta_equals_fee_quote` | Pre/post delta == get_fee_quote |
//! | `test_tier_and_volume_combined_discount_balance_delta` | Multiplicative discounts |
//!
//! ## Security Invariants
//!
//! - No attestation can be recorded without the fee being transferred first.
//!   `token::transfer` panics on insufficient balance, rolling back the entire
//!   transaction — so an attestation record can never exist without payment.
//! - `fee_paid` is computed on-chain from the live `FeeConfig`; the legacy
//!   `_fee_paid` argument passed by the caller is ignored.
//! - Flat and dynamic fees are independent: disabling one does not affect the other.
//! - Tier and volume discounts reduce the dynamic fee but never produce a negative charge.
//! - Collector addresses are set by the admin at configuration time; callers cannot
//!   redirect fees to an arbitrary address.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{vec, Address, BytesN, Env, String};

// ════════════════════════════════════════════════════════════════════
//  Test helpers
// ════════════════════════════════════════════════════════════════════

struct TestSetup<'a> {
    env: Env,
    client: AttestationContractClient<'a>,
    #[allow(dead_code)]
    admin: Address,
    token_addr: Address,
    collector: Address,
}

/// Deploy the attestation contract with a flat fee configured.
fn setup_with_flat_fees(amount: i128) -> TestSetup<'static> {
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

    // Configure flat fees.
    client.configure_flat_fee(&token_addr, &collector, &amount, &true);

    TestSetup {
        env,
        client,
        admin,
        token_addr,
        collector,
    }
}

/// Mint tokens to an address using the Stellar asset admin interface.
fn mint(env: &Env, token_addr: &Address, to: &Address, amount: i128) {
    StellarAssetClient::new(env, token_addr).mint(to, &amount);
}

/// Read the token balance of an address.
fn balance(env: &Env, token_addr: &Address, who: &Address) -> i128 {
    TokenClient::new(env, token_addr).balance(who)
}

/// Read the SAC balance of an address via the actual Stellar Asset client.
fn sac_balance(env: &Env, token_addr: &Address, who: &Address) -> i128 {
    StellarAssetClient::new(env, token_addr).balance(who)
}

/// Read the SAC allowance for a spender from an owner.
fn sac_allowance(env: &Env, token_addr: &Address, owner: &Address, spender: &Address) -> i128 {
    TokenClient::new(env, token_addr).allowance(owner, spender)
}

/// Deploy a fresh Stellar asset token, mint `amount` to `to`, and return
/// the token address.  Reuses the same `env` so all contracts share the
/// same ledger state.
fn deploy_and_fund_token(env: &Env, to: &Address, amount: i128) -> Address {
    let token_admin = Address::generate(env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin);
    let token_addr = token_contract.address().clone();
    StellarAssetClient::new(env, &token_addr).mint(to, &amount);
    token_addr
}

/// Submit a single attestation.  The `_fee_paid` legacy argument is always
/// passed as `&0i128`; the contract ignores it and computes the fee on-chain.
fn submit(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period_str: &str,
    root_byte: u8,
) {
    let period = String::from_str(env, period_str);
    let root = BytesN::from_array(env, &[root_byte; 32]);
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
//  Pre-existing flat-fee tests (fixed argument order)
// ════════════════════════════════════════════════════════════════════

/// Flat fee is deducted from the business and credited to the collector.
/// The stored `fee_paid` (record.3) must equal the configured amount.
#[test]
fn test_collect_flat_fee_success() {
    let t = setup_with_flat_fees(500);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 1_000);

    submit(&t.client, &t.env, &business, "2026-02", 1);

    assert_eq!(balance(&t.env, &t.token_addr, &business), 500);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 500);

    let record = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-02"))
        .unwrap();
    assert_eq!(record.3, 500);
}

/// When the flat fee is disabled, no tokens are transferred and record.3 == 0.
#[test]
fn test_flat_fee_disabled() {
    let t = setup_with_flat_fees(500);
    t.client
        .configure_flat_fee(&t.token_addr, &t.collector, &500, &false);

    let business = Address::generate(&t.env);
    submit(&t.client, &t.env, &business, "2026-02", 1);

    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 0);
    let record = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-02"))
        .unwrap();
    assert_eq!(record.3, 0);
}

/// A flat fee of 0 results in no transfer and record.3 == 0.
#[test]
fn test_zero_flat_fee() {
    let t = setup_with_flat_fees(0);
    let business = Address::generate(&t.env);
    submit(&t.client, &t.env, &business, "2026-02", 1);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 0);
}

/// The transaction panics when the business has insufficient balance.
/// This ensures no attestation can be recorded without payment.
#[test]
#[should_panic]
fn test_flat_fee_insufficient_balance() {
    let t = setup_with_flat_fees(500);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 499); // 1 stroop short
    submit(&t.client, &t.env, &business, "2026-02", 1);
}

/// Both dynamic and flat fees are collected in a single submission.
/// Each collector receives its configured amount; record.3 == sum.
#[test]
fn test_combined_fees() {
    let t = setup_with_flat_fees(500);
    let dyn_collector = Address::generate(&t.env);
    t.client
        .configure_fees(&t.token_addr, &dyn_collector, &1_000, &true);

    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 2_000);

    submit(&t.client, &t.env, &business, "2026-02", 1);

    // Total = 500 (flat) + 1_000 (dynamic) = 1_500.
    assert_eq!(balance(&t.env, &t.token_addr, &business), 500);
    assert_eq!(balance(&t.env, &t.token_addr, &t.collector), 500);
    assert_eq!(balance(&t.env, &t.token_addr, &dyn_collector), 1_000);

    let record = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-02"))
        .unwrap();
    assert_eq!(record.3, 1_500);
}

// ════════════════════════════════════════════════════════════════════
//  End-to-end token transfer tests
// ════════════════════════════════════════════════════════════════════

// ── Only flat fee enabled ────────────────────────────────────────────

/// When only the flat fee is configured (no dynamic fee), the entire
/// fee_paid amount must land in the flat-fee collector and nowhere else.
#[test]
fn test_only_flat_fee_transfers_to_flat_collector() {
    let t = setup_with_flat_fees(300);
    let business = Address::generate(&t.env);
    mint(&t.env, &t.token_addr, &business, 1_000);

    let collector_before = balance(&t.env, &t.token_addr, &t.collector);
    let business_before = balance(&t.env, &t.token_addr, &business);

    submit(&t.client, &t.env, &business, "2026-03", 2);

    assert_eq!(
        balance(&t.env, &t.token_addr, &business),
        business_before - 300,
        "business should be debited exactly the flat fee"
    );
    assert_eq!(
        balance(&t.env, &t.token_addr, &t.collector),
        collector_before + 300,
        "flat-fee collector should receive exactly the flat fee"
    );

    let record = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-03"))
        .unwrap();
    assert_eq!(
        record.3, 300,
        "fee_paid must equal flat fee when dynamic is absent"
    );
}

// ── Only dynamic fee enabled ─────────────────────────────────────────

/// When only the dynamic fee is configured (no flat fee), the entire
/// fee_paid amount must land in the dynamic-fee collector.
#[test]
fn test_only_dynamic_fee_transfers_to_dynamic_collector() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_addr = deploy_and_fund_token(&env, &business, 5_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Dynamic fee only — no flat fee configured.
    client.configure_fees(&token_addr, &dyn_collector, &1_000, &true);

    let dyn_before = balance(&env, &token_addr, &dyn_collector);
    let biz_before = balance(&env, &token_addr, &business);

    submit(&client, &env, &business, "2026-03", 3);

    assert_eq!(
        balance(&env, &token_addr, &business),
        biz_before - 1_000,
        "business should be debited exactly the dynamic fee"
    );
    assert_eq!(
        balance(&env, &token_addr, &dyn_collector),
        dyn_before + 1_000,
        "dynamic-fee collector should receive exactly the dynamic fee"
    );

    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-03"))
        .unwrap();
    assert_eq!(
        record.3, 1_000,
        "fee_paid must equal dynamic fee when flat is absent"
    );
}

// ── Both fees disabled ───────────────────────────────────────────────

/// When both fee systems are disabled, no tokens move and fee_paid == 0.
/// The business can have zero balance without the transaction panicking.
#[test]
fn test_both_fees_disabled_no_transfer() {
    let t = setup_with_flat_fees(500);
    // Disable flat fee.
    t.client
        .configure_flat_fee(&t.token_addr, &t.collector, &500, &false);

    // Configure dynamic fee but immediately disable it.
    let dyn_collector = Address::generate(&t.env);
    t.client
        .configure_fees(&t.token_addr, &dyn_collector, &1_000, &false);

    // Business has no tokens — any transfer would panic.
    let business = Address::generate(&t.env);
    submit(&t.client, &t.env, &business, "2026-04", 4);

    assert_eq!(
        balance(&t.env, &t.token_addr, &t.collector),
        0,
        "flat-fee collector must receive nothing when disabled"
    );
    assert_eq!(
        balance(&t.env, &t.token_addr, &dyn_collector),
        0,
        "dynamic-fee collector must receive nothing when disabled"
    );

    let record = t
        .client
        .get_attestation(&business, &String::from_str(&t.env, "2026-04"))
        .unwrap();
    assert_eq!(
        record.3, 0,
        "fee_paid must be 0 when both fees are disabled"
    );
}

// ── Combined fees: exact decomposition ──────────────────────────────

/// Verifies that `fee_paid == dynamic_fee + flat_fee` by checking each
/// collector's balance delta independently, then asserting their sum
/// equals the stored `record.3`.
///
/// Uses separate tokens for flat and dynamic fees so each collector's
/// balance delta is unambiguous.
#[test]
fn test_fee_paid_equals_dynamic_plus_flat_exact_decomposition() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let flat_collector = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    // Separate tokens so flat and dynamic balances are unambiguous.
    let flat_token = deploy_and_fund_token(&env, &business, 10_000);
    let dyn_token = deploy_and_fund_token(&env, &business, 10_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Flat fee: 400 stroops in flat_token.
    client.configure_flat_fee(&flat_token, &flat_collector, &400, &true);
    // Dynamic fee: 600 stroops base in dyn_token.
    client.configure_fees(&dyn_token, &dyn_collector, &600, &true);

    let flat_before = balance(&env, &flat_token, &flat_collector);
    let dyn_before = balance(&env, &dyn_token, &dyn_collector);

    submit(&client, &env, &business, "2026-05", 5);

    let flat_delta = balance(&env, &flat_token, &flat_collector) - flat_before;
    let dyn_delta = balance(&env, &dyn_token, &dyn_collector) - dyn_before;

    // Each collector receives exactly its configured fee.
    assert_eq!(flat_delta, 400, "flat collector delta must equal flat fee");
    assert_eq!(
        dyn_delta, 600,
        "dynamic collector delta must equal dynamic fee"
    );

    // Stored fee_paid must equal the sum of both deltas.
    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-05"))
        .unwrap();
    assert_eq!(
        record.3,
        flat_delta + dyn_delta,
        "fee_paid (record.3) must equal flat_delta + dyn_delta"
    );
    assert_eq!(record.3, 1_000);
}

// ── Tier discount reduces dynamic fee ───────────────────────────────

/// A business assigned to a discounted tier pays a reduced dynamic fee.
/// The flat fee is unaffected by tier discounts.
///
/// Formula: `effective = base × (10_000 − tier_bps) × (10_000 − vol_bps) / 100_000_000`
/// With tier_bps = 2_000 (20% off) and base = 1_000_000: effective = 800_000.
#[test]
fn test_tier_discount_reduces_dynamic_fee_and_record() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let flat_collector = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    // Use separate tokens so flat and dynamic fee balances are unambiguous.
    let flat_token = deploy_and_fund_token(&env, &business, 2_000_000);
    let dyn_token = deploy_and_fund_token(&env, &business, 2_000_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Flat fee: 200 stroops in flat_token (unaffected by tier).
    client.configure_flat_fee(&flat_token, &flat_collector, &200, &true);
    // Dynamic fee: 1_000_000 stroops base in dyn_token.
    client.configure_fees(&dyn_token, &dyn_collector, &1_000_000, &true);

    // Tier 1 = 20% discount (2_000 bps).
    // Expected dynamic fee = 1_000_000 × (10_000 − 2_000) × 10_000 / 100_000_000 = 800_000.
    client.set_tier_discount(&1, &2_000);
    client.set_business_tier(&business, &1);

    // Confirm the quote matches the expected discounted fee.
    // get_fee_quote returns dynamic + flat, so: 800_000 + 200 = 800_200.
    assert_eq!(
        client.get_fee_quote(&business),
        800_200,
        "fee quote must reflect tier discount (dynamic 800_000 + flat 200)"
    );

    let dyn_before = balance(&env, &dyn_token, &dyn_collector);
    let flat_before = balance(&env, &flat_token, &flat_collector);

    submit(&client, &env, &business, "2026-06", 6);

    let dyn_delta = balance(&env, &dyn_token, &dyn_collector) - dyn_before;
    let flat_delta = balance(&env, &flat_token, &flat_collector) - flat_before;

    assert_eq!(
        dyn_delta, 800_000,
        "dynamic collector must receive discounted fee"
    );
    assert_eq!(
        flat_delta, 200,
        "flat collector must be unaffected by tier discount"
    );

    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-06"))
        .unwrap();
    assert_eq!(
        record.3, 800_200,
        "fee_paid must equal discounted dynamic (800_000) + flat (200)"
    );
}

// ── Volume discount reduces dynamic fee ─────────────────────────────

/// After crossing a volume bracket threshold, the dynamic fee drops.
/// Verifies collector balance deltas before and after the threshold.
///
/// Bracket: ≥3 attestations → 25% off (2_500 bps).
/// Expected fee after threshold = 1_000 × (10_000 − 2_500) / 10_000 = 750.
#[test]
fn test_volume_discount_reduces_dynamic_fee_after_threshold() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_addr = deploy_and_fund_token(&env, &business, 100_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    client.configure_fees(&token_addr, &dyn_collector, &1_000, &true);
    let thresholds = vec![&env, 3u64];
    let discounts = vec![&env, 2_500u32];
    client.set_volume_brackets(&thresholds, &discounts);

    // Submit 3 attestations at full price (1_000 each).
    for i in 1u8..=3 {
        submit(&client, &env, &business, &std::format!("2026-{:02}", i), i);
    }

    // After 3 submissions the volume bracket kicks in for the 4th.
    assert_eq!(
        client.get_fee_quote(&business),
        750,
        "fee quote must reflect volume discount after threshold"
    );

    let dyn_before = balance(&env, &token_addr, &dyn_collector);
    let biz_before = balance(&env, &token_addr, &business);

    submit(&client, &env, &business, "2026-04", 4);

    let dyn_delta = balance(&env, &token_addr, &dyn_collector) - dyn_before;
    let biz_delta = biz_before - balance(&env, &token_addr, &business);

    assert_eq!(
        dyn_delta, 750,
        "dynamic collector must receive volume-discounted fee"
    );
    assert_eq!(
        biz_delta, 750,
        "business must be debited the discounted fee"
    );

    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-04"))
        .unwrap();
    assert_eq!(
        record.3, 750,
        "fee_paid must equal volume-discounted dynamic fee"
    );
}

// ── Collector balance accumulates across multiple submissions ────────

/// Submitting multiple attestations accumulates fees in the collector.
/// Verifies the running total after each submission.
#[test]
fn test_collector_balance_accumulates_across_submissions() {
    let t = setup_with_flat_fees(250);
    let business = Address::generate(&t.env);
    // Fund enough for 4 submissions.
    mint(&t.env, &t.token_addr, &business, 1_000);

    for i in 1u8..=4 {
        submit(
            &t.client,
            &t.env,
            &business,
            &std::format!("2026-{:02}", i),
            i,
        );

        // After each submission the collector balance grows by 250.
        assert_eq!(
            balance(&t.env, &t.token_addr, &t.collector),
            250 * i as i128,
            "collector balance must grow by flat fee after each submission"
        );
    }

    // Business is fully drained.
    assert_eq!(balance(&t.env, &t.token_addr, &business), 0);
}

// ── Exact pre/post balance delta assertion ───────────────────────────

/// Captures balances before and after submission and asserts the delta
/// equals the fee returned by `get_fee_quote`, providing a tight
/// end-to-end correctness check.
///
/// `get_fee_quote` returns `dynamic + flat`.  Uses separate tokens for
/// flat and dynamic fees so each collector's balance delta is unambiguous.
#[test]
fn test_balance_delta_equals_fee_quote() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let flat_collector = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    // Separate tokens so flat and dynamic balances are unambiguous.
    let flat_token = deploy_and_fund_token(&env, &business, 50_000);
    let dyn_token = deploy_and_fund_token(&env, &business, 50_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Flat: 150 in flat_token, dynamic: 850 in dyn_token.
    client.configure_flat_fee(&flat_token, &flat_collector, &150, &true);
    client.configure_fees(&dyn_token, &dyn_collector, &850, &true);

    // `get_fee_quote` returns dynamic + flat = 850 + 150 = 1_000.
    let total_quote = client.get_fee_quote(&business);
    assert_eq!(
        total_quote, 1_000,
        "get_fee_quote must return dynamic + flat"
    );

    let flat_before = balance(&env, &flat_token, &flat_collector);
    let dyn_before = balance(&env, &dyn_token, &dyn_collector);

    submit(&client, &env, &business, "2026-07", 7);

    let flat_delta = balance(&env, &flat_token, &flat_collector) - flat_before;
    let dyn_delta = balance(&env, &dyn_token, &dyn_collector) - dyn_before;

    // Each collector receives exactly its configured fee.
    assert_eq!(flat_delta, 150, "flat delta must equal configured flat fee");
    assert_eq!(
        dyn_delta, 850,
        "dynamic delta must equal configured dynamic fee"
    );

    // Sum of deltas must equal the pre-submission quote.
    assert_eq!(
        flat_delta + dyn_delta,
        total_quote,
        "flat_delta + dyn_delta must equal get_fee_quote"
    );

    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-07"))
        .unwrap();
    assert_eq!(record.3, total_quote, "fee_paid must equal get_fee_quote");
    assert_eq!(record.3, 1_000);
}

// ── Tier + volume combined discount ─────────────────────────────────

/// Applies both a tier discount and a volume discount simultaneously.
/// Verifies the multiplicative formula:
///
/// ```text
/// effective = base × (10_000 − tier_bps) × (10_000 − vol_bps) / 100_000_000
/// ```
///
/// With base = 1_000_000, tier_bps = 2_000, vol_bps = 1_000:
/// effective = 1_000_000 × 8_000 × 9_000 / 100_000_000 = 720_000.
#[test]
fn test_tier_and_volume_combined_discount_balance_delta() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let dyn_collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_addr = deploy_and_fund_token(&env, &business, 100_000_000);

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    // Base fee: 1_000_000.  Tier 1: 20% off.  Volume bracket ≥2: 10% off.
    client.configure_fees(&token_addr, &dyn_collector, &1_000_000, &true);
    client.set_tier_discount(&1, &2_000);
    client.set_business_tier(&business, &1);

    let thresholds = vec![&env, 2u64];
    let discounts = vec![&env, 1_000u32];
    client.set_volume_brackets(&thresholds, &discounts);

    // First two submissions at tier-only discount (800_000 each).
    for i in 1u8..=2 {
        submit(&client, &env, &business, &std::format!("2026-{:02}", i), i);
    }

    // Third submission: both discounts apply → 720_000.
    assert_eq!(client.get_fee_quote(&business), 720_000);

    let dyn_before = balance(&env, &token_addr, &dyn_collector);
    let biz_before = balance(&env, &token_addr, &business);

    submit(&client, &env, &business, "2026-03", 3);

    let dyn_delta = balance(&env, &token_addr, &dyn_collector) - dyn_before;
    let biz_delta = biz_before - balance(&env, &token_addr, &business);

    assert_eq!(dyn_delta, 720_000, "combined discount must yield 720_000");
    assert_eq!(biz_delta, 720_000);

    let record = client
        .get_attestation(&business, &String::from_str(&env, "2026-03"))
        .unwrap();
    assert_eq!(
        record.3, 720_000,
        "fee_paid must equal combined-discounted fee"
    );
}

/// End-to-end SAC-backed fee transfer integration.
///
/// Uses the actual Stellar Asset contract id as the fee token and reads
/// collector balance via the SAC client.
#[test]
fn test_sac_integration_fee_transfer_reads_collector_balance_via_sac_client() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    client.configure_flat_fee(&token_addr, &collector, &250, &true);
    client.configure_fees(&token_addr, &collector, &750, &true);

    mint(&env, &token_addr, &business, 2_000);
    let collector_before = sac_balance(&env, &token_addr, &collector);

    submit(&client, &env, &business, "2026-09", 9);

    assert_eq!(
        sac_balance(&env, &token_addr, &collector),
        collector_before + 1_000,
        "collector must receive dynamic + flat fees through the SAC contract"
    );

    let record = client.get_attestation(&business, &String::from_str(&env, "2026-09")).unwrap();
    assert_eq!(record.3, 1_000);
}

/// The fee transfer must succeed even when no allowance is set on the SAC.
#[test]
fn test_sac_integration_unset_allowance_does_not_block_direct_fee_transfer() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    client.configure_fees(&token_addr, &collector, &500, &true);

    mint(&env, &token_addr, &business, 1_000);
    assert_eq!(sac_allowance(&env, &token_addr, &business, &contract_id), 0);

    submit(&client, &env, &business, "2026-10", 10);

    assert_eq!(
        sac_balance(&env, &token_addr, &collector),
        500,
        "collector must receive the fee even with no allowance"
    );

    let record = client.get_attestation(&business, &String::from_str(&env, "2026-10")).unwrap();
    assert_eq!(record.3, 500);
}

/// The SAC integration must fail when the payer's balance is insufficient.
#[test]
#[should_panic]
fn test_sac_integration_insufficient_balance_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    client.configure_fees(&token_addr, &collector, &1_000, &true);

    mint(&env, &token_addr, &business, 999);
    submit(&client, &env, &business, "2026-11", 11);
}

/// The SAC integration must fail when the payer is deauthorized by the token admin.
#[test]
#[should_panic]
fn test_sac_integration_deauthorized_token_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    client.configure_fees(&token_addr, &collector, &500, &true);

    mint(&env, &token_addr, &business, 1_000);
    StellarAssetClient::new(&env, &token_addr).set_authorized(&business, &false);

    submit(&client, &env, &business, "2026-12", 12);
}

/// If a fee configuration rounds to zero, the SAC collector receives nothing
/// and the recorded fee remains zero.
#[test]
fn test_sac_integration_rounds_to_zero_with_high_discounts() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let collector = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    client.configure_fees(&token_addr, &collector, &1, &true);
    client.set_tier_discount(&1, &9_900);
    client.set_business_tier(&business, &1);
    let thresholds = vec![&env, 1u64];
    let discounts = vec![&env, 1_000u32];
    client.set_volume_brackets(&thresholds, &discounts);

    mint(&env, &token_addr, &business, 1_000);

    // After applying both discounts, the dynamic fee should truncate to zero.
    assert_eq!(client.get_fee_quote(&business), 0);

    submit(&client, &env, &business, "2027-01", 13);

    assert_eq!(sac_balance(&env, &token_addr, &collector), 0);
    let record = client.get_attestation(&business, &String::from_str(&env, "2027-01")).unwrap();
    assert_eq!(record.3, 0);
}

/// A fee collector may equal the business address; the contract must still
/// record the fee correctly and preserve the business's own balance.
#[test]
fn test_sac_integration_collector_equal_to_business_records_fee() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let business = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_addr = token_contract.address().clone();

    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);

    client.configure_fees(&token_addr, &business, &500, &true);

    mint(&env, &token_addr, &business, 1_000);
    let before = sac_balance(&env, &token_addr, &business);

    submit(&client, &env, &business, "2027-02", 14);

    assert_eq!(sac_balance(&env, &token_addr, &business), before, "self-transfer should preserve business balance");
    let record = client.get_attestation(&business, &String::from_str(&env, "2027-02")).unwrap();
    assert_eq!(record.3, 500);
}
