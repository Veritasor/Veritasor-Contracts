//! Fee bucket reconciliation: stored `fee_paid` must match pre-submit `get_fee_quote`.
//!
//! Issue #374 — confirms no drift between quote (`calculate_fee` + `calculate_flat_fee`)
//! and collection (`collect_fee_from` + `collect_flat_fee`) at submission time.

#![cfg(test)]

extern crate std;

use super::*;
use crate::dynamic_fees::compute_fee;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{vec, Address, Env, String};

struct Ctx {
    env: Env,
    client: AttestationContractClient<'static>,
    admin: Address,
}

fn fresh_ctx() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    Ctx {
        env,
        client,
        admin,
    }
}

fn deploy_and_fund(env: &Env, to: &Address, amount: i128) -> Address {
    let token_admin = Address::generate(env);
    let token = env
        .register_stellar_asset_contract_v2(token_admin)
        .address()
        .clone();
    StellarAssetClient::new(env, &token).mint(to, &amount);
    token
}

fn submit(
    client: &AttestationContractClient,
    env: &Env,
    business: &Address,
    period: &str,
    root_byte: u8,
) {
    let period_s = String::from_str(env, period);
    let root = BytesN::from_array(env, &[root_byte; 32]);
    client.submit_attestation(
        business,
        &period_s,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
}

/// Snapshot quote, submit, assert storage and event match the pre-call quote.
fn assert_reconciles_with_quote(
    ctx: &Ctx,
    business: &Address,
    period: &str,
    root_byte: u8,
    dyn_token: Option<&Address>,
) {
    let quote_before = ctx.client.get_fee_quote(business);
    let (_base, tier_bps, vol_bps, dynamic, flat) =
        ctx.client.get_fee_quote_detailed(business);
    assert_eq!(
        quote_before,
        dynamic + flat,
        "get_fee_quote must equal dynamic + flat components"
    );

    if dynamic > 0 {
        let expected_dynamic = compute_fee(_base, tier_bps, vol_bps);
        assert_eq!(
            dynamic, expected_dynamic,
            "quoted dynamic fee must match compute_fee formula"
        );
    }

    if let Some(token) = dyn_token {
        let collector = ctx
            .client
            .get_fee_config()
            .expect("dynamic fee configured")
            .collector;
        let before = TokenClient::new(&ctx.env, token).balance(&collector);
        submit(&ctx.client, &ctx.env, business, period, root_byte);
        let collected = TokenClient::new(&ctx.env, token).balance(&collector) - before;
        assert_eq!(collected, dynamic, "dynamic collector delta must match quote");
    } else {
        submit(&ctx.client, &ctx.env, business, period, root_byte);
    }

    let period_s = String::from_str(&ctx.env, period);
    let stored = ctx
        .client
        .get_attestation(business, &period_s)
        .expect("attestation must exist");
    assert_eq!(
        stored.3, quote_before,
        "stored fee_paid must equal pre-submit get_fee_quote"
    );

}

// ── Flat fee variants ───────────────────────────────────────────────

#[test]
fn reconcile_flat_fee_enabled() {
    let ctx = fresh_ctx();
    let business = Address::generate(&ctx.env);
    let collector = Address::generate(&ctx.env);
    let token = deploy_and_fund(&ctx.env, &business, 10_000);
    ctx.client
        .configure_flat_fee(&token, &collector, &250, &true);
    assert_reconciles_with_quote(&ctx, &business, "2026-01", 1, None);
}

#[test]
fn reconcile_flat_fee_disabled() {
    let ctx = fresh_ctx();
    let business = Address::generate(&ctx.env);
    let collector = Address::generate(&ctx.env);
    let token = deploy_and_fund(&ctx.env, &business, 0);
    ctx.client
        .configure_flat_fee(&token, &collector, &250, &false);
    assert_eq!(ctx.client.get_fee_quote(&business), 0);
    assert_reconciles_with_quote(&ctx, &business, "2026-01", 1, None);
}

// ── Dynamic fee + tier / volume permutations ──────────────────────────

#[test]
fn reconcile_tier_and_volume_discount_grid() {
    const TIERS: &[(u32, u32)] = &[(0, 0), (1, 2_000), (2, 5_000), (0, 10_000)];
    const VOL_BPS: &[u32] = &[0, 2_500, 5_000, 10_000];

    for (tier, tier_bps) in TIERS {
        for &vol_bps in VOL_BPS {
            let ctx = fresh_ctx();
            let business = Address::generate(&ctx.env);
            let collector = Address::generate(&ctx.env);
            let token = deploy_and_fund(&ctx.env, &business, 1_000_000_000_000);
            ctx.client.configure_fees(&token, &collector, &1_000_000, &true);
            if *tier_bps > 0 {
                ctx.client.set_tier_discount(tier, tier_bps);
                ctx.client.set_business_tier(&business, tier);
            }
            if vol_bps > 0 {
                let thresholds = vec![&ctx.env, 1u64];
                let discounts = vec![&ctx.env, vol_bps];
                ctx.client.set_volume_brackets(&thresholds, &discounts);
                submit(&ctx.client, &ctx.env, &business, "2026-00", 0);
            }
            assert_reconciles_with_quote(&ctx, &business, "2026-01", 1, Some(&token));
        }
    }
}

#[test]
fn reconcile_combined_dynamic_and_flat() {
    let ctx = fresh_ctx();
    let business = Address::generate(&ctx.env);
    let flat_collector = Address::generate(&ctx.env);
    let dyn_collector = Address::generate(&ctx.env);
    let flat_token = deploy_and_fund(&ctx.env, &business, 50_000);
    let dyn_token = deploy_and_fund(&ctx.env, &business, 50_000);
    ctx.client
        .configure_flat_fee(&flat_token, &flat_collector, &300, &true);
    ctx.client
        .configure_fees(&dyn_token, &dyn_collector, &700, &true);
    assert_reconciles_with_quote(&ctx, &business, "2026-02", 2, Some(&dyn_token));
}

#[test]
fn reconcile_dynamic_truncated_to_zero_flat_positive() {
    let ctx = fresh_ctx();
    let business = Address::generate(&ctx.env);
    let flat_collector = Address::generate(&ctx.env);
    let dyn_collector = Address::generate(&ctx.env);
    let flat_token = deploy_and_fund(&ctx.env, &business, 10_000);
    let dyn_token = deploy_and_fund(&ctx.env, &business, 10_000);
    ctx.client
        .configure_flat_fee(&flat_token, &flat_collector, &500, &true);
    ctx.client.configure_fees(&dyn_token, &dyn_collector, &1, &true);
    ctx.client.set_tier_discount(&0, &9_999);

    let quote = ctx.client.get_fee_quote(&business);
    let (_, _, _, dynamic, flat) = ctx.client.get_fee_quote_detailed(&business);
    assert_eq!(dynamic, 0, "discounts must truncate tiny base_fee to 0");
    assert_eq!(flat, 500);
    assert_eq!(quote, 500);

    assert_reconciles_with_quote(&ctx, &business, "2026-03", 3, Some(&dyn_token));
}

// ── Property-based sweep ────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_stored_fee_matches_quote(
        base_fee in 0i128..=1_000_000_000i128,
        tier_bps in 0u32..=10_000u32,
        vol_bps in 0u32..=10_000u32,
        flat_amount in 0i128..=100_000i128,
        flat_enabled in proptest::bool::ANY,
    ) {
        let ctx = fresh_ctx();
        let business = Address::generate(&ctx.env);
        let dyn_collector = Address::generate(&ctx.env);
        let flat_collector = Address::generate(&ctx.env);
        let dyn_token = deploy_and_fund(&ctx.env, &business, 0);
        let flat_token = deploy_and_fund(&ctx.env, &business, 0);

        ctx.client.configure_fees(&dyn_token, &dyn_collector, &base_fee, &true);
        ctx.client.set_tier_discount(&1, &tier_bps);
        ctx.client.set_business_tier(&business, &1);
        if vol_bps > 0 {
            let thresholds = vec![&ctx.env, 1u64];
            let discounts = vec![&ctx.env, vol_bps];
            ctx.client.set_volume_brackets(&thresholds, &discounts);
            let warm_quote = ctx.client.get_fee_quote(&business);
            StellarAssetClient::new(&ctx.env, &dyn_token).mint(&business, &warm_quote.saturating_add(1_000_000));
            if flat_enabled && flat_amount > 0 {
                StellarAssetClient::new(&ctx.env, &flat_token).mint(&business, &flat_amount.saturating_add(1_000_000));
            }
            submit(&ctx.client, &ctx.env, &business, "2026-warm", 8);
        }
        ctx.client.configure_flat_fee(
            &flat_token,
            &flat_collector,
            &flat_amount,
            &flat_enabled,
        );

        let quote = ctx.client.get_fee_quote(&business);
        let fund = quote.saturating_mul(2).saturating_add(10_000_000);
        StellarAssetClient::new(&ctx.env, &dyn_token).mint(&business, &fund);
        if flat_enabled && flat_amount > 0 {
            StellarAssetClient::new(&ctx.env, &flat_token).mint(&business, &fund);
        }
        let (_, _, _, dynamic, flat) = ctx.client.get_fee_quote_detailed(&business);
        prop_assert_eq!(quote, dynamic + flat);

        submit(&ctx.client, &ctx.env, &business, "2026-prop", 9);
        let stored = ctx.client
            .get_attestation(&business, &String::from_str(&ctx.env, "2026-prop"))
            .unwrap();
        prop_assert_eq!(stored.3, quote);
    }
}
