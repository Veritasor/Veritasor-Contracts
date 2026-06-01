//! Security tests for `submit_attestations_batch` authorization deduplication.
//!
//! The dedup loop tracks **business addresses** (`b == item.business`). Authorization
//! for business A must never satisfy `require_auth()` for business B. Soroban evaluates
//! `require_auth` per address at each call site; there is no cross-address reuse.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, IntoVal, String, Symbol, Vec};
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Ctx {
    env: Env,
    client: AttestationContractClient<'static>,
    contract_id: Address,
    admin: Address,
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    Ctx {
        env,
        client,
        contract_id,
        admin,
    }
}

fn register_and_approve(ctx: &Ctx, business: &Address) {
    ctx.client
        .grant_role(&ctx.admin, business, &ROLE_BUSINESS);
    ctx.client.register_business(
        business,
        &BytesN::from_array(&ctx.env, &[1u8; 32]),
        &Symbol::new(&ctx.env, "US"),
        &Vec::new(&ctx.env),
    );
    ctx.client.approve_business(&ctx.admin, business);
}

fn batch_item(
    env: &Env,
    business: &Address,
    period: &str,
    root_byte: u8,
) -> BatchAttestationItem {
    let mut root = [0u8; 32];
    root[0] = root_byte;
    BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(env, period),
        merkle_root: BytesN::from_array(env, &root),
        timestamp: 1_700_000_000,
        version: 1,
        proof_hash: None,
        expiry_timestamp: None,
    }
}

/// Submit with selective mocks (negative / impersonation tests).
fn mock_batch_submit(
    ctx: &Ctx,
    authorized: &[Address],
    items: &Vec<BatchAttestationItem>,
) {
    let invoke = MockAuthInvoke {
        contract: &ctx.contract_id,
        fn_name: "submit_attestations_batch",
        args: (items.clone(),).into_val(&ctx.env),
        sub_invokes: &[],
    };
    let mocks: std::vec::Vec<MockAuth> = authorized
        .iter()
        .map(|addr| MockAuth {
            address: addr,
            invoke: &invoke,
        })
        .collect();
    ctx.client
        .mock_auths(&mocks)
        .submit_attestations_batch(items);
}

/// Submit when every business in the batch is expected to authorize (positive paths).
/// Relies on `setup()` having enabled `mock_all_auths` for the whole test.
fn submit_batch_all_businesses_authed(ctx: &Ctx, items: &Vec<BatchAttestationItem>) {
    ctx.client.submit_attestations_batch(items);
}

fn count_auths_for(env: &Env, addr: &Address) -> usize {
    env.auths()
        .iter()
        .filter(|(a, _)| a == addr)
        .count()
}

#[test]
fn test_batch_same_business_twice_succeeds() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    register_and_approve(&ctx, &business);

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &business, "2026-01", 1));
    items.push_back(batch_item(&ctx.env, &business, "2026-02", 2));

    submit_batch_all_businesses_authed(&ctx, &items);

    assert!(ctx
        .client
        .get_attestation(&business, &String::from_str(&ctx.env, "2026-01"))
        .is_some());
    assert!(ctx
        .client
        .get_attestation(&business, &String::from_str(&ctx.env, "2026-02"))
        .is_some());
}

#[test]
fn test_batch_same_business_auth_observed_once_in_dedup_phase() {
    let ctx = setup();
    let business = Address::generate(&ctx.env);
    register_and_approve(&ctx, &business);

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &business, "2026-01", 1));
    items.push_back(batch_item(&ctx.env, &business, "2026-02", 2));
    items.push_back(batch_item(&ctx.env, &business, "2026-03", 3));

    submit_batch_all_businesses_authed(&ctx, &items);

    // Dedup loop: one require_auth per unique business; validation does not re-auth
    // when called from submit_attestations_batch (see require_business_auth flag).
    let auth_count = count_auths_for(&ctx.env, &business);
    assert_eq!(
        auth_count, 1,
        "expected exactly one require_auth for one business with 3 items in the dedup loop"
    );
}

#[test]
#[should_panic]
fn test_batch_second_business_unauthorized_panics() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    register_and_approve(&ctx, &biz_a);
    register_and_approve(&ctx, &biz_b);

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &biz_a, "2026-01", 1));
    items.push_back(batch_item(&ctx.env, &biz_b, "2026-01", 2));

    ctx.env.mock_auths(&[]);
    mock_batch_submit(&ctx, &[biz_a.clone()], &items);
}

#[test]
fn test_batch_second_business_unauthorized_no_partial_write() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    register_and_approve(&ctx, &biz_a);
    register_and_approve(&ctx, &biz_b);

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &biz_a, "2026-01", 1));
    items.push_back(batch_item(&ctx.env, &biz_b, "2026-01", 2));

    ctx.env.mock_auths(&[]);
    let result =
        catch_unwind(AssertUnwindSafe(|| mock_batch_submit(&ctx, &[biz_a.clone()], &items)));
    assert!(result.is_err(), "unauthorized business B must fail the batch");

    assert!(ctx
        .client
        .get_attestation(&biz_b, &String::from_str(&ctx.env, "2026-01"))
        .is_none());
}

#[test]
#[should_panic]
fn test_batch_reverse_order_unauthorized_panics() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    register_and_approve(&ctx, &biz_a);
    register_and_approve(&ctx, &biz_b);

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &biz_b, "2026-01", 2));
    items.push_back(batch_item(&ctx.env, &biz_a, "2026-01", 1));

    ctx.env.mock_auths(&[]);
    mock_batch_submit(&ctx, &[biz_a.clone()], &items);
}

#[test]
#[should_panic]
fn test_batch_three_businesses_only_two_authed_panics() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    let biz_c = Address::generate(&ctx.env);
    for b in [&biz_a, &biz_b, &biz_c] {
        register_and_approve(&ctx, b);
    }

    let mut items = Vec::new(&ctx.env);
    items.push_back(batch_item(&ctx.env, &biz_a, "2026-01", 1));
    items.push_back(batch_item(&ctx.env, &biz_b, "2026-02", 2));
    items.push_back(batch_item(&ctx.env, &biz_c, "2026-03", 3));

    ctx.env.mock_auths(&[]);
    mock_batch_submit(&ctx, &[biz_a.clone(), biz_b.clone()], &items);
}

#[test]
fn test_batch_max_25_three_businesses_all_authed_succeeds() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    let biz_c = Address::generate(&ctx.env);
    for b in [&biz_a, &biz_b, &biz_c] {
        register_and_approve(&ctx, b);
    }

    let businesses = [&biz_a, &biz_b, &biz_c];
    let counts = [9usize, 8, 8];
    let mut items = Vec::new(&ctx.env);
    for (b_idx, count) in counts.iter().enumerate() {
        for p_idx in 0..*count {
            let period = std::format!("B{}-P{}", b_idx, p_idx);
            items.push_back(batch_item(
                &ctx.env,
                businesses[b_idx],
                &period,
                (b_idx * 10 + p_idx) as u8,
            ));
        }
    }
    assert_eq!(items.len(), 25);

    submit_batch_all_businesses_authed(&ctx, &items);

    assert_eq!(ctx.client.get_business_count(&biz_a), 9);
    assert_eq!(ctx.client.get_business_count(&biz_b), 8);
    assert_eq!(ctx.client.get_business_count(&biz_c), 8);
}

#[test]
fn test_batch_max_25_partial_auth_panics() {
    let ctx = setup();
    let biz_a = Address::generate(&ctx.env);
    let biz_b = Address::generate(&ctx.env);
    let biz_c = Address::generate(&ctx.env);
    for b in [&biz_a, &biz_b, &biz_c] {
        register_and_approve(&ctx, b);
    }

    let businesses = [&biz_a, &biz_b, &biz_c];
    let counts = [9usize, 8, 8];
    let mut items = Vec::new(&ctx.env);
    for (b_idx, count) in counts.iter().enumerate() {
        for p_idx in 0..*count {
            let period = std::format!("B{}-P{}", b_idx, p_idx);
            items.push_back(batch_item(
                &ctx.env,
                businesses[b_idx],
                &period,
                (b_idx * 10 + p_idx) as u8,
            ));
        }
    }

    ctx.env.mock_auths(&[]);
    let result = catch_unwind(AssertUnwindSafe(|| {
        mock_batch_submit(&ctx, &[biz_a.clone(), biz_b.clone()], &items);
    }));
    assert!(result.is_err(), "third business must not be authorized");

    assert_eq!(ctx.client.get_business_count(&biz_a), 0);
    assert_eq!(ctx.client.get_business_count(&biz_b), 0);
    assert_eq!(ctx.client.get_business_count(&biz_c), 0);
}
