#![cfg(test)]

extern crate std;

use super::*;
use crate::access_control;
use crate::registry;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String as SorobanString, Symbol, Vec};
use std::any::Any;
use std::boxed::Box;
use std::panic::catch_unwind;
use std::string::String as StdString;

fn panic_message(panic: Box<dyn Any + Send>) -> StdString {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<StdString>() {
        s.clone()
    } else {
        StdString::from("unknown panic")
    }
}

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&admin, &0u64);
    access_control::grant_role(&env, &admin, ROLE_ADMIN, &admin);
    (env, client, admin)
}

fn register_pending_business(env: &Env, business: &Address) {
    access_control::grant_role(env, business, ROLE_BUSINESS, business);
    let name_hash = BytesN::from_array(env, &[0u8; 32]);
    let tags: Vec<Symbol> = Vec::new(env);
    registry::register_business(env, business, name_hash, symbol_short!("US"), tags);
}

fn approve_business(env: &Env, admin: &Address, business: &Address) {
    registry::approve_business(env, admin, business);
}

fn suspend_business(env: &Env, admin: &Address, business: &Address) {
    registry::suspend_business(env, admin, business, symbol_short!("test"));
}

#[test]
fn test_submit_attestation_rejects_unregistered_business() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = SorobanString::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    let result = catch_unwind(|| {
        client.submit_attestation(
            &business,
            &period,
            &root,
            &1_700_000_000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    });

    assert!(result.is_err(), "unregistered business should panic");
    assert_eq!(
        panic_message(result.unwrap_err()),
        String::from("business not registered")
    );
}

#[test]
fn test_submit_attestation_rejects_pending_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);
    let period = SorobanString::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[2u8; 32]);

    let result = catch_unwind(|| {
        client.submit_attestation(
            &business,
            &period,
            &root,
            &1_700_000_000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    });

    assert!(result.is_err(), "pending business should panic");
    assert_eq!(
        panic_message(result.unwrap_err()),
        String::from("business pending approval")
    );

    // Confirm no attestation was stored for the pending business.
    assert!(client.get_attestation(&business, &period).is_none());
}

#[test]
fn test_submit_attestation_rejects_suspended_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);
    approve_business(&env, &admin, &business);
    suspend_business(&env, &admin, &business);

    let period = SorobanString::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[3u8; 32]);

    let result = catch_unwind(|| {
        client.submit_attestation(
            &business,
            &period,
            &root,
            &1_700_000_000u64,
            &1u32,
            &0i128,
            &None,
            &None,
        );
    });

    assert!(result.is_err(), "suspended business should panic");
    assert_eq!(
        panic_message(result.unwrap_err()),
        String::from("business is suspended")
    );
}

#[test]
fn test_submit_attestation_accepts_active_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);
    approve_business(&env, &admin, &business);

    let period = SorobanString::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[4u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    let stored = client.get_attestation(&business, &period).expect("expected attestation");
    assert_eq!(stored.0, root);
}

#[test]
fn test_submit_attestation_accepts_reactivated_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);
    approve_business(&env, &admin, &business);
    suspend_business(&env, &admin, &business);
    registry::reactivate_business(&env, &admin, &business);

    let period = SorobanString::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[5u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    assert!(client.get_attestation(&business, &period).is_some());
}

#[test]
fn test_submit_attestations_batch_rejects_pending_business() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);

    let mut items = Vec::new(&env);
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: SorobanString::from_str(&env, "2026-01"),
        merkle_root: BytesN::from_array(&env, &[6u8; 32]),
        timestamp: 1_700_000_000,
        version: 1,
        expiry_timestamp: None,
    });

    let result = catch_unwind(std::panic::AssertUnwindSafe(|| client.submit_attestations_batch(&items)));
    assert!(result.is_err(), "pending business in batch should panic");
    assert_eq!(
        panic_message(result.unwrap_err()),
        String::from("business pending approval")
    );
}

#[test]
fn test_submit_attestations_batch_accepts_reactivated_business() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    register_pending_business(&env, &business);
    approve_business(&env, &admin, &business);
    suspend_business(&env, &admin, &business);
    registry::reactivate_business(&env, &admin, &business);

    let mut items = Vec::new(&env);
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: SorobanString::from_str(&env, "2026-02"),
        merkle_root: BytesN::from_array(&env, &[7u8; 32]),
        timestamp: 1_700_008_640,
        version: 1,
        expiry_timestamp: None,
    });

    client.submit_attestations_batch(&items);
    assert!(client
        .get_attestation(&business, &SorobanString::from_str(&env, "2026-02"))
        .is_some());
}


