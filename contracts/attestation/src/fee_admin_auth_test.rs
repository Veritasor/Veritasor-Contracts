//! Tests that every fee configuration method rejects non-admin callers
//! and succeeds for the admin.

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Vec};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// ── Uninitialized contract ────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_configure_fees_uninitialized_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &0i128, &false);
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_set_fee_enabled_uninitialized_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.set_fee_enabled(&false);
}

// ── Non-admin rejection ───────────────────────────────────────────────────────
// Each test clears all mocked auths after init so admin.require_auth() fails.

#[test]
#[should_panic]
fn test_non_admin_cannot_configure_fees() {
    let (env, client, _admin) = setup();
    env.mock_auths(&[]);
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &100i128, &true);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_set_tier_discount() {
    let (env, client, _admin) = setup();
    env.mock_auths(&[]);
    client.set_tier_discount(&0u32, &500u32);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_set_business_tier() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    env.mock_auths(&[]);
    client.set_business_tier(&business, &1u32);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_set_volume_brackets() {
    let (env, client, _admin) = setup();
    env.mock_auths(&[]);
    let thresholds: Vec<u64> = Vec::new(&env);
    let discounts: Vec<u32> = Vec::new(&env);
    client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_set_fee_enabled() {
    let (env, client, _admin) = setup();
    env.mock_auths(&[]);
    client.set_fee_enabled(&false);
}

#[test]
#[should_panic]
fn test_non_admin_cannot_configure_flat_fee() {
    let (env, client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    env.mock_auths(&[]);
    client.configure_flat_fee(&token, &collector, &50i128, &true);
}

// ── Admin success path ────────────────────────────────────────────────────────

#[test]
fn test_admin_can_configure_fees() {
    let (env, client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    // fee_quote for a fresh business should reflect the configured base fee
    let business = Address::generate(&env);
    client.configure_fees(&token, &collector, &1000i128, &true);
    assert_eq!(client.get_fee_quote(&business), 1000i128);
}

#[test]
fn test_admin_can_set_tier_discount() {
    let (_env, client, _admin) = setup();
    // Should not panic
    client.set_tier_discount(&1u32, &2000u32);
}

#[test]
fn test_admin_can_set_business_tier() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    // Should not panic
    client.set_business_tier(&business, &2u32);
}

#[test]
fn test_admin_can_set_volume_brackets() {
    let (env, client, _admin) = setup();
    let mut thresholds: Vec<u64> = Vec::new(&env);
    thresholds.push_back(10u64);
    let mut discounts: Vec<u32> = Vec::new(&env);
    discounts.push_back(500u32);
    client.set_volume_brackets(&thresholds, &discounts);
}

#[test]
fn test_admin_can_toggle_fee_enabled() {
    let (env, client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_fees(&token, &collector, &500i128, &true);

    // Disable — fee quote drops to zero
    client.set_fee_enabled(&false);
    let business = Address::generate(&env);
    assert_eq!(client.get_fee_quote(&business), 0i128);

    // Re-enable — fee quote returns
    client.set_fee_enabled(&true);
    assert_eq!(client.get_fee_quote(&business), 500i128);
}

#[test]
fn test_admin_can_configure_flat_fee() {
    let (env, client, _admin) = setup();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    client.configure_flat_fee(&token, &collector, &250i128, &true);
    let config = client.get_flat_fee_config().unwrap();
    assert_eq!(config.amount, 250);
    assert!(config.enabled);
}
