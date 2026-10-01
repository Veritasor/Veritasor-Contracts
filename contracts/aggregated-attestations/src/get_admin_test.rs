//! # Adversarial coverage for `get_admin`
//!
//! `get_admin` is the only unauthenticated read of the contract's governance
//! authority: it backs every `require_admin` check, the time-locked rotation
//! flow, and off-chain monitors that assert the configured admin has not
//! silently changed. This suite pins its observable contract beyond the happy
//! path:
//!
//! - the returned value is exactly the address written by `initialize`;
//! - an uninitialized contract is a hard error rather than a zero address;
//! - **rejected** operations leave the admin untouched (non-admin caller,
//!   early activation, duplicate `initialize`);
//! - the admin only flips once the rotation time-lock has actually expired,
//!   and the pending slot is cleared atomically;
//! - `get_admin` is side-effect free — repeated reads return the same value
//!   and consume no replay nonce;
//! - two contract instances in the same environment never leak admins.

#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

/// Deploy a fresh aggregated-attestations contract without initializing it.
fn deploy<'a>(env: &'a Env) -> AggregatedAttestationsContractClient<'a> {
    let id = env.register(AggregatedAttestationsContract, ());
    AggregatedAttestationsContractClient::new(env, &id)
}

#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);

    client.initialize(&admin, &0u64);

    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_get_admin_errors_before_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    // No admin is configured yet: the read must fail loudly (`contract not
    // initialized`) instead of returning some default/zero address that an
    // off-chain monitor would mistake for a real authority.
    let result = client.try_get_admin();
    assert!(result.is_err(), "get_admin must fail before initialize");
}

#[test]
fn test_get_admin_unchanged_after_non_admin_rotation_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);
    client.initialize(&admin, &0u64);

    let attacker = Address::generate(&env);
    let replacement = Address::generate(&env);

    // `require_admin` must reject the caller before the nonce is consumed.
    let nonce_before = client.get_replay_nonce(&attacker, &NONCE_CHANNEL_ADMIN_ROTATION);
    let result = client.try_set_pending_admin(&attacker, &0u64, &replacement, &1_000u64);
    assert!(result.is_err(), "non-admin rotation must be rejected");

    assert_eq!(client.get_admin(), admin);
    assert_eq!(
        client.get_replay_nonce(&attacker, &NONCE_CHANNEL_ADMIN_ROTATION),
        nonce_before,
        "rejected rotation must not burn the caller's replay nonce"
    );
}

#[test]
fn test_get_admin_unchanged_after_early_activation_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);
    client.initialize(&admin, &0u64);

    let replacement = Address::generate(&env);
    let delay = 1_000u64;
    client.set_pending_admin(&admin, &0u64, &replacement, &delay);

    // Activating before the time-lock expires must not promote the pending admin.
    let result = client.try_activate_admin();
    assert!(result.is_err(), "early activation must be rejected");
    assert_eq!(client.get_admin(), admin);

    // The pending proposal survives the rejection, so a later (valid) activation works.
    env.ledger().with_mut(|l| l.timestamp += delay + 1);
    client.activate_admin();
    assert_eq!(client.get_admin(), replacement);
}

#[test]
fn test_get_admin_flips_only_after_timelock_and_clears_pending() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);
    client.initialize(&admin, &0u64);

    let replacement = Address::generate(&env);
    let delay = 500u64;
    client.set_pending_admin(&admin, &0u64, &replacement, &delay);

    // Still the incumbent immediately after the proposal; the time-lock has
    // not been observed to have elapsed.
    assert_eq!(client.get_admin(), admin);

    env.ledger().with_mut(|l| l.timestamp += delay + 1);
    client.activate_admin();
    assert_eq!(client.get_admin(), replacement);

    // Pending slot was consumed: a second activation has nothing to promote.
    assert!(client.try_activate_admin().is_err());
    assert_eq!(client.get_admin(), replacement);
}

#[test]
fn test_get_admin_unchanged_after_duplicate_initialize_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);
    client.initialize(&admin, &0u64);

    let impostor = Address::generate(&env);
    let result = client.try_initialize(&impostor, &0u64);

    assert!(result.is_err(), "re-initialize must be rejected");
    assert_eq!(
        client.get_admin(),
        admin,
        "rejected re-initialize must not overwrite the admin"
    );
}

#[test]
fn test_get_admin_is_side_effect_free_read() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = deploy(&env);
    client.initialize(&admin, &0u64);

    // `initialize` consumed nonce 0 on the admin channel, so the next expected
    // nonce is 1. Pure reads must never advance it.
    let nonce_before = client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN);
    assert_eq!(nonce_before, 1);

    for _ in 0..5 {
        assert_eq!(client.get_admin(), admin);
    }

    assert_eq!(
        client.get_replay_nonce(&admin, &NONCE_CHANNEL_ADMIN),
        nonce_before,
        "repeated get_admin calls must not consume replay nonces"
    );
}

#[test]
fn test_get_admin_is_isolated_per_contract_instance() {
    let env = Env::default();
    env.mock_all_auths();

    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    let client_a = deploy(&env);
    let client_b = deploy(&env);

    client_a.initialize(&admin_a, &0u64);
    client_b.initialize(&admin_b, &0u64);

    assert_eq!(client_a.get_admin(), admin_a);
    assert_eq!(client_b.get_admin(), admin_b);
    assert_ne!(client_a.get_admin(), client_b.get_admin());
}
