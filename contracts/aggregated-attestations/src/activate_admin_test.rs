#![cfg(test)]

//! Focused adversarial coverage for
//! [`AggregatedAttestationsContract::activate_admin`].
//!
//! `activate_admin` is the terminal step of the time-locked admin rotation: it
//! promotes the pending admin only once the activation timestamp has elapsed
//! and must leave contract state untouched on every rejected attempt. The
//! existing `admin_rotation_test` exercises a single happy path; these tests
//! pin the boundary (`timestamp == activation_time`), the failure path with no
//! pending rotation, and the invariant that a rejected call neither rotates the
//! admin nor discards the pending rotation.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, String, Vec};

/// Fresh contract initialised with `admin` and a zero replay nonce.
fn new_client<'a>(env: &'a Env, admin: &Address) -> AggregatedAttestationsContractClient<'a> {
    let contract_address = env.register_contract(None, AggregatedAttestationsContract);
    let client = AggregatedAttestationsContractClient::new(env, &contract_address);
    client.initialize(admin, &0u64);
    client
}

#[test]
fn activate_admin_without_pending_rotation_panics_and_preserves_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let client = new_client(&env, &admin);

    assert_eq!(client.get_admin(), admin);

    // No rotation was ever proposed: activation must be rejected.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.activate_admin()));
    assert!(
        result.is_err(),
        "activation without pending admin must panic"
    );

    // Rejected operation must not mutate the stored admin.
    assert_eq!(client.get_admin(), admin);

    // The admin remains fully functional after the rejected activation.
    client.register_portfolio(
        &admin,
        &1u64,
        &String::from_str(&env, "p1"),
        &Vec::new(&env),
    );
    assert!(client
        .get_portfolio(&String::from_str(&env, "p1"))
        .is_some());
}

#[test]
fn activate_admin_at_exact_activation_boundary_rotates() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = new_client(&env, &admin);

    let delay = 1_000u64;
    client.set_pending_admin(&admin, &0u64, &new_admin, &delay);

    // `get_active_pending_admin` activates when `timestamp >= activation_time`,
    // so the exact boundary must succeed (not only `delay + 1`).
    env.ledger().with_mut(|l| l.timestamp = delay);
    client.activate_admin();

    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn activate_admin_one_tick_early_panics_and_keeps_pending_rotation() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = new_client(&env, &admin);

    let delay = 1_000u64;
    client.set_pending_admin(&admin, &0u64, &new_admin, &delay);

    // One tick before the activation time the rotation must be rejected and the
    // original admin retained.
    env.ledger().with_mut(|l| l.timestamp = delay - 1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.activate_admin()));
    assert!(
        result.is_err(),
        "activation before the time-lock must panic"
    );
    assert_eq!(client.get_admin(), admin);

    // A rejected attempt must not consume the pending rotation: the very same
    // pending admin still activates once the lock expires.
    env.ledger().with_mut(|l| l.timestamp = delay);
    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn activate_admin_success_clears_pending_rotation() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = new_client(&env, &admin);

    let delay = 500u64;
    client.set_pending_admin(&admin, &0u64, &new_admin, &delay);
    env.ledger().with_mut(|l| l.timestamp = delay + 1);

    client.activate_admin();
    assert_eq!(client.get_admin(), new_admin);

    // The pending rotation is cleared on success, so a second activation has
    // nothing to promote and must panic without changing the admin.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.activate_admin()));
    assert!(result.is_err(), "second activation must panic");
    assert_eq!(client.get_admin(), new_admin);
}
