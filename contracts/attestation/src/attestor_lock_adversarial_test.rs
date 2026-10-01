#![cfg(test)]
//! # Adversarial coverage for `access_control::require_attestor_not_locked`
//!
//! The guard has two independent rejection branches and is called on the hot
//! path of `submit_attestation`:
//!
//!   1. caller does not hold `ROLE_ATTESTOR`
//!   2. caller is locked because of an active dispute
//!
//! Every rejection must be deterministic, must not mutate the role bitmap, and
//! must not release the dispute lock. The tests below pin both branches, the
//! successful path, and the state-unchanged invariant after a rejected call.
extern crate std;

use super::*;
use crate::access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin, contract_id)
}

fn with_contract<F, R>(env: &Env, contract_id: &Address, f: F) -> R
where
    F: FnOnce() -> R,
{
    env.as_contract(contract_id, f)
}

fn is_locked(env: &Env, contract_id: &Address, attestor: &Address) -> bool {
    with_contract(env, contract_id, || {
        dispute::is_attestor_locked(env, attestor)
    })
}

/// Lock `attestor` the way an open dispute would, without driving the full
/// dispute lifecycle.
fn lock_for_dispute(env: &Env, contract_id: &Address, attestor: &Address, dispute_id: u64) {
    with_contract(env, contract_id, || {
        dispute::lock_attestor(
            env,
            attestor,
            &Address::generate(env),
            &String::from_str(env, "2026-02"),
            dispute_id,
        );
    });
}

fn check(env: &Env, contract_id: &Address, caller: &Address) {
    with_contract(env, contract_id, || {
        access_control::require_attestor_not_locked(env, caller);
    });
}

// ── Success path ───────────────────────────────────────────────────────────

#[test]
fn unlocked_attestor_passes_the_guard() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    check(&env, &contract_id, &attestor);

    assert!(client.has_role(&attestor, &ROLE_ATTESTOR));
    assert!(!is_locked(&env, &contract_id, &attestor));
}

#[test]
fn combined_role_holder_passes_the_guard() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &(ROLE_ATTESTOR | ROLE_BUSINESS));

    check(&env, &contract_id, &attestor);

    assert!(client.has_role(&attestor, &ROLE_ATTESTOR));
    assert!(client.has_role(&attestor, &ROLE_BUSINESS));
}

#[test]
fn attestor_passes_again_after_the_dispute_lock_is_released() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    lock_for_dispute(&env, &contract_id, &attestor, 1);
    assert!(is_locked(&env, &contract_id, &attestor));

    with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor);
    });

    check(&env, &contract_id, &attestor);
    assert!(!is_locked(&env, &contract_id, &attestor));
}

// ── Branch 1: missing ROLE_ATTESTOR ────────────────────────────────────────

#[test]
#[should_panic(expected = "caller does not have ATTESTOR role")]
fn business_role_is_rejected() {
    let (env, client, admin, contract_id) = setup();
    let business = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    check(&env, &contract_id, &business);
}

#[test]
#[should_panic(expected = "caller does not have ATTESTOR role")]
fn operator_role_is_rejected() {
    let (env, client, admin, contract_id) = setup();
    let operator = Address::generate(&env);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    check(&env, &contract_id, &operator);
}

#[test]
#[should_panic(expected = "caller does not have ATTESTOR role")]
fn admin_role_alone_is_rejected() {
    // ROLE_ADMIN does not imply ROLE_ATTESTOR: authorization here is exact.
    let (env, client, admin, contract_id) = setup();
    let other_admin = Address::generate(&env);
    client.grant_role(&admin, &other_admin, &ROLE_ADMIN);

    check(&env, &contract_id, &other_admin);
}

#[test]
#[should_panic(expected = "caller does not have ATTESTOR role")]
fn roleless_caller_is_rejected() {
    let (env, _client, _admin, contract_id) = setup();
    let stranger = Address::generate(&env);

    check(&env, &contract_id, &stranger);
}

#[test]
fn rejected_caller_keeps_a_zero_role_bitmap() {
    let (env, _client, _admin, contract_id) = setup();
    let stranger = Address::generate(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(&env, &contract_id, &stranger);
    }));

    assert!(result.is_err(), "roleless caller must be rejected");
    // A rejected authorization check must never grant roles as a side effect.
    let roles = with_contract(&env, &contract_id, || {
        access_control::get_roles(&env, &stranger)
    });
    assert_eq!(roles, 0);
}

// ── Branch 2: locked due to an active dispute ──────────────────────────────

#[test]
#[should_panic(expected = "attestor is locked due to an active dispute")]
fn locked_attestor_is_rejected() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    lock_for_dispute(&env, &contract_id, &attestor, 1);
    check(&env, &contract_id, &attestor);
}

#[test]
fn rejected_locked_attestor_keeps_role_and_lock_state() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);
    lock_for_dispute(&env, &contract_id, &attestor, 7);

    let roles_before = with_contract(&env, &contract_id, || {
        access_control::get_roles(&env, &attestor)
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(&env, &contract_id, &attestor);
    }));

    assert!(result.is_err(), "locked attestor must be rejected");
    // NOTE: unwinding through `env.as_contract` leaves the test-contract frame
    // on the host's stack, so every post-panic state read has to go through
    // `as_contract` as well — a further *client* call would be rejected by the
    // host as contract re-entry ("Contract re-entry is not allowed").
    assert!(is_locked(&env, &contract_id, &attestor));
    let roles_after = with_contract(&env, &contract_id, || {
        access_control::get_roles(&env, &attestor)
    });
    assert_eq!(roles_before, roles_after);
    // A rejected authorization check neither revokes the role nor releases the lock.
    assert_eq!(roles_after, ROLE_ATTESTOR);
}

#[test]
fn overlapping_disputes_keep_the_attestor_blocked_until_the_last_is_closed() {
    let (env, client, admin, contract_id) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Two concurrent disputes referencing the same attestor.
    lock_for_dispute(&env, &contract_id, &attestor, 1);
    lock_for_dispute(&env, &contract_id, &attestor, 2);

    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(&env, &contract_id, &attestor);
    }));
    assert!(first.is_err());

    // Closing one dispute must not release the lock…
    let still_locked = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor)
    });
    assert!(!still_locked);
    assert!(is_locked(&env, &contract_id, &attestor));

    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        check(&env, &contract_id, &attestor);
    }));
    assert!(second.is_err());

    // …closing the last one must.
    let fully_unlocked = with_contract(&env, &contract_id, || {
        dispute::unlock_attestor(&env, &attestor)
    });
    assert!(fully_unlocked);
    check(&env, &contract_id, &attestor);
    assert!(!is_locked(&env, &contract_id, &attestor));
}

// ── Ordering: role check precedes the lock check ───────────────────────────

#[test]
#[should_panic(expected = "caller does not have ATTESTOR role")]
fn role_check_fires_before_the_lock_check_for_roleless_callers() {
    let (env, _client, _admin, contract_id) = setup();
    let stranger = Address::generate(&env);
    lock_for_dispute(&env, &contract_id, &stranger, 1);

    // The caller is both roleless and locked; the role assertion must win so the
    // error surface stays stable and does not leak dispute state to outsiders.
    check(&env, &contract_id, &stranger);
}
