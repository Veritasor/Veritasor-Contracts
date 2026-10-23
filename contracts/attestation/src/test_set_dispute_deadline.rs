//! Adversarial coverage for `AttestationContract::set_dispute_deadline`.
//!
//! `set_dispute_deadline` is an admin-gated write with a closed input range
//! (`[MIN_DISPUTE_DEADLINE_SECONDS, MAX_DISPUTE_DEADLINE_SECONDS]`). The
//! existing `dispute_test` suite covers the default and the two off-by-one
//! rejections, but not the properties that make the setter safe to call
//! repeatedly:
//!
//! 1. An unauthenticated caller must be rejected even when the value itself is
//!    in range — and must not move the configured deadline.
//! 2. A rejected write must not roll the stored value back to the compile-time
//!    default; it must leave whatever was configured before intact.
//! 3. `0` and `u64::MAX` are the extreme i128-free boundaries of `u64` and are
//!    rejected by the range guard, not by arithmetic.

use super::dispute::{
    DISPUTE_DEADLINE_SECONDS, MAX_DISPUTE_DEADLINE_SECONDS, MIN_DISPUTE_DEADLINE_SECONDS,
};
use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

// ════════════════════════════════════════════════════════════════════
//  Baseline
// ════════════════════════════════════════════════════════════════════

#[test]
fn unconfigured_deadline_falls_back_to_the_compiled_in_default() {
    let (_env, client, _admin) = setup();

    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), 604_800u64);
}

#[test]
fn the_default_is_inside_the_accepted_range() {
    // Guards against the constants drifting apart: the fallback value must
    // satisfy the same bounds the setter enforces.
    assert!(DISPUTE_DEADLINE_SECONDS >= MIN_DISPUTE_DEADLINE_SECONDS);
    assert!(DISPUTE_DEADLINE_SECONDS <= MAX_DISPUTE_DEADLINE_SECONDS);

    let (_env, client, admin) = setup();
    // Re-setting the default explicitly is a no-op that must be accepted.
    client.set_dispute_deadline(&admin, &DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);
}

// ════════════════════════════════════════════════════════════════════
//  Boundary values
// ════════════════════════════════════════════════════════════════════

#[test]
fn every_in_range_boundary_is_accepted_verbatim() {
    let (_env, client, admin) = setup();

    for value in [
        MIN_DISPUTE_DEADLINE_SECONDS,
        MIN_DISPUTE_DEADLINE_SECONDS + 1,
        DISPUTE_DEADLINE_SECONDS,
        MAX_DISPUTE_DEADLINE_SECONDS - 1,
        MAX_DISPUTE_DEADLINE_SECONDS,
    ] {
        client.set_dispute_deadline(&admin, &value);
        assert_eq!(client.get_dispute_deadline(), value, "value {value}");
    }
}

#[test]
#[should_panic(expected = "deadline must be at least 1 hour")]
fn one_second_below_the_minimum_is_rejected() {
    let (_env, client, admin) = setup();
    client.set_dispute_deadline(&admin, &(MIN_DISPUTE_DEADLINE_SECONDS - 1));
}

#[test]
#[should_panic(expected = "deadline must not exceed 90 days")]
fn one_second_above_the_maximum_is_rejected() {
    let (_env, client, admin) = setup();
    client.set_dispute_deadline(&admin, &(MAX_DISPUTE_DEADLINE_SECONDS + 1));
}

#[test]
#[should_panic(expected = "deadline must be at least 1 hour")]
fn zero_is_rejected_as_below_the_minimum() {
    let (_env, client, admin) = setup();
    client.set_dispute_deadline(&admin, &0u64);
}

#[test]
#[should_panic(expected = "deadline must not exceed 90 days")]
fn u64_max_is_rejected_as_above_the_maximum() {
    let (_env, client, admin) = setup();
    client.set_dispute_deadline(&admin, &u64::MAX);
}

#[test]
fn out_of_range_values_leave_the_default_deadline_untouched() {
    let (_env, client, admin) = setup();

    for value in [
        0u64,
        1,
        MIN_DISPUTE_DEADLINE_SECONDS - 1,
        MAX_DISPUTE_DEADLINE_SECONDS + 1,
    ] {
        let result = client.try_set_dispute_deadline(&admin, &value);
        assert!(result.is_err(), "value {value} should be rejected");
        assert_eq!(
            client.get_dispute_deadline(),
            DISPUTE_DEADLINE_SECONDS,
            "value {value} must not change the deadline"
        );
    }
}

#[test]
fn a_rejected_write_does_not_reset_a_previously_configured_value() {
    let (_env, client, admin) = setup();

    let configured = MIN_DISPUTE_DEADLINE_SECONDS + 7;
    client.set_dispute_deadline(&admin, &configured);
    assert_eq!(client.get_dispute_deadline(), configured);

    // Both directions of the range guard, and the extremes.
    for rejected in [
        MIN_DISPUTE_DEADLINE_SECONDS - 1,
        MAX_DISPUTE_DEADLINE_SECONDS + 1,
        0,
        u64::MAX,
    ] {
        assert!(client.try_set_dispute_deadline(&admin, &rejected).is_err());
        assert_eq!(
            client.get_dispute_deadline(),
            configured,
            "rejected value {rejected} must not fall back to the default"
        );
    }
}

#[test]
fn a_rejected_write_does_not_clear_a_maximum_deadline() {
    let (_env, client, admin) = setup();

    client.set_dispute_deadline(&admin, &MAX_DISPUTE_DEADLINE_SECONDS);
    assert!(client.try_set_dispute_deadline(&admin, &0u64).is_err());

    assert_eq!(client.get_dispute_deadline(), MAX_DISPUTE_DEADLINE_SECONDS);
}

// ════════════════════════════════════════════════════════════════════
//  Authorization
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic]
fn an_unauthenticated_caller_cannot_set_the_deadline() {
    let (env, client, _admin) = setup();
    // Clear every mocked authorization: `require_admin` must reject the call
    // before the setter is reached.
    env.mock_auths(&[]);

    let outsider = Address::generate(&env);
    client.set_dispute_deadline(&outsider, &MIN_DISPUTE_DEADLINE_SECONDS);
}

#[test]
fn a_rejected_unauthorized_write_leaves_the_deadline_unchanged() {
    let (env, client, admin) = setup();

    let configured = MIN_DISPUTE_DEADLINE_SECONDS;
    client.set_dispute_deadline(&admin, &configured);

    // The stored admin is the only address allowed to write; with no mocked
    // auths even it is refused, and no outsider gains access.
    env.mock_auths(&[]);
    assert!(client
        .try_set_dispute_deadline(&admin, &MAX_DISPUTE_DEADLINE_SECONDS)
        .is_err());

    assert_eq!(client.get_dispute_deadline(), configured);
}

#[test]
fn the_admin_can_still_write_once_authorization_is_restored() {
    let (env, client, admin) = setup();

    env.mock_auths(&[]);
    assert!(client.try_set_dispute_deadline(&admin, &0u64).is_err());
    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);

    env.mock_all_auths();
    client.set_dispute_deadline(&admin, &MAX_DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), MAX_DISPUTE_DEADLINE_SECONDS);
}

// ════════════════════════════════════════════════════════════════════
//  Repeated writes
// ════════════════════════════════════════════════════════════════════

#[test]
fn the_last_successful_write_wins() {
    let (_env, client, admin) = setup();

    client.set_dispute_deadline(&admin, &MIN_DISPUTE_DEADLINE_SECONDS);
    client.set_dispute_deadline(&admin, &MAX_DISPUTE_DEADLINE_SECONDS);
    client.set_dispute_deadline(&admin, &DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);

    // A rejected attempt in the middle of a sequence changes nothing.
    assert!(client.try_set_dispute_deadline(&admin, &0u64).is_err());
    client.set_dispute_deadline(&admin, &MIN_DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), MIN_DISPUTE_DEADLINE_SECONDS);
}

#[test]
fn writes_are_idempotent_for_the_same_value() {
    let (_env, client, admin) = setup();

    for _ in 0..4 {
        client.set_dispute_deadline(&admin, &MIN_DISPUTE_DEADLINE_SECONDS);
        assert_eq!(client.get_dispute_deadline(), MIN_DISPUTE_DEADLINE_SECONDS);
    }
}
