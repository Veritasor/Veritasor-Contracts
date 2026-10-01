//! # `admin_count` adversarial coverage
//!
//! `access_control::admin_count` backs the `MIN_ADMIN_COUNT` guard that stops
//! the contract from being left with no administrator. These tests pin the
//! behaviour that guard depends on:
//!
//! - the count is derived from `ROLE_ADMIN` holders, never from the length of
//!   the `RoleHolders` list (which also tracks attestor/business/operator
//!   holders);
//! - repeated or combined grants to one address never double-count;
//! - rejected operations (last-admin removal, zero-address admin grant) leave
//!   the count and the role bitmaps untouched;
//! - the guard runs before the removal cooldown, so a quorum "large enough" on
//!   the count alone cannot bypass the time lock.

#![cfg(test)]

extern crate std;

use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

use crate::access_control::{
    self, AccessControlKey, ADMIN_REMOVAL_COOLDOWN_SECS, MIN_ADMIN_COUNT, ROLE_ADMIN,
    ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR,
};
use crate::{AttestationContract, AttestationContractClient};

/// StrKey encoding of the all-zero ed25519 public key.
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

/// Run an internal storage helper inside the contract context.
///
/// SDK 22 requires storage access to go through `env.as_contract` when the
/// helper is called directly from a test (outside a contract invocation).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

fn admin_count_of(env: &Env, contract: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::admin_count(e))
}

fn holder_count_of(env: &Env, contract: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::get_role_holders(e).len())
}

// ════════════════════════════════════════════════════════════════════
//  Baseline / derivation
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_count_is_zero_before_any_admin_is_recorded() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());

    // No `initialize` call: the role-holder list has never been written, so the
    // count must fall out as 0 rather than panicking on a missing key.
    assert_eq!(admin_count_of(&env, &contract_id), 0);
    assert_eq!(holder_count_of(&env, &contract_id), 0);
}

#[test]
fn admin_count_counts_the_initializing_admin_exactly_once() {
    let (env, client, _admin) = setup();

    assert_eq!(admin_count_of(&env, &client.address), 1);
    assert_eq!(holder_count_of(&env, &client.address), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Filtering: role holders are not admins
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_count_ignores_holders_of_non_admin_roles() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);
    let business = Address::generate(&env);
    let operator = Address::generate(&env);

    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    // Four addresses are tracked as role holders, but only one holds ADMIN.
    assert_eq!(holder_count_of(&env, &client.address), 4);
    assert_eq!(admin_count_of(&env, &client.address), 1);
}

#[test]
fn admin_count_drops_to_zero_when_the_last_admin_bit_is_removed_directly() {
    let (env, client, admin) = setup();

    // Write the bitmap directly: `revoke_role` refuses to remove the last admin,
    // so this is the only way to observe the count's zero case.
    in_contract(&env, &client.address, |e| {
        access_control::set_roles(e, &admin, 0);
    });

    assert_eq!(admin_count_of(&env, &client.address), 0);
    assert_eq!(holder_count_of(&env, &client.address), 0);
}

#[test]
fn admin_count_ignores_admin_weight_entries() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // A weight entry (even for a non-admin) is not an admin grant.
    in_contract(&env, &client.address, |e| {
        e.storage()
            .instance()
            .set(&AccessControlKey::AdminWeight(attestor.clone()), &7u32);
        e.storage()
            .instance()
            .set(&AccessControlKey::AdminWeight(admin.clone()), &250u32);
    });

    assert_eq!(admin_count_of(&env, &client.address), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Counting distinct admins
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_count_tracks_each_distinct_admin() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 2);

    client.grant_role(&admin, &third, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 3);
    assert_eq!(holder_count_of(&env, &client.address), 3);
}

#[test]
fn admin_count_never_double_counts_repeated_admin_grants() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &second, &ROLE_ADMIN);

    // `grant_role` is additive and the holder list deduplicates, so the same
    // address must contribute exactly one to the count.
    assert_eq!(admin_count_of(&env, &client.address), 2);
    assert_eq!(holder_count_of(&env, &client.address), 2);
}

#[test]
fn admin_count_counts_a_holder_with_several_roles_once() {
    let (env, client, admin) = setup();
    let multi = Address::generate(&env);

    client.grant_role(
        &admin,
        &multi,
        &(ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS),
    );
    assert_eq!(admin_count_of(&env, &client.address), 2);

    // Adding another non-admin role to the same address must not move the count.
    client.grant_role(&admin, &multi, &ROLE_OPERATOR);
    assert_eq!(admin_count_of(&env, &client.address), 2);
    assert_eq!(holder_count_of(&env, &client.address), 2);
}

#[test]
fn admin_count_reflects_role_revocation_immediately() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &third, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 3);

    client.revoke_role(&admin, &third, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 2);

    // Revoking a non-admin role must not move the admin count, even though the
    // holder keeps its entry in the role-holder list.
    //
    // Advance past the removal cooldown so the second removal is rejected (or
    // not) purely on its own merits.
    env.ledger().set_timestamp(ADMIN_REMOVAL_COOLDOWN_SECS);
    client.revoke_role(&admin, &second, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 1);
}

#[test]
fn admin_count_is_unaffected_by_removing_non_admin_roles() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    assert_eq!(admin_count_of(&env, &client.address), 1);

    client.revoke_role(&admin, &attestor, &ROLE_ATTESTOR);

    // The holder is gone from the list, but the admin count never included it.
    assert_eq!(holder_count_of(&env, &client.address), 1);
    assert_eq!(admin_count_of(&env, &client.address), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Rejected operations leave the count untouched
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_count_rejects_the_last_admin_removal_and_stays_unchanged() {
    let (env, client, admin) = setup();
    assert_eq!(admin_count_of(&env, &client.address), MIN_ADMIN_COUNT);

    let result = client.try_revoke_role(&admin, &admin, &ROLE_ADMIN);
    assert!(result.is_err(), "removing the only admin must be rejected");

    // Rejected operation: no role change, no cooldown recorded, count intact.
    assert_eq!(admin_count_of(&env, &client.address), 1);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "admin removal would violate MIN_ADMIN_COUNT")]
fn last_admin_removal_panics_with_the_documented_message() {
    let (_env, client, admin) = setup();

    client.revoke_role(&admin, &admin, &ROLE_ADMIN);
}

#[test]
#[should_panic(expected = "admin removal would violate MIN_ADMIN_COUNT")]
fn admin_count_boundary_rejects_removal_with_exactly_one_admin_left() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.revoke_role(&admin, &second, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), MIN_ADMIN_COUNT);

    // Isolate the min-count guard from the cooldown: the cooldown has elapsed,
    // so the only reason left to reject is `admin_count == MIN_ADMIN_COUNT`.
    env.ledger().set_timestamp(ADMIN_REMOVAL_COOLDOWN_SECS);

    client.revoke_role(&admin, &admin, &ROLE_ADMIN);
}

#[test]
fn admin_count_guard_is_evaluated_before_the_removal_cooldown() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &third, &ROLE_ADMIN);

    // First removal is allowed (count 3 > 1) and records the cooldown anchor.
    client.revoke_role(&admin, &third, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 2);

    // A count above the minimum is not sufficient on its own: the cooldown
    // still rejects the second removal and the count must not move.
    env.ledger().set_timestamp(1);
    let blocked = client.try_revoke_role(&admin, &second, &ROLE_ADMIN);
    assert!(
        blocked.is_err(),
        "second removal inside the cooldown must be rejected"
    );
    assert_eq!(admin_count_of(&env, &client.address), 2);
    assert!(client.has_role(&second, &ROLE_ADMIN));

    // Once the cooldown elapses the same removal succeeds.
    env.ledger().set_timestamp(ADMIN_REMOVAL_COOLDOWN_SECS);
    client.revoke_role(&admin, &second, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 1);
}

#[test]
fn admin_count_is_unchanged_when_an_admin_grant_to_the_zero_address_is_rejected() {
    let (env, client, admin) = setup();
    let zero = Address::from_str(&env, ZERO_ACCOUNT_STRKEY);
    let before = admin_count_of(&env, &client.address);

    let rejected = client.try_grant_role(&admin, &zero, &ROLE_ADMIN);
    assert!(
        rejected.is_err(),
        "ADMIN must never be granted to the zero address"
    );
    assert_eq!(admin_count_of(&env, &client.address), before);

    // Boundary: the same zero address may hold a non-admin role, which must not
    // make it count as an admin.
    client.grant_role(&admin, &zero, &ROLE_ATTESTOR);
    assert!(client.has_role(&zero, &ROLE_ATTESTOR));
    assert_eq!(admin_count_of(&env, &client.address), before);
}

// ════════════════════════════════════════════════════════════════════
//  Swaps
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_count_is_preserved_by_swap_admin() {
    let (env, client, admin) = setup();
    let second = Address::generate(&env);
    let third = Address::generate(&env);
    let replacement = Address::generate(&env);

    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &third, &ROLE_ADMIN);
    assert_eq!(admin_count_of(&env, &client.address), 3);

    client.swap_admin(&admin, &second, &replacement);

    // A swap is a replacement, so the count must not change.
    assert_eq!(admin_count_of(&env, &client.address), 3);
    assert!(!client.has_role(&second, &ROLE_ADMIN));
    assert!(client.has_role(&replacement, &ROLE_ADMIN));
}

#[test]
fn admin_count_is_unchanged_when_an_admin_swaps_with_itself() {
    let (env, client, admin) = setup();

    client.swap_admin(&admin, &admin, &admin);

    assert_eq!(admin_count_of(&env, &client.address), 1);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}
