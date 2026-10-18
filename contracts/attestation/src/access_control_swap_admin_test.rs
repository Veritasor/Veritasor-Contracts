//! # Adversarial coverage for `access_control::swap_admin` (issue #889)
//!
//! `swap_admin(old_admin, new_admin, swapped_by)` is a privileged,
//! state-changing operation: it revokes `ROLE_ADMIN` from `old_admin` and grants
//! it to `new_admin` atomically. It returns `()` and reports every rejection by
//! panicking, so each failing path below pins the exact panic contract and then
//! proves the rejected call left role state untouched.
//!
//! The public contract is driven only through `AttestationContractClient`; role
//! bitmaps, holder bookkeeping and the admin count are read back with the real
//! storage helpers inside the contract context.

use super::*;
use crate::access_control::{ROLE_ADMIN, ROLE_ATTESTOR};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Env};

/// Register the contract, initialize it and return a client plus its admin.
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
/// SDK 22 requires storage access to go through `env.as_contract` when called
/// directly from a test (outside a contract invocation).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

/// Raw role bitmap for `account`, read from contract storage.
fn stored_roles(env: &Env, contract: &Address, account: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::get_roles(e, account))
}

/// Number of addresses that currently hold `ROLE_ADMIN`.
fn admin_count(env: &Env, contract: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::admin_count(e))
}

/// Role-holder list maintained by `set_roles`.
fn holder_addresses(env: &Env, contract: &Address) -> soroban_sdk::Vec<Address> {
    in_contract(env, contract, |e| access_control::get_role_holders(e))
}

/// Extract a human-readable message from a `catch_unwind` error payload.
fn panic_message(err: &std::boxed::Box<dyn std::any::Any + Send>) -> std::string::String {
    if let Some(s) = err.downcast_ref::<&str>() {
        std::string::String::from(*s)
    } else if let Some(s) = err.downcast_ref::<std::string::String>() {
        s.clone()
    } else {
        std::string::String::from("(non-string panic payload)")
    }
}

// ════════════════════════════════════════════════════════════════════
//  Happy path
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_admin_moves_admin_bit_and_preserves_count() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);

    assert_eq!(stored_roles(&env, &client.address, &admin), ROLE_ADMIN);
    assert_eq!(stored_roles(&env, &client.address, &new_admin), 0);
    assert_eq!(admin_count(&env, &client.address), 1);
    assert_eq!(holder_addresses(&env, &client.address).len(), 1);

    client.swap_admin(&admin, &admin, &new_admin);

    // The old admin's ADMIN bit is cleared...
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert_eq!(stored_roles(&env, &client.address, &admin), 0);
    // ...the replacement holds exactly ROLE_ADMIN...
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    assert_eq!(stored_roles(&env, &client.address, &new_admin), ROLE_ADMIN);
    // ...and a swap preserves the admin count instead of removing one member.
    assert_eq!(admin_count(&env, &client.address), 1);
    // Role-holder bookkeeping tracks the replacement, not the former admin.
    let holders = holder_addresses(&env, &client.address);
    assert_eq!(holders.len(), 1);
    assert_eq!(holders.get(0).unwrap(), new_admin);
}

// ════════════════════════════════════════════════════════════════════
//  Unauthorized caller (require_admin)
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_swap_admin_non_admin_caller_panics() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    client.swap_admin(&non_admin, &admin, &new_admin);
}

#[test]
fn test_swap_admin_non_admin_caller_leaves_state_unchanged() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.swap_admin(&non_admin, &admin, &new_admin);
    }));
    let err = result.expect_err("non-admin caller must be rejected");
    assert!(panic_message(&err).contains("caller does not have ADMIN role"));

    // The rejected call must not have moved the ADMIN bit in either direction.
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert_eq!(stored_roles(&env, &client.address, &admin), ROLE_ADMIN);
    assert_eq!(stored_roles(&env, &client.address, &new_admin), 0);
    assert_eq!(admin_count(&env, &client.address), 1);
}

// ════════════════════════════════════════════════════════════════════
//  old_admin does not hold ROLE_ADMIN
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "old_admin does not have ADMIN role")]
fn test_swap_admin_old_admin_without_role_panics() {
    let (env, client, admin) = setup();
    let nobody = Address::generate(&env);
    let new_admin = Address::generate(&env);

    client.swap_admin(&admin, &nobody, &new_admin);
}

#[test]
fn test_swap_admin_old_without_role_grants_nothing_to_new_admin() {
    let (env, client, admin) = setup();
    let nobody = Address::generate(&env);
    let new_admin = Address::generate(&env);
    assert_eq!(stored_roles(&env, &client.address, &nobody), 0);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.swap_admin(&admin, &nobody, &new_admin);
    }));
    let err = result.expect_err("old_admin without ROLE_ADMIN must be rejected");
    assert!(panic_message(&err).contains("old_admin does not have ADMIN role"));

    // The `assert!` fires before any mutation: `new_admin` must NOT gain ADMIN.
    assert!(!client.has_role(&new_admin, &ROLE_ADMIN));
    assert_eq!(stored_roles(&env, &client.address, &new_admin), 0);
    assert_eq!(stored_roles(&env, &client.address, &nobody), 0);
    assert_eq!(stored_roles(&env, &client.address, &admin), ROLE_ADMIN);
    assert_eq!(admin_count(&env, &client.address), 1);
}

// ════════════════════════════════════════════════════════════════════
//  Boundary cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_admin_self_swap_is_bitmap_idempotent() {
    let (env, client, admin) = setup();
    // Give the admin a second role so the bitmap is not trivially single-bit.
    client.grant_role(&admin, &admin, &ROLE_ATTESTOR);

    let before = stored_roles(&env, &client.address, &admin);
    assert_eq!(before, ROLE_ADMIN | ROLE_ATTESTOR);
    assert_eq!(admin_count(&env, &client.address), 1);

    let events_before = env.events().all().len();
    // Documented edge case: `old_admin == new_admin` is a no-op on the bitmap.
    client.swap_admin(&admin, &admin, &admin);

    // The swap really executed (an empty body would emit nothing), yet the
    // bitmap and the admin count are unchanged.
    assert!(env.events().all().len() > events_before);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert_eq!(stored_roles(&env, &client.address, &admin), before);
    assert_eq!(admin_count(&env, &client.address), 1);
}

#[test]
fn test_swap_admin_new_admin_already_admin_keeps_single_bit() {
    let (env, client, admin) = setup();
    let other_admin = Address::generate(&env);
    client.grant_role(&admin, &other_admin, &ROLE_ADMIN);
    assert_eq!(admin_count(&env, &client.address), 2);

    client.swap_admin(&admin, &admin, &other_admin);

    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&other_admin, &ROLE_ADMIN));
    // Granting an already-held bit is idempotent: no duplicate role state.
    assert_eq!(
        stored_roles(&env, &client.address, &other_admin),
        ROLE_ADMIN
    );
    assert_eq!(admin_count(&env, &client.address), 1);
}

#[test]
fn test_swap_admin_sole_admin_keeps_exactly_one_admin() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    assert_eq!(admin_count(&env, &client.address), 1);

    // A swap is a replacement, so the last-admin guard must not block it...
    client.swap_admin(&admin, &admin, &new_admin);

    // ...and the "at least one admin" invariant still holds afterwards.
    assert_eq!(admin_count(&env, &client.address), 1);
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    let holders = holder_addresses(&env, &client.address);
    assert_eq!(holders.len(), 1);
    assert_eq!(holders.get(0).unwrap(), new_admin);
}

#[test]
fn test_swap_admin_grants_exactly_admin_bit_to_non_admin() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    assert_eq!(stored_roles(&env, &client.address, &new_admin), 0);

    client.swap_admin(&admin, &admin, &new_admin);

    // Exactly ROLE_ADMIN: no other role bit may leak into the new admin.
    assert_eq!(stored_roles(&env, &client.address, &new_admin), ROLE_ADMIN);
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
    assert!(!client.has_role(&new_admin, &ROLE_ATTESTOR));
}

// ════════════════════════════════════════════════════════════════════
//  Removal-cooldown interaction
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_admin_neither_consumes_nor_arms_removal_cooldown() {
    let (env, client, admin) = setup();
    let old_admin = Address::generate(&env);
    let other_admin = Address::generate(&env);
    let replacement = Address::generate(&env);

    client.grant_role(&admin, &old_admin, &ROLE_ADMIN);
    client.grant_role(&admin, &other_admin, &ROLE_ADMIN);
    assert_eq!(admin_count(&env, &client.address), 3);

    // A swap is not a removal: it must not arm the removal cooldown.
    client.swap_admin(&admin, &old_admin, &replacement);
    assert_eq!(admin_count(&env, &client.address), 3);
    assert!(client.has_role(&replacement, &ROLE_ADMIN));

    // So an immediate removal of a *different* admin still succeeds.
    client.revoke_role(&admin, &other_admin, &ROLE_ADMIN);
    assert!(!client.has_role(&other_admin, &ROLE_ADMIN));
    assert_eq!(admin_count(&env, &client.address), 2);

    // The revoke above did arm the cooldown (unlike the swap): the next removal
    // is rejected deterministically...
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.revoke_role(&admin, &replacement, &ROLE_ADMIN);
    }));
    let err = result.expect_err("a second immediate removal must be rejected");
    assert!(panic_message(&err).contains("admin removal cooldown not elapsed"));

    // ...and the rejected removal leaves the role state untouched.
    assert!(client.has_role(&replacement, &ROLE_ADMIN));
    assert_eq!(admin_count(&env, &client.address), 2);
}
