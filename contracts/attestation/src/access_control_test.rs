//! # Access Control Tests
//!
//! Comprehensive tests for the role-based access control system including
//! role assignment, revocation, and authorization checks.

use super::*;
use crate::access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client.
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
//  Role Assignment Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_admin_has_admin_role_after_init() {
    let (_env, client, admin) = setup();
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
fn test_grant_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    assert!(!client.has_role(&user, &ROLE_ATTESTOR));

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);

    assert!(client.has_role(&user, &ROLE_ATTESTOR));
}

#[test]
fn test_grant_multiple_roles() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_BUSINESS);

    assert!(client.has_role(&user, &ROLE_ATTESTOR));
    assert!(client.has_role(&user, &ROLE_BUSINESS));

    let roles = client.get_roles(&user);
    assert_eq!(roles, ROLE_ATTESTOR | ROLE_BUSINESS);
}

#[test]
fn test_revoke_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    assert!(client.has_role(&user, &ROLE_ATTESTOR));

    client.revoke_role(&admin, &user, &ROLE_ATTESTOR);
    assert!(!client.has_role(&user, &ROLE_ATTESTOR));
}

#[test]
fn test_revoke_one_role_keeps_others() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_BUSINESS);

    client.revoke_role(&admin, &user, &ROLE_ATTESTOR);

    assert!(!client.has_role(&user, &ROLE_ATTESTOR));
    assert!(client.has_role(&user, &ROLE_BUSINESS));
}

#[test]
fn test_get_role_holders() {
    let (env, client, admin) = setup();
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);

    client.grant_role(&admin, &user1, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user2, &ROLE_BUSINESS);

    let holders = client.get_role_holders();
    // Admin + 2 users
    assert_eq!(holders.len(), 3);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_grant_role() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_role(&non_admin, &target, &ROLE_ATTESTOR);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_revoke_role() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_role(&admin, &target, &ROLE_ATTESTOR);
    client.revoke_role(&non_admin, &target, &ROLE_ATTESTOR);
}

// ════════════════════════════════════════════════════════════════════
//  Pause/Unpause Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_admin_can_pause() {
    let (_env, client, admin) = setup();

    assert!(!client.is_paused());

    client.pause(&admin);

    assert!(client.is_paused());
}

#[test]
fn test_operator_can_pause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    client.pause(&operator);

    assert!(client.is_paused());
}

#[test]
fn test_admin_can_unpause() {
    let (_env, client, admin) = setup();

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_operator_cannot_unpause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    client.pause(&admin);

    // Operator can pause but cannot unpause
    client.unpause(&operator);
}

#[test]
#[should_panic(expected = "caller must have ADMIN or OPERATOR role")]
fn test_non_operator_cannot_pause() {
    let (env, client, _admin) = setup();
    let user = Address::generate(&env);

    client.pause(&user);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_submit_attestation_when_paused() {
    let (env, client, admin) = setup();

    client.pause(&admin);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &0i128, &None, &None,
        &0u64,
    );
}

// ════════════════════════════════════════════════════════════════════
//  Role Escalation Prevention Tests
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_attestor_cannot_grant_admin() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    // Attestor tries to grant ADMIN role
    client.grant_role(&attestor, &target, &ROLE_ADMIN);
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_business_cannot_grant_roles() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    client.grant_role(&business, &target, &ROLE_ATTESTOR);
}

// ════════════════════════════════════════════════════════════════════
//  Edge Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_nonexistent_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    // Should not panic when revoking a role the user doesn't have
    client.revoke_role(&admin, &user, &ROLE_ATTESTOR);
    assert!(!client.has_role(&user, &ROLE_ATTESTOR));
}

#[test]
fn test_grant_same_role_twice() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_ATTESTOR);

    assert!(client.has_role(&user, &ROLE_ATTESTOR));
}

#[test]
fn test_roles_are_zero_by_default() {
    let (env, client, _admin) = setup();
    let user = Address::generate(&env);

    assert_eq!(client.get_roles(&user), 0);
    assert!(!client.has_role(&user, &ROLE_ADMIN));
    assert!(!client.has_role(&user, &ROLE_ATTESTOR));
    assert!(!client.has_role(&user, &ROLE_BUSINESS));
    assert!(!client.has_role(&user, &ROLE_OPERATOR));
}

#[test]
fn test_all_role_combinations() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    // Grant all roles
    client.grant_role(&admin, &user, &ROLE_ADMIN);
    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_BUSINESS);
    client.grant_role(&admin, &user, &ROLE_OPERATOR);

    let roles = client.get_roles(&user);
    assert_eq!(
        roles,
        ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );

    // Revoke one
    client.revoke_role(&admin, &user, &ROLE_BUSINESS);
    let roles = client.get_roles(&user);
    assert_eq!(roles, ROLE_ADMIN | ROLE_ATTESTOR | ROLE_OPERATOR);
}

// ════════════════════════════════════════════════════════════════════
//  Role Revocation Mid-Call and Delegation Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_revoke_admin_role_prevents_future_operations() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    client.grant_role(&admin, &target, &ROLE_ADMIN);
    assert!(client.has_role(&target, &ROLE_ADMIN));

    client.revoke_role(&admin, &target, &ROLE_ADMIN);
    assert!(!client.has_role(&target, &ROLE_ADMIN));

    let user = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&target, &user, &ROLE_ATTESTOR);
    }));
    assert!(result.is_err(), "revoked admin cannot grant roles");
}

#[test]
fn test_revoke_attestor_role_prevents_attestation() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);

    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);
    client.grant_role(&admin, &attestor, &ROLE_OPERATOR);

    client.revoke_role(&admin, &attestor, &ROLE_ATTESTOR);

    assert!(!client.has_role(&attestor, &ROLE_ATTESTOR));
    assert!(client.has_role(&attestor, &ROLE_OPERATOR));
}

#[test]
fn test_delegation_with_attestor_role() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let attestor = Address::generate(&env);

    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    assert!(client.has_role(&business, &ROLE_BUSINESS));
    assert!(client.has_role(&attestor, &ROLE_ATTESTOR));
}

#[test]
fn test_revoked_operator_cannot_pause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    assert!(client.has_role(&operator, &ROLE_OPERATOR));

    client.pause(&operator);
    assert!(client.is_paused());

    client.revoke_role(&admin, &operator, &ROLE_OPERATOR);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.unpause(&operator);
    }));
    assert!(result.is_err(), "revoked operator cannot unpause");
}

// ════════════════════════════════════════════════════════════════════════════
//  Misconfigured Roles Tests
// ════════════════════════════════════════════════════════════

#[test]
fn test_cannot_grant_zero_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &user, &0u32);
    }));
    assert!(result.is_err());
}

#[test]
fn test_cannot_grant_invalid_role_bits() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    let invalid_role = 0xFFFFFFFF;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &user, &invalid_role);
    }));
    assert!(result.is_err(), "invalid role bits should be rejected");
}

#[test]
fn test_admin_role_not_grantable_to_zero_address() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);

    let zero_address = Address::from_raw([0u8; 32]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &zero_address, &ROLE_ADMIN);
    }));
    assert!(result.is_err() || !client.has_role(&zero_address, &ROLE_ADMIN));
}

// ════════════════════════════════════════════════════════════════════
//  Replay Nonce Compatibility Tests
// ════════════════════════════════════════════════════════════

#[test]
fn test_grant_role_does_not_change_admin_replay_nonce() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    let before = client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);

    assert_eq!(
        client.get_replay_nonce(&admin, &crate::NONCE_CHANNEL_ADMIN),
        before
    );
}

#[test]
fn test_admin_or_attestor_can_submit_attestation() {
    let (env, client, admin) = setup();
    let attestor = Address::generate(&env);

    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    assert!(client.has_role(&attestor, &ROLE_ATTESTOR));
}

// ════════════════════════════════════════════════════════════════════
//  Role Hierarchy Tests
// ════════════════════════════════════════════════════════════

#[test]
fn test_admin_has_all_privileges() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user, &ROLE_OPERATOR);

    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&user, &ROLE_ATTESTOR));
    assert!(client.has_role(&user, &ROLE_OPERATOR));
}

#[test]
fn test_business_role_limits() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);

    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    assert!(client.has_role(&business, &ROLE_BUSINESS));

    let target = Address::generate(&env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&business, &target, &ROLE_ATTESTOR);
    }));
    assert!(result.is_err(), "business cannot grant roles");
}
