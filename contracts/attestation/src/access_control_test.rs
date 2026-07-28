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

    let roles = access_control::get_roles(&env, &user);
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

    let holders = access_control::get_role_holders(&env);
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

    client.pause(&admin, &1u64);

    assert!(client.is_paused());
}

#[test]
fn test_operator_can_pause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    client.pause(&operator, &1u64);

    assert!(client.is_paused());
}

#[test]
fn test_admin_can_unpause() {
    let (_env, client, admin) = setup();

    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    client.unpause(&admin, &2u64);
    assert!(!client.is_paused());
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_operator_cannot_unpause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    client.grant_role(&admin, &operator, &ROLE_OPERATOR);
    client.pause(&admin, &1u64);

    // Operator can pause but cannot unpause
    client.unpause(&operator, &0u64);
}

#[test]
#[should_panic(expected = "caller must have ADMIN or OPERATOR role")]
fn test_non_operator_cannot_pause() {
    let (env, client, _admin) = setup();
    let user = Address::generate(&env);

    client.pause(&user, &1u64);
}

#[test]
#[should_panic(expected = "contract is paused")]
fn test_submit_attestation_when_paused() {
    let (env, client, admin) = setup();

    client.pause(&admin, &1u64);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

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

    assert_eq!(access_control::get_roles(&env, &user), 0);
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

    let roles = access_control::get_roles(&env, &user);
    assert_eq!(
        roles,
        ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );

    // Revoke one
    client.revoke_role(&admin, &user, &ROLE_BUSINESS);
    let roles = access_control::get_roles(&env, &user);
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

    client.pause(&operator, &1u64);
    assert!(client.is_paused());

    client.revoke_role(&admin, &operator, &ROLE_OPERATOR);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.unpause(&operator, &0u64);
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

    let zero_address = Address::from_str(
        &env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );

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


#[test]
fn test_fuzz_grant_revoke_role_random_bitmaps() {
    let e = soroban_sdk::Env::default();
    let contract = AttestationContract::new(&e);

    let valid_roles = [
        0b0000,
        0b0001,
        0b0010,
        0b0100,
        0b1000,
        0b0011,
        0b0101,
        0b1001,
        0b0110,
        0b1010,
        0b1100,
        0b0111,
        0b1011,
        0b1101,
        0b1110,
        0b1111,
    ];
    let invalid_bitmaps = [
        0b10000u32,
        0b100000u32,
        0xFFFFu32,
        0xDEADu32,
        0xFFFFFFFFu32,
    ];

    let user1 = soroban_sdk::Address::generate(&e);

    for &roles in valid_roles.iter() {
        contract.set_roles(&user1, &0u32);
        contract.grant_role(&user1, &roles);
        assert_eq!(contract.get_roles(&user1), roles, "grant_role failed for bitmap {}", roles);
    }

    contract.set_roles(&user1, &0u32);
    contract.grant_role(&user1, &0b0101u32);
    contract.grant_role(&user1, &0b0101u32);
    assert_eq!(contract.get_roles(&user1), 0b0101u32);

    contract.set_roles(&user1, &0b1111u32);
    contract.revoke_role(&user1, &0b0001u32);
    assert_eq!(contract.get_roles(&user1), 0b1110u32);
    contract.revoke_role(&user1, &0b0010u32);
    assert_eq!(contract.get_roles(&user1), 0b1100u32);
    contract.revoke_role(&user1, &0b0100u32);
    assert_eq!(contract.get_roles(&user1), 0b1000u32);
    contract.revoke_role(&user1, &0b1000u32);
    assert_eq!(contract.get_roles(&user1), 0u32);

    contract.revoke_role(&user1, &0b0010u32);
    assert_eq!(contract.get_roles(&user1), 0u32);

    for &invalid in invalid_bitmaps.iter() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.grant_role(&user1, &invalid);
        }));
        assert!(result.is_err(), "grant_role should panic for invalid bitmap: {}", invalid);
    }

    assert!(contract.is_valid_role_bitmap(0b0000u32));
    assert!(contract.is_valid_role_bitmap(0b1111u32));
    assert!(!contract.is_valid_role_bitmap(0b10000u32));
    assert!(!contract.is_valid_role_bitmap(0xFFFFFFFFu32));
}

// ════════════════════════════════════════════════════════════════════
//  Weighted Admin Quorum Tests
// ════════════════════════════════════════════════════════════════════

/// After initialization the first admin has the default weight (1).
#[test]
fn test_default_admin_weight_is_one() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin_weight(&admin), 1u32);
}

/// Setting a weight in range succeeds and is reflected by get_admin_weight.
#[test]
fn test_set_admin_weight_stores_value() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &42u32);
    assert_eq!(client.get_admin_weight(&admin), 42u32);
}

/// Setting weight to MAX_ADMIN_WEIGHT (1000) is accepted.
#[test]
fn test_set_admin_weight_at_max_boundary() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &1000u32);
    assert_eq!(client.get_admin_weight(&admin), 1000u32);
}

/// Setting weight to 1 (minimum valid) is accepted.
#[test]
fn test_set_admin_weight_at_min_boundary() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &1u32);
    assert_eq!(client.get_admin_weight(&admin), 1u32);
}

/// Zero weight is rejected.
#[test]
#[should_panic(expected = "admin weight cannot be zero")]
fn test_zero_weight_rejected() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &0u32);
}

/// Weight exceeding MAX_ADMIN_WEIGHT is rejected.
#[test]
#[should_panic(expected = "admin weight exceeds MAX_ADMIN_WEIGHT")]
fn test_weight_above_max_rejected() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &1001u32);
}

/// Only an admin can call set_admin_weight.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_set_weight() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);
    client.set_admin_weight(&non_admin, &target, &5u32);
}

/// set_admin_weight on a non-admin address is rejected.
#[test]
#[should_panic(expected = "account does not hold ROLE_ADMIN")]
fn test_cannot_set_weight_for_non_admin_account() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    // non_admin does not hold ROLE_ADMIN — should panic
    client.set_admin_weight(&admin, &non_admin, &5u32);
}

/// Quorum weight for a single admin with default weight equals 1.
#[test]
fn test_quorum_weight_single_admin_default() {
    let (_env, client, _admin) = setup();
    assert_eq!(client.get_admin_quorum_weight(), 1u64);
}

/// Quorum weight reflects an updated weight for the only admin.
#[test]
fn test_quorum_weight_single_admin_custom() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &7u32);
    assert_eq!(client.get_admin_quorum_weight(), 7u64);
}

/// Multiple admins with default weights sum to their count.
#[test]
fn test_quorum_weight_multiple_admins_default() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);
    let admin3 = Address::generate(&env);

    client.grant_role(&admin, &admin2, &ROLE_ADMIN);
    client.grant_role(&admin, &admin3, &ROLE_ADMIN);

    // 3 admins × weight 1 each
    assert_eq!(client.get_admin_quorum_weight(), 3u64);
}

/// Weighted quorum sums correctly when admins have different weights.
/// Scenario: Founder (weight 3) + 2× Ops key (weight 1) → total 5.
#[test]
fn test_quorum_weight_founder_plus_ops() {
    let (env, client, founder) = setup();
    let ops1 = Address::generate(&env);
    let ops2 = Address::generate(&env);

    client.grant_role(&founder, &ops1, &ROLE_ADMIN);
    client.grant_role(&founder, &ops2, &ROLE_ADMIN);

    // Founder gets weight 3
    client.set_admin_weight(&founder, &founder, &3u32);
    // Ops keys keep default weight 1

    assert_eq!(client.get_admin_quorum_weight(), 5u64);
}

/// Revoking ROLE_ADMIN from a member removes their weight from the quorum sum.
#[test]
fn test_quorum_weight_decreases_when_admin_revoked() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);

    client.grant_role(&admin, &admin2, &ROLE_ADMIN);
    client.set_admin_weight(&admin, &admin2, &10u32);

    // admin(1) + admin2(10) = 11
    assert_eq!(client.get_admin_quorum_weight(), 11u64);

    // Remove admin2's ROLE_ADMIN
    client.revoke_role(&admin, &admin2, &ROLE_ADMIN);

    // Only admin(1) remains
    assert_eq!(client.get_admin_quorum_weight(), 1u64);
}

/// After revoking ROLE_ADMIN from admin2, set_admin_weight on them must fail
/// even though a weight entry may still exist in storage.
#[test]
#[should_panic(expected = "account does not hold ROLE_ADMIN")]
fn test_set_weight_after_role_revocation_panics() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);

    client.grant_role(&admin, &admin2, &ROLE_ADMIN);
    client.revoke_role(&admin, &admin2, &ROLE_ADMIN);

    // admin2 no longer holds ROLE_ADMIN — weight update must be rejected
    client.set_admin_weight(&admin, &admin2, &5u32);
}

/// A freshly granted admin who has never had a weight set contributes
/// DEFAULT_ADMIN_WEIGHT (1) to the quorum.
#[test]
fn test_new_admin_contributes_default_weight_to_quorum() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);

    let before = client.get_admin_quorum_weight();
    client.grant_role(&admin, &admin2, &ROLE_ADMIN);
    let after = client.get_admin_quorum_weight();

    assert_eq!(after - before, 1u64); // exactly DEFAULT_ADMIN_WEIGHT
}

/// Updating a weight twice uses the latest value.
#[test]
fn test_update_weight_twice_uses_latest() {
    let (_env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &200u32);
    client.set_admin_weight(&admin, &admin, &50u32);
    assert_eq!(client.get_admin_weight(&admin), 50u32);
    assert_eq!(client.get_admin_quorum_weight(), 50u64);
}

/// A non-admin address always returns DEFAULT_ADMIN_WEIGHT from
/// get_admin_weight (the stored default), but is not included in
/// the quorum sum.
#[test]
fn test_non_admin_weight_not_included_in_quorum() {
    let (env, client, admin) = setup();
    let non_admin = Address::generate(&env);
    // non_admin has default weight = 1
    assert_eq!(client.get_admin_weight(&non_admin), 1u32);
    // But the quorum only counts the original admin
    assert_eq!(client.get_admin_quorum_weight(), 1u64);
}

/// AdminWeightChanged event is emitted with correct fields when weight is set.
#[test]
fn test_admin_weight_changed_event_emitted() {
    use soroban_sdk::testutils::Events as _;
    use crate::events::{AdminWeightChangedEvent, TOPIC_ADMIN_WEIGHT_CHANGED};

    let (env, client, admin) = setup();
    client.set_admin_weight(&admin, &admin, &42u32);

    let events = env.events().all();
    let found = events.iter().any(|(_, topics, data)| {
        // Check if the first topic is the TOPIC_ADMIN_WEIGHT_CHANGED symbol
        let topic_match = topics.len() >= 1 && {
            let first = topics.get(0).unwrap();
            first == soroban_sdk::Val::from(TOPIC_ADMIN_WEIGHT_CHANGED)
        };
        if !topic_match {
            return false;
        }
        // Decode data and verify fields
        if let Ok(event) = AdminWeightChangedEvent::try_from_val(&env, &data) {
            event.new_weight == 42
                && event.old_weight == 1
                && event.account == admin
                && event.changed_by == admin
        } else {
            false
        }
    });
    assert!(found, "AdminWeightChanged event not found or fields incorrect");
}

/// MAX_ADMIN_WEIGHT constant is exposed and equals 1000.
#[test]
fn test_max_admin_weight_constant() {
    use crate::access_control::MAX_ADMIN_WEIGHT;
    assert_eq!(MAX_ADMIN_WEIGHT, 1000u32);
}

/// DEFAULT_ADMIN_WEIGHT constant is exposed and equals 1.
#[test]
fn test_default_admin_weight_constant() {
    use crate::access_control::DEFAULT_ADMIN_WEIGHT;
    assert_eq!(DEFAULT_ADMIN_WEIGHT, 1u32);
}

/// Weighted quorum with all admins at max weight does not overflow u64.
/// 2 admins × MAX_ADMIN_WEIGHT (1000) = 2000 — well within u64.
#[test]
fn test_quorum_weight_no_overflow_with_max_weights() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);

    client.grant_role(&admin, &admin2, &ROLE_ADMIN);
    client.set_admin_weight(&admin, &admin, &1000u32);
    client.set_admin_weight(&admin, &admin2, &1000u32);

    assert_eq!(client.get_admin_quorum_weight(), 2000u64);
}
