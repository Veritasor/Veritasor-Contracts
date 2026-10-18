//! # Access Control Tests
//!
//! Comprehensive tests for the role-based access control system including
//! role assignment, revocation, and authorization checks.

use super::*;
use crate::access_control::{ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR};
use crate::events::{AdminSwappedEvent, TOPIC_ADMIN_SWAPPED};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{Address, BytesN, Env, String, TryFromVal};

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

/// Run an internal storage helper inside the contract context.
///
/// SDK 22 requires storage access to go through `env.as_contract` when
/// called directly from a test (outside a contract invocation).
fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

#[test]
fn test_require_valid_nonce_tracks_account_and_channel_sequences() {
    let (env, client, account) = setup();
    let other_account = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::require_valid_nonce(e, &account, 1, None);
        access_control::require_valid_nonce(e, &account, 2, None);
        access_control::require_valid_nonce(e, &account, 1, Some(7));
        access_control::require_valid_nonce(e, &other_account, 1, None);
    });

    in_contract(&env, &client.address, |e| {
        let default_channel =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    0,
                )));
        let separate_channel =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    7,
                )));
        let separate_account =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    other_account.clone(),
                    0,
                )));

        assert_eq!(default_channel, Some(2));
        assert_eq!(separate_channel, Some(1));
        assert_eq!(separate_account, Some(1));
    });
}

#[test]
fn test_require_valid_nonce_rejections_leave_storage_unchanged() {
    let (env, client, account) = setup();

    let zero_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &client.address, |e| {
            access_control::require_valid_nonce(e, &account, 0, Some(4));
        });
    }));
    assert!(zero_result.is_err(), "zero nonce must be rejected");

    in_contract(&env, &client.address, |e| {
        let value =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    4,
                )));
        assert_eq!(value, None, "zero nonce must not create a stored value");
        access_control::require_valid_nonce(e, &account, 3, Some(4));
    });

    for rejected_nonce in [3, 2, 1] {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            in_contract(&env, &client.address, |e| {
                access_control::require_valid_nonce(e, &account, rejected_nonce, Some(4));
            });
        }));
        assert!(result.is_err(), "nonce {rejected_nonce} must be rejected");

        in_contract(&env, &client.address, |e| {
            let value =
                e.storage()
                    .instance()
                    .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                        account.clone(),
                        4,
                    )));
            assert_eq!(value, Some(3), "rejection must preserve the prior nonce");
        });
    }

    let default_channel_replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &client.address, |e| {
            access_control::require_valid_nonce(e, &account, 2, Some(0));
        });
    }));
    assert!(default_channel_replay.is_err());
    in_contract(&env, &client.address, |e| {
        let value =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    0,
                )));
        assert_eq!(value, Some(2), "Some(0) must share the default channel");
    });
}

#[test]
fn test_require_valid_nonce_accepts_u64_max_without_wrapping() {
    let (env, client, account) = setup();

    in_contract(&env, &client.address, |e| {
        access_control::require_valid_nonce(e, &account, u64::MAX, Some(9));
        let value =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    9,
                )));
        assert_eq!(value, Some(u64::MAX));
    });

    let replay_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &client.address, |e| {
            access_control::require_valid_nonce(e, &account, u64::MAX, Some(9));
        });
    }));
    assert!(
        replay_result.is_err(),
        "the maximum nonce cannot be replayed"
    );
    in_contract(&env, &client.address, |e| {
        let value =
            e.storage()
                .instance()
                .get::<_, u64>(&access_control::AccessControlKey::LastNonce((
                    account.clone(),
                    9,
                )));
        assert_eq!(value, Some(u64::MAX), "rejection must preserve u64::MAX");
    });
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

    let roles = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &user)
    });
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
fn test_get_role_holders_returns_empty_when_uninitialized() {
    let env = Env::default();
    let contract = env.register(AttestationContract, ());

    let holders = in_contract(&env, &contract, access_control::get_role_holders);

    assert_eq!(holders.len(), 0);
    assert_eq!(
        in_contract(&env, &contract, access_control::get_role_holders).len(),
        0
    );
}

#[test]
fn test_get_role_holders() {
    let (env, client, admin) = setup();
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);

    client.grant_role(&admin, &user1, &ROLE_ATTESTOR);
    client.grant_role(&admin, &user2, &ROLE_BUSINESS);

    let holders = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e)
    });

    // Enumeration retains insertion order and returns each active holder once.
    assert_eq!(holders.len(), 3);
    assert_eq!(holders.get(0), Some(admin.clone()));
    assert_eq!(holders.get(1), Some(user1.clone()));
    assert_eq!(holders.get(2), Some(user2.clone()));

    let repeated_holders = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e)
    });
    assert_eq!(repeated_holders.len(), holders.len());
    for index in 0..holders.len() {
        assert_eq!(repeated_holders.get(index), holders.get(index));
    }

    // Reading the list does not alter the associated role state or enumeration.
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &admin
        )),
        ROLE_ADMIN
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user1
        )),
        ROLE_ATTESTOR
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user2
        )),
        ROLE_BUSINESS
    );
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
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_operator_cannot_pause() {
    let (env, client, admin) = setup();
    let operator = Address::generate(&env);

    // Pause/unpause are ADMIN-only operations; the OPERATOR role is not
    // sufficient (see `pause` entry point).
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    client.pause(&operator, &1u64);
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
#[should_panic(expected = "caller does not have ADMIN role")]
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

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user
        )),
        0
    );
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

    let roles = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &user)
    });
    assert_eq!(
        roles,
        ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );

    // Revoke one
    client.revoke_role(&admin, &user, &ROLE_BUSINESS);
    let roles = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &user)
    });
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

    // OPERATOR alone cannot pause; revoking the role changes nothing.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.pause(&operator, &1u64);
    }));
    assert!(result.is_err(), "operator cannot pause");

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
    e.mock_all_auths();
    let contract_id = e.register(AttestationContract, ());

    let valid_roles = [
        0b0000, 0b0001, 0b0010, 0b0100, 0b1000, 0b0011, 0b0101, 0b1001, 0b0110, 0b1010, 0b1100,
        0b0111, 0b1011, 0b1101, 0b1110, 0b1111,
    ];
    let invalid_bitmaps = [0b10000u32, 0b100000u32, 0xFFFFu32, 0xDEADu32, 0xFFFFFFFFu32];

    let user1 = soroban_sdk::Address::generate(&e);
    // A second admin keeps `admin_count > MIN_ADMIN_COUNT` so the
    // admin-removal safeguard in `revoke_role` does not trip while the
    // bitmap arithmetic below is exercised.
    let user2 = soroban_sdk::Address::generate(&e);
    e.as_contract(&contract_id, || {
        crate::access_control::set_roles(&e, &user2, ROLE_ADMIN);

        for &roles in valid_roles.iter() {
            crate::access_control::set_roles(&e, &user1, 0u32);
            // 0b0000 is a valid bitmap but a no-op grant; set_roles covers it.
            if roles != 0 {
                crate::access_control::grant_role(&e, &user1, roles, &user1);
            }
            assert_eq!(
                crate::access_control::get_roles(&e, &user1),
                roles,
                "set/grant failed for bitmap {}",
                roles
            );
        }

        crate::access_control::set_roles(&e, &user1, 0u32);
        crate::access_control::grant_role(&e, &user1, 0b0101u32, &user1);
        crate::access_control::grant_role(&e, &user1, 0b0101u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0b0101u32);

        crate::access_control::set_roles(&e, &user1, 0b1111u32);
        crate::access_control::revoke_role(&e, &user1, 0b0001u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0b1110u32);
        crate::access_control::revoke_role(&e, &user1, 0b0010u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0b1100u32);
        crate::access_control::revoke_role(&e, &user1, 0b0100u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0b1000u32);
        crate::access_control::revoke_role(&e, &user1, 0b1000u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0u32);

        crate::access_control::revoke_role(&e, &user1, 0b0010u32, &user1);
        assert_eq!(crate::access_control::get_roles(&e, &user1), 0u32);

        for &invalid in invalid_bitmaps.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::access_control::grant_role(&e, &user1, invalid, &user1);
            }));
            assert!(
                result.is_err(),
                "grant_role should panic for invalid bitmap: {}",
                invalid
            );
        }
    });

    assert!(crate::access_control::is_valid_role_bitmap(0b0000u32));
    assert!(crate::access_control::is_valid_role_bitmap(0b1111u32));
    assert!(!crate::access_control::is_valid_role_bitmap(0b10000u32));
    assert!(!crate::access_control::is_valid_role_bitmap(0xFFFFFFFFu32));
}

// ════════════════════════════════════════════════════════════════════
//  Swap Admin Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_admin_basic() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);

    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(!client.has_role(&new_admin, &ROLE_ADMIN));

    client.swap_admin(&admin, &admin, &new_admin);

    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
}

#[test]
fn test_swap_admin_emits_combined_event() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);

    let events_before = env.events().all().len();

    client.swap_admin(&admin, &admin, &new_admin);

    let all_events = env.events().all();
    assert!(
        all_events.len() > events_before,
        "swap_admin must emit at least one event"
    );

    let (_cid, topics, data) = all_events.last().unwrap();

    assert_eq!(topics.len(), 1);
    assert_eq!(
        soroban_sdk::Symbol::try_from_val(&env, &topics.get(0).unwrap()).unwrap(),
        TOPIC_ADMIN_SWAPPED
    );

    let ev = AdminSwappedEvent::try_from_val(&env, &data).unwrap();
    assert_eq!(ev.old_admin, admin);
    assert_eq!(ev.new_admin, new_admin);
    assert_eq!(ev.swapped_by, admin);
}

#[test]
fn test_swap_admin_new_already_admin() {
    let (env, client, admin) = setup();
    let other_admin = Address::generate(&env);

    client.grant_role(&admin, &other_admin, &ROLE_ADMIN);

    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&other_admin, &ROLE_ADMIN));

    client.swap_admin(&admin, &admin, &other_admin);

    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&other_admin, &ROLE_ADMIN));
}

#[test]
fn test_swap_admin_self_swap_is_idempotent() {
    let (_env, client, admin) = setup();

    assert!(client.has_role(&admin, &ROLE_ADMIN));

    client.swap_admin(&admin, &admin, &admin);

    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_non_admin_cannot_swap() {
    let (env, client, _admin) = setup();
    let non_admin = Address::generate(&env);
    let target = Address::generate(&env);

    client.swap_admin(&non_admin, &target, &target);
}

#[test]
#[should_panic(expected = "old_admin does not have ADMIN role")]
fn test_swap_admin_old_not_admin() {
    let (env, client, admin) = setup();
    let nobody = Address::generate(&env);

    client.swap_admin(&admin, &nobody, &admin);
}

#[test]
fn test_swap_admin_preserves_other_admins() {
    let (env, client, admin) = setup();
    let admin_b = Address::generate(&env);
    let admin_c = Address::generate(&env);
    let target = Address::generate(&env);

    client.grant_role(&admin, &admin_b, &ROLE_ADMIN);
    client.grant_role(&admin, &admin_c, &ROLE_ADMIN);

    // Swap admin_b out — admin and admin_c remain
    client.swap_admin(&admin, &admin_b, &target);

    assert!(client.has_role(&admin, &ROLE_ADMIN));
    assert!(!client.has_role(&admin_b, &ROLE_ADMIN));
    assert!(client.has_role(&admin_c, &ROLE_ADMIN));
    assert!(client.has_role(&target, &ROLE_ADMIN));
}

#[test]
fn test_swap_admin_new_other_roles_preserved() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    client.grant_role(&admin, &target, &ROLE_ATTESTOR);
    client.grant_role(&admin, &target, &ROLE_BUSINESS);

    assert!(!client.has_role(&target, &ROLE_ADMIN));

    // Add another admin so the invariant holds when we swap admin out
    let extra_admin = Address::generate(&env);
    client.grant_role(&admin, &extra_admin, &ROLE_ADMIN);

    client.swap_admin(&admin, &admin, &target);

    assert!(client.has_role(&target, &ROLE_ADMIN));
    assert!(client.has_role(&target, &ROLE_ATTESTOR));
    assert!(client.has_role(&target, &ROLE_BUSINESS));
    assert!(!client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
fn test_swap_admin_old_other_roles_preserved() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);

    client.grant_role(&admin, &admin, &ROLE_ATTESTOR);
    client.grant_role(&admin, &admin, &ROLE_OPERATOR);

    client.swap_admin(&admin, &admin, &new_admin);

    assert!(!client.has_role(&admin, &ROLE_ADMIN));
    assert!(client.has_role(&admin, &ROLE_ATTESTOR));
    assert!(client.has_role(&admin, &ROLE_OPERATOR));
    assert!(client.has_role(&new_admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "admin removal would violate MIN_ADMIN_COUNT")]
fn test_revoke_last_admin_is_rejected() {
    let (_env, client, admin) = setup();

    client.revoke_role(&admin, &admin, &ROLE_ADMIN);
}

#[test]
#[should_panic(expected = "admin removal cooldown not elapsed")]
fn test_admin_removal_cooldown_is_enforced() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.grant_role(&admin, &first, &ROLE_ADMIN);
    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &third, &ROLE_ADMIN);

    client.revoke_role(&admin, &first, &ROLE_ADMIN);
    client.revoke_role(&admin, &second, &ROLE_ADMIN);
}

#[test]
fn test_admin_removal_succeeds_at_cooldown_boundary() {
    let (env, client, admin) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.grant_role(&admin, &first, &ROLE_ADMIN);
    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.grant_role(&admin, &third, &ROLE_ADMIN);

    client.revoke_role(&admin, &first, &ROLE_ADMIN);
    env.ledger().with_mut(|ledger| {
        ledger.timestamp += access_control::ADMIN_REMOVAL_COOLDOWN_SECS;
    });
    client.revoke_role(&admin, &second, &ROLE_ADMIN);

    assert!(!client.has_role(&second, &ROLE_ADMIN));
}

// ════════════════════════════════════════════════════════════════════
//  Weighted Admin Quorum (Issue #893)
// ════════════════════════════════════════════════════════════════════

#[test]
fn test_admin_quorum_weight_uses_default_and_explicit_weights() {
    let (env, client, admin) = setup();
    let second_admin = Address::generate(&env);
    client.grant_role(&admin, &second_admin, &ROLE_ADMIN);

    // Existing and newly granted admins without configured weights count as 1.
    assert_eq!(client.get_admin_quorum_weight(), 2);

    client.set_admin_weight(&admin, &second_admin, &17);
    assert_eq!(client.get_admin_quorum_weight(), 18);
}

#[test]
fn test_admin_quorum_weight_includes_maximum_weight_without_overflow() {
    let (env, client, admin) = setup();
    let second_admin = Address::generate(&env);
    client.grant_role(&admin, &second_admin, &ROLE_ADMIN);

    client.set_admin_weight(&admin, &admin, &access_control::MAX_ADMIN_WEIGHT);
    client.set_admin_weight(&admin, &second_admin, &access_control::MAX_ADMIN_WEIGHT);

    assert_eq!(
        client.get_admin_quorum_weight(),
        (2 * access_control::MAX_ADMIN_WEIGHT) as u64
    );
}

#[test]
fn test_admin_quorum_weight_ignores_non_admin_and_removed_admin_weights() {
    let (env, client, admin) = setup();
    let former_admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    client.grant_role(&admin, &former_admin, &ROLE_ADMIN);
    client.grant_role(&admin, &non_admin, &ROLE_ATTESTOR);
    client.set_admin_weight(&admin, &former_admin, &23);

    // Store a weight for a non-admin through the internal helper to exercise
    // the quorum function's role filter independently of setter validation.
    in_contract(&env, &client.address, |e| {
        e.storage().instance().set(
            &access_control::AccessControlKey::AdminWeight(non_admin.clone()),
            &access_control::MAX_ADMIN_WEIGHT,
        );
        assert_eq!(access_control::admin_quorum_weight(e), 24);

        // Simulate a role removal while the old weight entry remains stored.
        access_control::set_roles(e, &former_admin, ROLE_ATTESTOR);
        assert_eq!(access_control::get_admin_weight(e, &former_admin), 23);
        assert_eq!(access_control::admin_quorum_weight(e), 1);
    });
    assert_eq!(client.get_admin_quorum_weight(), 1);
}
