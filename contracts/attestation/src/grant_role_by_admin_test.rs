//! Focused adversarial coverage for `access_control::grant_role_by_admin` (issue #887).
//!
//! `grant_role_by_admin` is the admin-gated entry point that composes
//! `require_admin` with `grant_role`. The legacy `access_control_test` module is
//! gated behind the `full-tests` feature and never runs with the default feature
//! set, so this module pins the authorization contract, the additive-role
//! semantics, the input-validation boundaries, and the "rejected operations do
//! not mutate role state" invariant.

use super::*;
use crate::access_control::{
    self, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR, ROLE_VALID_MASK,
};
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

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

fn holder_count(env: &Env, contract: &Address, account: &Address) -> usize {
    in_contract(env, contract, |e| {
        access_control::get_role_holders(e)
            .iter()
            .filter(|h| h == account)
            .count()
    })
}

// ════════════════════════════════════════════════════════════════════
//  Authorized grants
// ════════════════════════════════════════════════════════════════════

#[test]
fn admin_grant_adds_exactly_the_requested_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_ATTESTOR)
    });

    assert!(client.has_role(&user, &ROLE_ATTESTOR));
    assert!(!client.has_role(&user, &ROLE_ADMIN));
    assert!(!client.has_role(&user, &ROLE_BUSINESS));
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user
        )),
        ROLE_ATTESTOR,
    );
}

#[test]
fn admin_grant_is_additive_across_calls() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_ATTESTOR)
    });
    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_BUSINESS)
    });
    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_OPERATOR)
    });

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user
        )),
        ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR,
    );
}

#[test]
fn granting_a_role_twice_is_idempotent_and_does_not_duplicate_the_holder() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_ATTESTOR)
    });
    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_ATTESTOR)
    });

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user
        )),
        ROLE_ATTESTOR,
    );
    assert_eq!(
        holder_count(&env, &client.address, &user),
        1,
        "a repeated grant must not append the holder twice",
    );
}

#[test]
fn granting_admin_role_increments_admin_count_and_quorum_weight() {
    let (env, client, admin) = setup();
    let second_admin = Address::generate(&env);

    let before_count = in_contract(&env, &client.address, |e| access_control::admin_count(e));
    let before_weight = in_contract(&env, &client.address, |e| {
        access_control::admin_quorum_weight(e)
    });

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &second_admin, ROLE_ADMIN)
    });

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::admin_count(e)),
        before_count + 1,
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| {
            access_control::admin_quorum_weight(e)
        }),
        before_weight + access_control::DEFAULT_ADMIN_WEIGHT as u64,
    );
}

#[test]
fn granting_non_admin_roles_does_not_change_active_admin_count() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    let before = in_contract(&env, &client.address, |e| access_control::admin_count(e));
    for role in [ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR] {
        in_contract(&env, &client.address, |e| {
            access_control::grant_role_by_admin(e, &admin, &user, role)
        });
    }

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::admin_count(e)),
        before,
    );
}

#[test]
fn admin_grant_accepts_the_full_valid_bitmap() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &user, ROLE_VALID_MASK)
    });

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &user
        )),
        ROLE_VALID_MASK,
    );
}

#[test]
fn admin_revoke_removes_only_the_targeted_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    for role in [ROLE_ATTESTOR, ROLE_BUSINESS] {
        in_contract(&env, &client.address, |e| {
            access_control::grant_role_by_admin(e, &admin, &user, role)
        });
    }

    in_contract(&env, &client.address, |e| {
        access_control::revoke_role_by_admin(e, &admin, &user, ROLE_ATTESTOR)
    });

    assert!(!client.has_role(&user, &ROLE_ATTESTOR));
    assert!(client.has_role(&user, &ROLE_BUSINESS));
}

// ════════════════════════════════════════════════════════════════════
//  Unauthorized callers
// ════════════════════════════════════════════════════════════════════

#[test]
fn non_admin_grant_is_rejected_and_target_roles_unchanged() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);

    let result = client.try_grant_role(&stranger, &target, &ROLE_ATTESTOR);

    assert!(result.is_err(), "non-admin caller must be rejected");
    assert!(
        !client.has_role(&target, &ROLE_ATTESTOR),
        "rejected grant must not mutate the target",
    );
    assert_eq!(
        holder_count(&env, &client.address, &target),
        0,
        "rejected grant must not register a holder",
    );
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn grant_role_by_admin_panics_for_non_admin_caller() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &stranger, &target, ROLE_ATTESTOR)
    });
}

// ════════════════════════════════════════════════════════════════════
//  Input validation boundaries
// ════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "invalid role: must be non-zero and within valid range")]
fn grant_role_by_admin_rejects_zero_bitmap() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &target, 0u32)
    });
}

#[test]
#[should_panic(expected = "invalid role: must be non-zero and within valid range")]
fn grant_role_by_admin_rejects_undefined_bit() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &target, 1u32 << 4)
    });
}

#[test]
#[should_panic(expected = "invalid role: must be non-zero and within valid range")]
fn grant_role_by_admin_rejects_valid_role_combined_with_undefined_bit() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &target, ROLE_ATTESTOR | (1u32 << 7))
    });
}

#[test]
#[should_panic(expected = "ADMIN role cannot be granted to zero address")]
fn grant_role_by_admin_rejects_admin_role_to_zero_address() {
    let (env, client, admin) = setup();
    let zero_address = Address::from_str(
        &env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &zero_address, ROLE_ADMIN)
    });
}

#[test]
fn rejected_invalid_bitmap_leaves_target_state_unchanged() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &client.address, |e| {
            access_control::grant_role_by_admin(e, &admin, &target, 1u32 << 4)
        });
    }));

    assert!(result.is_err(), "undefined role bit must be rejected");
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(
            e, &target
        )),
        0,
        "rejected grant must not write any roles",
    );
    assert_eq!(holder_count(&env, &client.address, &target), 0);
}
