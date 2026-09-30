//! Focused adversarial coverage for `access_control::require_business`.

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

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

fn rejected_call(env: &Env, contract: &Address, caller: &Address) -> bool {
    let env_ref = env.clone();
    let contract_id = contract.clone();
    let caller_ref = caller.clone();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env_ref.as_contract(&contract_id, || {
            access_control::require_business(&env_ref, &caller_ref);
        });
    }))
    .is_err()
}

#[test]
fn business_role_and_composite_role_are_accepted() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let multi_role = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    client.grant_role(&admin, &multi_role, &(ROLE_BUSINESS | ROLE_OPERATOR));

    in_contract(&env, &client.address, |e| {
        access_control::require_business(e, &business);
        access_control::require_business(e, &multi_role);
    });
}

#[test]
fn caller_without_roles_is_rejected_without_state_changes() {
    let (env, client, _admin) = setup();
    let caller = Address::generate(&env);
    let roles_before = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &caller)
    });
    let holders_before = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e)
    });

    assert!(rejected_call(&env, &client.address, &caller));

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(e, &caller)),
        roles_before
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_role_holders(e)),
        holders_before
    );
}

#[test]
#[should_panic(expected = "caller does not have BUSINESS role")]
fn missing_business_role_has_deterministic_error() {
    let (env, client, _admin) = setup();
    let caller = Address::generate(&env);

    in_contract(&env, &client.address, |e| {
        access_control::require_business(e, &caller);
    });
}

#[test]
fn non_business_roles_do_not_authorize_business_access() {
    let (env, client, admin) = setup();
    let caller = Address::generate(&env);
    client.grant_role(
        &admin,
        &caller,
        &(ROLE_ADMIN | ROLE_ATTESTOR | ROLE_OPERATOR),
    );
    let roles_before = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &caller)
    });
    let holders_before = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e)
    });

    assert!(rejected_call(&env, &client.address, &caller));

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(e, &caller)),
        roles_before
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_role_holders(e)),
        holders_before
    );
}

#[test]
fn revoked_business_role_is_rejected() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    in_contract(&env, &client.address, |e| {
        access_control::require_business(e, &business);
    });

    client.revoke_role(&admin, &business, &ROLE_BUSINESS);
    assert!(rejected_call(&env, &client.address, &business));
}

#[test]
fn missing_auth_is_rejected_without_changing_business_role() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);
    let roles_before = in_contract(&env, &client.address, |e| {
        access_control::get_roles(e, &business)
    });
    let holders_before = in_contract(&env, &client.address, |e| {
        access_control::get_role_holders(e)
    });

    env.mock_auths(&[]);
    assert!(rejected_call(&env, &client.address, &business));

    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_roles(e, &business)),
        roles_before
    );
    assert_eq!(
        in_contract(&env, &client.address, |e| access_control::get_role_holders(e)),
        holders_before
    );
}