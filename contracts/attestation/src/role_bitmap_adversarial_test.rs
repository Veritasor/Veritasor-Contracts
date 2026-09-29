use crate::access_control::{self, ROLE_ADMIN, ROLE_VALID_MASK};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    let contract = env.register(crate::AttestationContract, ());
    (env, contract)
}

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

#[test]
fn get_roles_returns_zero_for_unknown_accounts_without_creating_state() {
    let (env, contract) = setup();
    let account = Address::generate(&env);

    assert_eq!(
        in_contract(&env, &contract, |env| access_control::get_roles(env, &account)),
        0
    );
    assert!(in_contract(&env, &contract, access_control::get_role_holders).is_empty());
}

#[test]
fn get_roles_reads_composite_bitmaps_and_preserves_them_after_rejected_update() {
    let (env, contract) = setup();
    let account = Address::generate(&env);
    let composite = ROLE_ADMIN | crate::access_control::ROLE_ATTESTOR;

    in_contract(&env, &contract, |env| {
        access_control::set_roles(env, &account, composite);
    });
    assert_eq!(
        in_contract(&env, &contract, |env| access_control::get_roles(env, &account)),
        composite
    );

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            access_control::set_roles(env, &account, ROLE_VALID_MASK + 1);
        });
    }));
    assert!(rejected.is_err());
    assert_eq!(
        in_contract(&env, &contract, |env| access_control::get_roles(env, &account)),
        composite
    );
}

#[test]
fn set_roles_accepts_all_defined_bits_and_tracks_holder() {
    let (env, contract) = setup();
    let account = Address::generate(&env);

    in_contract(&env, &contract, |env| {
        access_control::set_roles(env, &account, ROLE_VALID_MASK);
    });

    assert_eq!(
        in_contract(&env, &contract, |env| {
            access_control::get_roles(env, &account)
        }),
        ROLE_VALID_MASK
    );
    let holders = in_contract(&env, &contract, access_control::get_role_holders);
    assert_eq!(holders.len(), 1);
    assert_eq!(holders.get(0), Some(account));
}

#[test]
fn set_roles_rejects_undefined_bits_without_mutating_state() {
    let (env, contract) = setup();
    let account = Address::generate(&env);
    let existing_roles = ROLE_ADMIN;

    in_contract(&env, &contract, |env| {
        access_control::set_roles(env, &account, existing_roles);
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            access_control::set_roles(env, &account, ROLE_VALID_MASK + 1);
        });
    }));

    assert!(result.is_err(), "undefined role bits must be rejected");
    assert_eq!(
        in_contract(&env, &contract, |env| {
            access_control::get_roles(env, &account)
        }),
        existing_roles
    );
    let holders = in_contract(&env, &contract, access_control::get_role_holders);
    assert_eq!(holders.len(), 1);
    assert_eq!(holders.get(0), Some(account));
}

#[test]
fn set_roles_zero_clears_roles_and_removes_holder() {
    let (env, contract) = setup();
    let account = Address::generate(&env);

    in_contract(&env, &contract, |env| {
        access_control::set_roles(env, &account, ROLE_ADMIN);
        access_control::set_roles(env, &account, 0);
    });

    assert_eq!(
        in_contract(&env, &contract, |env| {
            access_control::get_roles(env, &account)
        }),
        0
    );
    let holders = in_contract(&env, &contract, access_control::get_role_holders);
    assert!(holders.is_empty());
}
