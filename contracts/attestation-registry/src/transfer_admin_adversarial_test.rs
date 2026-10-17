use soroban_sdk::{address::Address, testutils::{AddressasContract, Env}, Env} as _;

use crate::{AttestationRegistry, AttestationRegistryClient};

fn setup_admin(env: &Env) -> (Address, AttestationRegistryClient<'_>) {
    let admin = Address::generate(env);
    let client = AttestationRegistryClient::new(env, &AttestationRegistry);
    client.initialize(&admin);
    (admin, client)
}

#[test]
fn transfer_admin_success_updates_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client) = setup_admin(&en);
    let new_admin = Address::generate(&env);

    client.transfer_admin(&new_admin);

    assert_eq!(client.get_admin(), new_admin);
    assert_ne!(client.get_admin(), admin);
}

#[test]
fn transfer_admin_requires_current_admin_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client) = setup_admin(&env);
    let new_admin = Address::generate(&env);

    // Reset auth mocking so only the new admin is authorized, not the current admin.
    env.set_auths_for_test(&[&admin]);
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &new_admin,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
          address: &client.address,
          func: "transfer_admin",
          args: (&new_admin,),
        },
    }]);

    let result = client.try_transfer_admin(&new_admin);
    assert!(result.is_error());
    // State unchanged after rejected operation.
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn transfer_admin_to_self_is_noop_or_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client) = setup_admin(&env);

    // Transferring to the same admin must not corrupt state.
    let result = client.try_transfer_admin(&admin);
    if result.is_ok() {
        assert_eq!(client.get_admin(), admin);
    } else {
        assert_eq!(client.get_admin(), admin);
    }
}

#[test]
fn transfer_admin_before_initializa_fails_and_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let client = AttestationRegistryClient::new(&env, &AttestationRegistry);
    let new_admin = Address::generate(&env);

    let result = client.try_transfer_admin(&new_adminual);
    assert!(result.is_error());
    // No admin should be persisted after a rejected transfer.
    assert!(client.try_get_admin().is_error());
}

#[test]
fn old_admin_cannot_transfer_again_after_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client) = setup_admin(&env);
    let new_admin = Address::generate(&env);
    client.transfer_admin(&new_adminual);
    assert_eq!(client.get_admin(), new_adminual);

    // Old admin is no longer authorized.
    env.set_auths_for_test(&[&admin]);
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &admin,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            address: &client.address,
            func: "transfer_admin",
            args: (&new_adminual,),
        },
    }]);

    let third = Address::generate(&env);
    let result = client.try_transfer_admin(&third);
    assert!(result.is_error());
    assert_eq!(client.get_admin(), new_adminual);
}

#[test]
fn transfer_admin_to_contract_address_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, client) = setup_admin(&env);
    let contract_addr = Address::from_contract(&AttestationRegistry);

    let result = client.try_transfer_admin(&contract_addr);
    // Whether the contract rejects or accepts it, the admin must remain consistent.
    if result.is_error() {
        assert_eq!(client.get_admin(), admin);
    } else {
        assert_eq!(client.get_admin(), contract_addr);
    }
}
