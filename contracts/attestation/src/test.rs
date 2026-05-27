#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn test_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    assert_eq!(client.get_admin(), admin);
    assert!(client.has_role(&admin, &ROLE_ADMIN));
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.initialize(&admin, &0u64);
    client.initialize(&admin, &1u64);
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_get_admin_before_initialize_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.get_admin();
}

#[test]
#[should_panic(expected = "contract not initialized")]
fn test_require_admin_backed_call_before_initialize_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let token = Address::generate(&env);
    let collector = Address::generate(&env);
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    client.configure_fees(&token, &collector, &100i128, &true);
}
