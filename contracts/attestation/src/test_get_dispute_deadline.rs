//! Focused adversarial coverage for `AttestationContract::get_dispute_deadline`.

use super::dispute::{
    DISPUTE_DEADLINE_SECONDS, MAX_DISPUTE_DEADLINE_SECONDS, MIN_DISPUTE_DEADLINE_SECONDS,
};
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

#[test]
fn uninitialized_contract_returns_default_without_authorization() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    env.mock_auths(&[]);
    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), DISPUTE_DEADLINE_SECONDS);
}

#[test]
fn unauthenticated_reads_return_configured_boundary_values_unchanged() {
    let (env, client, admin) = setup();

    client.set_dispute_deadline(&admin, &MIN_DISPUTE_DEADLINE_SECONDS);
    env.mock_auths(&[]);
    assert_eq!(client.get_dispute_deadline(), MIN_DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), MIN_DISPUTE_DEADLINE_SECONDS);

    env.mock_all_auths();
    client.set_dispute_deadline(&admin, &MAX_DISPUTE_DEADLINE_SECONDS);
    env.mock_auths(&[]);
    assert_eq!(client.get_dispute_deadline(), MAX_DISPUTE_DEADLINE_SECONDS);
    assert_eq!(client.get_dispute_deadline(), MAX_DISPUTE_DEADLINE_SECONDS);
}