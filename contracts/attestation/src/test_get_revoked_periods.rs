#![cfg(test)]

//! Focused adversarial coverage for the read-only `get_revoked_periods` query.

use crate::access_control::ROLE_BUSINESS;
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Symbol, Vec};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn register_business(client: &AttestationContractClient, admin: &Address, business: &Address) {
    let _ = client.try_grant_role(admin, business, &ROLE_BUSINESS);
    let _ = client.try_register_business(
        business,
        &BytesN::from_array(&client.env, &[1u8; 32]),
        &Symbol::new(&client.env, "US"),
        &Vec::new(&client.env),
    );
    let _ = client.try_approve_business(admin, business);
}

fn submit_and_revoke(
    env: &Env,
    client: &AttestationContractClient,
    admin: &Address,
    business: &Address,
    period: &String,
    seed: u8,
) {
    register_business(client, admin, business);
    client.submit_attestation(
        business,
        period,
        &BytesN::from_array(env, &[seed; 32]),
        &1_700_000_000u64,
        &1u32,
        &0i128,
        &None,
        &None,
    );
    client.revoke_attestation(
        business,
        business,
        period,
        &String::from_str(env, "focused test"),
        &0u64,
    );
}

#[test]
fn get_revoked_periods_returns_empty_for_uninitialized_businesses() {
    let (env, client, _admin) = setup();
    let first_business = Address::generate(&env);
    let second_business = Address::generate(&env);

    assert_eq!(client.get_revoked_periods(&first_business).len(), 0);
    assert_eq!(client.get_revoked_periods(&second_business).len(), 0);
    assert_eq!(client.get_revoked_periods(&client.address).len(), 0);
}

#[test]
fn get_revoked_periods_returns_periods_in_revocation_order() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let periods = ["2026-01", "2026-02", "2026-03"];

    for (index, value) in periods.iter().enumerate() {
        let period = String::from_str(&env, value);
        submit_and_revoke(&env, &client, &admin, &business, &period, (index + 1) as u8);
    }

    let actual = client.get_revoked_periods(&business);
    assert_eq!(actual.len(), periods.len() as u32);
    for (index, value) in periods.iter().enumerate() {
        assert_eq!(
            actual.get(index as u32).unwrap(),
            String::from_str(&env, value)
        );
    }
}

#[test]
fn get_revoked_periods_isolated_by_business_address() {
    let (env, client, admin) = setup();
    let first_business = Address::generate(&env);
    let second_business = Address::generate(&env);
    let first_period = String::from_str(&env, "2026-04");
    let second_period = String::from_str(&env, "2026-05");

    submit_and_revoke(&env, &client, &admin, &first_business, &first_period, 4);
    submit_and_revoke(&env, &client, &admin, &second_business, &second_period, 5);

    assert_eq!(client.get_revoked_periods(&first_business).len(), 1);
    assert_eq!(
        client.get_revoked_periods(&first_business).get(0),
        Some(first_period)
    );
    assert_eq!(client.get_revoked_periods(&second_business).len(), 1);
    assert_eq!(
        client.get_revoked_periods(&second_business).get(0),
        Some(second_period)
    );
}

#[test]
fn failed_duplicate_revocation_leaves_the_query_result_unchanged() {
    let (env, client, admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-06");

    submit_and_revoke(&env, &client, &admin, &business, &period, 6);
    let before = client.get_revoked_periods(&business);

    let rejected = client.try_revoke_attestation(
        &business,
        &business,
        &period,
        &String::from_str(&env, "duplicate"),
        &0u64,
    );
    assert!(rejected.is_err());
    assert_eq!(client.get_revoked_periods(&business), before);
}
