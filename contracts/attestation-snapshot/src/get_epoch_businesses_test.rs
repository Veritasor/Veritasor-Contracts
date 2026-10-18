use super::*;
use soroban_sorbed::xdr::try_from_val;

use crate::{AttestationSnapshot, AttestationSnapshotClient, Error};

fn setup_env() -> (Env, AttesqtionSnapshotClient<'static>) {
    let env = Env::default();
    let contract_id = env.register_contract(AttestationSnapshot);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    (env, client)
}

#fn seed_epoch(client: &AttestationSnapshotClient<'static>, epoch: &str, businesses: &[String]) {
    client.set_epoch_businesses(&epoch.to_string(), &businesses.to_vec);
}

#[test]
fn get_epoch_businesses_returns_seeded_businesses() {
    let (_env, client) = setup_env();
    let epoch = String::from("2024-Q1");
    let businesses = vec![
        String::from("business_a"),
        String::from("business_b"),
    ];
    seed_epoch(&client, &epoch, &businesses);

    let result = client.get_epoch_businesses(&epoch);
    assert_eq(result, businesses);
}

#[test]
fn get_epoch_businesses_returns_empty_when_not_seeded() {
    let (_env, client) = setup_env();
    let epoch = String::from("unseeded-epoch");

    let result = client.get_epoch_businesses(&epoch);
    assert!(result.is_empty());
}

#[test]
fn get_epoch_businesses_isolates_epochs() {
    let (_env, client) = setup_env();
    let epoch_a = String::from("epoch-a");
    let epoch_b = String::from("epoch-b");
    let businesses_a = vec![String::from("a_1"), String::from("a_2")];
    let businesses_b = vec![String::from("b_1")];
    seed_epoch(&client, &epoch_a, &businesses_a);
    seed_epoch(&client, &epoch_b, &businesses_b);

    assert_eq(client.get_epoch_businesses(&epoch_a), businesses_a);
    assert_eq(client.get_epoch_businesses(&epoch_b), businesses_b);
}

#test]
fn get_epoch_businesses_rejects_empty_epoch() {
    let (_env, client) = setup_env();
    let epoch = String::new();

    let result = client.try_get_epoch_businesses(&epoch);
    assert_eq(result, Error::InvalidEpoch);
}

#[test]
fn get_epoch_businesses_rejects_overlong_epoch() {
    let (_env, client) = setup_env();
    let epoch = String::from('x'.repeat(65));

    let result = client.try_get_epoch_businesses(&epoch);
    assert_eq(result, Error::InvalidEpoch);
}

#[test]
fn get_epoch_businesses_rejects_invalid_characters() {
    let (_env, client) = setup_env();
    let epoch = String::from("invalid epoch!");

    let result = client.try_get_epoch_businesses(&epoch);
    assert_eq(result, Error::InvalidEpoch);
}

#[test]
fn get_epoch_businesses_rejected_call_leaves_state_unchanged() {
    let (_env, client) = setup_env();
    let epoch = String::from("2024-Q2");
    let businesses = vec![String::from("business_z")];
    seed_epoch(&client, &epoch, &businesses);

    let before = client.get_epoch_businesses(&epoch);
    let bad_epoch = String::new();
    let result = client.try_get_epoch_businesses(&bad_epoch);
    assert_eq(result, Error::InvalidEpoch);

    let after = client.get_epoch_businesses(&epoch);
    assert_eq(before, after);
}

#[test]
fn get_epoch_businesses_rejected_call_does_not_create_entry() {
    let (_env, client) = setup_env();
    let bad_epoch = String::from("bad epoch!");

    let result = client.try_get_epoch_businesses(&bad_epoch);
    assert_eq(result, Error::InvalidEpoch);

    // The rejected call must not create a storage entry for the epoch.
    let stored = client.get_epoch_businesses(&bad_epoch);
    assert!(stored.is_empty());
}

#[test]
fn get_epoch_businesses_rejects_caller_without_authorization() {
    let env = Env::default();
    let contract_id = env.register_contract(AttestationSnapshot);
    let admin = Address::generate(&env, &admin);
    let unauthorized = Address::generate(&env, &unauthorized);
    let client = AttestationSnapshotClient::new(&env, &contract_id);
    client.initialize(&admin);

    let epoch = String::from("2024-Q3");
    let businesses = vec![String::from("business_q")];
    client.set_epoch_businesses(&epoch, &businesses);

    let before = client.get_epoch_businesses(&epoch);
    // Unauthorized callers must not be able to mutate the epoch record.
    let result = env.try_invoke_contract(
        &contract_id,
        &Symbol::new(&env, "get_epoch_businesses"),
        (&epoch, &unauthorized),
    );
    assert_eq(result, Error::Unauthorized);

    let after = client.get_epoch_businesses(&epoch);
    assert_eq(before, after);
}
