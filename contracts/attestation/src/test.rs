//! Core attestation tests — verifies submit, get, verify, and duplicate
//! prevention. These tests run without fee configuration (backward compat).

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

/// Helper: register the contract and return a client.
fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env));
    (env, client)
}

#[test]
fn submit_and_get_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1_700_000_000u64;
    let version = 1u32;

    client.submit_attestation(&business, &period, &root, &timestamp, &version);

    let (stored_root, stored_ts, stored_ver, stored_fee) =
        client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored_root, root);
    assert_eq!(stored_ts, timestamp);
    assert_eq!(stored_ver, version);
    // No fees configured — fee_paid should be 0.
    assert_eq!(stored_fee, 0i128);
}

#[test]
fn verify_attestation() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32);

    assert!(client.verify_attestation(&business, &period, &root));
    let other_root = BytesN::from_array(&env, &[3u8; 32]);
    assert!(!client.verify_attestation(&business, &period, &other_root));
}

#[test]
#[should_panic(expected = "attestation already exists")]
fn duplicate_attestation_panics() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[0u8; 32]);

    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32);
    // Second submission for the same (business, period) must panic.
    client.submit_attestation(&business, &period, &root, &1_700_000_001u64, &1u32);
}

#[test]
fn attestation_count_increments() {
    let (env, client) = setup();

    let business = Address::generate(&env);
    assert_eq!(client.get_business_count(&business), 0);

    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-01"),
        &root,
        &1u64,
        &1u32,
    );
    assert_eq!(client.get_business_count(&business), 1);

    let root2 = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(
        &business,
        &String::from_str(&env, "2026-02"),
        &root2,
        &2u64,
        &1u32,
    );
    assert_eq!(client.get_business_count(&business), 2);
}
