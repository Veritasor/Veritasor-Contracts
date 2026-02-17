#![cfg(test)]
use super::*;
use soroban_sdk::{Address, BytesN, Env, String};

#[test]
fn submit_and_get_attestation() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let timestamp = 1700000000u64;
    let version = 1u32;

    client.submit_attestation(&business, &period, &root, &timestamp, &version);

    let stored = client.get_attestation(&business, &period).unwrap();
    assert_eq!(stored.0, root);
    assert_eq!(stored.1, timestamp);
    assert_eq!(stored.2, version);
}

#[test]
fn verify_attestation() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[2u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);

    assert!(client.verify_attestation(&business, &period, &root));
    let other_root = BytesN::from_array(&env, &[3u8; 32]);
    assert!(!client.verify_attestation(&business, &period, &other_root));
}

#[test]
#[should_panic(expected = "attestation already exists")]
fn duplicate_attestation_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);

    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[0u8; 32]);

    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.submit_attestation(&business, &period, &root, &1700000001u64, &1u32);
}
