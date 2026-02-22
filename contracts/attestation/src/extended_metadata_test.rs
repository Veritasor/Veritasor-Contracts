//! Tests for extended attestation metadata (currency and net/gross).

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String};

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn test_submit_without_metadata_backward_compat() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32, &None);

    let att = client.get_attestation(&business, &period).unwrap();
    assert_eq!(att.0, root);
    assert!(client
        .get_attestation_metadata(&business, &period)
        .is_none());
}

#[test]
fn test_submit_with_metadata() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let currency = String::from_str(&env, "USD");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &true,
    );

    let meta = client.get_attestation_metadata(&business, &period).unwrap();
    assert_eq!(meta.currency_code, currency);
    assert!(meta.is_net);
}

#[test]
fn test_get_attestation_metadata_gross() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-Q1");
    let root = BytesN::from_array(&env, &[2u8; 32]);
    let currency = String::from_str(&env, "EUR");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &false,
    );

    let meta = client.get_attestation_metadata(&business, &period).unwrap();
    assert_eq!(meta.currency_code, String::from_str(&env, "EUR"));
    assert!(!meta.is_net);
}

#[test]
fn test_currency_code_validation_three_chars() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let currency = String::from_str(&env, "GBP");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &true,
    );

    let meta = client.get_attestation_metadata(&business, &period).unwrap();
    assert_eq!(meta.currency_code, String::from_str(&env, "GBP"));
}

#[test]
#[should_panic(expected = "currency code cannot be empty")]
fn test_currency_code_empty_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let currency = String::from_str(&env, "");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &true,
    );
}

#[test]
#[should_panic(expected = "currency code must be at most")]
fn test_currency_code_too_long_panics() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let currency = String::from_str(&env, "USDC");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &true,
    );
}

#[test]
fn test_currency_code_three_chars_allowed() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    let currency = String::from_str(&env, "USD");

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &currency,
        &true,
    );
    let meta = client.get_attestation_metadata(&business, &period).unwrap();
    assert_eq!(meta.currency_code, String::from_str(&env, "USD"));
}

#[test]
fn test_metadata_missing_for_old_attestation() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-01");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation(&business, &period, &root, &1_700_000_000u64, &1u32, &None);

    assert!(client.get_attestation(&business, &period).is_some());
    assert!(client
        .get_attestation_metadata(&business, &period)
        .is_none());
}

#[test]
fn test_multiple_attestations_different_metadata() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation_with_metadata(
        &business,
        &String::from_str(&env, "2026-01"),
        &root,
        &1u64,
        &1u32,
        &String::from_str(&env, "USD"),
        &true,
    );
    client.submit_attestation_with_metadata(
        &business,
        &String::from_str(&env, "2026-02"),
        &root,
        &2u64,
        &1u32,
        &String::from_str(&env, "EUR"),
        &false,
    );

    let m1 = client
        .get_attestation_metadata(&business, &String::from_str(&env, "2026-01"))
        .unwrap();
    let m2 = client
        .get_attestation_metadata(&business, &String::from_str(&env, "2026-02"))
        .unwrap();
    assert_eq!(m1.currency_code, String::from_str(&env, "USD"));
    assert_eq!(m2.currency_code, String::from_str(&env, "EUR"));
    assert!(m1.is_net);
    assert!(!m2.is_net);
}

#[test]
fn test_verify_attestation_unchanged_with_metadata() {
    let (env, client, _admin) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);

    client.submit_attestation_with_metadata(
        &business,
        &period,
        &root,
        &1_700_000_000u64,
        &1u32,
        &String::from_str(&env, "USD"),
        &true,
    );

    assert!(client.verify_attestation(&business, &period, &root));
}
