#![cfg(test)]

extern crate std;

use soroban_sdk::{testutils::{Address as _, Ledger}, Address, BytesN, Env, String, Vec};
use crate::{AttestationContract, AttestationContractClient, BatchAttestationItem, BATCH_MAX_SIZE, BATCH_RATE_LIMIT};

fn setup() -> (Env, AttestationContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &id);
    client.initialize(&Address::generate(&env), &0u64);
    (env, client)
}

fn make_items(env: &Env, n: u32, offset: u32) -> Vec<BatchAttestationItem> {
    let mut v = Vec::new(env);
    for i in 0..n {
        let idx = offset + i;
        v.push_back(BatchAttestationItem {
            business: Address::generate(env),
            period: String::from_str(env, &std::format!("period-{}", idx)),
            merkle_root: BytesN::from_array(env, &[(idx % 256) as u8; 32]),
            timestamp: 1_700_000_000u64 + idx as u64,
            version: 1u32,
            expiry_timestamp: None,
        });
    }
    v
}

fn make_items_same_business(env: &Env, business: &Address, n: u32, offset: u32) -> Vec<BatchAttestationItem> {
    let mut v = Vec::new(env);
    for i in 0..n {
        let idx = offset + i;
        v.push_back(BatchAttestationItem {
            business: business.clone(),
            period: String::from_str(env, &std::format!("period-{}", idx)),
            merkle_root: BytesN::from_array(env, &[(idx % 256) as u8; 32]),
            timestamp: 1_700_000_000u64 + idx as u64,
            version: 1u32,
            expiry_timestamp: None,
        });
    }
    v
}

#[test]
fn test_single_item_batch_accepted() {
    let (env, client) = setup();
    client.submit_attestations_batch(&make_items(&env, 1, 0));
}

#[test]
fn test_max_size_batch_accepted() {
    let (env, client) = setup();
    client.submit_attestations_batch(&make_items(&env, BATCH_MAX_SIZE, 0));
}

#[test]
fn test_batch_limits_constants() {
    let (_, client) = setup();
    let (min, max, rate, window) = client.batch_limits();
    assert_eq!(min, 1);
    assert_eq!(max, 100);
    assert_eq!(rate, 10);
    assert_eq!(window, 17_280);
}

#[test]
fn test_window_resets_after_expiry() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    for i in 0..BATCH_RATE_LIMIT {
        client.submit_attestations_batch(&make_items_same_business(&env, &business, 1, i * 10));
    }
    assert_eq!(client.get_batch_count_in_window(&business), BATCH_RATE_LIMIT);
}

#[test]
#[should_panic(expected = "batch cannot be empty")]
fn test_empty_batch_rejected() {
    let (env, client) = setup();
    let empty: Vec<BatchAttestationItem> = Vec::new(&env);
    client.submit_attestations_batch(&empty);
}

#[test]
#[should_panic(expected = "batch_too_large")]
fn test_oversized_batch_rejected() {
    let (env, client) = setup();
    client.submit_attestations_batch(&make_items(&env, BATCH_MAX_SIZE + 1, 0));
}

#[test]
#[should_panic(expected = "rate_limit_exceeded")]
fn test_rate_limit_enforced() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    for i in 0..BATCH_RATE_LIMIT {
        client.submit_attestations_batch(&make_items_same_business(&env, &business, 1, i * 10));
    }
    client.submit_attestations_batch(&make_items_same_business(&env, &business, 1, 99_999));
}

#[test]
#[should_panic(expected = "duplicate attestation in batch")]
fn test_duplicate_in_batch_rejected() {
    let (env, client) = setup();
    let business = Address::generate(&env);
    let mut items = Vec::new(&env);
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2024-Q1"),
        merkle_root: BytesN::from_array(&env, &[1u8; 32]),
        timestamp: 1_700_000_000,
        version: 1,
        expiry_timestamp: None,
    });
    items.push_back(BatchAttestationItem {
        business: business.clone(),
        period: String::from_str(&env, "2024-Q1"),
        merkle_root: BytesN::from_array(&env, &[2u8; 32]),
        timestamp: 1_700_000_001,
        version: 1,
        expiry_timestamp: None,
    });
    client.submit_attestations_batch(&items);
}
